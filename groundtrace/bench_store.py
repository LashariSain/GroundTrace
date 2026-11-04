"""
Persisted benchmark ledger for the multi-model layer.

A one-off `bench.json` tells you which model won *this morning*; it can't tell
you whether a model's grounding has drifted, whether a new release is faster,
or which model to pin for a task. This stores every benchmark run and its
per-model results in the same SQLite DB as findings (`GROUNDTRACE_DB_PATH`), so
evaluations accumulate and can be compared over time.

Three tables:
  - bench_runs      one row per invocation (task, input, prompt version, time)
  - bench_results   one row per model in that run (latency + task metrics)
  - bench_selection the pinned winner/fallback per task (a product decision)

`leaderboard()` aggregates results across all runs into a per-model quality
score, and `suggest_selection()` reads the top two off it.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .config import get_config

_SCHEMA = """
CREATE TABLE IF NOT EXISTS bench_runs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    task           TEXT NOT NULL,          -- summary | ioc
    input_label    TEXT DEFAULT '',        -- which fixed input was used
    prompt_version TEXT DEFAULT '',
    model_count    INTEGER DEFAULT 0,
    started_at     TEXT NOT NULL,
    notes          TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS bench_results (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        INTEGER NOT NULL REFERENCES bench_runs(id),
    model         TEXT NOT NULL,
    task          TEXT NOT NULL,
    latency_s     REAL,
    ok            INTEGER DEFAULT 1,       -- 0 if the provider raised
    error         TEXT DEFAULT '',
    -- summary-task metrics
    hallucination INTEGER,                 -- 1 if ungrounded tokens present
    ungrounded    INTEGER,                 -- count of ungrounded tokens
    sentences     INTEGER,
    -- ioc-task metrics
    rejected      INTEGER,                 -- count of hallucinated IOCs dropped
    parse_error   TEXT DEFAULT '',
    -- common
    output_summary TEXT DEFAULT '',        -- truncated output / extracted data
    recorded_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_bench_results_model ON bench_results(model);
CREATE INDEX IF NOT EXISTS idx_bench_results_task ON bench_results(task);
CREATE INDEX IF NOT EXISTS idx_bench_results_run ON bench_results(run_id);

CREATE TABLE IF NOT EXISTS bench_selection (
    task       TEXT PRIMARY KEY,           -- summary | ioc
    winner     TEXT,
    fallback   TEXT,
    reason     TEXT DEFAULT '',
    updated_at TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class BenchStore:
    def __init__(self, db_path: Optional[str] = None):
        p = Path(db_path or get_config().db_path).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        # Same multi-process story as FindingStore: the bench CLI may run while
        # the API/watcher touch the same file. WAL + busy_timeout, not failure.
        self.conn = sqlite3.connect(str(p), check_same_thread=False, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=30000")
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    # --- recording ----------------------------------------------------------
    def start_run(self, task: str, *, input_label: str = "",
                  prompt_version: str = "", notes: str = "") -> int:
        cur = self.conn.execute(
            "INSERT INTO bench_runs (task, input_label, prompt_version, started_at, notes) "
            "VALUES (?, ?, ?, ?, ?)",
            (task, input_label, prompt_version, _now(), notes))
        self.conn.commit()
        return cur.lastrowid

    def save_result(self, run_id: int, task: str, row: dict) -> None:
        """Persist one model's row from a bench run (the dict bench.py builds)."""
        ok = "error" not in row
        g = row  # grounding fields are merged flat into the summary row
        output = row.get("output", "")
        if task == "ioc":
            # No free-form text; summarize the structured extraction instead.
            output = json.dumps(row.get("data", {}), default=str)
        self.conn.execute(
            "INSERT INTO bench_results (run_id, model, task, latency_s, ok, error, "
            "hallucination, ungrounded, sentences, rejected, parse_error, "
            "output_summary, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (run_id, row.get("model", ""), task, row.get("latency_s"),
             int(ok), row.get("error", ""),
             None if not ok else int(bool(g.get("hallucination_flag"))),
             None if not ok else len(g.get("ungrounded_tokens", []) or []),
             g.get("sentence_count"),
             None if not ok else len(_flatten(row.get("rejected", {}))),
             row.get("parse_error", ""),
             (output or "")[:500], _now()))
        self.conn.commit()

    def finish_run(self, run_id: int, model_count: int) -> None:
        self.conn.execute("UPDATE bench_runs SET model_count = ? WHERE id = ?",
                          (model_count, run_id))
        self.conn.commit()

    # --- reading ------------------------------------------------------------
    def list_runs(self, *, task: Optional[str] = None, limit: int = 20) -> list[dict]:
        sql = "SELECT * FROM bench_runs"
        params: list = []
        if task:
            sql += " WHERE task = ?"
            params.append(task)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def results_for_run(self, run_id: int) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM bench_results WHERE run_id = ? ORDER BY id", (run_id,)).fetchall()]

    def leaderboard(self, task: str) -> list[dict]:
        """Aggregate every result for `task` into a per-model quality score.

        Scores run 0..100, higher better; latency is the ordering tiebreaker,
        not part of the score (reliability/grounding matter more than speed).
        """
        rows = self.conn.execute(
            "SELECT * FROM bench_results WHERE task = ?", (task,)).fetchall()
        by_model: dict[str, list] = {}
        for r in rows:
            by_model.setdefault(r["model"], []).append(r)

        board = []
        for model, rs in by_model.items():
            n = len(rs)
            ok = [r for r in rs if r["ok"]]
            n_ok = len(ok)
            error_rate = (n - n_ok) / n if n else 0.0
            latencies = [r["latency_s"] for r in ok if r["latency_s"] is not None]
            avg_latency = round(sum(latencies) / len(latencies), 4) if latencies else None
            agg = {"model": model, "runs": n, "error_rate": round(error_rate, 3),
                   "avg_latency_s": avg_latency}

            if task == "summary":
                halluc_rate = (sum(r["hallucination"] or 0 for r in ok) / n_ok) if n_ok else 1.0
                fmt_ok = (sum(1 for r in ok if r["sentences"] == 3) / n_ok) if n_ok else 0.0
                agg.update(hallucination_rate=round(halluc_rate, 3),
                           format_ok_rate=round(fmt_ok, 3),
                           score=_score_summary(error_rate, halluc_rate, fmt_ok))
            else:  # ioc
                parse_rate = (sum(1 for r in ok if r["parse_error"]) / n_ok) if n_ok else 1.0
                avg_rejected = (sum(r["rejected"] or 0 for r in ok) / n_ok) if n_ok else 0.0
                agg.update(parse_error_rate=round(parse_rate, 3),
                           avg_rejected=round(avg_rejected, 2),
                           score=_score_ioc(error_rate, parse_rate, avg_rejected))
            board.append(agg)

        # best score first; faster wins ties (None latency sorts last)
        board.sort(key=lambda a: (-a["score"],
                                  a["avg_latency_s"] if a["avg_latency_s"] is not None else 1e9))
        return board

    # --- selection (pinned winner/fallback per task) ------------------------
    def set_selection(self, task: str, winner: str, fallback: str = "",
                      reason: str = "") -> None:
        self.conn.execute(
            "INSERT INTO bench_selection (task, winner, fallback, reason, updated_at) "
            "VALUES (?, ?, ?, ?, ?) ON CONFLICT(task) DO UPDATE SET "
            "winner = excluded.winner, fallback = excluded.fallback, "
            "reason = excluded.reason, updated_at = excluded.updated_at",
            (task, winner, fallback, reason, _now()))
        self.conn.commit()

    def get_selection(self, task: Optional[str] = None) -> list[dict]:
        sql = "SELECT * FROM bench_selection"
        params: list = []
        if task:
            sql += " WHERE task = ?"
            params.append(task)
        sql += " ORDER BY task"
        return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def suggest_selection(self, task: str) -> dict:
        """Winner/fallback the current leaderboard would pick (top two).

        Only models that produced at least one successful result are eligible —
        a provider that always errored is never suggested as a winner or
        fallback, however it happens to sort.
        """
        board = self.leaderboard(task)
        eligible = [a for a in board if a["error_rate"] < 1.0]
        return {"task": task,
                "winner": eligible[0]["model"] if eligible else None,
                "fallback": eligible[1]["model"] if len(eligible) > 1 else None,
                "leaderboard": board}

    def close(self) -> None:
        self.conn.close()


def _flatten(d: dict) -> list:
    out: list = []
    for v in (d or {}).values():
        out.extend(v if isinstance(v, list) else [v])
    return out


def _score_summary(error_rate: float, halluc_rate: float, fmt_ok_rate: float) -> float:
    """Reliability (provider answered) and grounding (no invented numbers)
    weigh most; respecting the 3-sentence format is a lighter factor."""
    return round(100 * (0.4 * (1 - error_rate) + 0.4 * (1 - halluc_rate)
                        + 0.2 * fmt_ok_rate), 1)


def _score_ioc(error_rate: float, parse_error_rate: float, avg_rejected: float) -> float:
    """Reliability and valid-JSON output weigh most; the soft cleanliness term
    penalizes a model that invents IOCs the regex ground truth then drops."""
    cleanliness = 1 / (1 + avg_rejected)
    return round(100 * (0.4 * (1 - error_rate) + 0.3 * (1 - parse_error_rate)
                        + 0.3 * cleanliness), 1)
