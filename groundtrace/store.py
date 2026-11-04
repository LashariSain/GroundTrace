"""
SQLite persistence for CVE findings and run history.

Every analysis run is recorded (what was asked, when, how many results), and
each Finding is upserted by CVE id — so re-running `recent` refreshes scores
(EPSS/KEV change over time) instead of piling up duplicates, while
`finding_history` keeps a snapshot per run for "what did we know on date X".
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .models import Finding
from .classify.ai_discovery import detect_ai_discovery

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    mode         TEXT NOT NULL,          -- recent | cve | file | demo | unified
    params       TEXT DEFAULT '{}',      -- JSON of the CLI args that mattered
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    result_count INTEGER DEFAULT 0,
    status       TEXT DEFAULT 'running'  -- running | done | failed
);

CREATE TABLE IF NOT EXISTS findings (
    cve_id         TEXT PRIMARY KEY,
    title          TEXT,
    published      TEXT,
    cvss           REAL,
    cvss_severity  TEXT,
    epss           REAL,
    risk           REAL,
    in_kev         INTEGER DEFAULT 0,
    cwe_ids        TEXT DEFAULT '[]',
    data           TEXT NOT NULL,        -- full Finding.to_dict() JSON
    first_seen     TEXT NOT NULL,
    last_updated   TEXT NOT NULL,
    last_run_id    INTEGER REFERENCES runs(id)
);

CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(cvss_severity);
CREATE INDEX IF NOT EXISTS idx_findings_kev ON findings(in_kev);
CREATE INDEX IF NOT EXISTS idx_findings_risk ON findings(risk);
CREATE INDEX IF NOT EXISTS idx_findings_published ON findings(published);

CREATE TABLE IF NOT EXISTS finding_history (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id    TEXT NOT NULL,
    run_id    INTEGER NOT NULL REFERENCES runs(id),
    epss      REAL,
    risk      REAL,
    in_kev    INTEGER,
    recorded_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_history_cve ON finding_history(cve_id);

CREATE TABLE IF NOT EXISTS alerts (
    key        TEXT PRIMARY KEY,     -- dedup key, e.g. "kev:CVE-2026-1234"
    kind       TEXT NOT NULL,
    title      TEXT NOT NULL,
    detail     TEXT DEFAULT '',
    url        TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    delivered  TEXT DEFAULT ''       -- JSON {channel: result}; '' = baseline, not sent
);

CREATE TABLE IF NOT EXISTS radar (
    cve_id      TEXT PRIMARY KEY,
    score       REAL NOT NULL,
    level       TEXT NOT NULL,           -- hot | warming | watch
    data        TEXT NOT NULL,           -- full radar entry JSON (components + evidence)
    computed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS watchlist (
    term       TEXT PRIMARY KEY COLLATE NOCASE,  -- keyword(s), every word must match
    created_at TEXT NOT NULL
);
"""

_SEARCH_TEXT = ("(cve_id || ' ' || COALESCE(title, '') || ' ' || "
                "COALESCE(json_extract(data, '$.description'), '') || ' ' || "
                "COALESCE(json_extract(data, '$.affected'), ''))")
_SEARCH_TEXT_REFS = (_SEARCH_TEXT[:-1] +
                     " || ' ' || COALESCE(json_extract(data, '$.references'), ''))")


def _like_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _ai_found_by(description, references_json, credits_json=None):
    """SQL function: computed at query time so CVEs stored before the detector
    existed are covered too, with no backfill."""
    def load(s):
        try:
            return json.loads(s) if s else []
        except ValueError:
            return []
    return detect_ai_discovery(description or "", load(references_json), load(credits_json))[0]


_AI_FOUND_SQL = ("ai_found_by(json_extract(data, '$.description'), "
                 "json_extract(data, '$.references'), json_extract(data, '$.credits'))")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class FindingStore:
    def __init__(self, db_path: str):
        p = Path(db_path).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        # timeout/busy_timeout: the API server and the watcher are separate
        # processes writing the same file — wait for a lock, don't fail.
        # WAL lets readers (dashboard) proceed while the watcher writes.
        self.conn = sqlite3.connect(str(p), check_same_thread=False, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=30000")
        self.conn.executescript(_SCHEMA)
        self.conn.commit()
        self.conn.create_function("ai_found_by", 3, _ai_found_by, deterministic=True)

    # --- runs ---------------------------------------------------------------
    def start_run(self, mode: str, params: Optional[dict] = None) -> int:
        cur = self.conn.execute(
            "INSERT INTO runs (mode, params, started_at) VALUES (?, ?, ?)",
            (mode, json.dumps(params or {}, default=str), _now()))
        self.conn.commit()
        return cur.lastrowid

    def finish_run(self, run_id: int, count: int, status: str = "done",
                   params: Optional[dict] = None) -> None:
        self.conn.execute(
            "UPDATE runs SET finished_at = ?, result_count = ?, status = ?, "
            "params = COALESCE(?, params) WHERE id = ?",
            (_now(), count, status,
             json.dumps(params, default=str) if params is not None else None, run_id))
        self.conn.commit()

    def list_runs(self, limit: int = 20) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    # --- findings -----------------------------------------------------------
    def save_findings(self, findings: list[Finding], run_id: int) -> int:
        """Upsert findings; returns how many CVEs were new to the store."""
        now = _now()
        existing = {r[0] for r in self.conn.execute(
            f"SELECT cve_id FROM findings WHERE cve_id IN "
            f"({','.join('?' * len(findings))})",
            [f.cve_id for f in findings]).fetchall()} if findings else set()

        for f in findings:
            # A --no-epss run has epss=None; reuse the last known value so
            # risk (derived from EPSS), the column, and the JSON stay
            # consistent instead of silently falling back to the 0.1 default.
            if f.scores.epss is None and f.cve_id in existing:
                row = self.conn.execute(
                    "SELECT epss FROM findings WHERE cve_id = ?", (f.cve_id,)).fetchone()
                if row and row["epss"] is not None:
                    f.scores.epss = row["epss"]
            d = f.to_dict()
            if d.get("credits") is None and f.cve_id in existing:
                # An NVD re-pull carries no credits; keep the ones fetched earlier.
                row = self.conn.execute(
                    "SELECT json_extract(data, '$.credits') FROM findings WHERE cve_id = ?",
                    (f.cve_id,)).fetchone()
                if row and row[0] is not None:
                    d["credits"] = json.loads(row[0])
            s = d["scores"]
            self.conn.execute("""
                INSERT INTO findings (cve_id, title, published, cvss, cvss_severity,
                    epss, risk, in_kev, cwe_ids, data, first_seen, last_updated, last_run_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    title = excluded.title, cvss = excluded.cvss,
                    cvss_severity = excluded.cvss_severity,
                    epss = COALESCE(excluded.epss, findings.epss),
                    risk = excluded.risk, in_kev = excluded.in_kev,
                    cwe_ids = excluded.cwe_ids, data = excluded.data,
                    last_updated = excluded.last_updated,
                    last_run_id = excluded.last_run_id
            """, (f.cve_id, d.get("title"), d.get("published"), s.get("cvss"),
                  s.get("cvss_severity"), s.get("epss"), s.get("risk"),
                  int(d["disclosure"].get("in_kev", False)),
                  json.dumps(d.get("cwe_ids", [])), json.dumps(d), now, now, run_id))
            self.conn.execute(
                "INSERT INTO finding_history (cve_id, run_id, epss, risk, in_kev, recorded_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (f.cve_id, run_id, s.get("epss"), s.get("risk"),
                 int(d["disclosure"].get("in_kev", False)), now))
        self.conn.commit()
        return len({f.cve_id for f in findings} - existing)

    def missing_epss(self, limit: int = 5000) -> list[str]:
        return [r[0] for r in self.conn.execute(
            "SELECT cve_id FROM findings WHERE epss IS NULL ORDER BY published DESC LIMIT ?",
            (limit,)).fetchall()]

    def missing_credits(self, limit: int = 5000) -> list[str]:
        return [r[0] for r in self.conn.execute(
            "SELECT cve_id FROM findings WHERE json_extract(data, '$.credits') IS NULL "
            "ORDER BY published DESC LIMIT ?", (limit,)).fetchall()]

    def set_credits(self, credits: dict[str, list[str]]) -> int:
        n = 0
        for cve_id, value in credits.items():
            n += self.conn.execute(
                "UPDATE findings SET data = json_set(data, '$.credits', json(?)) WHERE cve_id = ?",
                (json.dumps(value), cve_id)).rowcount
        self.conn.commit()
        return n

    def set_epss(self, scores: dict[str, float]) -> int:
        """Fill in EPSS for stored findings and recompute their risk, keeping
        the columns and the stored JSON consistent."""
        from .models import Scores
        n = 0
        for cve_id, epss in scores.items():
            row = self.conn.execute("SELECT data FROM findings WHERE cve_id = ?", (cve_id,)).fetchone()
            if not row:
                continue
            d = json.loads(row["data"])
            s = d.setdefault("scores", {})
            s["epss"] = epss
            s["risk"] = Scores(cvss=s.get("cvss"), epss=epss,
                               asset_criticality=s.get("asset_criticality", 1.0),
                               in_kev=bool((d.get("disclosure") or {}).get("in_kev"))).risk
            s.pop("explanation", None)  # rebuilt when served
            self.conn.execute("UPDATE findings SET epss = ?, risk = ?, data = ? WHERE cve_id = ?",
                              (epss, s["risk"], json.dumps(d), cve_id))
            n += 1
        self.conn.commit()
        return n

    def query(self, *, severity: Optional[str] = None, kev_only: bool = False,
              since: Optional[str] = None, min_risk: Optional[float] = None,
              search: Optional[str] = None, limit: int = 50,
              include_refs: bool = False, ai_only: bool = False) -> list[dict]:
        sql = ("SELECT cve_id, title, published, cvss, cvss_severity, epss, risk, "
               "in_kev, last_updated, json_extract(data, '$.description') AS _desc, "
               "json_extract(data, '$.references') AS _refs, "
               "json_extract(data, '$.credits') AS _credits FROM findings WHERE 1=1")
        params: list = []
        if ai_only:
            sql += f" AND {_AI_FOUND_SQL} IS NOT NULL"
        if severity:
            sql += " AND cvss_severity = ?"
            params.append(severity.upper())
        if kev_only:
            sql += " AND in_kev = 1"
        if since:
            sql += " AND published >= ?"
            params.append(since)
        if min_risk is not None:
            sql += " AND risk >= ?"
            params.append(min_risk)
        if search:
            # Every word must appear in the id, title, description or affected
            # products (CPE vendor:product). Not the whole JSON blob: that
            # matched reference URLs and analysis boilerplate, so "fortinet"
            # returned CVEs that merely cited a Fortinet blog post.
            # include_refs is the fallback for vulnerability nicknames
            # ("php2shell") that only appear in a write-up's URL.
            text = _SEARCH_TEXT_REFS if include_refs else _SEARCH_TEXT
            for term in search.split():
                sql += f" AND {text} LIKE ? ESCAPE '\\'"
                params.append("%" + _like_escape(term) + "%")
        sql += " ORDER BY in_kev DESC, risk DESC NULLS LAST, published DESC LIMIT ?"
        params.append(limit)
        rows = [dict(r) for r in self.conn.execute(sql, params).fetchall()]
        # Label only the rows returned, not the whole table, for the badge.
        for r in rows:
            r["ai_found_by"] = _ai_found_by(r.pop("_desc"), r.pop("_refs"), r.pop("_credits"))
        return rows

    def get(self, cve_id: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT data FROM findings WHERE cve_id = ?", (cve_id,)).fetchone()
        return json.loads(row["data"]) if row else None

    def history(self, cve_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT run_id, epss, risk, in_kev, recorded_at FROM finding_history "
            "WHERE cve_id = ? ORDER BY id", (cve_id,)).fetchall()
        return [dict(r) for r in rows]

    def last_run(self, mode: str, *, finished: bool = False) -> Optional[dict]:
        sql = "SELECT * FROM runs WHERE mode = ?"
        if finished:
            sql += " AND finished_at IS NOT NULL"
        row = self.conn.execute(sql + " ORDER BY id DESC LIMIT 1", (mode,)).fetchone()
        return dict(row) if row else None

    def alert_counts(self) -> dict:
        """Alerts actually sent somewhere, by kind."""
        rows = self.conn.execute(
            "SELECT kind, COUNT(*) AS n FROM alerts WHERE delivered != '' GROUP BY kind").fetchall()
        return {r["kind"]: r["n"] for r in rows}

    def alert_volume(self) -> dict:
        """Delivered vs baselined, so row count is never read as alert volume.

        Most rows in `alerts` are baseline: recorded on first sight so the
        watcher does not alert on a backlog it has only just loaded. Counting
        the table reports thousands where tens were sent.
        """
        rows = self.conn.execute(
            "SELECT CASE WHEN delivered != '' THEN 'delivered' ELSE 'baselined' END AS state, "
            "kind, COUNT(*) AS n FROM alerts GROUP BY state, kind").fetchall()
        out = {"delivered": {}, "baselined": {}}
        for r in rows:
            out[r["state"]][r["kind"]] = r["n"]
        out["delivered_total"] = sum(out["delivered"].values())
        out["baselined_total"] = sum(out["baselined"].values())
        out["rows_total"] = out["delivered_total"] + out["baselined_total"]
        out["note"] = ("baselined rows were recorded on first sight and never sent; "
                       "only delivered_total is alert volume")
        return out

    def stats(self) -> dict:
        row = self.conn.execute("""
            SELECT COUNT(*) AS total,
                   SUM(cvss_severity = 'CRITICAL') AS critical,
                   SUM(cvss_severity = 'HIGH') AS high,
                   SUM(in_kev) AS kev,
                   (SELECT COUNT(*) FROM runs) AS runs
            FROM findings""").fetchone()
        return dict(row)

    # --- radar --------------------------------------------------------------
    def radar_candidates(self, since: str, extra_ids: list[str]) -> list[dict]:
        """Non-KEV findings published since `since`, plus any of `extra_ids`
        (CVEs in recent threat intel) we hold, whatever their age."""
        sql = ("SELECT cve_id, title, published, cvss, cvss_severity, epss, in_kev "
               "FROM findings WHERE in_kev = 0 AND (published >= ?")
        params: list = [since]
        for i in range(0, len(extra_ids), 500):
            chunk = extra_ids[i:i + 500]
            sql += f" OR cve_id IN ({','.join('?' * len(chunk))})"
            params += chunk
        return [dict(r) for r in self.conn.execute(sql + ")", params).fetchall()]

    def save_radar(self, entries: list[dict]) -> None:
        """Replace the radar snapshot with the latest computation."""
        now = _now()
        self.conn.execute("DELETE FROM radar")
        self.conn.executemany(
            "INSERT INTO radar (cve_id, score, level, data, computed_at) VALUES (?, ?, ?, ?, ?)",
            [(e["cve_id"], e["score"], e["level"], json.dumps(e), now) for e in entries])
        self.conn.commit()

    def get_radar(self, limit: int = 50) -> list[dict]:
        rows = self.conn.execute(
            "SELECT data, computed_at FROM radar ORDER BY score DESC LIMIT ?", (limit,)).fetchall()
        return [dict(json.loads(r["data"]), computed_at=r["computed_at"]) for r in rows]

    # --- watchlist ----------------------------------------------------------
    def watch_terms(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT term, created_at FROM watchlist ORDER BY created_at").fetchall()]

    def add_watch(self, term: str) -> bool:
        """True if newly added (terms are case-insensitive)."""
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO watchlist (term, created_at) VALUES (?, ?)", (term, _now()))
        self.conn.commit()
        return cur.rowcount == 1

    def remove_watch(self, term: str) -> bool:
        cur = self.conn.execute("DELETE FROM watchlist WHERE term = ?", (term,))
        self.conn.commit()
        return cur.rowcount == 1

    # --- alerts -------------------------------------------------------------
    def has_alerts(self, kind: Optional[str] = None) -> bool:
        if kind:
            return self.conn.execute(
                "SELECT 1 FROM alerts WHERE kind = ? LIMIT 1", (kind,)).fetchone() is not None
        return self.conn.execute("SELECT 1 FROM alerts LIMIT 1").fetchone() is not None

    def existing_cves(self, cve_ids: list[str]) -> set[str]:
        if not cve_ids:
            return set()
        return {r[0] for r in self.conn.execute(
            f"SELECT cve_id FROM findings WHERE cve_id IN ({','.join('?' * len(cve_ids))})",
            cve_ids).fetchall()}

    def new_alert_keys(self, keys: list[str]) -> set[str]:
        """Which of these keys have never been recorded."""
        if not keys:
            return set()
        seen = set()
        for i in range(0, len(keys), 500):  # stay under SQLite's variable limit
            chunk = keys[i:i + 500]
            seen |= {r[0] for r in self.conn.execute(
                f"SELECT key FROM alerts WHERE key IN ({','.join('?' * len(chunk))})",
                chunk).fetchall()}
        return set(keys) - seen

    def record_alerts(self, alerts: list, delivered: dict | None) -> None:
        """delivered=None marks them as baseline (seen, deliberately not sent)."""
        now = _now()
        status = json.dumps(delivered) if delivered is not None else ""
        self.conn.executemany(
            "INSERT OR IGNORE INTO alerts (key, kind, title, detail, url, created_at, delivered) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(a.key, a.kind, a.title, a.detail, a.url, now, status) for a in alerts])
        self.conn.commit()

    def list_alerts(self, limit: int = 50, include_baseline: bool = False) -> list[dict]:
        sql = "SELECT * FROM alerts"
        if not include_baseline:
            sql += " WHERE delivered != ''"
        sql += " ORDER BY created_at DESC LIMIT ?"
        return [dict(r) for r in self.conn.execute(sql, (limit,)).fetchall()]

    def close(self) -> None:
        self.conn.close()
