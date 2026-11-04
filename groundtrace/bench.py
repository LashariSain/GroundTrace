"""
Multi-model benchmark: same fixed input, several providers, compare output.

  # run a benchmark (results are persisted to the ledger by default)
  python -m groundtrace.bench run offline ollama:llama3.1 [--task summary|ioc] [--out f.json]

  # compare across every stored run
  python -m groundtrace.bench leaderboard [--task summary|ioc]
  python -m groundtrace.bench history [--task summary] [--limit 20]

  # pin a production winner + fallback per task (a product decision)
  python -m groundtrace.bench select summary --winner ollama:qwen2.5 --fallback offline --reason "..."
  python -m groundtrace.bench selection   # show current pins + what the data suggests

Per model a `run` records latency, output, error, and a grounding check: every
number/CVE id/KEV-style fact in the output must appear in the input facts
(flags likely hallucinations), plus whether the output respects the
3-sentence format. The ledger (SQLite, `GROUNDTRACE_DB_PATH`) keeps these across
runs so model quality can be tracked over time instead of one-off JSON files.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path

from .bench_store import BenchStore
from .llm import run_prompt
from .unified import analyze_unified, _facts

_TOKEN = re.compile(r"CVE-\d{4}-\d{4,}|\d+(?:\.\d+)?")


def grounding(facts: str, output: str) -> dict:
    known = set(_TOKEN.findall(facts))
    used = set(_TOKEN.findall(output))
    ungrounded = sorted(used - known)
    sentences = [s for s in re.split(r"(?<=[.!?])\s+", output.strip()) if s]
    return {"ungrounded_tokens": ungrounded,
            "hallucination_flag": bool(ungrounded),
            "sentence_count": len(sentences)}


def sample_facts() -> str:
    p = Path(__file__).parent / "data" / "sample_cve.json"
    raw = json.loads(p.read_text(encoding="utf-8"))
    if isinstance(raw.get("published"), str):
        raw["published"] = date.fromisoformat(raw["published"])
    dd, pd = raw.pop("disclosure_date", None), raw.pop("patch_date", None)
    rep = analyze_unified(raw, in_kev=raw.pop("in_kev", False), epss=raw.pop("epss", None),
                          disclosure_date=date.fromisoformat(dd) if dd else None,
                          patch_date=date.fromisoformat(pd) if pd else None)
    return _facts(rep.finding, rep.signals, rep.underground_priority)


_SAMPLE_POST = (
    "Selling a working RCE exploit for Fortinet FortiOS (CVE-2024-21762), "
    "pre-auth, unpatched on latest. Price: 2.5 BTC, DM for details. This is "
    "being used by APT36 in active campaigns against government targets. "
    "Sample hash: 5f4dcc3b5aa765d61d8327deb882cf99. C2 server at "
    "185.220.101.47, backup domain evil-c2panel.ru."
)


def _bench_ioc(models: list[str]) -> list[dict]:
    from darkfeeds.llm_extract import extract_with_llm
    results = []
    for m in models:
        row = {"model": m}
        try:
            r = extract_with_llm(_SAMPLE_POST, provider=m)
            row.update(latency_s=r.latency_s, data=r.data, rejected=r.rejected,
                       parse_error=r.parse_error, raw_output=r.raw_output)
        except Exception as e:
            row["error"] = f"{type(e).__name__}: {e}"
        results.append(row)
        print(f"{m:30} {row.get('latency_s', '-')}s "
              f"rejected={row.get('rejected', {}) or '-'} "
              f"parse_err={row.get('parse_error', '')} "
              f"err={row.get('error', '')}")
    return results


def _bench_summary(models: list[str]) -> tuple[list[dict], str]:
    facts = sample_facts()
    results = []
    for m in models:
        row = {"model": m}
        try:
            r = run_prompt("threat_summary", facts, provider=m)
            row.update(latency_s=r.latency_s, output=r.text,
                       prompt_version=r.prompt_version, **grounding(facts, r.text))
        except Exception as e:  # provider down / model missing
            row["error"] = f"{type(e).__name__}: {e}"
        results.append(row)
        print(f"{m:30} {row.get('latency_s', '-')}s "
              f"halluc={row.get('hallucination_flag', '-')} "
              f"err={row.get('error', '')}")
    return results, facts


def _prompt_version(results: list[dict]) -> str:
    for r in results:
        if r.get("prompt_version"):
            return r["prompt_version"]
    return ""


def _cmd_run(args) -> int:
    task = args.task
    if task == "ioc":
        results = _bench_ioc(args.models)
        input_label, prompt_version = "sample_post", "ioc_extraction:v1"
    else:
        results, _ = _bench_summary(args.models)
        input_label, prompt_version = "sample_cve", _prompt_version(results)

    if args.out:
        Path(args.out).write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")

    if not args.no_save:
        store = BenchStore(args.db)
        try:
            run_id = store.start_run(task, input_label=input_label,
                                     prompt_version=prompt_version, notes=args.notes or "")
            for row in results:
                store.save_result(run_id, task, row)
            store.finish_run(run_id, len(results))
            print(f"\nsaved bench run #{run_id} ({len(results)} models, task={task})")
        finally:
            store.close()
    return 0


def _cmd_leaderboard(args) -> int:
    store = BenchStore(args.db)
    try:
        board = store.leaderboard(args.task)
        if not board:
            print(f"no stored results for task={args.task}; run a benchmark first")
            return 0
        print(f"leaderboard - task={args.task} (higher score is better)\n")
        if args.task == "summary":
            print(f"{'#':<3}{'model':30}{'score':>7}{'runs':>6}{'err':>7}"
                  f"{'halluc':>8}{'fmt_ok':>8}{'latency':>9}")
            for i, a in enumerate(board, 1):
                print(f"{i:<3}{a['model']:30}{a['score']:>7}{a['runs']:>6}"
                      f"{a['error_rate']:>7}{a['hallucination_rate']:>8}"
                      f"{a['format_ok_rate']:>8}"
                      f"{(a['avg_latency_s'] if a['avg_latency_s'] is not None else '-'):>9}")
        else:
            print(f"{'#':<3}{'model':30}{'score':>7}{'runs':>6}{'err':>7}"
                  f"{'parse_err':>10}{'avg_rej':>9}{'latency':>9}")
            for i, a in enumerate(board, 1):
                print(f"{i:<3}{a['model']:30}{a['score']:>7}{a['runs']:>6}"
                      f"{a['error_rate']:>7}{a['parse_error_rate']:>10}"
                      f"{a['avg_rejected']:>9}"
                      f"{(a['avg_latency_s'] if a['avg_latency_s'] is not None else '-'):>9}")
    finally:
        store.close()
    return 0


def _cmd_history(args) -> int:
    store = BenchStore(args.db)
    try:
        runs = store.list_runs(task=args.task, limit=args.limit)
        if not runs:
            print("no stored bench runs yet")
            return 0
        for r in runs:
            print(f"#{r['id']:<4} {r['started_at']}  task={r['task']:8} "
                  f"models={r['model_count']:<3} input={r['input_label']} "
                  f"prompt={r['prompt_version']}")
            if args.verbose:
                for res in store.results_for_run(r["id"]):
                    flag = (f"halluc={res['hallucination']} sent={res['sentences']}"
                            if res["task"] == "summary"
                            else f"rejected={res['rejected']} parse_err={res['parse_error']}")
                    err = f" ERROR {res['error']}" if not res["ok"] else ""
                    print(f"       {res['model']:28} {res['latency_s']}s {flag}{err}")
    finally:
        store.close()
    return 0


def _cmd_select(args) -> int:
    store = BenchStore(args.db)
    try:
        store.set_selection(args.task, args.winner, args.fallback or "", args.reason or "")
        print(f"pinned task={args.task}: winner={args.winner} "
              f"fallback={args.fallback or '-'}")
    finally:
        store.close()
    return 0


def _cmd_selection(args) -> int:
    store = BenchStore(args.db)
    try:
        pins = {p["task"]: p for p in store.get_selection()}
        tasks = [args.task] if args.task else ["summary", "ioc"]
        for task in tasks:
            pin = pins.get(task)
            print(f"task={task}")
            if pin:
                print(f"  pinned:    winner={pin['winner']} fallback={pin['fallback'] or '-'}")
                if pin["reason"]:
                    print(f"             reason: {pin['reason']}")
                print(f"             updated: {pin['updated_at']}")
            else:
                print("  pinned:    (none)")
            sug = store.suggest_selection(task)
            if sug["winner"]:
                print(f"  data says: winner={sug['winner']} fallback={sug['fallback'] or '-'} "
                      f"(from {len(sug['leaderboard'])} models)")
            else:
                print("  data says: (no benchmark results yet)")
    finally:
        store.close()
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m groundtrace.bench")
    ap.add_argument("--db", help="override GROUNDTRACE_DB_PATH for this command")
    sub = ap.add_subparsers(dest="cmd")

    p_run = sub.add_parser("run", help="run a benchmark across models")
    p_run.add_argument("models", nargs="+")
    p_run.add_argument("--task", choices=["summary", "ioc"], default="summary",
                       help="summary = threat_summary narrative; ioc = IOC extraction")
    p_run.add_argument("--out", help="also write raw results to this JSON file")
    p_run.add_argument("--no-save", action="store_true", help="don't persist to the ledger")
    p_run.add_argument("--notes", help="free-text note stored with the run")
    p_run.set_defaults(func=_cmd_run)

    p_lb = sub.add_parser("leaderboard", help="aggregate ranking across all stored runs")
    p_lb.add_argument("--task", choices=["summary", "ioc"], default="summary")
    p_lb.set_defaults(func=_cmd_leaderboard)

    p_hist = sub.add_parser("history", help="list past benchmark runs")
    p_hist.add_argument("--task", choices=["summary", "ioc"])
    p_hist.add_argument("--limit", type=int, default=20)
    p_hist.add_argument("-v", "--verbose", action="store_true", help="show per-model rows")
    p_hist.set_defaults(func=_cmd_history)

    p_sel = sub.add_parser("select", help="pin a winner/fallback for a task")
    p_sel.add_argument("task", choices=["summary", "ioc"])
    p_sel.add_argument("--winner", required=True)
    p_sel.add_argument("--fallback", default="")
    p_sel.add_argument("--reason", default="")
    p_sel.set_defaults(func=_cmd_select)

    p_cur = sub.add_parser("selection", help="show pinned + data-suggested selections")
    p_cur.add_argument("--task", choices=["summary", "ioc"])
    p_cur.set_defaults(func=_cmd_selection)

    args = ap.parse_args(argv)
    if not args.cmd:
        ap.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
