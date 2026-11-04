"""
CLI entrypoint.

  python -m groundtrace demo                      # offline, uses bundled sample
  python -m groundtrace cve CVE-2021-44228        # live (needs network)
  python -m groundtrace file report.json          # analyze your own research JSON
  python -m groundtrace cve CVE-2021-44228 --json # emit structured JSON instead

Add --out report.md to save, and --criticality 0.8 to weight the asset.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date
from pathlib import Path

from . import analyze, analyze_cve, analyze_recent, render_markdown


def _load_sample() -> dict:
    p = Path(__file__).parent / "data" / "sample_cve.json"
    return json.loads(p.read_text(encoding="utf-8"))


def _coerce_dates(raw: dict) -> dict:
    for k in ("published",):
        if isinstance(raw.get(k), str):
            try:
                raw[k] = date.fromisoformat(raw[k])
            except ValueError:
                raw[k] = None
    return raw


def _emit(finding, args):
    if args.json:
        out = json.dumps(finding.to_dict(), indent=2)
    else:
        out = render_markdown(finding)
    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")
        print(f"[+] wrote {args.out}")
    else:
        print(out)


def _persist(mode: str, findings: list, args) -> None:
    """Record the run and upsert its findings. Never fatal — a storage
    problem shouldn't lose the analysis the user just waited for."""
    if args.no_save or not findings:
        return
    from .config import get_config
    from .store import FindingStore
    try:
        store = FindingStore(get_config().db_path)
        keys = ("target", "criticality") + (
            ("days", "min_severity", "max_cves", "no_epss") if mode == "recent" else ())
        params = {k: v for k, v in vars(args).items()
                  if k in keys and v not in (None, False)}
        run_id = store.start_run(mode, params)
        new = store.save_findings(findings, run_id)
        store.finish_run(run_id, len(findings))
        store.close()
        print(f"[+] saved run #{run_id}: {len(findings)} finding(s), {new} new",
              file=sys.stderr)
    except Exception as e:  # sqlite/disk errors
        print(f"[!] could not save to store: {e}", file=sys.stderr)


def _cmd_store(args) -> int:
    from .config import get_config
    from .store import FindingStore
    store = FindingStore(get_config().db_path)
    try:
        if args.mode == "stats":
            print(json.dumps(store.stats(), indent=2))
        elif args.mode == "runs":
            for r in store.list_runs(args.limit):
                print(f"#{r['id']:<4} {r['started_at']}  {r['mode']:<8} "
                      f"{r['result_count']:>6} results  {r['status']}  {r['params']}")
        elif args.mode == "show":
            if not args.target:
                print("error: provide a CVE id", file=sys.stderr)
                return 2
            d = store.get(args.target)
            if d is None:
                print(f"[!] {args.target} not in store", file=sys.stderr)
                return 1
            d["history"] = store.history(args.target)
            print(json.dumps(d, indent=2))
        elif args.mode == "query":
            rows = store.query(severity=args.severity, kev_only=args.kev,
                               since=args.since, min_risk=args.min_risk,
                               search=args.target, limit=args.limit)
            if args.json:
                print(json.dumps(rows, indent=2))
            else:
                for r in rows:
                    kev = "KEV " if r["in_kev"] else "    "
                    risk = f"{r['risk']:>5}" if r["risk"] is not None else "    -"
                    print(f"{kev}{r['cve_id']:<18} {r['cvss_severity'] or '-':<9} "
                          f"risk {risk}  {(r['title'] or '')[:90]}")
                print(f"\n{len(rows)} result(s)", file=sys.stderr)
        return 0
    finally:
        store.close()


def _load_dotenv(path: str = ".env") -> None:
    """Read KEY=VALUE lines from ./.env into the environment, without
    overriding variables already set (stdlib only, no python-dotenv)."""
    try:
        lines = open(path, encoding="utf-8").read().splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().removeprefix("export ").strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key:
            os.environ.setdefault(key, value)


def _criticality(raw: str) -> float:
    """argparse type for --criticality, so a bad value is a usage error.

    Without this the value reaches Scores() and raises, which reads as a
    crash rather than "you passed the wrong number".
    """
    try:
        v = float(raw)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{raw!r} is not a number")
    if not 0.0 <= v <= 1.0:
        raise argparse.ArgumentTypeError(
            f"must be between 0.0 and 1.0 (a fraction of a critical asset), got {v}")
    return v


def main(argv=None) -> int:
    _load_dotenv()
    # Windows consoles default to cp1252; force UTF-8 so emoji/·/⚠️ print.
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

    p = argparse.ArgumentParser(prog="groundtrace",
                                description="Third-party vulnerability intelligence & reporting")
    p.add_argument("mode", choices=["demo", "cve", "file", "unified", "recent",
                                    "query", "show", "runs", "stats", "serve",
                                    "watch", "alerts"])
    p.add_argument("target", nargs="?",
                   help="CVE id (cve/show), path (file), or search text (query)")
    p.add_argument("--no-save", action="store_true",
                   help="don't record this run/its findings in the local store")
    p.add_argument("--severity", help="query: filter by CVSS severity")
    p.add_argument("--kev", action="store_true", help="query: only KEV-listed CVEs")
    p.add_argument("--since", help="query: published on/after YYYY-MM-DD")
    p.add_argument("--min-risk", type=float, help="query: minimum risk score")
    p.add_argument("--limit", type=int, default=50, help="query/runs: max rows")
    p.add_argument("--json", action="store_true", help="emit JSON not Markdown")
    p.add_argument("--out", help="write output to a file")
    p.add_argument("--criticality", type=_criticality, default=1.0,
                   help="asset criticality 0-1 (default 1.0)")
    p.add_argument("--db", help="darkfeeds SQLite db to correlate signals from")
    p.add_argument("--provider", help="LLM provider name (default: offline)")
    p.add_argument("--days", type=int,
                   help="recent/watch: how many days back (default 30 for recent, 2 for watch)")
    p.add_argument("--interval", type=float, default=6.0, help="watch: hours between cycles")
    p.add_argument("--once", action="store_true", help="watch: run one cycle and exit")
    p.add_argument("--dry-run", action="store_true",
                   help="watch: show what would alert, record/send nothing")
    p.add_argument("--alert-critical", action="store_true",
                   help="watch: also alert on every new CRITICAL CVE (noisy)")
    p.add_argument("--no-darkweb", action="store_true", help="watch: skip darkfeeds collection")
    p.add_argument("--max-alerts", type=int, default=20,
                   help="watch: max alert lines per digest message")
    p.add_argument("--no-epss", action="store_true",
                   help="for `recent` mode: skip per-CVE EPSS lookups (faster)")
    p.add_argument("--max-cves", type=int,
                   help="for `recent` mode: cap results, e.g. to bound a free-tier pull")
    p.add_argument("--min-severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                   help="for `recent` mode: drop CVEs below this CVSS severity "
                        "before EPSS enrichment (KEV-listed CVEs are always kept)")
    p.add_argument("--host", default="127.0.0.1", help="serve: bind address")
    p.add_argument("--port", type=int, default=8080, help="serve: port")
    args = p.parse_args(argv)

    if args.mode == "watch":
        from .watch import watch
        watch(interval_hours=args.interval, once=args.once, days=args.days or 2,
              min_severity=args.min_severity or "HIGH", darkweb=not args.no_darkweb,
              alert_critical=args.alert_critical, max_alerts=args.max_alerts,
              dry_run=args.dry_run)
        return 0

    if args.mode == "alerts":
        from .config import get_config
        from .store import FindingStore
        store = FindingStore(get_config().db_path)
        rows = store.list_alerts(args.limit)
        store.close()
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            for r in rows:
                print(f"{r['created_at']}  [{r['kind']:<11}] {r['title']}\n"
                      f"{'':27}{r['detail'][:150]}")
            print(f"\n{len(rows)} alert(s)", file=sys.stderr)
        return 0

    if args.mode == "serve":
        from .api import serve
        serve(args.host, args.port)
        return 0

    if args.mode in ("query", "show", "runs", "stats"):
        return _cmd_store(args)

    if args.mode == "recent":
        args.days = args.days or 30
        findings = analyze_recent(days=args.days, asset_criticality=args.criticality,
                                  fetch_epss=not args.no_epss, max_cves=args.max_cves,
                                  min_severity=args.min_severity)
        if not findings:
            print("[!] No CVEs found — offline, or no CVEs published in that window.",
                  file=sys.stderr)
            return 1
        _persist("recent", findings, args)
        if args.json:
            out = json.dumps([f.to_dict() for f in findings], indent=2)
        else:
            out = "\n\n---\n\n".join(render_markdown(f) for f in findings)
        if args.out:
            Path(args.out).write_text(out, encoding="utf-8")
            print(f"[+] wrote {len(findings)} findings to {args.out}")
        else:
            print(out)
        return 0

    if args.mode == "unified":
        from .unified import analyze_unified
        if args.target:
            report = analyze_unified(cve_id=args.target, db_path=args.db,
                                     provider=args.provider,
                                     asset_criticality=args.criticality)
        else:
            raw = _coerce_dates(_load_sample())
            dd, pd = raw.pop("disclosure_date", None), raw.pop("patch_date", None)
            report = analyze_unified(
                raw, db_path=args.db, provider=args.provider,
                asset_criticality=args.criticality,
                in_kev=raw.pop("in_kev", False), epss=raw.pop("epss", None),
                disclosure_date=date.fromisoformat(dd) if dd else None,
                patch_date=date.fromisoformat(pd) if pd else None)
        if report is None:
            print("[!] Could not reach NVD (offline?).", file=sys.stderr)
            return 1
        if args.target:  # don't store the bundled sample as if it were live data
            _persist("unified", [report.finding], args)
        print(json.dumps(report.to_dict(), indent=2))
        return 0

    if args.mode == "demo":
        raw = _coerce_dates(_load_sample())
        dd = raw.pop("disclosure_date", None)
        pd = raw.pop("patch_date", None)
        finding = analyze(
            raw,
            asset_criticality=args.criticality,
            disclosure_date=date.fromisoformat(dd) if dd else None,
            patch_date=date.fromisoformat(pd) if pd else None,
            in_kev=raw.pop("in_kev", False),
            epss=raw.pop("epss", None),
        )
        _emit(finding, args)
        return 0

    if args.mode == "cve":
        if not args.target:
            print("error: provide a CVE id, e.g. cve CVE-2021-44228", file=sys.stderr)
            return 2
        from .feeds import FeedUnavailable
        from .pipeline import missing_cve_reason
        try:
            finding = analyze_cve(args.target, asset_criticality=args.criticality)
        except FeedUnavailable:
            print("[!] Could not reach NVD (offline / rate-limited). Try again, "
                  "or `python -m groundtrace demo`.", file=sys.stderr)
            return 1
        if finding is None:
            print(f"[!] {missing_cve_reason(args.target)}", file=sys.stderr)
            return 1
        _persist("cve", [finding], args)
        _emit(finding, args)
        return 0

    if args.mode == "file":
        if not args.target:
            print("error: provide a JSON path", file=sys.stderr)
            return 2
        raw = _coerce_dates(json.loads(Path(args.target).read_text(encoding="utf-8")))
        dd = raw.pop("disclosure_date", None)
        pd = raw.pop("patch_date", None)
        finding = analyze(
            raw, asset_criticality=args.criticality,
            disclosure_date=date.fromisoformat(dd) if dd else None,
            patch_date=date.fromisoformat(pd) if pd else None,
            in_kev=raw.pop("in_kev", False), epss=raw.pop("epss", None),
        )
        _persist("file", [finding], args)
        _emit(finding, args)
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
