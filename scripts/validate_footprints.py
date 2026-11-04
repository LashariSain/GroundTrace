#!/usr/bin/env python
"""Measure how often a footprint match names the right group.

This is the credibility asset: the number this prints is the number the UI is
allowed to show next to an actor name. Nothing else may claim a reliability.

Method -- leave-one-out over the stored indicator catalogue:

  For each test indicator, its own group's footprint is rebuilt *without* that
  indicator, every other group's footprint is left alone, and the indicator is
  then matched against all of them. A match is correct when the top-ranked
  group is the group the indicator actually belongs to.

Why tests are capped per group. One "group" in the catalogue (a
phishing-as-a-service platform) holds 42,193 of 56,624 indicators -- 74% of
everything. A uniform sample is therefore mostly that one feed, whose thousands
of unrelated customer domains share no habits and are close to unlearnable.
Measured 2026-10-30: pooled precision is 25.2% on its indicators alone, 33.1%
on a uniform catalogue sample, and 55.7% with it excluded. Quoting the uniform
figure would describe that feed rather than the matcher. So tests are capped at
--per-group per group, and the headline is the MACRO average (the mean over
groups, each weighted equally) with the pooled micro figure shown beside it.

Why the catalogue is split. Choosing a score threshold by looking at results
and then quoting those same results as the threshold's precision is fitting and
reporting on one set, which inflates the number. So groups are split by a hash
of their key: the FIT half is what you may tune against, the REPORT half is
untouched and is the only source of a published figure. The split is
deterministic, so the same --seed always reproduces the same partition.

Usage:
    python scripts/validate_footprints.py                     # sample, both halves
    python scripts/validate_footprints.py --all               # every indicator
    python scripts/validate_footprints.py --db path/to/apt.db
    python scripts/validate_footprints.py --sweep             # threshold table

Exits non-zero if strict precision on the REPORT half is below --min-precision
(default 0.60), so CI fails rather than letting an accuracy claim rot.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import random
import sqlite3
import sys
from collections import defaultdict
from datetime import date

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from groundtrace import fingerprint  # noqa: E402

# Thresholds under test. match() applies its own floor, so we always call it
# in broad mode (the lower floor) and no threshold below BROAD is observable.
STRICT, BROAD = fingerprint.MIN_SCORE_STRICT, fingerprint.MIN_SCORE_BROAD
MIN_GROUP_SIZE = 3          # mirrors fingerprint.build_all()


def load(db: str) -> dict[str, list[dict]]:
    """Attributed domain/IP indicators, grouped by group_key."""
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    by_group: dict[str, list[dict]] = defaultdict(list)
    for r in con.execute(
        "SELECT value, type, family, group_key FROM iocs "
        "WHERE group_key != '' AND type IN ('domain','ip')"
    ):
        by_group[r["group_key"]].append(
            {"value": r["value"], "type": r["type"], "family": r["family"] or ""})
    con.close()
    # A group needs MIN_GROUP_SIZE indicators to have a footprint at all, and
    # one more than that to survive having one held out.
    return {g: rows for g, rows in by_group.items() if len(rows) >= MIN_GROUP_SIZE}


def half(group_key: str, seed: int, fit_fraction: float) -> str:
    """Deterministic fit/report assignment, stable across runs and machines."""
    h = hashlib.md5(f"{seed}:{group_key}".encode()).digest()[0]
    return "fit" if h < fit_fraction * 256 else "report"


def evaluate(by_group: dict[str, list[dict]], tests: list[tuple[str, int]],
             thresholds: list[float]) -> dict[float, dict]:
    """Run leave-one-out over `tests` and tally outcomes per threshold."""
    footprints = {g: fingerprint.footprint_for(rows) for g, rows in by_group.items()}
    names: dict[str, dict] = {}
    stats = {t: {"n": 0, "surfaced": 0, "correct": 0, "wrong": 0} for t in thresholds}
    # per group, per threshold: [surfaced, correct] -- for the macro average
    per_group: dict[float, dict[str, list[int]]] = {t: defaultdict(lambda: [0, 0])
                                                    for t in thresholds}

    for gk, idx in tests:
        rows = by_group[gk]
        held = rows[idx]
        kept = rows[:idx] + rows[idx + 1:]
        if len(kept) < MIN_GROUP_SIZE:
            continue
        # Only the held-out indicator's own footprint changes.
        trial = dict(footprints)
        trial[gk] = fingerprint.footprint_for(kept)

        # Broad mode has the lower floor, so this is the widest view of the
        # scores available; thresholds are then applied here.
        results = fingerprint.match(held["value"], held["type"], trial, names,
                                    limit=6, mode="broad")
        for t in thresholds:
            above = [r for r in results if r["score"] >= t]
            s = stats[t]
            s["n"] += 1
            if not above:
                continue
            s["surfaced"] += 1
            per_group[t][gk][0] += 1
            if above[0]["group"] == gk:
                s["correct"] += 1
                per_group[t][gk][1] += 1
            else:
                s["wrong"] += 1
    for t in thresholds:
        stats[t]["per_group"] = dict(per_group[t])
    return stats


def summarise(s: dict) -> dict:
    n, surf = s["n"], s["surfaced"]
    # Macro: each group contributes one precision value, so a single huge
    # group cannot set the headline. Only groups that surfaced a match count.
    pg = [c / sf for sf, c in s.get("per_group", {}).values() if sf]
    return {
        "tests": n,
        "surfaced": surf,
        "groups_scored": len(pg),
        "macro_precision": (sum(pg) / len(pg)) if pg else None,
        "precision": (s["correct"] / surf) if surf else None,
        "wrong_group_rate": (s["wrong"] / n) if n else None,
        "abstention": ((n - surf) / n) if n else None,
        "correct_matches": s["correct"],
    }


def _fmt(v, pct=True):
    if v is None:
        return "   n/a"
    return f"{v * 100:5.1f}%" if pct else f"{v:5d}"


def table(title: str, rows: list[tuple[float, dict]]) -> None:
    print(f"\n{title}")
    print(f"  {'thresh':>7} {'tests':>7} {'surfaced':>9} {'MACRO':>8} {'micro':>8} "
          f"{'wrong-grp':>10} {'abstain':>9} {'grps':>6}")
    for t, m in rows:
        print(f"  {t:>7.1f} {m['tests']:>7d} {m['surfaced']:>9d} "
              f"{_fmt(m['macro_precision']):>8} {_fmt(m['precision']):>8} "
              f"{_fmt(m['wrong_group_rate']):>10} "
              f"{_fmt(m['abstention']):>9} {m['groups_scored']:>6d}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default=os.path.expanduser("~/.groundtrace/apt.db"))
    # These defaults are the ones the published figures were measured with, so
    # running this script with no arguments reproduces the numbers in README.md.
    # Changing them changes the result, which is why they are not arbitrary:
    # a low per-group cap is what keeps a 42,000-indicator feed from setting
    # the headline for a catalogue of 254 groups.
    ap.add_argument("--sample", type=int, default=1500,
                    help="indicators to test per half (default 1500)")
    ap.add_argument("--per-group", type=int, default=15,
                    help="max tests drawn from any one group (default 15); "
                         "stops a bulk feed dominating the result")
    ap.add_argument("--all", action="store_true", help="test every indicator")
    ap.add_argument("--seed", type=int, default=20261030,
                    help="fit/report split + sampling seed")
    ap.add_argument("--fit-fraction", type=float, default=0.7)
    ap.add_argument("--sweep", action="store_true",
                    help="sweep thresholds on the FIT half (tuning only)")
    ap.add_argument("--min-precision", type=float, default=0.60,
                    help="fail if REPORT-half strict precision is below this")
    args = ap.parse_args(argv)

    if not os.path.exists(args.db):
        print(f"error: no such database: {args.db}", file=sys.stderr)
        return 2

    by_group = load(args.db)
    if not by_group:
        print("error: no attributed domain/IP indicators found", file=sys.stderr)
        return 2

    halves: dict[str, list[str]] = defaultdict(list)
    for gk in by_group:
        halves[half(gk, args.seed, args.fit_fraction)].append(gk)

    total = sum(len(r) for r in by_group.values())
    print(f"database        {args.db}")
    print(f"run date        {date.today().isoformat()}")
    print(f"groups          {len(by_group)} with >= {MIN_GROUP_SIZE} indicators")
    print(f"indicators      {total}")
    print(f"split           seed {args.seed}, fit {len(halves['fit'])} groups / "
          f"report {len(halves['report'])} groups")
    print(f"thresholds      strict {STRICT}, broad {BROAD} "
          f"(evaluated via broad mode; nothing below {BROAD} is observable)")
    print(f"token weight    rarest token scores {fingerprint._TOKEN_MAX_W}")

    rng = random.Random(args.seed)
    thresholds = ([t for t in (2.0, 2.5, 3.0, 3.5, 4.0, 5.0, 6.0) if t >= BROAD]
                  if args.sweep else sorted({BROAD, STRICT}))

    out: dict[str, dict] = {}
    for name in ("fit", "report"):
        tests = []
        for gk in halves[name]:
            idxs = list(range(len(by_group[gk])))
            if len(idxs) > args.per_group:
                idxs = rng.sample(idxs, args.per_group)
            tests += [(gk, i) for i in idxs]
        if not args.all and len(tests) > args.sample:
            tests = rng.sample(tests, args.sample)
        print(f"\n[{name}] running {len(tests)} leave-one-out tests ...", flush=True)
        stats = evaluate(by_group, tests, thresholds)
        rows = [(t, summarise(stats[t])) for t in thresholds]
        label = ("FIT half -- tuning only, never quote these numbers"
                 if name == "fit" else
                 "REPORT half -- the only publishable figures")
        table(label, rows)
        out[name] = {t: m for t, m in rows}

    rep = out["report"].get(STRICT)
    print()
    if rep and rep["macro_precision"] is not None:
        basis = (f"leave-one-out, {rep['tests']} tests, "
                 f"{rep['groups_scored']} held-out groups, "
                 f"max {args.per_group}/group, {date.today().isoformat()}")
        print(f"PUBLISHABLE  strict precision {rep['macro_precision']:.3f} "
              f"(macro; pooled micro {rep['precision']:.3f})")
        print(f"             reliability_basis = {basis!r}")
        broad = out["report"].get(BROAD)
        if broad and broad["macro_precision"] is not None:
            print(f"             broad  precision {broad['macro_precision']:.3f} "
                  f"(macro; pooled micro {broad['precision']:.3f})")
        if rep["macro_precision"] < args.min_precision:
            print(f"\nFAIL  strict macro precision {rep['macro_precision']:.3f} is below the "
                  f"{args.min_precision:.2f} gate.\n"
                  f"      Do not ship a reliability claim. Either improve the "
                  f"scoring or\n      present matches as unquantified hunting "
                  f"leads only.", file=sys.stderr)
            return 1
        print(f"\nPASS  above the {args.min_precision:.2f} gate.")
    else:
        print("FAIL  no matches surfaced on the report half; nothing to quote.",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
