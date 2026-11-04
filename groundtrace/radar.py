"""Attention list: CVEs worth a look before CISA KEV confirms exploitation.

This is a RANKED WATCHLIST, not a forecast. It makes no claim about whether
any CVE will be exploited, and nothing here should be read as a probability.
That restraint is deliberate -- see "Why there is no hot label" below.

A KEV listing is the confirmation; this gathers the signs that tend to precede
it:

  EPSS level     (35)  FIRST's current exploitation probability
  EPSS momentum  (25)  how much that probability rose over the last 7 days
  Chatter        (20)  distinct threat-intel / news sources naming the CVE this week
  Public PoCs    (20)  repos in the PoC-in-GitHub index, plus whether one
                       existed before NVD published the CVE

Every component carries the evidence behind its points, the same way the risk
score explains itself. KEV-listed CVEs are left out: they are already confirmed,
and the findings view ranks them first anyway.

Why there is no hot label. The score once carried hot/warming/watch bands at
60 and 40 out of 100, and the dashboard showed "HOT 0" permanently: across the
40 stored entries EPSS momentum and Public PoCs had never contributed a single
point, holding every score at or below 55.

The band was not the first problem. Those two zeroes were not findings. A
failed PoC-index lookup was recorded as "no public PoC indexed" -- 8 of the
top 12 stored candidates in fact had public PoCs, one of them 725 repos -- so
the score was reporting absence of data as evidence of absence. With that
fixed, 60 is reachable again.

The band still goes, for a different reason: 60 and 40 were invented, not
fitted. Nothing establishes what either threshold predicts, and a label that
sorts CVEs into "hot" and "not" is a forecast whether or not it is called one.
Earning it back means calibrating against a year of historical outcomes --
which CVEs in a given week went on to be exploited -- and until that exists
this ranks and explains, and predicts nothing.

So a component now reports whether it could be measured at all, points are
summed only over what was measurable, and `points_available` says how much of
the scale applied. An entry with too little coverage is "insufficient" rather
than low-scoring. Restoring a band would need calibration against a year of
historical outcomes; until that exists, this ranks and explains, and predicts
nothing.
"""
from __future__ import annotations

import json
import math
import sqlite3
from datetime import date, datetime, timedelta, timezone
from typing import Optional

# Minimum fraction of the 100-point scale that must be measurable before an
# entry is ranked at all. Below it the entry is "insufficient": the evidence
# was not gathered, which is not the same as the evidence being absent.
MIN_COVERAGE = 0.6
_MAX_CANDIDATES = 40     # each costs one PoC-index request
_WINDOW_DAYS = 30
_CHATTER_DAYS = 7


def _level(coverage: float) -> str:
    """Entries are ranked or they are not; no band implies a prediction."""
    return "ranked" if coverage >= MIN_COVERAGE else "insufficient"


def _epss_7d_ago(series: list[tuple[str, float]], today: date) -> Optional[tuple[str, float]]:
    """The oldest point in the series that is at most 7 days old (series is newest first)."""
    cutoff = (today - timedelta(days=7)).isoformat()
    inside = [p for p in series if p[0] >= cutoff]
    return inside[-1] if inside else None


def score_entry(f: dict, series: list[tuple[str, float]], mentions: dict,
                repos: list[dict], today: date) -> dict:
    """Radar entry for one CVE. Pure: all inputs are passed in."""
    comps = []
    epss_now = series[0][1] if series else f.get("epss")

    comps.append({"name": "EPSS level", "points": round(35 * (epss_now or 0), 1), "max": 35,
                  "available": epss_now is not None,
                  "evidence": (f"EPSS {epss_now:.4f} (FIRST, {series[0][0]})" if series
                               else f"EPSS {epss_now:.4f}" if epss_now is not None
                               else "FIRST has published no EPSS score for this CVE")})

    past = _epss_7d_ago(series, today)
    if epss_now is not None and past and past[0] != series[0][0]:
        rise = epss_now - past[1]
        pts, avail = 25 * min(1.0, max(0.0, rise) / 0.3), True
        ev = f"{past[1]:.4f} on {past[0]} → {epss_now:.4f} ({'+' if rise >= 0 else ''}{rise:.4f})"
    else:
        # Two points a week apart are needed to speak of a rise. Without them
        # this is unmeasured, not flat -- scoring it 0 would read as "no rise".
        pts, avail = 0.0, False
        ev = "fewer than two EPSS points in the last 7 days: momentum not measurable"
    comps.append({"name": "EPSS momentum", "points": round(pts, 1), "max": 25,
                  "available": avail, "evidence": ev,
                  # The raw 7-day change, so callers can apply their own line
                  # instead of reverse-engineering it from the points.
                  "rise": round(rise, 4) if avail else None})

    sources = sorted(mentions.get("sources", []))
    pts = min(20.0, 7.0 * len(sources))
    comps.append({"name": "Chatter", "points": round(pts, 1), "max": 20,
                  # We hold the feed locally, so silence here is an observation.
                  "available": True,
                  "evidence": (f"{len(sources)} source(s) this week: {', '.join(sources[:4])}"
                               if sources else "no threat-intel or news mentions this week"),
                  "items": mentions.get("items", [])[:3]})

    if repos is None:
        pts, avail, early = 0.0, False, False
        ev = "PoC index lookup failed: whether a public PoC exists is unknown"
    else:
        n = len(repos)
        pts, avail = (0.0 if n == 0 else min(20.0, 6 + 4 * math.log2(n))), True
        ev = f"{n} repo(s) in PoC-in-GitHub" if n else "no public PoC indexed"
        first = min((r.get("created_at") or "")[:10] for r in repos) if repos else ""
        early = bool(first and f.get("published") and first < f["published"])
        if early:
            ev += f"; first one created {first}, before NVD published the CVE ({f['published']})"
    comps.append({"name": "Public PoCs", "points": round(pts, 1), "max": 20,
                  "available": avail, "evidence": ev})

    score = round(sum(c["points"] for c in comps if c["available"]), 1)
    points_available = sum(c["max"] for c in comps if c["available"])
    coverage = points_available / 100.0
    missing = [c["name"] for c in comps if not c["available"]]
    return {"cve_id": f["cve_id"], "title": f.get("title") or "", "published": f.get("published"),
            "cvss": f.get("cvss"), "cvss_severity": f.get("cvss_severity"),
            "score": score,
            # Out of what could actually be measured, so a failed lookup never
            # masquerades as a low score.
            "points_available": points_available,
            "coverage": round(coverage, 2),
            "score_of_available": (round(score / points_available * 100, 1)
                                   if points_available else None),
            "unmeasured": missing,
            "level": _level(coverage), "poc_before_publication": early,
            "components": comps}


def _chatter(df_db_path: str, since: str) -> dict[str, dict]:
    """{cve: {"sources": set, "items": [{title, url, source}]}} from darkfeeds."""
    out: dict[str, dict] = {}
    try:
        conn = sqlite3.connect(f"file:{df_db_path}?mode=ro", uri=True)
        rows = conn.execute(
            "SELECT cve_ids, source_name, title, source_url FROM signals "
            "WHERE cve_ids != '[]' AND collected_at >= ? ORDER BY collected_at DESC", (since,)).fetchall()
        conn.close()
    except sqlite3.Error:
        return out
    for cve_json, source, title, url in rows:
        try:
            cves = json.loads(cve_json or "[]")
        except ValueError:
            continue
        for cve in cves:
            m = out.setdefault(cve.upper(), {"sources": set(), "items": []})
            m["sources"].add(source or "unknown")
            if len(m["items"]) < 3:
                m["items"].append({"title": (title or "")[:140], "source": source,
                                   "url": url if (url or "").startswith("http") else ""})
    return out


def compute_radar(store, df_db_path: str, *, today: Optional[date] = None) -> list[dict]:
    """Score candidate CVEs and save the snapshot. Network: one bulk EPSS
    time-series call per 50 candidates and one PoC-index call per candidate."""
    from . import feeds
    from .poc import indexed_repos

    today = today or datetime.now(timezone.utc).date()
    chatter_since = (today - timedelta(days=_CHATTER_DAYS)).isoformat()
    chatter = _chatter(df_db_path, chatter_since)
    cands = store.radar_candidates((today - timedelta(days=_WINDOW_DAYS)).isoformat(), list(chatter))

    # Cheap pre-rank (stored EPSS + chatter + severity) so the per-CVE
    # PoC lookups go to the CVEs most likely to matter.
    def pre(f):
        return ((f.get("epss") or 0) * 35 + min(20, 7 * len(chatter.get(f["cve_id"], {}).get("sources", ())))
                + (f.get("cvss") or 0))
    cands = sorted(cands, key=pre, reverse=True)[:_MAX_CANDIDATES]

    series = feeds.fetch_epss_timeseries([f["cve_id"] for f in cands])
    entries = [score_entry(f, series.get(f["cve_id"], []), chatter.get(f["cve_id"], {}),
                           indexed_repos(f["cve_id"]), today) for f in cands]
    entries.sort(key=lambda e: e["score"], reverse=True)
    store.save_radar(entries)
    return entries
