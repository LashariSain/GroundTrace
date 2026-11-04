"""
Unified orchestration (Sprint 1): CVE finding + dark-web signals + LLM summary.

    raw/live CVE -> analyze() -> Finding
    darkfeeds Store -> signals mentioning that CVE
    -> UnifiedReport (finding, signals, escalated priority, summary)
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date
from typing import Optional

from .models import Finding
from .pipeline import analyze, analyze_cve
from .llm import run_prompt, LLMResult


@dataclass
class UnifiedReport:
    finding: Finding
    signals: list[dict] = field(default_factory=list)
    underground_priority: Optional[str] = None   # best (lowest) P-level seen
    summary: Optional[LLMResult] = None

    def to_dict(self) -> dict:
        return {
            "finding": self.finding.to_dict(),
            "signals": self.signals,
            "underground_priority": self.underground_priority,
            "summary": self.summary.__dict__ if self.summary else None,
        }


def _signals_for_cve(cve_id: str, db_path: str, limit: int = 25) -> list[dict]:
    """Query the darkfeeds store for signals tagged with this CVE."""
    from darkfeeds.store import Store
    store = Store(db_path)
    try:
        rows = store.conn.execute(
            "SELECT * FROM signals WHERE cve_ids LIKE ? "
            "ORDER BY relevance_score DESC, collected_at DESC LIMIT ?",
            (f'%"{cve_id}"%', limit),
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            for k in ("cve_ids", "malware_hashes", "ip_addresses", "domains",
                      "urls", "product_names", "tags"):
                try:
                    d[k] = json.loads(d.get(k) or "[]")
                except json.JSONDecodeError:
                    d[k] = []
            out.append(d)
        return out
    finally:
        store.close()


def _facts(f: Finding, signals: list[dict], priority: Optional[str]) -> str:
    lines = [f"{f.cve_id}: {f.title or f.description[:120]}",
             f"CVSS {f.scores.cvss} ({f.scores.cvss_severity}), "
             f"EPSS {f.scores.epss}, KEV={f.disclosure.in_kev}, "
             f"risk={f.scores.risk}."]
    if signals:
        kinds = sorted({s["signal_type"] for s in signals})
        actors = sorted({s["threat_actor"] for s in signals if s["threat_actor"]})
        lines.append(f"{len(signals)} underground signal(s): {', '.join(kinds)}; "
                     f"highest priority {priority}."
                     + (f" Actors: {', '.join(actors)}." if actors else ""))
    else:
        lines.append("No underground signals observed for this CVE.")
    return " ".join(lines)


def analyze_unified(
    raw: Optional[dict] = None, *, cve_id: Optional[str] = None,
    db_path: Optional[str] = None, provider: Optional[str] = None,
    asset_criticality: float = 1.0, in_kev: bool = False,
    epss: Optional[float] = None,
    disclosure_date: Optional[date] = None, patch_date: Optional[date] = None,
) -> Optional[UnifiedReport]:
    """Run the full pipeline from a raw dict (offline) or a CVE id (live)."""
    if raw is not None:
        finding = analyze(raw, asset_criticality=asset_criticality, in_kev=in_kev,
                          epss=epss, disclosure_date=disclosure_date,
                          patch_date=patch_date)
    elif cve_id:
        from .feeds import FeedUnavailable
        try:
            finding = analyze_cve(cve_id, asset_criticality=asset_criticality,
                                  disclosure_date=disclosure_date, patch_date=patch_date)
        except FeedUnavailable:
            return None
        if finding is None:
            return None
    else:
        raise ValueError("provide raw or cve_id")

    signals = _signals_for_cve(finding.cve_id, db_path) if db_path else []
    priority = min((s["priority"] for s in signals), default=None)  # "P1" < "P2"

    # Underground chatter with an exploit/zero-day is evidence of exploitation.
    if any(s["signal_type"] in ("exploit_sale", "exploit_share", "zero_day")
           for s in signals):
        finding.disclosure.exploit_public = True

    summary = run_prompt("threat_summary", _facts(finding, signals, priority),
                         provider=provider)
    return UnifiedReport(finding, signals, priority, summary)
