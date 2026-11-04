"""Turn a stored alert into what an analyst needs to judge it.

Stored alerts stay untouched: the rows are also the watcher's dedup ledger, so
deleting one would make it fire again. Stale alerts are hidden here instead,
with the reason attached, and can always be shown.
"""
from __future__ import annotations

import json
import re
from datetime import date, datetime, timezone

MAX_ALERT_AGE_DAYS = 30     # older than this is history, not something to act on
MAX_MENTION_CVE_AGE_DAYS = 365  # a mention of an old CVE is not news

_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_DUE = re.compile(r"added (\d{4}-\d{2}-\d{2}), federal due date (\d{4}-\d{2}-\d{2})")
_MENTION_PREFIX = re.compile(r"^(https?://\S+|[A-Za-z][\w .-]{1,40}):\s+")
_SCORE_SUFFIX = re.compile(r"\s*\[[^\]]*\]\s*$")

_WHY = {
    "kev": "Newly added to CISA KEV: exploitation has been observed.",
    "watch": "Matches a term on your watchlist.",
    "exploitdb": "A new public exploit references something you track.",
    "critical": "Crossed your critical-risk threshold.",
    "sandbox": "A fresh sandbox run matches your watchlist.",
}
_NEXT = {
    "kev": "Check whether you run this product, then patch or isolate it first.",
    "watch": "Check whether the affected version is deployed.",
    "exploitdb": "Check exposure. Exploit code is public, so expect scanning.",
    "critical": "Check exposure and schedule the fix.",
    "sandbox": "Review the captured indicators and block what applies.",
    "underground": "Read the source, then check whether you run this product.",
}


def _source_label(detail: str, url: str) -> str:
    """A generic kind of source: feed names stay out of the API."""
    text = f"{detail} {url}".lower()
    if "cisa.gov" in text:
        return "CISA advisory"
    if "alienvault" in text or "otx." in text:
        return "Community threat report"
    if re.search(r"feedburner|thehackernews|bleepingcomputer|securityweek|\bnews\b", text):
        return "Security news"
    return "Underground source"


def _product(affected: list | None) -> str:
    """'vendor product' from the first CPE, plus how many entries there are."""
    for cpe in affected or []:
        parts = str(cpe).split(":")
        if len(parts) > 4:
            name = parts[4] if parts[3] == parts[4] else f"{parts[3]} {parts[4]}"
            name = name.replace("_", " ")
            n = len(affected)
            return name if n == 1 else f"{name} ({n} affected entries)"
    return ""


def _age_days(day: str, today: date) -> int | None:
    try:
        return (today - date.fromisoformat((day or "")[:10])).days
    except ValueError:
        return None


def _delivery(raw: str) -> str:
    try:
        channels = list(json.loads(raw or "{}"))
    except ValueError:
        channels = []
    real = [c for c in channels if c != "stderr"]
    return f"Sent to {', '.join(real)}" if real else "Printed on this machine only"


def _hide_reason(kind: str, created_at: str, published: str, today: date) -> str:
    age = _age_days(created_at, today)
    if age is not None and age > MAX_ALERT_AGE_DAYS:
        return f"Raised more than {MAX_ALERT_AGE_DAYS} days ago"
    if kind == "underground":
        cve_age = _age_days(published, today)
        if cve_age is not None and cve_age > MAX_MENTION_CVE_AGE_DAYS:
            return "A mention of an old CVE, not new information"
    return ""


def describe(alert: dict, finding: dict | None, today: date | None = None) -> dict:
    """The alert plus why it fired, the CVE's facts and whether it is worth showing."""
    today = today or datetime.now(timezone.utc).date()
    kind = alert.get("kind", "")
    title, detail, url = alert.get("title", ""), alert.get("detail", ""), alert.get("url", "")
    m = _CVE.search(alert.get("key", "")) or _CVE.search(title)
    finding = finding or {}
    scores = finding.get("scores") or {}
    remedy = finding.get("remediation") or {}
    disclosure = finding.get("disclosure") or {}
    published = finding.get("published") or ""

    source = ""
    if kind == "underground":
        source = _source_label(detail, url)
        cve = m.group(0) if m else "This CVE"
        title = (f"{cve} seen in an underground source" if source == "Underground source"
                 else f"{cve} mentioned in: {source}")
        why = f"Named in a report from: {source}."
        detail = _SCORE_SUFFIX.sub("", _MENTION_PREFIX.sub("", detail))
    else:
        why = _WHY.get(kind, "Raised by the watcher.")

    due = _DUE.search(detail)
    headline = detail
    if kind == "kev":  # "Vendor Product: Name of the flaw; added ..., federal due date ..."
        headline = detail.split(";")[0].split(": ", 1)[-1].strip()
    if finding and not headline:
        headline = (finding.get("title") or "").split(": ", 1)[-1]
    reason = _hide_reason(kind, alert.get("created_at", ""), published, today)
    return {
        "key": alert.get("key"), "kind": kind, "title": title, "headline": headline or title, "detail": detail, "url": url,
        "created_at": alert.get("created_at"), "cve_id": m.group(0) if m else "",
        "why": why, "next_step": _NEXT.get(kind, "Review the details."),
        "source_kind": source, "delivery": _delivery(alert.get("delivered", "")),
        "kev_added": due.group(1) if due else "", "due_date": due.group(2) if due else "",
        "severity": scores.get("cvss_severity") or "", "cvss": scores.get("cvss"),
        "epss": scores.get("epss"), "risk": scores.get("risk"),
        "in_kev": bool(scores.get("in_kev") or disclosure.get("in_kev")),
        "published": published, "product": _product(finding.get("affected")),
        "exploit_public": bool(disclosure.get("exploit_public")),
        "fixed_version": remedy.get("fixed_version") or "",
        "workaround": remedy.get("workaround") or "",
        "hidden": bool(reason), "hidden_reason": reason,
    }


def feed(rows: list[tuple[dict, dict | None]], limit: int = 50,
         include_hidden: bool = False, today: date | None = None) -> dict:
    """Filter first, limit second: a small limit must not be used up by hidden alerts."""
    described = [describe(a, f, today) for a, f in rows]
    # One CVE, one card: a KEV listing already says more than a mention.
    kev = {a["cve_id"] for a in described if a["kind"] == "kev"}
    for a in described:
        if a["kind"] == "underground" and a["cve_id"] in kev and not a["hidden"]:
            a.update(hidden=True, hidden_reason="Already covered by its CISA KEV alert")
    # Confirmed exploitation outranks a mention, however recent the mention is.
    described.sort(key=lambda a: a["kind"] != "kev")
    shown = [a for a in described if not a["hidden"]]
    results = (described if include_hidden else shown)[:limit]
    return {"count": len(results), "results": results,
            "relevant": len(shown), "hidden": len(described) - len(shown)}
