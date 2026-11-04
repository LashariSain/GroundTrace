"""
Orchestrator: ingest -> enrich -> classify -> analyze -> Finding.

analyze() builds a Finding from either live feeds (by CVE id) or a raw dict
(offline / your own research data), then runs the discovery + disclosure
classifiers and fills the narrative fields.
"""
from __future__ import annotations

import re
from datetime import date
from typing import Optional

from .models import (Finding, Scores, Analysis, Remediation)
from .classify.discovery import classify_discovery
from .classify.ai_discovery import detect_ai_discovery
from .classify.disclosure import classify_disclosure
from .classify.principles import principle_for, name_for, outcomes_for
from . import feeds
from .config import get_config

# Sentences containing these causal markers are the ones that actually explain
# *why* the bug is exploitable — pulled out of the (often long) NVD
# description so root-cause reads as an explanation, not a re-paste.
_CAUSAL_MARKERS = re.compile(
    r"\b(do(es)? not (validate|sanitiz|protect|restrict|check|verify)|"
    r"fail(s)? to|improperly|insecurely|without (validat|sanitiz|authenticat)|"
    r"allows? (an )?attacker|can (execute|access|read|write|bypass)|"
    r"is (not|insufficiently) (validated|sanitized|restricted))",
    re.IGNORECASE,
)


def _split_sentences(text: str) -> list[str]:
    # Good enough for advisory prose; avoids a heavy NLP dependency.
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+", text) if s.strip()]


def _causal_sentences(description: str, limit: int = 2) -> list[str]:
    found = []
    for sentence in _split_sentences(description):
        if _CAUSAL_MARKERS.search(sentence):
            found.append(sentence)
        if len(found) >= limit:
            break
    return found


def _root_cause_narrative(f: Finding) -> str:
    """Build a multi-part root-cause explanation: weakness name(s), the
    causal sentence(s) pulled from the source description, and the design
    principle they violate — instead of one generic templated line."""
    cwes = f.cwe_ids
    if cwes:
        names = ", ".join(f"{c} ({name_for(c)})" for c in cwes)
        weakness_line = f"Classified as {names}."
    else:
        weakness_line = "No CWE classification was published for this CVE."

    causal = _causal_sentences(f.description)
    if causal:
        mechanism_line = "Mechanism, per the source advisory: " + " ".join(causal)
    else:
        mechanism_line = ("The advisory text did not contain an explicit causal "
                          "statement — read the vendor patch/commit diff to "
                          "confirm the exact coding mistake.")

    principle_name, principle_expl = principle_for(cwes)
    principle_line = (f"This is fundamentally a **{principle_name}** failure: "
                      f"{principle_expl}")

    return f"{weakness_line}\n\n{mechanism_line}\n\n{principle_line}"


def _impact_sentence(f: Finding) -> str:
    sev = (f.scores.cvss_severity or "").upper()
    verb = {"CRITICAL": "can lead to full system compromise",
            "HIGH": "can lead to significant compromise",
            "MEDIUM": "can cause partial compromise or data exposure",
            "LOW": "has limited impact"}.get(sev, "has undetermined impact")

    outcomes = outcomes_for(f.cwe_ids)
    outcome_line = ""
    if outcomes:
        bullets = "\n".join(f"- {o.capitalize()}" for o in outcomes)
        outcome_line = f"\n\nSpecifically, this weakness class:\n{bullets}"

    scope_line = ""
    n = len(f.affected)
    if n == 1:
        scope_line = f" It affects {n} identified product/version range."
    elif n > 1:
        scope_line = f" It affects {n} identified product/version ranges — assess exposure across all of them."

    extra = ""
    if f.disclosure.in_kev:
        extra = (" It is on CISA's Known Exploited Vulnerabilities catalog, "
                "meaning exploitation is confirmed and not theoretical — "
                "treat remediation as urgent regardless of internal risk appetite.")
    elif f.disclosure.leaked_before_fix:
        extra = (" It was disclosed publicly before a patch existed, which "
                "widened the window during which no official fix was available.")

    risk = f.scores.risk
    risk_line = (f"\n\nComposite risk score: **{risk}**/100 "
                f"(CVSS severity × EPSS exploit-probability × asset criticality)."
                if risk is not None else "")

    return (f"A successful exploit {verb}.{scope_line}{extra}"
            f"{outcome_line}{risk_line}")


def analyze(
    raw: dict,
    *,
    asset_criticality: float = 1.0,
    disclosure_date: Optional[date] = None,
    patch_date: Optional[date] = None,
    in_kev: bool = False,
    epss: Optional[float] = None,
) -> Finding:
    """Build and classify a Finding from a normalized dict."""
    refs = raw.get("references", []) or []
    text = " ".join(filter(None, [raw.get("description", ""), " ".join(refs)]))

    disclosure = classify_disclosure(
        raw.get("description", ""), refs,
        disclosure_date=disclosure_date, patch_date=patch_date, in_kev=in_kev,
    )
    discovery = classify_discovery(
        text, in_kev=in_kev, exploit_public=disclosure.exploit_public,
    )
    discovery.ai_found_by, discovery.ai_evidence = detect_ai_discovery(
        raw.get("description", ""), refs, raw.get("credits"))

    principle_name, principle_expl = principle_for(raw.get("cwe_ids", []))

    f = Finding(
        cve_id=raw.get("cve_id", "CVE-UNKNOWN"),
        title=raw.get("title", ""),
        description=raw.get("description", ""),
        cwe_ids=raw.get("cwe_ids", []),
        affected=raw.get("affected", []),
        published=raw.get("published"),
        references=refs,
        credits=raw.get("credits"),
        scores=Scores(
            cvss=raw.get("cvss"),
            cvss_severity=raw.get("cvss_severity"),
            epss=epss if epss is not None else raw.get("epss"),
            asset_criticality=asset_criticality,
            in_kev=in_kev,
        ),
        discovery=discovery,
        disclosure=disclosure,
        remediation=Remediation(
            fixed_version=raw.get("fixed_version"),
            upgrade_path=raw.get("upgrade_path"),
            workaround=raw.get("workaround"),
            references=refs,
        ),
    )

    how_found = (f"Discovery method: **{discovery.method.value}** "
                f"(confidence: {discovery.confidence.value}). "
                f"Disclosure basis: **{disclosure.basis.value}** "
                f"(confidence: {disclosure.confidence.value}).")
    if discovery.found_by:
        how_found += f" Credited to: {discovery.found_by}."
    if disclosure.leaked_before_fix:
        how_found += (" Note: public disclosure preceded the availability of "
                      "a patch, so this should be treated as having been an "
                      "effective zero-day at time of release.")

    f.analysis = Analysis(
        what_it_is=raw.get("description", ""),
        root_cause=raw.get("root_cause") or _root_cause_narrative(f),
        how_found=how_found,
        business_impact=_impact_sentence(f),
        principle_violated=f"{principle_name} — {principle_expl}",
    )
    return f


def analyze_cve(
    cve_id: str, *, asset_criticality: float = 1.0,
    disclosure_date: Optional[date] = None, patch_date: Optional[date] = None,
) -> Optional[Finding]:
    """Pull a CVE live from NVD/KEV/EPSS and analyze it.

    Returns None if NVD has no such *published* CVE (unknown or reserved id);
    use `missing_cve_reason(cve_id)` to explain which. Raises
    feeds.FeedUnavailable if NVD could not be reached (offline/rate-limited).
    """
    raw = feeds.fetch_nvd(cve_id)
    if raw is None:
        return None
    in_kev = cve_id in feeds.load_kev()
    epss = feeds.fetch_epss(cve_id)
    return analyze(raw, asset_criticality=asset_criticality,
                   disclosure_date=disclosure_date, patch_date=patch_date,
                   in_kev=in_kev, epss=epss)


def analyze_keyword(keyword: str, *, days: Optional[int] = None, limit: int = 50,
                    asset_criticality: float = 1.0) -> list[Finding]:
    """Newest CVEs in NVD matching `keyword`, fully analyzed (KEV + bulk EPSS).
    Raises feeds.FeedUnavailable if NVD can't be reached."""
    raw_list = feeds.search_nvd(keyword, days=days, limit=limit,
                                api_key=get_config().nvd_api_key)
    kev = feeds.load_kev()
    epss = feeds.fetch_epss_bulk([r["cve_id"] for r in raw_list])
    return [analyze(r, asset_criticality=asset_criticality,
                    in_kev=r["cve_id"] in kev, epss=epss.get(r["cve_id"]))
            for r in raw_list]


_CVE_IN_TEXT = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)


def resolve_nickname(name: str, *, max_cves: int = 5) -> dict:
    """Map a vulnerability nickname to CVE ids using web search results.

    Keeps ids that at least two independent results (different hosts) cite,
    or the single most-cited one if no id clears that bar, so one stray page
    can't redirect the lookup. Returns {"cves": [...], "sources": [urls]}.
    """
    from urllib.parse import urlparse
    from .websearch import search_web
    hosts: dict[str, set[str]] = {}
    sources: dict[str, list[str]] = {}
    for r in search_web(f"{name} CVE", max_results=10):
        host = urlparse(r["url"]).netloc.lower()
        for cve in {c.upper() for c in _CVE_IN_TEXT.findall(r["title"] + " " + r["snippet"])}:
            hosts.setdefault(cve, set()).add(host)
            sources.setdefault(cve, []).append(r["url"])
    ranked = sorted(hosts, key=lambda c: -len(hosts[c]))
    cves = [c for c in ranked if len(hosts[c]) >= 2][:max_cves] or ranked[:1]
    return {"cves": cves, "sources": sorted({u for c in cves for u in sources[c]})[:6]}


def missing_cve_reason(cve_id: str) -> str:
    """A human explanation for why `analyze_cve` returned None (not in NVD).

    Consults the CVE.org registry so a reserved/embargoed CVE reads differently
    from a non-existent id. Best-effort: if the registry can't be reached, it
    falls back to a generic (still accurate) message.
    """
    try:
        reg = feeds.fetch_cve_registry(cve_id)
    except feeds.FeedUnavailable:
        reg = None
    if reg and reg.get("state") == "RESERVED":
        who = f" by {reg['assigner']}" if reg.get("assigner") else ""
        return (f"{cve_id} is RESERVED{who} in the CVE registry — the assigning "
                f"CNA has not published details yet, so there is nothing to "
                f"analyze until it does.")
    if reg:
        state = reg.get("state") or "present"
        return (f"{cve_id} is in the CVE registry (state {state}) but is not in "
                f"NVD yet — try again once NVD ingests it.")
    return (f"{cve_id} was not found in NVD or the CVE.org registry — it may be "
            f"reserved/embargoed, not yet published, or not a valid CVE id.")


_SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def analyze_recent(
    days: int = 30, *, asset_criticality: float = 1.0,
    api_key: Optional[str] = None, fetch_epss: bool = True,
    max_cves: Optional[int] = None, min_severity: Optional[str] = None,
) -> list[Finding]:
    """Analyze every CVE published in the last `days` days (default 30).

    Free-tier NVD (no API key) allows 5 req/30s and EPSS is throttled to a
    polite 2 req/s — both enforced in feeds.py, so this call can be slow by
    design rather than risk a ban. `max_cves` caps how many results are kept
    (and how many EPSS lookups run) — useful on a free tier to bound a 30-day
    pull, which can otherwise be 10,000+ CVEs. A day of description/CVSS/CWE
    data doesn't need EPSS granularity; triage first, enrich with EPSS later.

    min_severity (e.g. "HIGH") filters BEFORE EPSS enrichment and before
    max_cves is applied — the efficient order on a free tier, since severity
    is already in the NVD record (no extra API call) and typically drops the
    bulk of a 30-day pull (most published CVEs are LOW/MEDIUM). A CVE on
    CISA's KEV list is always kept regardless of its CVSS severity — active
    exploitation overrides the severity filter, since that's the stronger
    signal for what actually needs attention.

    EPSS is looked up per-CVE (one request each) unless fetch_epss=False,
    since FIRST has no bulk-by-date endpoint — set it False for a quick pass
    over a large window. KEV is one bulk fetch, cached for the whole batch.
    """
    api_key = api_key or get_config().nvd_api_key
    raw_list = feeds.fetch_recent_cves(days=days, api_key=api_key)
    kev = feeds.load_kev()

    if min_severity:
        threshold = _SEVERITY_RANK.get(min_severity.upper())
        if threshold is None:
            raise ValueError(f"min_severity must be one of {list(_SEVERITY_RANK)}")
        raw_list = [
            r for r in raw_list
            if r.get("cve_id") in kev
            or _SEVERITY_RANK.get((r.get("cvss_severity") or "").upper(), 0) >= threshold
        ]

    if max_cves is not None:
        raw_list = raw_list[:max_cves]

    findings = []
    for raw in raw_list:
        cve_id = raw.get("cve_id", "")
        epss = feeds.fetch_epss(cve_id) if fetch_epss else None
        findings.append(analyze(
            raw, asset_criticality=asset_criticality,
            in_kev=cve_id in kev, epss=epss,
        ))
    return findings
