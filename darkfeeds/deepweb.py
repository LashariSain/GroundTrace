"""Deep/dark-web text normalization helpers for underground intelligence."""
from __future__ import annotations
from . import focus

import hashlib

from .extractors import extract_all
from .models import Confidence, Priority, SignalSource, SignalType, ThreatSignal


def build_deepweb_signal(raw_text: str, *, source_name: str = "deepweb", source_url: str = "", title: str | None = None) -> ThreatSignal:
    """Normalize a dark-web or paste-source posting into a ThreatSignal."""
    text = (raw_text or "").strip()
    if not text:
        raise ValueError("raw_text must not be empty")

    extraction = extract_all(text)
    if extraction.threat_actor:
        signal_type = SignalType.THREAT_ACTOR
    elif extraction.malware_family:
        signal_type = SignalType.MALWARE_SAMPLE
    elif extraction.cve_ids:
        signal_type = SignalType.VULN_DISCUSSION
    else:
        signal_type = SignalType.GENERAL_INTEL

    signal_title = title or text[:160].strip() or source_name
    signal = ThreatSignal(
        signal_id=hashlib.sha256(f"{source_name}:{text[:200]}".encode()).hexdigest()[:16],
        signal_type=signal_type,
        priority=Priority.HIGH if extraction.threat_actor or extraction.focus_relevance > 0.5 else Priority.MEDIUM,
        confidence=Confidence.MEDIUM,
        source=SignalSource.ONION_FORUM,
        source_name=source_name,
        source_url=source_url,
        title=signal_title,
        raw_text=text,
        cve_ids=extraction.cve_ids,
        malware_hashes=extraction.hashes,
        malware_family=extraction.malware_family,
        ip_addresses=extraction.ips,
        domains=extraction.domains,
        urls=extraction.urls,
        product_names=extraction.products,
        exploit_type=extraction.exploit_type,
        price=extraction.price,
        threat_actor=extraction.threat_actor,
        target_country=focus.target(extraction.focus_relevance),
        relevance_score=extraction.overall_score,
        evidence_snippet=text[:300],
        tags=["deepweb", "threat-intel"],
    )
    return signal
