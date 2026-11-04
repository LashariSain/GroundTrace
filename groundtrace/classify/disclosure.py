"""
Disclosure-basis classifier: on what BASIS did the vulnerability go public?

Combines (a) keyword signals from text/references with (b) hard signals from the
reference URLs (ExploitDB, GHSA, vendor advisories) and (c) the timeline
relationship between disclosure_date and patch_date.
"""
from __future__ import annotations

import re
from datetime import date
from typing import Optional

from ..models import Disclosure, DisclosureBasis, Confidence

# Domains that map directly to a channel/basis.
_URL_SIGNALS: list[tuple[str, DisclosureBasis, str]] = [
    (r"exploit-db\.com", DisclosureBasis.EXPLOIT_PUBLISHED, "ExploitDB"),
    (r"github\.com/.+/(poc|exploit)", DisclosureBasis.EXPLOIT_PUBLISHED, "GitHub PoC"),
    (r"packetstormsecurity", DisclosureBasis.EXPLOIT_PUBLISHED, "PacketStorm"),
    (r"seclists\.org/fulldisclosure", DisclosureBasis.FULL_DISCLOSURE, "Full Disclosure list"),
    (r"github\.com/advisories|ghsa", DisclosureBasis.VENDOR_ADVISORY, "GHSA"),
    (r"security advisory|/security/|advisory", DisclosureBasis.VENDOR_ADVISORY, "Vendor advisory"),
]

_TEXT_RULES: dict[DisclosureBasis, list[tuple[str, int]]] = {
    DisclosureBasis.COORDINATED: [
        (r"coordinated disclosure", 3), (r"embargo", 2),
        (r"agreed .*(release|disclosure) date", 2),
    ],
    DisclosureBasis.FULL_DISCLOSURE: [
        (r"full disclosure", 3), (r"published .*without (a )?patch", 3),
    ],
    DisclosureBasis.ZERO_DAY_LEAK: [
        (r"zero[- ]day", 3), (r"before a (patch|fix) was available", 3),
        (r"no patch (is )?available", 2),
    ],
    DisclosureBasis.EXPLOIT_PUBLISHED: [
        (r"proof[- ]of[- ]concept|\bPoC\b", 2), (r"exploit (code )?(is )?public", 3),
    ],
    DisclosureBasis.ACCIDENTAL_LEAK: [
        (r"leaked (via|through|in)", 3), (r"accidental", 2),
        (r"commit (history|message)", 2), (r"changelog", 1),
    ],
    DisclosureBasis.THREAT_INTEL: [
        (r"dark web", 3), (r"threat (intel|actor)", 2), (r"malware (sample|analysis)", 2),
    ],
    DisclosureBasis.VENDOR_ADVISORY: [
        (r"vendor (released|published|confirmed)", 2), (r"official advisory", 2),
    ],
}


def classify_disclosure(
    text: str,
    references: Optional[list[str]] = None,
    *,
    disclosure_date: Optional[date] = None,
    patch_date: Optional[date] = None,
    in_kev: bool = False,
) -> Disclosure:
    text = text or ""
    references = references or []
    scores: dict[DisclosureBasis, int] = {}
    evidence: dict[DisclosureBasis, list[str]] = {}
    channels: list[str] = []       # distinct channel names, in first-seen order
    channel_hits: dict[str, int] = {}
    exploit_public = False

    # 1. URL signals (strong, unambiguous). Score each *matching URL* once so
    # ten reposts on the same site don't outweigh one signal from elsewhere,
    # but still count hits per channel so we can report "seen on N sources".
    seen_bases: set[tuple[DisclosureBasis, str]] = set()
    for url in references:
        for pattern, basis, name in _URL_SIGNALS:
            if re.search(pattern, url, re.IGNORECASE):
                channel_hits[name] = channel_hits.get(name, 0) + 1
                if name not in channels:
                    channels.append(name)
                if basis == DisclosureBasis.EXPLOIT_PUBLISHED:
                    exploit_public = True
                # Only the first match against a given (basis, channel) pair
                # contributes to scoring/evidence — repeats are just noise.
                key = (basis, name)
                if key in seen_bases:
                    break
                seen_bases.add(key)
                scores[basis] = scores.get(basis, 0) + 3
                evidence.setdefault(basis, []).append(name)
                break

    # 2. Text signals
    for basis, rules in _TEXT_RULES.items():
        for pattern, weight in rules:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                scores[basis] = scores.get(basis, 0) + weight
                evidence.setdefault(basis, []).append(m.group(0))

    # 3. Timeline signal — leaked before fix strongly implies zero-day leak.
    leaked_before_fix = None
    if disclosure_date and patch_date:
        leaked_before_fix = patch_date > disclosure_date
        if leaked_before_fix:
            scores[DisclosureBasis.ZERO_DAY_LEAK] = \
                scores.get(DisclosureBasis.ZERO_DAY_LEAK, 0) + 2
            evidence.setdefault(DisclosureBasis.ZERO_DAY_LEAK, []).append(
                "disclosed before patch")

    if not scores:
        basis = DisclosureBasis.UNKNOWN
        confidence = Confidence.LOW
        ev = []
    else:
        basis = max(scores, key=scores.get)
        top = scores[basis]
        confidence = (Confidence.HIGH if top >= 3
                      else Confidence.MEDIUM if top == 2 else Confidence.LOW)
        # De-duplicate while preserving order, and annotate a channel with
        # how many distinct reference URLs corroborated it.
        ev = []
        for item in evidence.get(basis, []):
            if item in channel_hits and channel_hits[item] > 1:
                label = f"{item} ({channel_hits[item]} sources)"
            else:
                label = item
            if label not in ev:
                ev.append(label)

    channel = ", ".join(channels) if channels else None

    return Disclosure(
        basis=basis,
        channel=channel,
        disclosure_date=disclosure_date,
        patch_date=patch_date,
        exploit_public=exploit_public,
        in_kev=in_kev,
        confidence=confidence,
        evidence=ev,
    )
