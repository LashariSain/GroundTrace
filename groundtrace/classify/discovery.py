"""
Discovery-method classifier: HOW was the vulnerability found?

Strategy = transparent, weighted keyword rules over the CVE description +
references, with an optional LLM fallback hook. Rule-based is deliberate: for
research you want the label to be *explainable* (you can cite the phrase that
triggered it), not a black box. Every match is recorded in `evidence`.
"""
from __future__ import annotations

import re
from ..models import Discovery, DiscoveryMethod, Confidence

# method -> list of (regex, weight). Higher weight = stronger signal.
_RULES: dict[DiscoveryMethod, list[tuple[str, int]]] = {
    DiscoveryMethod.FUZZING: [
        (r"\bfuzz(ing|er|ed)?\b", 3), (r"\bafl\b|libfuzzer|oss-fuzz", 3),
        (r"malformed (input|packet|file|request)", 2),
    ],
    DiscoveryMethod.EXPLOITED_IN_WILD: [
        (r"exploited in the wild", 4), (r"actively exploited", 4),
        (r"zero[- ]day", 3), (r"observed .*attack", 2), (r"\bAPT\b", 2),
    ],
    DiscoveryMethod.BUG_BOUNTY: [
        (r"bug bounty", 4), (r"hackerone|bugcrowd|zerodium", 3),
        (r"zero day initiative|\bZDI\b", 3),
    ],
    DiscoveryMethod.PENTEST: [
        (r"penetration test", 3), (r"\bpentest", 3), (r"red team", 2),
    ],
    DiscoveryMethod.STATIC_ANALYSIS: [
        (r"static analysis|\bSAST\b", 3), (r"code review|source code audit", 2),
        (r"codeql|semgrep|coverity", 3),
    ],
    DiscoveryMethod.DYNAMIC_ANALYSIS: [
        (r"\bDAST\b|dynamic analysis", 3), (r"runtime (analysis|testing)", 2),
    ],
    DiscoveryMethod.INTERNAL_AUDIT: [
        (r"internal (security )?(audit|review|team)", 3),
        (r"security audit", 2), (r"discovered internally", 3),
    ],
    DiscoveryMethod.DEPENDENCY_SCAN: [
        (r"dependency|software composition|\bSCA\b|sbom", 2),
        (r"supply chain", 2),
    ],
    DiscoveryMethod.RESPONSIBLE_DISCLOSURE: [
        (r"responsibl[ey] disclos", 3), (r"reported (privately|to the vendor)", 3),
        (r"credited to|reported by", 2),
    ],
}

# Try to pull a "found by <name>" attribution.
_FOUND_BY = re.compile(
    r"(?:reported by|credited to|discovered by|found by)\s+([A-Z][\w .'&-]{2,60})",
    re.IGNORECASE,
)
_SIGNAL = re.compile(
    r"((?:buffer overflow|use[- ]after[- ]free|crash|out[- ]of[- ]bounds|"
    r"race condition|memory corruption|null pointer)[\w .-]{0,40})",
    re.IGNORECASE,
)


def classify_discovery(text: str, *, in_kev: bool = False,
                       exploit_public: bool = False) -> Discovery:
    text = text or ""
    scores: dict[DiscoveryMethod, int] = {}
    evidence: dict[DiscoveryMethod, list[str]] = {}

    for method, rules in _RULES.items():
        for pattern, weight in rules:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                scores[method] = scores.get(method, 0) + weight
                evidence.setdefault(method, []).append(m.group(0))

    # Strong external signals override weak text.
    if in_kev or exploit_public:
        scores[DiscoveryMethod.EXPLOITED_IN_WILD] = \
            scores.get(DiscoveryMethod.EXPLOITED_IN_WILD, 0) + (3 if in_kev else 1)
        evidence.setdefault(DiscoveryMethod.EXPLOITED_IN_WILD, []).append(
            "CISA KEV listing" if in_kev else "public exploit")

    if not scores:
        return Discovery(method=DiscoveryMethod.UNKNOWN, confidence=Confidence.LOW)

    best = max(scores, key=scores.get)
    top = scores[best]
    confidence = (Confidence.HIGH if top >= 3
                  else Confidence.MEDIUM if top == 2 else Confidence.LOW)

    found_by = None
    fb = _FOUND_BY.search(text)
    if fb:
        found_by = fb.group(1).strip().rstrip(".")

    signal = None
    sg = _SIGNAL.search(text)
    if sg:
        signal = sg.group(1).strip()

    return Discovery(
        method=best,
        found_by=found_by,
        detection_signal=signal,
        confidence=confidence,
        evidence=evidence.get(best, []),
    )
