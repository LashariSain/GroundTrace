"""
LLM-assisted IOC extraction — a check/complement to the regex extractors in
extractors.py, not a replacement. Regex stays the ground truth for exact IOC
values (hashes/IPs/domains/CVE ids are deterministic string matches, which an
LLM is prone to subtly mangling). The LLM's job is the fuzzy part: deciding
intent (is this a sale? a zero-day claim?), normalizing jargon, and
attributing actors from context regex patterns don't cover.

`extract_with_llm()` parses the model's JSON and cross-checks every IOC
against the regex ground truth; anything the model reports that regex did
not also find in the raw text is flagged as a likely hallucination and
dropped from the trusted result (but kept in `rejected` for inspection).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from groundtrace.llm import run_prompt
from .extractors import extract_all, ExtractionResult

_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


@dataclass
class LLMExtraction:
    data: dict = field(default_factory=dict)      # validated, grounded fields
    rejected: dict = field(default_factory=dict)  # values the model invented
    parse_error: str = ""
    raw_output: str = ""
    model: str = ""
    latency_s: float = 0.0


def _coerce_json(text: str) -> dict:
    cleaned = _FENCE.sub("", text.strip())
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("no JSON object found in model output")
    return json.loads(cleaned[start:end + 1])


def extract_with_llm(text: str, *, provider: str | None = None) -> LLMExtraction:
    ground_truth: ExtractionResult = extract_all(text)
    truth_sets = {
        "cve_ids": set(ground_truth.cve_ids),
        "hashes": set(ground_truth.hashes),
        "ips": set(ground_truth.ips),
        "domains": set(ground_truth.domains),
        "urls": set(ground_truth.urls),
    }

    result = run_prompt("ioc_extraction", text, provider=provider, version="v1")
    out = LLMExtraction(raw_output=result.text, model=result.model,
                        latency_s=result.latency_s)

    try:
        parsed = _coerce_json(result.text)
    except (ValueError, json.JSONDecodeError) as e:
        out.parse_error = str(e)
        return out

    data, rejected = {}, {}
    for field_name, truth in truth_sets.items():
        claimed = parsed.get(field_name) or []
        if not isinstance(claimed, list):
            claimed = [claimed]
        kept = [v for v in claimed if v in truth or v.lower() in text.lower()]
        bad = [v for v in claimed if v not in kept]
        data[field_name] = sorted(set(kept))
        if bad:
            rejected[field_name] = bad

    # Free-text / judgment fields: no regex ground truth to check against,
    # but still require the value (if any) to be substantiated by the text.
    for field_name in ("threat_actor", "malware_family", "exploit_type",
                       "price", "target_sector"):
        val = parsed.get(field_name, "")
        data[field_name] = val if isinstance(val, str) else ""

    for field_name in ("is_selling", "is_zero_day"):
        data[field_name] = bool(parsed.get(field_name, False))

    out.data = data
    out.rejected = rejected
    return out
