"""
Model interface + registry (Sprint 1).

Every LLM backend implements `LLMProvider.complete()`. Providers are looked up
by name from a registry, so swapping models is a config change, not a code
change. The built-in `offline` provider is deterministic and needs no network,
so the pipeline and tests always work unconfigured.

Real providers (OpenAI/Anthropic/Gemini/local) register themselves with
`register_provider()`; none are imported here to keep this dependency-free.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Callable, Optional, Protocol


@dataclass
class LLMResult:
    text: str
    model: str
    latency_s: float = 0.0
    prompt_version: str = ""


class LLMProvider(Protocol):
    name: str

    def complete(self, system: str, prompt: str) -> str: ...


class OfflineProvider:
    """Deterministic stand-in: returns the prompt's own facts, no generation."""
    name = "offline"

    def complete(self, system: str, prompt: str) -> str:
        return prompt.strip()


_REGISTRY: dict[str, Callable[[], LLMProvider]] = {"offline": OfflineProvider}

# Versioned prompts so evaluation runs can be compared across changes.
PROMPTS: dict[str, dict[str, str]] = {
    "threat_summary": {
        "v1": ("You are a threat-intel analyst. Using ONLY the facts given, "
               "write a 3-sentence analyst summary. Do not invent details."),
        "v2": ("You are a threat-intel analyst. Using ONLY the facts given, "
               "write exactly 3 sentences of analyst summary. Do not invent "
               "details or numbers not present in the facts. Output ONLY the "
               "3 sentences — no preamble, no headers, no meta-commentary."),
    },
    "ioc_extraction": {
        "v1": ("You are a threat-intel extraction engine. Read the underground "
               "forum/paste post below and extract structured intelligence as "
               "STRICT JSON ONLY — no markdown fences, no commentary, no "
               "explanation, just the JSON object. Copy IOC values (hashes, "
               "IPs, domains, URLs, CVE ids) EXACTLY as they appear in the "
               "text — never normalize, guess, complete, or invent one that "
               "is not literally present. If a field has no value, use an "
               "empty string or empty list. Schema:\n"
               '{"cve_ids": [], "hashes": [], "ips": [], "domains": [], '
               '"urls": [], "threat_actor": "", "malware_family": "", '
               '"exploit_type": "", "price": "", "is_selling": false, '
               '"is_zero_day": false, "target_sector": ""}'),
    },
}


def register_provider(name: str, factory: Callable[[], LLMProvider]) -> None:
    _REGISTRY[name] = factory


def available_providers() -> list[str]:
    return sorted(_REGISTRY)


def get_provider(name: Optional[str] = None) -> LLMProvider:
    """Resolve provider by explicit name, else GROUNDTRACE_LLM_PROVIDER, else offline."""
    name = name or os.environ.get("GROUNDTRACE_LLM_PROVIDER", "offline")
    base_name = name.split(":", 1)[0]
    if base_name not in _REGISTRY:
        from .providers_local import register_local_providers
        from .providers_cloud import register_cloud_providers
        register_local_providers()
        register_cloud_providers()
    if ":" in name and name.split(":", 1)[0] in _REGISTRY:  # e.g. ollama:qwen2.5
        base, model = name.split(":", 1)
        return _REGISTRY[base](model)
    if name not in _REGISTRY:
        raise KeyError(f"unknown LLM provider {name!r}; available: {available_providers()}")
    return _REGISTRY[name]()


def run_prompt(task: str, facts: str, *, provider: Optional[str] = None,
               version: str = "v2") -> LLMResult:
    p = get_provider(provider)
    system = PROMPTS[task][version]
    t0 = time.perf_counter()
    text = p.complete(system, facts)
    return LLMResult(text=text, model=p.name,
                     latency_s=round(time.perf_counter() - t0, 4),
                     prompt_version=f"{task}:{version}")
