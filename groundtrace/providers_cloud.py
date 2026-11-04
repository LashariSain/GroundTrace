"""
Free-tier cloud LLM providers (stdlib only, no SDK dependency).

  gemini     -> Google Gemini free tier (GROUNDTRACE_GEMINI_API_KEY, GROUNDTRACE_GEMINI_MODEL)
  openrouter -> OpenRouter, routes to any model incl. free ones
               (GROUNDTRACE_OPENROUTER_API_KEY, GROUNDTRACE_OPENROUTER_MODEL)

Both require an API key the user supplies via environment variable — never
hardcoded, never asked for interactively. Missing key raises immediately with
a clear message rather than failing deep inside a request.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .llm import register_provider

_TIMEOUT = 60


def _post_json(url: str, payload: dict, headers: dict) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", **headers})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {e.code} from {url}: {body[:500]}") from e


class GeminiProvider:
    """Google Gemini free tier — https://ai.google.dev (generateContent API)."""

    def __init__(self, model: str | None = None):
        self.model = model or os.environ.get("GROUNDTRACE_GEMINI_MODEL", "gemini-3.5-flash-lite")
        self.name = f"gemini:{self.model}"
        self.api_key = os.environ.get("GROUNDTRACE_GEMINI_API_KEY")
        if not self.api_key:
            raise RuntimeError(
                "GROUNDTRACE_GEMINI_API_KEY is not set. Get a free key at "
                "https://aistudio.google.com/apikey and set that env var.")

    def complete(self, system: str, prompt: str) -> str:
        url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
               f"{self.model}:generateContent?key={self.api_key}")
        data = _post_json(url, {
            "system_instruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0},
        }, {})
        try:
            return data["candidates"][0]["content"]["parts"][0]["text"].strip()
        except (KeyError, IndexError) as e:
            raise RuntimeError(f"unexpected Gemini response shape: {data}") from e


class OpenRouterProvider:
    """OpenRouter — https://openrouter.ai (OpenAI-compatible chat completions,
    routes to many models including free ones, e.g. a '*:free' model id)."""

    def __init__(self, model: str | None = None):
        self.model = model or os.environ.get(
            "GROUNDTRACE_OPENROUTER_MODEL", "meta-llama/llama-3.1-8b-instruct:free")
        self.name = f"openrouter:{self.model}"
        self.api_key = os.environ.get("GROUNDTRACE_OPENROUTER_API_KEY")
        if not self.api_key:
            raise RuntimeError(
                "GROUNDTRACE_OPENROUTER_API_KEY is not set. Get a free key at "
                "https://openrouter.ai/keys and set that env var.")

    def complete(self, system: str, prompt: str) -> str:
        data = _post_json(
            "https://openrouter.ai/api/v1/chat/completions",
            {"model": self.model, "temperature": 0,
             "messages": [{"role": "system", "content": system},
                          {"role": "user", "content": prompt}]},
            {"Authorization": f"Bearer {self.api_key}"},
        )
        try:
            return data["choices"][0]["message"]["content"].strip()
        except (KeyError, IndexError) as e:
            raise RuntimeError(f"unexpected OpenRouter response shape: {data}") from e


def register_cloud_providers() -> None:
    register_provider("gemini", GeminiProvider)
    register_provider("openrouter", OpenRouterProvider)
