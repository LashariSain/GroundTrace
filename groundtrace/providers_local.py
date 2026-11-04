"""
Local LLM providers (stdlib only, no extra dependencies).

  ollama:<model>   -> Ollama server   (GROUNDTRACE_OLLAMA_URL, default http://localhost:11434)
  openai_local     -> any OpenAI-compatible local server (LM Studio, llama.cpp, vLLM)
                      (GROUNDTRACE_LOCAL_URL default http://localhost:1234/v1,
                       GROUNDTRACE_LOCAL_MODEL)

Register with `register_local_providers()`; done automatically on import of
groundtrace.llm consumers via get_provider("ollama") etc.
"""
from __future__ import annotations

import json
import os
import urllib.request

from .llm import register_provider


def _post(url: str, payload: dict, timeout: float) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


class OllamaProvider:
    def __init__(self, model: str | None = None):
        self.model = model or os.environ.get("GROUNDTRACE_OLLAMA_MODEL", "llama3.1")
        self.name = f"ollama:{self.model}"
        self.url = os.environ.get("GROUNDTRACE_OLLAMA_URL", "http://localhost:11434")
        self.timeout = float(os.environ.get("GROUNDTRACE_LLM_TIMEOUT", "120"))

    def complete(self, system: str, prompt: str) -> str:
        data = _post(f"{self.url}/api/chat", {
            "model": self.model, "stream": False,
            "options": {"temperature": 0},
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": prompt}],
        }, self.timeout)
        return data["message"]["content"].strip()


class OpenAICompatLocalProvider:
    def __init__(self, model: str | None = None):
        self.model = model or os.environ.get("GROUNDTRACE_LOCAL_MODEL", "local-model")
        self.name = f"openai_local:{self.model}"
        self.url = os.environ.get("GROUNDTRACE_LOCAL_URL", "http://localhost:1234/v1")
        self.timeout = float(os.environ.get("GROUNDTRACE_LLM_TIMEOUT", "120"))

    def complete(self, system: str, prompt: str) -> str:
        data = _post(f"{self.url}/chat/completions", {
            "model": self.model, "temperature": 0,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": prompt}],
        }, self.timeout)
        return data["choices"][0]["message"]["content"].strip()


def register_local_providers() -> None:
    register_provider("ollama", OllamaProvider)
    register_provider("openai_local", OpenAICompatLocalProvider)
