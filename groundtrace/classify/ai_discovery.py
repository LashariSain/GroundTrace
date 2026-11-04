"""
AI-discovery detector: was this vulnerability FOUND BY an AI system?

Separate from the discovery-method classifier on purpose: an AI agent that
fuzzes is still "fuzzing" by method, but "found by AI" is its own question.

Rules are phrased around the act of discovery ("discovered using an LLM",
"Big Sleep"), not around AI as a topic, so a prompt-injection bug *in* an
LLM app does not count. Every hit returns the phrase that triggered it.
"""
from __future__ import annotations

import re
from typing import Optional

# Named AI vulnerability-finding systems -> display label. Mentioned anywhere
# in description or reference URLs, these are strong enough on their own.
_NAMED = [
    (re.compile(r"big[ _-]?sleep", re.I), "Google Big Sleep"),
    (re.compile(r"\bnaptime\b", re.I), "Google Project Naptime"),
    (re.compile(r"\bcodemender\b", re.I), "Google CodeMender"),
    (re.compile(r"\bxbow\b", re.I), "XBOW"),
    (re.compile(r"\baixcc\b|ai cyber challenge", re.I), "DARPA AIxCC"),
    (re.compile(r"\bvulnhuntr\b", re.I), "Vulnhuntr"),
    (re.compile(r"zeropath", re.I), "ZeroPath"),
    (re.compile(r"\baardvark\b.{0,40}openai|openai.{0,40}\baardvark\b", re.I), "OpenAI Aardvark"),
]

# Nouns after "AI-powered" etc. are research activities only: "AI-powered
# agents" is how AI products describe themselves (Langflow), not a finder.
# "AI" is matched case-sensitively so "reported by Aiden" can't trigger it.
_AI = (r"(?:an? )?(?:AI|LLMs?|(?i:artificial intelligence|large language models?|"
       r"AI[- ]?agents?|autonomous (?:AI )?agents?|machine learning))")
_PHRASES = [
    re.compile(r"(?i:discovered|found|identified|uncovered|detected|reported)\s+"
               r"(?i:by|using|with|via|through|with the help of)\s+(?:the help of\s+)?" + _AI),
    re.compile(r"\bAI[- ](?i:assisted|powered|driven|based|generated|aided)\s+"
               r"(?i:fuzz\w*|analysis|discovery|research|audit\w*|code review|"
               r"vulnerability|vulnerabilities|scanner|scanning)"),
    re.compile(r"(?i:LLM|large language model)[- ](?i:assisted|powered|driven|based|aided)\s+"
               r"(?i:fuzz\w*|analysis|discovery|research|audit\w*|code review|"
               r"vulnerability|vulnerabilities|scanner|scanning)"),
]


# In a CVE.org credit the subject is already "who found it", so naming an AI
# model or tool there is enough ("finder: ... with assistance from Claude").
_CREDIT_AI = re.compile(
    r"\b(?:Claude|ChatGPT|GPT-?\d[\w.]*|Codex|Gemini|Copilot|AISLE|depthfirst|"
    r"(?-i:AI|LLMs?)|artificial intelligence|language models?|AI agents?)\b", re.I)


def detect_ai_discovery(description: str, references: list[str] | None = None,
                        credits: list[str] | None = None
                        ) -> tuple[Optional[str], list[str]]:
    """Return (label, evidence). label is None when nothing indicates AI discovery."""
    credit_text = " ".join(credits or [])
    text = " ".join(filter(None, [description or "", " ".join(references or []), credit_text]))
    for pattern, label in _NAMED:
        m = pattern.search(text)
        if m:
            return label, [m.group(0)]
    for pattern in _PHRASES:
        m = pattern.search(text)
        if m:
            return "AI-assisted", [m.group(0)]
    m = _CREDIT_AI.search(credit_text)
    if m:
        credit = next(c for c in credits if m.group(0) in c)
        # Label with the credited finder ("CodeAnt AI Security Research Team"),
        # not the bare keyword that matched.
        name = credit.split(": ", 1)[-1]
        return (name if len(name) <= 40 else name[:39] + "…"), [credit]
    return None, []
