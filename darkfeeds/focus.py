"""Optional focus country, read from a local file and off by default.

A deployment that cares about one country can describe it in a JSON file kept
outside the repository (GROUNDTRACE_FOCUS_FILE, default ~/.groundtrace/focus.json):

    {"country": "exampleland", "code": "EX",
     "signals": [["(?i)\\\\bexampleland\\\\b", 0.4]],
     "otx_searches": ["exampleland"],
     "hunt_tags": ["SomeMalware"],
     "crawl_queries": ["exampleland leak"]}

Signals mentioning it are scored as relevant and labelled with that target.
"""
from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

RELEVANT = 0.2


@dataclass
class Focus:
    country: str = ""
    code: str = ""
    signals: list = field(default_factory=list)
    otx_searches: list = field(default_factory=list)
    hunt_tags: list = field(default_factory=list)
    crawl_queries: list = field(default_factory=list)


_cache: tuple[Optional[str], Optional[float], Focus] = (None, None, Focus())


def _path() -> Path:
    raw = os.environ.get("GROUNDTRACE_FOCUS_FILE")
    return Path(raw).expanduser() if raw else Path.home() / ".groundtrace" / "focus.json"


def _parse(raw: dict) -> Focus:
    strs = lambda k: [s for s in raw.get(k) or [] if isinstance(s, str) and s]
    return Focus(country=str(raw.get("country") or "").strip().lower(),
                 code=str(raw.get("code") or "").strip().upper(),
                 signals=[(re.compile(p), float(w)) for p, w in raw.get("signals") or []],
                 otx_searches=strs("otx_searches"), hunt_tags=strs("hunt_tags"),
                 crawl_queries=strs("crawl_queries"))


def get() -> Focus:
    """The configured focus, or an empty one. A broken file warns and is ignored."""
    global _cache
    path = _path()
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return Focus()
    if _cache[0] == str(path) and _cache[1] == mtime:
        return _cache[2]
    try:
        loaded = _parse(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError, re.error) as e:
        print(f"[!] ignoring focus file {path}: {e}", file=sys.stderr)
        loaded = Focus()
    _cache = (str(path), mtime, loaded)
    return loaded


def relevance(text: str) -> float:
    """Score 0-1 how relevant this text is to the focus country."""
    return min(sum(w for p, w in get().signals if p.search(text)), 1.0)


def target(score: float) -> str:
    """The target label for a relevance score, or "" when it isn't relevant."""
    return get().country if score > RELEVANT else ""
