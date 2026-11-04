"""Malware family reference data: Malpedia and MISP Galaxy.

Both are downloaded to the local data directory and never shipped with this
project. Malpedia's content is CC BY-NC-SA 3.0, so it is non-commercial and is
credited wherever it is shown. Set GROUNDTRACE_MALPEDIA=0 to leave it out; the
MISP Galaxy clusters (CC0 or BSD) are then the only source.

Pages only read the local index, so a page view never waits on these sites.
"""
from __future__ import annotations

import http.client
import json
import os
import re
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Optional

from .config import get_config

MALPEDIA_URL = "https://malpedia.caad.fkie.fraunhofer.de/api/get/families"
MALPEDIA_PAGE = "https://malpedia.caad.fkie.fraunhofer.de/details/"
MISP_URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/{}.json"
MISP_CLUSTERS = ("malpedia", "tool", "rat", "botnet", "stealer", "ransomware")
CREDITS = {"Malpedia": {"name": "Malpedia (Fraunhofer FKIE), CC BY-NC-SA 3.0",
                        "url": "https://malpedia.caad.fkie.fraunhofer.de/"},
           "MISP Galaxy": {"name": "MISP Galaxy, CC0 / BSD",
                           "url": "https://github.com/MISP/misp-galaxy"}}
_PLATFORMS = {"win": "Windows", "elf": "Linux", "osx": "macOS", "apk": "Android",
              "ios": "iOS", "js": "JavaScript", "php": "PHP", "py": "Python",
              "jar": "Java", "ps1": "PowerShell", "vbs": "VBScript", "aix": "AIX",
              "asp": "ASP", "pl": "Perl", "symbian": "Symbian", "fas": "AutoLISP"}
_MAX_AGE = 7 * 24 * 3600
_MAX_BYTES = 64 * 1024 * 1024
_MAX_REFS = 8

_index: dict = {}
_index_mtime: Optional[float] = None


def norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def _index_path() -> Path:
    return Path(get_config().db_path).expanduser().parent / "family_index.json"


def _malpedia_enabled() -> bool:
    return os.environ.get("GROUNDTRACE_MALPEDIA", "1").strip().lower() not in ("0", "false", "no", "off")


def _fetch(url: str) -> Optional[dict]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "groundtrace/0.1 (research tool)"})
        with urllib.request.urlopen(req, timeout=120) as r:
            raw = r.read(_MAX_BYTES + 1)
        if len(raw) > _MAX_BYTES:
            raise ValueError("response too large")
        data = json.loads(raw)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError, http.client.HTTPException) as e:
        print(f"[family_refs] {url}: {e}", file=sys.stderr)
        return None


def _web(urls) -> list[str]:
    return [u for u in urls or [] if isinstance(u, str) and re.match(r"https?://", u)][:_MAX_REFS]


def _text(value) -> str:
    return (value or "").strip()[:1500] if isinstance(value, str) else ""


def _strs(values) -> list[str]:
    return [v for v in values or [] if isinstance(v, str) and v]


def build(malpedia: Optional[dict], clusters: dict[str, dict]) -> dict:
    """{normalised name: entry}. A family's own name beats another's alias, and
    Malpedia is preferred; MISP Galaxy fills what Malpedia leaves out."""
    entries: list[tuple[list[str], list[str], dict]] = []
    for key, v in (malpedia or {}).items():
        if not isinstance(v, dict):
            continue
        name = v.get("common_name") or key.split(".", 1)[-1]
        prefix = key.split(".", 1)[0]
        aliases = _strs(v.get("alt_names"))
        entries.append(([name, key.split(".", 1)[-1]], aliases, {
            "name": name, "aliases": aliases, "description": _text(v.get("description")),
            "description_source": "Malpedia" if _text(v.get("description")) else "",
            "platforms": [_PLATFORMS[prefix]] if prefix in _PLATFORMS else [],
            "attribution": _strs(v.get("attribution")),
            "refs": _web(v.get("urls")), "source": "Malpedia",
            "url": MALPEDIA_PAGE + key if re.fullmatch(r"[\w.\-]+", key) else ""}))
    for cluster in clusters.values():
        for v in cluster.get("values") or []:
            if not isinstance(v, dict) or not isinstance(v.get("value"), str):
                continue
            meta = v.get("meta") if isinstance(v.get("meta"), dict) else {}
            aliases = _strs(meta.get("synonyms"))
            entries.append(([v["value"]], aliases, {
                "name": v["value"], "aliases": aliases, "description": _text(v.get("description")),
                "description_source": "MISP Galaxy" if _text(v.get("description")) else "",
                "platforms": [], "attribution": [], "refs": _web(meta.get("refs")),
                "source": "MISP Galaxy", "url": ""}))
    out: dict[str, dict] = {}
    for by_alias in (False, True):
        for names, aliases, entry in entries:
            for n in map(norm, aliases if by_alias else names):
                if not n:
                    continue
                have = out.get(n)
                if have is None:
                    out[n] = {**entry}
                elif not have["description"] and entry["description"]:
                    have["description"] = entry["description"]
                    have["description_source"] = entry["description_source"]
    return out


def build_index(malpedia: Optional[dict], clusters: dict[str, dict]) -> dict:
    """Two views, so switching Malpedia off falls back to the open data at once."""
    return {"all": build(malpedia, clusters), "open": build(None, clusters)}


def refresh(force: bool = False) -> bool:
    """Weekly. Any failed download keeps the previous index, so one site being
    down can't silently drop its data for a week."""
    idx = _index_path()
    if not force and idx.exists() and time.time() - idx.stat().st_mtime < _MAX_AGE:
        return False
    use_malpedia = _malpedia_enabled()
    malpedia = _fetch(MALPEDIA_URL) if use_malpedia else None
    clusters = {c: d for c in MISP_CLUSTERS if (d := _fetch(MISP_URL.format(c)))}
    complete = (malpedia is not None or not use_malpedia) and len(clusters) == len(MISP_CLUSTERS)
    if idx.exists() and not complete:
        return False
    built = build_index(malpedia, clusters)
    if not built["open"] and not built["all"]:
        return False
    tmp = idx.with_suffix(f".{os.getpid()}.{threading.get_ident()}.tmp")  # server and watcher both refresh
    tmp.write_text(json.dumps(built), encoding="utf-8")
    os.replace(tmp, idx)
    return True


def lookup(family: str) -> Optional[dict]:
    """The local entry for this exact family name or alias, if any."""
    global _index, _index_mtime
    idx = _index_path()
    if not idx.exists():
        return None
    if idx.stat().st_mtime != _index_mtime:
        _index, _index_mtime = json.loads(idx.read_text(encoding="utf-8")), idx.stat().st_mtime
    found = _index.get("all" if _malpedia_enabled() else "open", {}).get(norm(family))
    if not found:
        return None
    used = {found["source"], found["description_source"]} - {""}
    return {**found, "credits": [CREDITS[s] for s in sorted(used)]}
