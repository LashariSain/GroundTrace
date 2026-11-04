"""MITRE ATT&CK, straight from the source: per group, its techniques (with
names and tactics) and the software it uses.

APTmap's copy carries technique ids for only ~70 groups (APT36: none);
ATT&CK itself documents ~170 groups (APT36 / G0134: 14 techniques, 5 malware).
The STIX bundle (~55 MB) is downloaded weekly and compacted; ATT&CK is free to
use with attribution to The MITRE Corporation.
"""
from __future__ import annotations

import threading
import json
import os
import re
import sys
import time
import urllib.request
from pathlib import Path
from typing import Optional

from .config import get_config

URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
       "enterprise-attack/enterprise-attack.json")
CREDIT = {"name": "MITRE ATT&CK®", "url": "https://attack.mitre.org/"}
_MAX_AGE = 7 * 24 * 3600

_index: dict = {}
_index_mtime: Optional[float] = None


def _dir() -> Path:
    return Path(get_config().db_path).expanduser().parent


def bundle_path() -> Path:
    return _dir() / "attack.json"


def _index_path() -> Path:
    return _dir() / "attack_index.json"


_refresh_lock = threading.Lock()


def refresh(force: bool = False) -> bool:
    """One download at a time: a second caller waits, then finds it fresh."""
    with _refresh_lock:
        return _refresh(force)


def _refresh(force: bool) -> bool:
    raw, idx = bundle_path(), _index_path()
    if not force and idx.exists() and time.time() - idx.stat().st_mtime < _MAX_AGE:
        return False
    tmp = raw.with_suffix(f".{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        req = urllib.request.Request(URL, headers={"User-Agent": "groundtrace/0.1 (research tool)"})
        with urllib.request.urlopen(req, timeout=180) as r, open(tmp, "wb") as f:
            while chunk := r.read(1 << 16):
                f.write(chunk)
        os.replace(tmp, raw)
    except OSError as e:
        print(f"[mitre] download failed, keeping the previous copy: {e}", file=sys.stderr)
        tmp.unlink(missing_ok=True)
        if not raw.exists():
            return False
    build_index(raw, idx)
    return True


def _ext_id(o: dict) -> tuple[str, str]:
    ref = next((r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), {})
    return ref.get("external_id", ""), ref.get("url", "")


def _plain(text: str) -> str:
    """ATT&CK prose without its markdown links and citation markers."""
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    return re.sub(r"\s*\(Citation:[^)]*\)", "", text).strip()


def build_index(raw: Path, idx: Path) -> None:
    objs = {o["id"]: o for o in json.loads(raw.read_text(encoding="utf-8")).get("objects", [])
            if not o.get("revoked") and not o.get("x_mitre_deprecated")}
    groups, software = {}, {}
    for o in objs.values():
        if o["type"] in ("malware", "tool"):
            sid, surl = _ext_id(o)
            software[o["id"]] = {"id": sid, "url": surl, "name": o["name"], "type": o["type"],
                                 "aliases": [a for a in o.get("x_mitre_aliases") or [] if a != o["name"]],
                                 "description": _plain(o.get("description") or "")[:1500],
                                 "platforms": o.get("x_mitre_platforms") or [],
                                 "techniques": {}, "groups": {}}
    for rel in objs.values():
        if rel["type"] != "relationship" or rel.get("relationship_type") != "uses":
            continue
        s, t = software.get(rel.get("source_ref")), objs.get(rel.get("target_ref"))
        if s and t and t["type"] == "attack-pattern":
            tid, turl = _ext_id(t)
            s["techniques"][tid] = {"id": tid, "name": t["name"], "url": turl,
                                    "tactics": [p["phase_name"] for p in t.get("kill_chain_phases", [])]}
        s, g = software.get(rel.get("target_ref")), objs.get(rel.get("source_ref"))
        if s and g and g["type"] == "intrusion-set":
            gid, gurl = _ext_id(g)
            s["groups"][gid] = {"id": gid, "name": g["name"], "url": gurl}
    for o in objs.values():
        if o["type"] != "intrusion-set":
            continue
        gid, url = _ext_id(o)
        groups[o["id"]] = {"id": gid, "url": url, "name": o["name"],
                           "aliases": [a for a in o.get("aliases") or [] if a != o["name"]],
                           "description": (o.get("description") or "")[:3000],
                           "modified": (o.get("modified") or "")[:10],
                           "techniques": {}, "software": {}}
    for rel in objs.values():
        if rel["type"] != "relationship" or rel.get("relationship_type") != "uses":
            continue
        g, t = groups.get(rel.get("source_ref")), objs.get(rel.get("target_ref"))
        if not g or not t:
            continue
        tid, turl = _ext_id(t)
        if t["type"] == "attack-pattern":
            g["techniques"][tid] = {"id": tid, "name": t["name"], "url": turl,
                                    "tactics": [p["phase_name"] for p in t.get("kill_chain_phases", [])]}
        elif t["type"] in ("malware", "tool"):
            g["software"][tid] = {"id": tid, "name": t["name"], "type": t["type"], "url": turl}
    out = []
    for g in groups.values():
        g["techniques"] = sorted(g["techniques"].values(), key=lambda x: x["id"])
        g["software"] = sorted(g["software"].values(), key=lambda x: x["name"].lower())
        out.append(g)
    tmp = idx.with_suffix(f".{os.getpid()}.{threading.get_ident()}.tmp")
    tmp.write_text(json.dumps({"groups": out, "software": [
        {**s, "techniques": sorted(s["techniques"].values(), key=lambda x: x["id"]),
         "groups": sorted(s["groups"].values(), key=lambda x: x["name"].lower())}
        for s in software.values()]}), encoding="utf-8")
    os.replace(tmp, idx)


def _load() -> dict:
    global _index, _index_mtime
    idx = _index_path()
    if not idx.exists():
        if bundle_path().exists():
            build_index(bundle_path(), idx)
        else:
            refresh()
    if not idx.exists():
        return {"groups": []}
    if idx.stat().st_mtime != _index_mtime:
        _index, _index_mtime = json.loads(idx.read_text(encoding="utf-8")), idx.stat().st_mtime
    if "software" not in _index and bundle_path().exists():  # index from an older version
        build_index(bundle_path(), idx)
        _index, _index_mtime = json.loads(idx.read_text(encoding="utf-8")), idx.stat().st_mtime
    return _index


def software_for(family: str) -> Optional[dict]:
    """The ATT&CK entry whose name or alias is exactly this family, if any."""
    from .aptdb import _norm
    want = _norm(family)
    if not want:
        return None
    for s in _load().get("software", []):
        if want in {_norm(n) for n in [s["name"], *s["aliases"]]}:
            return {**s, "credit": CREDIT}
    return None


def group_for(names: list[str]) -> Optional[dict]:
    """The ATT&CK group for a catalog group: names[0] is its primary name.
    A group matching the primary name wins; otherwise the one sharing the most
    aliases. (The catalog lists APT38 as a Lazarus alias, but ATT&CK tracks
    them apart; first-alias-wins mapped Lazarus to APT38.)"""
    from .aptdb import _norm
    if not names:
        return None
    primary, want = _norm(names[0]), {_norm(n) for n in names if n} - {""}
    best, best_score = None, 0
    for g in _load()["groups"]:
        theirs = {_norm(n) for n in [g["name"], *g["aliases"]]}
        score = (100 if primary in theirs else 0) + len(want & theirs)
        if score > best_score:
            best, best_score = g, score
    return {**best, "credit": CREDIT} if best else None
