"""What is known about one malware family, and how each statement is known.

Everything here is evidence with a source. There is deliberately no danger
score: nothing we collect measures victims or damage.
"""
from __future__ import annotations

import json
import re
import sqlite3
from datetime import date

from . import family_refs, mitre
from .geo import _category

_TYPES = {"Ransomware": "Ransomware", "Post-exploitation C2": "Post-exploitation framework",
          "Infostealer": "Infostealer", "Loader": "Loader",
          "Botnet / DDoS": "Botnet / DDoS", "RAT C2": "Remote access trojan"}
ACTIVE_DAYS, RECENT_DAYS = 7, 30


def activity(last_seen: str, latest: str) -> dict:
    """Measured against the newest collection, not today, so a stopped
    collector reads as old data rather than as malware going quiet."""
    try:
        days = (date.fromisoformat(latest) - date.fromisoformat(last_seen)).days
    except ValueError:
        return {"status": "unknown", "days_before_latest": None, "latest_collection": latest}
    status = "active" if days <= ACTIVE_DAYS else "recent" if days <= RECENT_DAYS else "quiet"
    return {"status": status, "days_before_latest": days, "latest_collection": latest}


def family_type(family: str, tag_lists: list[list[str]]) -> dict:
    """The family's own name decides; otherwise most of its signals' tags must agree."""
    kind = _TYPES.get(_category("", family, [], ""))
    if kind:
        return {"type": kind, "basis": "family name"}
    counts: dict[str, int] = {}
    for tags in tag_lists:
        k = _TYPES.get(_category("", "", tags, ""))
        if k:
            counts[k] = counts.get(k, 0) + 1
    if counts:
        best = max(counts, key=lambda k: counts[k])
        if counts[best] * 2 > len(tag_lists):
            return {"type": best, "basis": "feed tags"}
    return {"type": "", "basis": ""}


def names_actor(actor: str, family: str, text: str) -> bool:
    """Does the text itself name the actor, apart from the family's own name?

    Extraction can assign an actor from a family name alone, which is how
    "Akira Stealer" came to be credited to the Akira group. That is not evidence.
    """
    rest = re.sub(re.escape(family), " ", text or "", flags=re.I)
    names = [n.strip() for n in re.split(r"[()/]", actor) if n.strip()]
    return any(re.search(rf"(?<!\w){re.escape(n)}(?!\w)", rest, re.I) for n in names)


def reported_groups(rows: list[tuple], family: str) -> list[dict]:
    """rows: (actor, title, raw_text, day, url). Only reports naming the group count."""
    out: dict[str, dict] = {}
    for actor, title, raw, day, url in rows:
        if not names_actor(actor, family, f"{title or ''} {raw or ''}"):
            continue
        g = out.setdefault(actor, {"group": actor, "reports": 0, "last_reported": "", "url": ""})
        g["reports"] += 1
        if (day or "") >= g["last_reported"]:
            g["last_reported"], g["url"] = day or "", url or ""
    return sorted(out.values(), key=lambda g: g["last_reported"], reverse=True)


def build(db_path: str, profile: dict) -> dict:
    family = profile["family"]
    con = sqlite3.connect(db_path)
    try:
        latest = (con.execute("SELECT MAX(collected_at) FROM signals").fetchone()[0] or "")[:10]
        tags = [json.loads(r[0] or "[]") for r in con.execute(
            "SELECT tags FROM signals WHERE malware_family = ? COLLATE NOCASE", (family,))]
        reported = reported_groups(con.execute(
            "SELECT threat_actor, title, raw_text, "
            "SUBSTR(COALESCE(NULLIF(posted_at, ''), collected_at), 1, 10), source_url "
            "FROM signals WHERE malware_family = ? COLLATE NOCASE AND threat_actor != ''",
            (family,)).fetchall(), family)
    finally:
        con.close()
    return {"activity": activity(profile["last_seen"], latest),
            **family_type(family, tags),
            "attack": mitre.software_for(family), "refs": family_refs.lookup(family),
            "reported_groups": reported}
