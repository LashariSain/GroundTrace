"""APT <-> CVE links: which groups have exploited which vulnerabilities.

Every link keeps the evidence that names the CVE (the sentence, trimmed),
its kind, its date when known, and a confidence:

  high    an operation record or technique note says the group exploited it
  medium  it appears in the group's description or tool list
  low     it is only listed among the group's published indicators, or in
          one of our signals attributed to the group

Links are rebuilt from the local copies of the catalog, ATT&CK, the
operation records and our signals (no network), into the sightings DB.
"""
from __future__ import annotations

import json
import re
import sqlite3
from collections import defaultdict
from pathlib import Path
from typing import Optional

from . import aptdb

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
CONFIDENCE = {"operation": "high", "technique": "high", "description": "medium",
              "tool": "medium", "indicator": "low", "telemetry": "low"}
_RANK = {"high": 0, "medium": 1, "low": 2}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cve_links (
    group_key  TEXT NOT NULL,
    cve        TEXT NOT NULL,
    kind       TEXT NOT NULL,     -- operation | technique | description | tool | indicator | telemetry
    confidence TEXT NOT NULL,
    evidence   TEXT DEFAULT '',
    day        TEXT DEFAULT '',   -- when the evidence is dated
    url        TEXT DEFAULT '',
    PRIMARY KEY (group_key, cve, kind, evidence)
);
CREATE INDEX IF NOT EXISTS idx_cve_links_cve ON cve_links(cve);
"""


def connect(path: Optional[str] = None) -> sqlite3.Connection:
    from . import apt_sightings
    con = apt_sightings.connect(path)
    con.executescript(_SCHEMA)
    return con


def _sentence(text: str, cve: str, width: int = 240) -> str:
    """The sentence naming the CVE, without ATT&CK's (Citation: ...) marks."""
    text = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    text = re.sub(r"\[([^\]]+)\]\(https?://[^)]+\)", r"\1", text)  # markdown links -> their text
    text = " ".join(text.split())
    i = text.upper().find(cve.upper())
    if i < 0:
        return text[:width]
    # The sentence holding the CVE; if it is long, a window centred on the
    # CVE, cut at word boundaries so the snippet is about this CVE.
    s_start = text.rfind(". ", 0, i)
    s_start = 0 if s_start < 0 else s_start + 2
    s_end = text.find(". ", i + len(cve))
    s_end = len(text) if s_end < 0 else s_end + 1
    start, end = s_start, s_end
    if end - start > width:
        start = max(s_start, i - width // 3)
        end = min(s_end, start + width)
        if start > s_start:
            start = text.find(" ", start) + 1 or start
        if end < s_end:
            end = text.rfind(" ", start, end) if text.rfind(" ", start, end) > i else end
    snippet = text[start:end].strip()
    return ("…" if start > 0 else "") + snippet + ("…" if end < len(text) else "")


def collect(signals_db: Optional[str] = None, attack_json: Optional[str] = None,
            cards: Optional[list] = None) -> list[dict]:
    """All links from local data. Pure function of its inputs (testable)."""
    links: list[dict] = []

    def add(group_key, text, kind, day="", url=""):
        for cve in {c.upper() for c in CVE_RE.findall(text or "")}:
            links.append({"group_key": group_key, "cve": cve, "kind": kind, "confidence": CONFIDENCE[kind],
                          "evidence": _sentence(text, cve), "day": day or "", "url": url or ""})

    data = aptdb._load()
    for g in data["groups"]:
        add(g["uuid"], g["description"], "description")
        for t in g["tools"]:
            add(g["uuid"], f"{t['name']}: {t['description']}".strip(": "), "tool")
        for c in g.get("otx_cves") or []:
            links.append({"group_key": g["uuid"], "cve": c, "kind": "indicator", "confidence": "low",
                          "evidence": f"{c} is listed among the group's published indicators.", "day": "", "url": ""})

    # ATT&CK: group descriptions and the notes on each technique a group uses.
    if attack_json is None:
        from . import mitre
        attack_json = str(mitre.bundle_path())
    if attack_json and Path(attack_json).exists():
        objs = {o["id"]: o for o in json.loads(Path(attack_json).read_text(encoding="utf-8")).get("objects", []) if o.get("id")}
        groups = {}
        for o in objs.values():
            if o.get("type") == "intrusion-set" and not o.get("revoked"):
                g = aptdb.resolve(o["name"]) or next((aptdb.resolve(a) for a in o.get("aliases") or [] if aptdb.resolve(a)), None)
                if g:
                    groups[o["id"]] = g["uuid"]
                    add(g["uuid"], o.get("description", ""), "description")
        for rel in objs.values():
            if rel.get("type") == "relationship" and rel.get("relationship_type") == "uses" and rel.get("source_ref") in groups:
                target = objs.get(rel.get("target_ref"), {})
                ext = next((r for r in target.get("external_references", []) if r.get("source_name") == "mitre-attack"), {})
                add(groups[rel["source_ref"]], rel.get("description", ""), "technique", url=ext.get("url", ""))

    # Dated operation records.
    from . import apt_sightings, etda
    for card in cards if cards is not None else etda.cards():
        gk = apt_sightings.etda_group_key(card)
        if gk:
            for op in card["operations"]:
                add(gk, op["text"], "operation", day=op["day"], url=op["url"])

    # Our signals naming both a group and a CVE.
    if signals_db and Path(signals_db).exists():
        con = sqlite3.connect(signals_db)
        try:
            rows = con.execute("SELECT threat_actor, cve_ids, title, source_url, COALESCE(posted_at, collected_at) "
                               "FROM signals WHERE COALESCE(threat_actor, '') != '' AND cve_ids NOT IN ('', '[]')").fetchall()
        finally:
            con.close()
        for actor, cves, title, url, ts in rows:
            g = aptdb.resolve(actor)
            if not g:
                continue
            for c in json.loads(cves or "[]"):
                links.append({"group_key": g["uuid"], "cve": c.upper(), "kind": "telemetry", "confidence": "low",
                              "evidence": (title or "")[:240], "day": (ts or "")[:10], "url": url or ""})
    return links


def rebuild(con: sqlite3.Connection, links: list[dict]) -> int:
    con.execute("DELETE FROM cve_links")
    con.executemany("INSERT OR IGNORE INTO cve_links (group_key, cve, kind, confidence, evidence, day, url) "
                    "VALUES (:group_key, :cve, :kind, :confidence, :evidence, :day, :url)", links)
    con.commit()
    return con.execute("SELECT COUNT(*) FROM cve_links").fetchone()[0]


def _best(rows) -> dict:
    """Collapse several evidence rows into one link with its strongest confidence."""
    rows = sorted(rows, key=lambda r: (_RANK[r["confidence"]], r["day"] == "", r["day"]), reverse=False)
    dated = sorted((r["day"] for r in rows if r["day"]), reverse=True)
    return {"confidence": rows[0]["confidence"], "last_dated": dated[0] if dated else "",
            "evidence": [{"kind": r["kind"], "confidence": r["confidence"], "text": r["evidence"],
                          "day": r["day"], "url": r["url"]} for r in rows[:6]],
            "evidence_count": len(rows)}


def groups_for_cve(con: sqlite3.Connection, cve: str) -> list[dict]:
    by = defaultdict(list)
    for r in con.execute("SELECT * FROM cve_links WHERE cve = ?", (cve.upper(),)):
        by[r["group_key"]].append(dict(r))
    out = []
    for gk, rows in by.items():
        g = aptdb._load()["by_uuid"].get(gk, {})
        out.append({"group": gk, "name": g.get("name", gk[5:] if gk.startswith("name:") else gk),
                    "country": g.get("country", ""), **_best(rows)})
    return sorted(out, key=lambda x: (_RANK[x["confidence"]], -x["evidence_count"], x["name"]))


def cves_for_group(con: sqlite3.Connection, group_key: str) -> list[dict]:
    by = defaultdict(list)
    for r in con.execute("SELECT * FROM cve_links WHERE group_key = ?", (group_key,)):
        by[r["cve"]].append(dict(r))
    out = [{"cve": c, **_best(rows)} for c, rows in by.items()]
    return sorted(out, key=lambda x: (_RANK[x["confidence"]], x["cve"]), reverse=False)
