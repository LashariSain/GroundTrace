"""APT catalog: who each threat group is, where it is from, whom it targets,
and what malware it uses — joined with what our own feeds see it doing now.

Catalog source: APTmap by Andrea Cristaldi (github.com/andreacristaldi/APTmap,
CC BY 4.0), which merges MISP Galaxy, MITRE ATT&CK, ETDA and OTX into one
GeoJSON of ~800 groups. It is downloaded weekly and compacted into a small
index; credit is shown on every profile. The live layer (recent signals,
infrastructure, CVEs) comes from the darkfeeds store, matched through each
group's aliases — that part is ours, and is what a static encyclopedia lacks.
"""
from __future__ import annotations

import threading
import json
import os
import re
import sqlite3
import sys
import time
import urllib.request
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path
from typing import Optional

from .config import get_config

_URL = "https://raw.githubusercontent.com/andreacristaldi/APTmap/master/apt.json"
_UA = {"User-Agent": "groundtrace/0.1 (research tool)"}
_MAX_AGE = 7 * 24 * 3600
CREDIT = {"name": "APTmap by Andrea Cristaldi (MISP, MITRE ATT&CK, ETDA, OTX)",
          "url": "https://github.com/andreacristaldi/APTmap", "license": "CC BY 4.0"}

_MAX_LINKS = 40
_MAX_OTX_IOCS = 500
# Seeing a malware family attributes a signal to a group only when the
# family is malware unique to that one group in the catalog AND not a
# commodity kit sold or shared across criminals (Vidar, Formbook, Sliver...):
# those say nothing about who is behind a sighting.
_COMMODITY = ("vidar", "formbook", "xloader", "sliver", "havoc", "xmrig", "danabot", "bitrat",
              "venom", "mimikatz", "psexec", "plugx", "shadowpad", "netwire", "darkcomet",
              "poisonivy", "gh0st", "emotet", "trickbot", "qakbot", "qbot", "icedid", "ursnif",
              "lokibot", "nanocore", "warzone", "avemaria", "dcrat", "xworm", "metasploit",
              "cobaltstrike", "bruteratel", "vshell", "mythic", "covenant", "supershell",
              "lumma", "redline", "stealc", "raccoon", "rhadamanthys", "amadey", "agenttesla",
              "smokeloader", "gootloader", "bumblebee", "pikabot", "latrodectus", "guloader",
              "privateloader", "mirai", "gafgyt", "mozi", "asyncrat", "remcos", "njrat",
              "quasar", "purerat", "venomrat", "redlinestealer")

# APTmap target names that differ from the world map's country names.
_COUNTRY_ALIASES = {
    "usa": "US", "united states of america": "US", "us": "US", "uk": "GB",
    "england": "GB", "great britain": "GB", "czech": "CZ", "czechia": "CZ",
    "south korea": "KR", "korea": "KR", "republic of korea": "KR", "north korea": "KP",
    "russia": "RU", "russian federation": "RU", "iran": "IR", "syria": "SY",
    "vietnam": "VN", "viet nam": "VN", "laos": "LA", "taiwan": "TW", "uae": "AE",
    "palestine": "PS", "macedonia": "MK", "north macedonia": "MK", "moldova": "MD",
    "bolivia": "BO", "venezuela": "VE", "tanzania": "TZ", "ivory coast": "CI",
    "cote d'ivoire": "CI", "brunei": "BN", "burma": "MM", "hong kong": "HK",
    "macau": "MO", "the netherlands": "NL", "holland": "NL", "vatican": "VA",
    "democratic republic of the congo": "CD", "drc": "CD", "congo": "CG",
    "east timor": "TL", "eswatini": "SZ", "swaziland": "SZ", "kyrgyzstan": "KG",
    "cape verde": "CV", "micronesia": "FM", "slovak republic": "SK",
    "korea (republic of)": "KR", "lebonon": "LB", "macao": "MO", "gaza": "PS",
    "central-african republic": "CF", "chechnya": "RU",
}

_index: dict = {}
_index_mtime: Optional[float] = None


def _dir() -> Path:
    return Path(get_config().db_path).expanduser().parent


def _raw_path() -> Path:
    return _dir() / "aptmap.json"


def _index_path() -> Path:
    return _dir() / "apt_index.json"


def _norm(s: str) -> str:
    """Alias key: 'Operation “Transparent Tribe”' -> 'transparenttribe',
    'Lazarus Group' -> 'lazarus'."""
    s = re.sub(r"\b(operation|group|team|gang|the)\b", "", (s or "").lower())
    return re.sub(r"[^a-z0-9]", "", s)


def _country_codes() -> dict[str, str]:
    """English country name -> ISO-3166 alpha-2, from the dashboard's map."""
    svg = (Path(__file__).parent / "static" / "world.svg").read_text(encoding="utf-8")
    names = {}
    for label, cc in re.findall(r'aria-label="([^"]+)"\s+id="([a-z]{2})"', svg):
        names[label.lower()] = cc.upper()
    names.update(_COUNTRY_ALIASES)
    return names


def _to_cc(name: str, codes: dict) -> Optional[str]:
    n = (name or "").strip().lower()
    if len(n) == 2 and n.upper() in codes.values():
        return n.upper()
    return codes.get(n) or codes.get(re.sub(r"^the ", "", n))


def _is_commodity(name: str) -> bool:
    n = _norm(name)
    return any(k in n for k in _COMMODITY)


def _clean_text(s) -> str:
    return re.sub(r"\s+\n", "\n", str(s or "")).strip()


def _compact(feature: dict, codes: dict) -> dict:
    p = feature.get("properties") or {}
    coords = (feature.get("geometry") or {}).get("coordinates") or []
    targets = [t for t in p.get("targets") or [] if isinstance(t, str)]
    tools = []
    for t in p.get("tools") or []:
        if isinstance(t, dict) and t.get("value"):
            desc = _clean_text(t.get("description"))
            tools.append({"name": t["value"], "category": t.get("category") or "",
                          "description": "" if desc.startswith("No description") else desc[:600],
                          "refs": [r for r in t.get("refs") or [] if isinstance(r, str)][:3]})
    iocs = p.get("otx_iocs") or []
    # Indicators are {"type", "value"}; older exports used "indicator".
    val = lambda i: i.get("value") or i.get("indicator")
    of = lambda *types: sorted({val(i) for i in iocs if isinstance(i, dict) and i.get("type") in types and val(i)})
    ips, domains = of("IPv4", "IPv6"), of("domain", "hostname")
    cve_iocs = sorted({c.upper() for c in of("CVE") if c.upper().startswith("CVE-")})
    conf = p.get("attribution-confidence")
    return {
        "uuid": p.get("uuid") or "",
        "name": (p.get("name") or "").strip(),
        "aliases": sorted({a.strip() for a in p.get("other-names") or [] if isinstance(a, str) and a.strip()}),
        "country": (p.get("country") or "").upper(),
        "location": p.get("location") or "",
        "sponsor": p.get("sponsor") or "",
        "motivations": [m for m in p.get("motivations") or [] if isinstance(m, str)],
        "first_seen": str(p.get("first-seen") or ""),
        "description": _clean_text(p.get("description"))[:4000],
        "targets": targets,
        "target_ccs": sorted({c for c in (_to_cc(t, codes) for t in targets) if c}),
        "target_categories": [c for c in p.get("target-category") or [] if isinstance(c, str)],
        "tools": tools,
        "ttps": sorted({t.get("techniqueID") for t in p.get("TTP") or []
                        if isinstance(t, dict) and t.get("techniqueID")}),
        "links": [{"url": l["url"], "description": l.get("description") or ""}
                  for l in p.get("ext-links") or [] if isinstance(l, dict)
                  and str(l.get("url", "")).startswith(("http://", "https://"))][:_MAX_LINKS],
        "sources": [{"name": s.get("name") or "", "url": s.get("url") or ""}
                    for s in p.get("sources") or [] if isinstance(s, dict)],
        "related": [{"uuid": r.get("dest-uuid"), "type": r.get("type") or "",
                     "likelihood": next((t.split("=", 1)[1].strip('"') for t in r.get("tags") or []
                                         if "likelihood-probability" in t), "")}
                    for r in p.get("related") or [] if isinstance(r, dict) and r.get("dest-uuid")],
        "attribution_confidence": int(conf) if str(conf or "").isdigit() else None,
        "point": coords[:2] if len(coords) >= 2 else None,
        "otx_ips": ips[:_MAX_OTX_IOCS],
        "otx_domains": domains[:_MAX_OTX_IOCS],
        "otx_ioc_count": len(iocs),
        "otx_cves": cve_iocs,
    }


_refresh_lock = threading.Lock()


def refresh(force: bool = False) -> bool:
    """One download at a time: a second caller waits, then finds it fresh."""
    with _refresh_lock:
        return _refresh(force)


def _refresh(force: bool) -> bool:
    """Download APTmap weekly and rebuild the compact index (~70 MB in,
    a few MB out). On failure the previous index stays in use."""
    raw, idx = _raw_path(), _index_path()
    if not force and idx.exists() and time.time() - idx.stat().st_mtime < _MAX_AGE:
        return False
    tmp = raw.with_suffix(f".{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        req = urllib.request.Request(_URL, headers=_UA)
        with urllib.request.urlopen(req, timeout=120) as r, open(tmp, "wb") as f:
            while chunk := r.read(1 << 16):
                f.write(chunk)
        os.replace(tmp, raw)
    except OSError as e:
        print(f"[aptdb] download failed, keeping the previous catalog: {e}", file=sys.stderr)
        tmp.unlink(missing_ok=True)
        if not raw.exists():
            return False
    build_index(raw, idx)
    return True


def build_index(raw: Path, idx: Path) -> None:
    codes = _country_codes()
    features = json.loads(raw.read_text(encoding="utf-8")).get("features") or []
    groups = [g for g in (_compact(f, codes) for f in features) if g["uuid"] and g["name"]]
    names = {g["uuid"]: g["name"] for g in groups}
    tool_users = Counter(_norm(t["name"]) for g in groups for t in g["tools"])
    for g in groups:
        # Relations to other groups get their names; ones pointing at tools
        # or malware entries the catalog doesn't carry are dropped.
        g["related"] = [{**r, "name": names[r["uuid"]]} for r in g["related"] if r["uuid"] in names]
        for t in g["tools"]:
            t["distinctive"] = (tool_users[_norm(t["name"])] == 1 and t["category"] == "Malware"
                                and not _is_commodity(t["name"]))
    tmp = idx.with_suffix(f".{os.getpid()}.{threading.get_ident()}.tmp")
    tmp.write_text(json.dumps({"built": date.today().isoformat(), "credit": CREDIT,
                               "groups": groups}), encoding="utf-8")
    os.replace(tmp, idx)


def _load() -> dict:
    global _index, _index_mtime
    idx = _index_path()
    if not idx.exists():
        refresh()
    if not idx.exists():
        return {"groups": [], "credit": CREDIT}
    mtime = idx.stat().st_mtime
    if mtime != _index_mtime:
        data = json.loads(idx.read_text(encoding="utf-8"))
        by_alias: dict = {}
        by_tool: dict = defaultdict(list)
        for g in data["groups"]:
            for a in [g["name"], *g["aliases"]]:
                by_alias.setdefault(_norm(a), g)
            for t in g["tools"]:
                if t.get("distinctive"):
                    by_tool[_norm(t["name"])].append(g)
        data["by_uuid"] = {g["uuid"]: g for g in data["groups"]}
        data["by_alias"] = {k: v for k, v in by_alias.items() if len(k) >= 3}
        data["by_tool"] = by_tool
        _index, _index_mtime = data, mtime
    return _index


def resolve(name: str) -> Optional[dict]:
    """Catalog group for any of its names: 'APT36', 'Transparent Tribe',
    'Mythic Leopard' and 'Operation C-Major' all resolve to the same group."""
    if not name:
        return None
    aliases = _load()["by_alias"]
    # Feeds combine names: "APT36 (Transparent Tribe)", "Lazarus / APT38".
    for part in [name, *re.split(r"[()/,;|]", name)]:
        g = aliases.get(_norm(part))
        if g:
            return g
    return None


def groups_for_tool(family: str) -> list[dict]:
    return _load()["by_tool"].get(_norm(family), []) if family else []


# --------------------------------------------------------------------------- #
# Live layer: what our feeds see each group doing
# --------------------------------------------------------------------------- #
def _days_before(ref: str, day: str) -> int:
    try:
        return (date.fromisoformat(ref) - date.fromisoformat(day)).days
    except ValueError:
        return 10 ** 6


_live_cache: dict[str, tuple[float, dict]] = {}


def live_activity(signals_db: str, max_age: float = 60.0) -> dict[str, dict]:
    """uuid -> recent activity, cached briefly: one scan of ~20k signals
    serves the map and the profiles opened from it."""
    ts, data = _live_cache.get(signals_db, (0.0, {}))
    if time.time() - ts > max_age or _index_mtime is None:
        data = _scan_live(signals_db)
        _live_cache[signals_db] = (time.time(), data)
    return data


def _scan_live(signals_db: str) -> dict[str, dict]:
    """A signal counts for a group when its actor is one of the group's names
    ("direct"), or when its malware family is that group's signature malware
    ("via tooling")."""
    _load()
    con = sqlite3.connect(signals_db)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(
            "SELECT title, threat_actor, malware_family, source_name, source_url, cve_ids, "
            "ip_enrichment, target_country, tags, collected_at FROM signals "
            "WHERE COALESCE(threat_actor, '') != '' OR COALESCE(malware_family, '') != '' "
            "ORDER BY collected_at DESC").fetchall()
    finally:
        con.close()
    ref = (rows[0]["collected_at"] or "")[:10] if rows else ""
    out: dict = {}
    for r in rows:
        hits = []
        g = resolve(r["threat_actor"] or "")
        if g:
            hits.append((g, "direct"))
        for tg in groups_for_tool(r["malware_family"] or ""):
            if not g or tg["uuid"] != g["uuid"]:
                hits.append((tg, "via tooling"))
        if not hits:
            continue
        day = (r["collected_at"] or "")[:10]
        try:
            enr = json.loads(r["ip_enrichment"] or "{}")
            cves = json.loads(r["cve_ids"] or "[]")
            tags = json.loads(r["tags"] or "[]")
        except ValueError:
            enr, cves, tags = {}, [], []
        for grp, how in hits:
            a = out.setdefault(grp["uuid"], {
                "signals": 0, "direct": 0, "via_tooling": 0, "last_7d": 0, "last_30d": 0,
                "last_seen": day, "families": Counter(), "cves": Counter(), "infra": {},
                "targets": Counter(), "recent": []})
            a["signals"] += 1
            a["direct" if how == "direct" else "via_tooling"] += 1
            age = _days_before(ref, day)
            a["last_7d"] += age <= 7
            a["last_30d"] += age <= 30
            if r["malware_family"]:
                a["families"][r["malware_family"]] += 1
            for c in cves:
                a["cves"][c] += 1
            for ip, d in enr.items():
                if d and d.get("country") and ip not in a["infra"]:
                    a["infra"][ip] = {"ip": ip, "cc": d["country"].upper(), "asn": str(d.get("asn") or ""),
                                      "org": d.get("org") or d.get("as_name") or "", "seen": day, "how": how}
            tc = (r["target_country"] or "").strip()
            for t in [tc] + [t[7:] for t in tags if isinstance(t, str) and t.startswith("target:")]:
                if t:
                    a["targets"][t.title()] += 1
            if len(a["recent"]) < 15:
                a["recent"].append({"title": r["title"] or "", "date": day, "how": how,
                                    "family": r["malware_family"] or "", "source": r["source_name"] or "",
                                    "url": r["source_url"] or "", "cves": cves[:4]})
    for a in out.values():
        a["families"] = a["families"].most_common(8)
        a["cves"] = [c for c, _ in a["cves"].most_common(12)]
        a["targets"] = a["targets"].most_common(10)
        a["infra"] = sorted(a["infra"].values(), key=lambda i: i["seen"], reverse=True)[:100]
        a["status"] = "active" if a["last_7d"] else "recent" if a["last_30d"] else "quiet"
    return out


def _mitre_for(g: dict) -> Optional[dict]:
    from . import mitre
    try:
        return mitre.group_for([g["name"], *g["aliases"]])
    except (OSError, ValueError):
        return None


_etda_cache: tuple[float, dict] = (0.0, {})


def etda_card(uuid: str) -> Optional[dict]:
    """The ETDA card for a catalog group (operations, vendor names, ...)."""
    global _etda_cache
    from . import apt_sightings, etda
    ts, by_group = _etda_cache
    if time.time() - ts > 300:
        by_group = {}
        for card in etda.cards():
            gk = apt_sightings.etda_group_key(card)
            if gk and (gk not in by_group or len(card["operations"]) > len(by_group[gk]["operations"])):
                by_group[gk] = card
        _etda_cache = (time.time(), by_group)
    card = by_group.get(uuid)
    return {**card, "credit": etda.CREDIT} if card else None


_graph_cache: tuple[Optional[float], dict] = (None, {})


def graph() -> dict:
    """APTmap's network graph: groups, the tools they use, and group-to-group
    relations (with MISP's likelihood). Tools are merged by name across
    groups, so a shared tool becomes a hub linking its users."""
    global _graph_cache
    data = _load()
    if _graph_cache[0] == _index_mtime and _graph_cache[1]:
        return _graph_cache[1]
    nodes, links, tools, pairs = [], [], {}, set()
    for g in data["groups"]:
        nodes.append({"id": g["uuid"], "name": g["name"], "kind": "group", "country": g["country"]})
        for t in g["tools"]:
            tid = "tool:" + _norm(t["name"])
            if tid not in tools:
                tools[tid] = {"id": tid, "name": t["name"], "kind": "tool", "category": t["category"], "users": 0}
            tools[tid]["users"] += 1
            links.append({"source": g["uuid"], "target": tid, "type": "uses"})
        for r in g["related"]:
            # Each pair once; relations are often listed on one side only.
            pair = frozenset((g["uuid"], r["uuid"]))
            if len(pair) == 2 and pair not in pairs:
                pairs.add(pair)
                links.append({"source": g["uuid"], "target": r["uuid"], "type": r["type"], "likelihood": r["likelihood"]})
    out = {"nodes": nodes + list(tools.values()), "links": links, "credit": data.get("credit", CREDIT)}
    _graph_cache = (_index_mtime, out)
    return out


def status_for(days_since: Optional[int]) -> str:
    """Evidence-based status from the sightings ledger (all sources)."""
    if days_since is None:
        return "catalog"
    return "active" if days_since <= 30 else "recent" if days_since <= 180 else "dormant"


def summary(signals_db: str, ledger: Optional[str] = None) -> dict:
    """Map payload: every group with an origin, its targets, when it was last
    seen anywhere (sightings ledger) and which countries it hit recently."""
    from . import apt_sightings
    data = _load()
    live = live_activity(signals_db)
    con = apt_sightings.connect(ledger)
    try:
        seen = apt_sightings.last_seen_all(con)
    finally:
        con.close()
    groups = []

    def entry(key, name, aliases, country, target_ccs, tools, motivations, point=None, extra=None):
        s = seen.get(key, {})
        return {**(extra or {}), "uuid": key, "name": name, "aliases": aliases[:12], "country": country, "point": point,
                "target_ccs": target_ccs, "tools": tools, "motivations": motivations,
                "status": status_for(s.get("days_since")), "last_seen": s.get("last_seen", ""),
                "days_since": s.get("days_since"), "sightings": s.get("sightings", 0),
                "recent_ccs": s.get("recent_ccs", []),
                "signals": live.get(key, {}).get("signals", 0)}

    # Every catalog group: those without an origin are APTmap's "other APTs
    # not in map" list. Extra fields feed the charts, filters and table.
    for g in data["groups"]:
        groups.append(entry(g["uuid"], g["name"], g["aliases"], g["country"], g["target_ccs"],
                            len(g["tools"]), g["motivations"], g["point"] if g["country"] else None,
                            {"first_seen": g["first_seen"], "sectors": g["target_categories"],
                             "tool_names": [t["name"] for t in g["tools"]],
                             "tool_cats": [t["category"] for t in g["tools"] if t["category"]],
                             "ttps": len(g["ttps"]), "sponsor": g["sponsor"]}))
    # Ransomware brands the catalog doesn't know still show where they hit.
    for key, s in seen.items():
        if key.startswith("name:"):
            groups.append({**entry(key, key[5:], [], "", [], 0, ["Financial gain"],
                                   extra={"first_seen": "", "sectors": [], "tool_names": [], "tool_cats": [],
                                          "ttps": 0, "sponsor": ""}), "uncatalogued": True})

    origins = Counter(g["country"] for g in groups if g["country"])
    hit = Counter(c for g in groups for c in g["recent_ccs"])
    order = {"active": 0, "recent": 1, "dormant": 2, "catalog": 3}
    groups.sort(key=lambda g: (order[g["status"]], g["days_since"] if g["days_since"] is not None else 10 ** 6,
                               -g["sightings"], g["name"].lower()))
    return {"groups": groups, "origins": dict(origins), "hit_recent": dict(hit),
            "credit": data.get("credit", CREDIT), "built": data.get("built", ""),
            "active": sum(g["status"] == "active" for g in groups)}


def profile(uuid: str, signals_db: str, ledger: Optional[str] = None) -> Optional[dict]:
    from . import apt_sightings
    con = apt_sightings.connect(ledger)
    try:
        activity = apt_sightings.activity(con, uuid)
    finally:
        con.close()
    g = _load()["by_uuid"].get(uuid)
    if not g:
        if not uuid.startswith("name:") or not activity.get("sightings"):
            return None
        # A ransomware brand without a catalog entry: activity only.
        g = {"uuid": uuid, "name": uuid[5:], "aliases": [], "country": "", "location": "", "sponsor": "",
             "motivations": ["Financial gain"], "first_seen": "", "description": "", "targets": [],
             "target_ccs": [], "target_categories": [], "tools": [], "ttps": [], "links": [],
             "sources": [], "related": [], "attribution_confidence": None, "otx_ips": [],
             "otx_domains": [], "otx_ioc_count": 0, "uncatalogued": True}
    return {**g, "live": live_activity(signals_db).get(uuid), "activity": activity,
            "etda": etda_card(uuid),
            "mitre": _mitre_for(g),
            "status": status_for(activity.get("days_since") if activity.get("sightings") else None),
            "credit": _load().get("credit", CREDIT)}
