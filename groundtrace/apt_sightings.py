"""APT sightings ledger: dated evidence of each group's activity.

APTmap says who a group is and whom it has *ever* targeted. This ledger
answers what it lacks: when was the group last seen, and which regions and
sectors is it hitting *now*. Every row is one dated, linkable piece of
evidence:

  otx          OTX pulses that name the group (years of history, with the
               pulse's targeted countries and industries)
  ransomware   leak-site victim claims (ransomware.live: victim country, sector)
  mitre        MITRE ATT&CK campaigns attributed to the group (first/last seen)
  feed         our own darkfeeds signals (direct, or via signature malware)
  news         security news articles that mention one of the group's names

Groups are keyed by catalog uuid; ransomware brands missing from the catalog
are kept under "name:<brand>" so their activity still counts.
"""
from __future__ import annotations

import json
import re
import sqlite3
import sys
import time
import urllib.parse
import urllib.request
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Optional

from . import aptdb
from .config import get_config

_UA = {"User-Agent": "groundtrace/0.1 (research tool)"}
RECENT_DAYS = 90

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sightings (
    key        TEXT PRIMARY KEY,      -- source-specific dedup key
    group_key  TEXT NOT NULL,         -- catalog uuid, or name:<brand>
    day        TEXT NOT NULL,         -- YYYY-MM-DD the activity happened / was reported
    source     TEXT NOT NULL,         -- otx | ransomware | mitre | feed | news
    countries  TEXT DEFAULT '[]',     -- ISO-3166 alpha-2 codes affected
    sectors    TEXT DEFAULT '[]',
    title      TEXT DEFAULT '',
    url        TEXT DEFAULT '',
    inferred   INTEGER DEFAULT 0      -- 1 = matched via signature malware, not named
);
CREATE INDEX IF NOT EXISTS idx_sight_group ON sightings(group_key, day);
CREATE TABLE IF NOT EXISTS sweep_state (
    name TEXT PRIMARY KEY, value TEXT NOT NULL
);
"""


def _db_path() -> Path:
    return Path(get_config().db_path).expanduser().parent / "apt.db"


def connect(path: Optional[str] = None) -> sqlite3.Connection:
    con = sqlite3.connect(str(path or _db_path()), timeout=30, check_same_thread=False)
    con.row_factory = sqlite3.Row
    # The watcher rebuilds tables here while the dashboard reads them: WAL
    # lets readers carry on during a write instead of waiting or failing.
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA busy_timeout=30000")
    con.executescript(_SCHEMA)
    return con


def record(con: sqlite3.Connection, rows: Iterable[dict]) -> int:
    """Insert sightings; returns how many were new."""
    n = 0
    for r in rows:
        cur = con.execute(
            "INSERT OR IGNORE INTO sightings (key, group_key, day, source, countries, sectors, "
            "title, url, inferred) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (r["key"], r["group_key"], r["day"], r["source"], json.dumps(sorted(set(r.get("countries") or []))),
             json.dumps(sorted(set(r.get("sectors") or []))), (r.get("title") or "")[:300],
             r.get("url") or "", int(bool(r.get("inferred")))))
        n += cur.rowcount
    con.commit()
    return n


def _group_key(name: str) -> Optional[str]:
    g = aptdb.resolve(name)
    if g:
        return g["uuid"]
    n = aptdb._norm(name)
    return f"name:{n}" if len(n) >= 3 else None


def _cc(name: str) -> Optional[str]:
    return aptdb._to_cc(name, _codes())


_codes_cache: dict = {}


def _codes() -> dict:
    if not _codes_cache:
        _codes_cache.update(aptdb._country_codes())
    return _codes_cache


def _get_json(url: str, headers: Optional[dict] = None, timeout: int = 30):
    try:
        req = urllib.request.Request(url, headers={**_UA, **(headers or {})})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except (OSError, ValueError) as e:
        print(f"[sightings] {urllib.parse.urlparse(url).netloc}: {e}", file=sys.stderr)
        return None


# --------------------------------------------------------------------------- #
# Collectors
# --------------------------------------------------------------------------- #
def collect_ransomware(con: sqlite3.Connection) -> int:
    """ransomware.live's free recent-victims feed: group, victim country,
    sector, attack date. The darkfeeds collector stores claims without the
    country; this keeps the part that says which region is being hit."""
    data = _get_json("https://api.ransomware.live/v2/recentvictims")
    if not isinstance(data, list):
        return 0
    rows = []
    for v in data:
        gk = _group_key(v.get("group") or "")
        day = (v.get("attackdate") or v.get("discovered") or "")[:10]
        if not gk or not day:
            continue
        cc = (v.get("country") or "").upper()
        rows.append({"key": f"rw:{v.get('url') or v.get('victim')}", "group_key": gk, "day": day,
                     "source": "ransomware", "countries": [cc] if len(cc) == 2 else [],
                     "sectors": [v["activity"]] if v.get("activity") and v["activity"] != "Not Found" else [],
                     "title": f"{v.get('group')}: {v.get('victim') or ''}", "url": v.get("url") or ""})
    return record(con, rows)


def collect_mitre(con: sqlite3.Connection, attack_json: Optional[str] = None) -> int:
    """MITRE ATT&CK campaigns attributed to a group, with first/last seen."""
    if not attack_json:
        from . import mitre
        mitre.refresh()  # weekly download shared with the techniques index
        attack_json = str(mitre.bundle_path())
    bundle = json.loads(Path(attack_json).read_text(encoding="utf-8")) if Path(attack_json).exists() else None
    if not bundle:
        return 0
    objs = {o["id"]: o for o in bundle.get("objects", [])}
    rows = []
    for rel in objs.values():
        if rel.get("type") != "relationship" or rel.get("relationship_type") != "attributed-to":
            continue
        camp, grp = objs.get(rel.get("source_ref")), objs.get(rel.get("target_ref"))
        if not camp or not grp or camp.get("revoked") or camp.get("type") != "campaign":
            continue
        gk = None
        for n in [grp.get("name", ""), *(grp.get("aliases") or [])]:
            g = aptdb.resolve(n)
            if g:
                gk = g["uuid"]
                break
        if not gk:
            continue
        ext = next((r for r in camp.get("external_references", []) if r.get("source_name") == "mitre-attack"), {})
        for which in ("first_seen", "last_seen"):
            if camp.get(which):
                rows.append({"key": f"mitre:{camp['id']}:{which}", "group_key": gk,
                             "day": camp[which][:10], "source": "mitre",
                             "title": f"{camp['name']} ({which.replace('_', ' ')})",
                             "url": ext.get("url") or ""})
    return record(con, rows)


def _otx_search(term: str, key: str, limit: int = 20) -> Optional[list[dict]]:
    """Pulses for a term; None when OTX could not be reached (vs [] = no hits)."""
    url = (f"https://otx.alienvault.com/api/v1/search/pulses?q={urllib.parse.quote(term)}"
           f"&sort=-created&limit={limit}")
    data = _get_json(url, {"X-OTX-API-KEY": key}, timeout=20)
    return None if data is None else (data.get("results") or [])


def _pulse_names_group(p: dict, names: list[str]) -> bool:
    """Only count a pulse that names the group in its title, tags or
    adversary field — OTX search also matches loose full-text hits."""
    hay = " ".join([p.get("name") or "", p.get("adversary") or "", " ".join(p.get("tags") or [])])
    hay = aptdb._norm(hay)
    return any(len(aptdb._norm(n)) >= 4 and aptdb._norm(n) in hay for n in names)


def sweep_otx(con: sqlite3.Connection, key: str, groups_per_run: int = 20,
              pause: float = 0.5) -> int:
    """Walk the catalog a slice at a time (state persisted), searching OTX for
    each group's distinctive names. OTX search is slow (10-20 s a query), so
    a cycle covers 20 groups; a full pass over ~500 groups takes a few days
    of watcher cycles, then starts over to pick up new pulses."""
    # Best-documented groups first (most tools/targets/techniques): those are
    # the ones analysts ask about, so they get fresh data soonest.
    groups = sorted((g for g in aptdb._load()["groups"] if g["country"] or g["target_ccs"]),
                    key=lambda g: (-(len(g["tools"]) + len(g["target_ccs"]) + len(g["ttps"])), g["name"]))
    row = con.execute("SELECT value FROM sweep_state WHERE name = 'otx_pos'").fetchone()
    pos = int(row["value"]) if row else 0
    batch = groups[pos:pos + groups_per_run] or groups[:groups_per_run]
    new = 0
    # A group counts as done only if every search for it succeeded; at the
    # first group with a failed search the sweep stops there, so the next
    # cycle retries it instead of skipping it until the next full pass.
    done = 0
    for g in batch:
        names = [g["name"], *[a for a in g["aliases"] if re.search(r"\d|[A-Z]{3,}", a)][:2]]
        seen, failed = set(), False
        for term in dict.fromkeys(names):
            pulses = _otx_search(term, key)
            if pulses is None:  # OTX unreachable or erroring: don't hammer it
                failed = True
                break
            for p in pulses:
                if p.get("id") in seen or not _pulse_names_group(p, [g["name"], *g["aliases"]]):
                    continue
                seen.add(p.get("id"))
                day = (p.get("created") or "")[:10]
                if not day or con.execute("SELECT 1 FROM sightings WHERE key = ?",
                                          (f"otx:{p['id']}:{g['uuid']}",)).fetchone():
                    continue
                # Search results omit targeted countries; fetch the full pulse,
                # but only for the last year, which is what "region now" needs.
                if _ago(day, date.today()) <= 365:
                    p = _get_json(f"https://otx.alienvault.com/api/v1/pulses/{p['id']}",
                                  {"X-OTX-API-KEY": key}, timeout=20) or p
                ccs = [c for c in (_cc(t) for t in p.get("targeted_countries") or []) if c]
                new += record(con, [{
                    "key": f"otx:{p['id']}:{g['uuid']}", "group_key": g["uuid"],
                    "day": day, "source": "otx", "countries": ccs,
                    "sectors": p.get("industries") or [], "title": p.get("name") or "",
                    "url": f"https://otx.alienvault.com/pulse/{p['id']}"}])
            time.sleep(pause)
        if failed:
            break
        done += 1
    nxt = pos + done
    con.execute("INSERT OR REPLACE INTO sweep_state (name, value) VALUES ('otx_pos', ?)",
                (str(nxt if nxt < len(groups) else 0),))
    con.commit()
    return new


# Catalog aliases that are also company names (MISP lists "Alibaba" for the
# Iranian group Cleaver); in news prose they mean the company.
def etda_group_key(card: dict) -> Optional[str]:
    """Catalog group for an ETDA card: its title parts, then its names."""
    for n in [*card["title"].split(","), *(x["name"] for x in card["names"])]:
        g = aptdb.resolve(n.strip())
        if g:
            return g["uuid"]
    return None


def collect_etda(con: sqlite3.Connection, cards: Optional[list] = None) -> int:
    """ETDA's dated operations and counter-operations. A country counts as
    affected only if the operation's text names it AND ETDA lists it among the
    group's observed countries AND it is not the group's own country — so
    'Pakistani officials collecting data on Indian troops' yields India only."""
    from . import etda
    rows = []
    for card in cards if cards is not None else etda.cards():
        gk = etda_group_key(card)
        if not gk:
            continue
        observed = {c for c in (_cc(x) for x in card["observed_countries"]) if c}
        own = _cc(card["country"])
        for kind, ops in (("operation", card["operations"]), ("counter-operation", card["counter_operations"])):
            for i, op in enumerate(ops):
                text = op["text"]
                named = {c for c in observed if re.search(r"\b" + re.escape(_cc_name(c)) + r"\b", text, re.I)
                         or (c in _DEMONYM and re.search(_DEMONYM[c], text, re.I))}
                rows.append({"key": f"etda:{card['slug']}:{kind}:{op['day']}:{i}", "group_key": gk,
                             "day": op["day"], "source": "etda",
                             "countries": sorted(named - {own}) if kind == "operation" else [],
                             "title": (f"Counter-operation: {text}" if kind != "operation" else text)[:300],
                             "url": op["url"] or card["url"]})
    return record(con, rows)


# Adjectives used in operation write-ups ("targeting Indian entities").
_DEMONYM = {"IN": r"\bIndian\b", "PK": r"\bPakistani\b", "AF": r"\bAfghan\b", "US": r"\bAmerican\b|\bU\.S\.",
            "GB": r"\bBritish\b|\bU\.K\.", "UA": r"\bUkrainian\b", "IL": r"\bIsraeli\b", "IR": r"\bIranian\b",
            "KR": r"\bSouth Korean\b", "TW": r"\bTaiwanese\b", "VN": r"\bVietnamese\b", "SA": r"\bSaudi\b",
            "DE": r"\bGerman\b", "FR": r"\bFrench\b", "JP": r"\bJapanese\b", "CN": r"\bChinese\b",
            "RU": r"\bRussian\b", "TR": r"\bTurkish\b", "BD": r"\bBangladeshi\b", "NP": r"\bNepal(?:i|ese)\b",
            "LK": r"\bSri Lankan\b", "MM": r"\bMyanmar\b|\bBurmese\b", "PH": r"\bFilipino\b|\bPhilippine\b"}


def _cc_name(cc: str) -> str:
    """Display name for matching: the world map's English name."""
    if not _names_cache:
        for name, code in _codes().items():
            _names_cache.setdefault(code, name)
    return _names_cache.get(cc, cc)


_names_cache: dict = {}


_NEWS_STOP = {"alibaba", "microsoft", "google", "amazon", "apple", "meta", "oracle", "cisco",
              "samsung", "sony", "tesla", "twitter", "facebook", "telegram", "discord", "github",
              "zoom", "adobe", "intel", "nvidia", "openai", "deepseek", "tencent", "baidu"}

_NEWS_SOURCES = ("feedburner", "bleepingcomputer", "krebsonsecurity", "cisa.gov", "therecord",
                 "securityweek", "darkreading")


def collect_feeds(con: sqlite3.Connection, signals_db: str) -> int:
    """Our own signals: actor named (or signature malware) -> a sighting.
    News articles also count when they name a group, but only as a dated
    sighting: countries in news prose include the attacker's own and the
    agencies co-signing an advisory, so they are not used as victim regions."""
    src = sqlite3.connect(signals_db)
    src.row_factory = sqlite3.Row
    try:
        rows = src.execute(
            "SELECT signal_id, source_name, source_url, title, raw_text, threat_actor, "
            "malware_family, target_country, tags, COALESCE(posted_at, collected_at) AS ts "
            "FROM signals").fetchall()
    finally:
        src.close()
    data = aptdb._load()
    # Distinctive names worth searching news text for: at least 5 characters
    # or containing a digit (APT28), so "Play" or "Cobalt" don't match prose.
    names = {}
    for g in data["groups"]:
        for n in [g["name"], *g["aliases"]]:
            if (len(n) >= 5 or re.search(r"\d", n)) and n.lower() not in _NEWS_STOP:
                names.setdefault(n, g)
    # Case-sensitive: an alias that is also a word ("Cleaver") must appear
    # capitalised as a name, not in lowercase prose.
    pattern = re.compile(r"\b(" + "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True)) + r")\b"
                         ) if names else None
    out = []
    for r in rows:
        day = (r["ts"] or "")[:10]
        if not day:
            continue
        hits = []
        g = aptdb.resolve(r["threat_actor"] or "")
        if g:
            hits.append((g["uuid"], False))
        elif r["threat_actor"] and r["source_name"] in ("ransomlook.io", "ransomware.live"):
            gk = _group_key(r["threat_actor"])
            if gk:
                hits.append((gk, False))
        for tg in aptdb.groups_for_tool(r["malware_family"] or ""):
            hits.append((tg["uuid"], True))
        is_news = any(s in (r["source_name"] or "") for s in _NEWS_SOURCES)
        text = f"{r['title'] or ''} {r['raw_text'] or ''}"
        if is_news and pattern:
            for m in pattern.finditer(text):
                hits.append((names[m.group(1)]["uuid"], False))
        if not hits:
            continue
        ccs = set()
        tc = _cc(r["target_country"] or "")
        if tc:
            ccs.add(tc)
        try:
            ccs |= {c for c in (_cc(t[7:]) for t in json.loads(r["tags"] or "[]")
                                if isinstance(t, str) and t.startswith("target:")) if c}
        except ValueError:
            pass
        for gk, inferred in dict.fromkeys(hits):
            out.append({"key": f"sig:{r['signal_id']}:{gk}", "group_key": gk, "day": day,
                        "source": "news" if is_news else "feed", "countries": ccs,
                        "title": r["title"] or "", "url": r["source_url"] or "", "inferred": inferred})
    return record(con, out)


# --------------------------------------------------------------------------- #
# Read side
# --------------------------------------------------------------------------- #
def _ago(day: str, ref: date) -> int:
    try:
        return (ref - date.fromisoformat(day)).days
    except ValueError:
        return 10 ** 6


def activity(con: sqlite3.Connection, group_key: str, today: Optional[date] = None) -> dict:
    """Last seen, timeline and affected regions for one group."""
    today = today or datetime.now(timezone.utc).date()
    rows = con.execute("SELECT * FROM sightings WHERE group_key = ? ORDER BY day DESC",
                       (group_key,)).fetchall()
    if not rows:
        return {"sightings": 0}
    recent_cc, all_cc, recent_sec = Counter(), Counter(), Counter()
    months, by_source = Counter(), Counter()
    for r in rows:
        ccs, secs = json.loads(r["countries"]), json.loads(r["sectors"])
        all_cc.update(ccs)
        by_source[r["source"]] += 1
        months[r["day"][:7]] += 1
        if _ago(r["day"], today) <= RECENT_DAYS:
            recent_cc.update(ccs)
            recent_sec.update(secs)
    named = [r for r in rows if not r["inferred"]]
    last = (named or rows)[0]
    start = (today.replace(day=1) - timedelta(days=730)).strftime("%Y-%m")
    return {
        "sightings": len(rows),
        "last_seen": last["day"], "last_seen_source": last["source"],
        "last_seen_title": last["title"], "last_seen_url": last["url"],
        "last_seen_inferred": not named,
        "days_since": _ago(last["day"], today),
        "first_seen": rows[-1]["day"],
        "by_source": dict(by_source),
        "timeline": sorted((m, n) for m, n in months.items() if m >= start),
        "regions_recent": recent_cc.most_common(25),
        "regions_all": all_cc.most_common(40),
        "sectors_recent": recent_sec.most_common(10),
        "evidence": [{"day": r["day"], "source": r["source"], "title": r["title"], "url": r["url"],
                      "countries": json.loads(r["countries"]), "inferred": bool(r["inferred"])}
                     for r in rows[:25]],
    }


def last_seen_all(con: sqlite3.Connection) -> dict[str, dict]:
    """group_key -> {last_seen, sightings, recent_ccs} for the map and list."""
    today = datetime.now(timezone.utc).date()
    cutoff = (today - timedelta(days=RECENT_DAYS)).isoformat()
    out: dict = {}
    for r in con.execute("SELECT group_key, MAX(CASE WHEN inferred = 0 THEN day END) AS named, "
                         "MAX(day) AS any_day, COUNT(*) AS n FROM sightings GROUP BY group_key"):
        day = r["named"] or r["any_day"]
        out[r["group_key"]] = {"last_seen": day, "sightings": r["n"], "days_since": _ago(day, today),
                               "recent_ccs": []}
    for r in con.execute("SELECT group_key, countries FROM sightings WHERE day >= ?", (cutoff,)):
        out[r["group_key"]]["recent_ccs"].extend(json.loads(r["countries"]))
    for v in out.values():
        v["recent_ccs"] = [c for c, _ in Counter(v["recent_ccs"]).most_common(15)]
    return out


def _etda_refresh() -> int:
    from . import etda
    return etda.refresh(max_cards=60)  # ~2 min a cycle; all 500 cards within a week


def refresh_all(signals_db: str, otx_key: str = "", otx_groups: int = 20) -> dict:
    """One watcher-cycle's worth of collection; each source fails on its own."""
    con = connect()
    out = {}
    try:
        for name, fn in (("feeds", lambda: collect_feeds(con, signals_db)),
                         ("ransomware", lambda: collect_ransomware(con)),
                         ("etda", lambda: (_etda_refresh(), collect_etda(con))[1]),
                         ("otx", lambda: sweep_otx(con, otx_key, otx_groups) if otx_key else 0)):
            try:
                out[name] = fn()
            except Exception as e:  # one broken source must not stop the rest
                out[name] = f"error: {type(e).__name__}: {e}"
        row = con.execute("SELECT value FROM sweep_state WHERE name = 'mitre_day'").fetchone()
        if not row or _ago(row["value"], datetime.now(timezone.utc).date()) >= 7:
            try:
                out["mitre"] = collect_mitre(con)
                con.execute("INSERT OR REPLACE INTO sweep_state (name, value) VALUES ('mitre_day', ?)",
                            (datetime.now(timezone.utc).date().isoformat(),))
                con.commit()
            except Exception as e:
                out["mitre"] = f"error: {type(e).__name__}: {e}"
    finally:
        con.close()
    return out
