"""IOC store: every indicator we hold, searchable and exportable.

Two inputs, rebuilt locally (no network):
  catalog    indicators published for each APT group (~150k: domains,
             hostnames, file hashes, URLs, IPs, emails, wallets)
  telemetry  IPs, domains, hashes and URLs in our own signals, with dates,
             malware family and the group when the signal names one

Values are normalised (lower-case domains/hashes, defanged input accepted),
typed (ip, cidr, domain, url, md5, sha1, sha256, email, btc), and each row
links an indicator to a group (or to none, for unattributed telemetry).
An indicator not seen for STALE_DAYS — or catalog-only, with no date — is
"historical": useful for hunting and retro-search, risky to block blindly.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
import sqlite3
import uuid as uuidlib
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Optional

from . import aptdb

STALE_DAYS = 180

_SCHEMA = """
CREATE TABLE IF NOT EXISTS iocs (
    value      TEXT NOT NULL,
    type       TEXT NOT NULL,       -- ip | cidr | domain | url | md5 | sha1 | sha256 | email | btc
    group_key  TEXT NOT NULL,       -- catalog uuid, name:<brand>, or '' when unattributed
    kind       TEXT NOT NULL,       -- catalog | telemetry
    family     TEXT DEFAULT '',
    first_seen TEXT DEFAULT '',
    last_seen  TEXT DEFAULT '',
    hits       INTEGER DEFAULT 1,
    url        TEXT DEFAULT '',     -- reference for telemetry rows
    PRIMARY KEY (value, type, group_key, kind)
);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
CREATE INDEX IF NOT EXISTS idx_iocs_group ON iocs(group_key);
"""

_CATALOG_TYPES = {"IPv4": "ip", "IPv6": "ip", "CIDR": "cidr", "domain": "domain", "hostname": "domain",
                  "URL": "url", "FileHash-MD5": "md5", "FileHash-SHA1": "sha1", "FileHash-SHA256": "sha256",
                  "email": "email", "BitcoinAddress": "btc"}
_HASH_BY_LEN = {32: "md5", 40: "sha1", 64: "sha256"}


def connect(path: Optional[str] = None) -> sqlite3.Connection:
    from . import apt_sightings
    con = apt_sightings.connect(path)
    con.executescript(_SCHEMA)
    return con


def refang(v: str) -> str:
    """Accept defanged input: hxxp://, [.] (.) {.}, [:], [@]."""
    v = (v or "").strip().strip("'\"<>")
    v = re.sub(r"^hxxp", "http", v, flags=re.I)
    v = re.sub(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]", ".", v, flags=re.I)
    return v.replace("[:]", ":").replace("[@]", "@").replace("[at]", "@")


def defang(v: str, t: str) -> str:
    if t in ("ip", "cidr", "domain", "email"):
        return v.replace(".", "[.]").replace("@", "[@]")
    if t == "url":
        return re.sub(r"^http", "hxxp", v, flags=re.I).replace(".", "[.]")
    return v


def classify(raw: str) -> tuple[str, str]:
    """(normalised value, type) for a free-form indicator; type '' if unknown."""
    v = refang(raw)
    if re.fullmatch(r"[0-9a-fA-F]+", v) and len(v) in _HASH_BY_LEN:
        return v.lower(), _HASH_BY_LEN[len(v)]
    try:
        if "/" in v and not v.lower().startswith(("http", "ftp")):
            return str(ipaddress.ip_network(v, strict=False)), "cidr"
        return str(ipaddress.ip_address(v)), "ip"
    except ValueError:
        pass
    if re.match(r"^[a-z][a-z0-9+.-]*://", v, re.I):
        return v, "url"
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[a-z]{2,}", v, re.I):
        return v.lower(), "email"
    if re.fullmatch(r"(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}", v):
        return v, "btc"
    if re.fullmatch(r"(?=.{4,253}$)([a-z0-9-_]+\.)+[a-z]{2,63}\.?", v, re.I):
        return v.lower().rstrip("."), "domain"
    return v, ""


def _norm(value: str, t: str) -> str:
    return value.lower().rstrip(".") if t in ("domain", "md5", "sha1", "sha256", "email") else value.strip()


def collect(raw_catalog: Optional[Path] = None, signals_db: Optional[str] = None) -> list[dict]:
    rows: dict[tuple, dict] = {}

    def add(value, t, group_key, kind, family="", day="", url=""):
        if not value or not t:
            return
        value = _norm(value, t)
        k = (value, t, group_key, kind)
        r = rows.get(k)
        if r is None:
            rows[k] = {"value": value, "type": t, "group_key": group_key, "kind": kind, "family": family or "",
                       "first_seen": day or "", "last_seen": day or "", "hits": 1, "url": url or ""}
            return
        r["hits"] += 1
        if day:
            r["first_seen"] = min(filter(None, [r["first_seen"], day]))
            r["last_seen"] = max(r["last_seen"], day)
        if family and not r["family"]:
            r["family"] = family

    raw_catalog = raw_catalog or aptdb._raw_path()
    if raw_catalog and Path(raw_catalog).exists():
        for f in json.loads(Path(raw_catalog).read_text(encoding="utf-8")).get("features") or []:
            p = f.get("properties") or {}
            gk = p.get("uuid") or ""
            for i in p.get("otx_iocs") or []:
                if isinstance(i, dict) and i.get("type") in _CATALOG_TYPES:
                    add(i.get("value") or i.get("indicator"), _CATALOG_TYPES[i["type"]], gk, "catalog")

    if signals_db and Path(signals_db).exists():
        con = sqlite3.connect(signals_db)
        try:
            sig = con.execute("SELECT threat_actor, malware_family, ip_addresses, domains, malware_hashes, urls, "
                              "source_url, COALESCE(posted_at, collected_at) FROM signals").fetchall()
        finally:
            con.close()
        for actor, family, ips, domains, hashes, urls, ref, ts in sig:
            g = aptdb.resolve(actor or "")
            groups = [g["uuid"]] if g else [t["uuid"] for t in aptdb.groups_for_tool(family or "")] or [""]
            day = (ts or "")[:10]
            fam = "" if (family or "").lower() in ("", "unknown", "unknown malware", "n/a") else family
            for col, kind_of in ((ips, None), (domains, "domain"), (hashes, None), (urls, "url")):
                try:
                    values = json.loads(col or "[]")
                except ValueError:
                    continue
                for v in values:
                    nv, t = classify(v) if kind_of is None else (v, kind_of)
                    for gk in groups:
                        add(nv, t, gk, "telemetry", fam, day, ref)
    return list(rows.values())


def rebuild(con: sqlite3.Connection, rows: list[dict]) -> int:
    con.execute("DELETE FROM iocs")
    con.executemany("INSERT OR REPLACE INTO iocs (value, type, group_key, kind, family, first_seen, last_seen, hits, url) "
                    "VALUES (:value, :type, :group_key, :kind, :family, :first_seen, :last_seen, :hits, :url)", rows)
    con.commit()
    return con.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]


# Which feed an indicator came from, by the host of its reference URL. Used to
# answer "where did this come from" without a schema change: telemetry and
# sandbox rows carry a permalink, and catalogue rows are the catalogue.
_SOURCE_NAMES = {
    "threatfox.abuse.ch": "ThreatFox (abuse.ch)",
    "bazaar.abuse.ch": "MalwareBazaar (abuse.ch)",
    "urlhaus.abuse.ch": "URLhaus (abuse.ch)",
    "feodotracker.abuse.ch": "Feodo Tracker (abuse.ch)",
    "otx.alienvault.com": "AlienVault OTX",
    "www.virustotal.com": "VirusTotal",
    "virustotal.com": "VirusTotal",
    "www.ransomware.live": "Ransomware.live",
    "ransomware.live": "Ransomware.live",
}


def source_of(row: dict) -> dict:
    """Where this indicator came from: {"name", "url", "kind"}.

    Every indicator can name its origin. Telemetry and sandbox rows carry a
    permalink to the record that reported them; catalogue rows have none,
    because they come from the aggregated APT catalogue rather than from a
    feed with per-indicator records. Saying "APT catalogue" is accurate;
    inventing a URL for them would not be.
    """
    url = (row.get("url") or "").strip()
    kind = row.get("kind") or ""
    if url:
        host = url.split("/")[2].lower() if "//" in url else ""
        if host.endswith(".onion"):
            return {"name": "Dark-web leak site", "url": url, "kind": kind}
        return {"name": _SOURCE_NAMES.get(host) or host or "unnamed source",
                "url": url, "kind": kind}
    if kind == "catalog":
        return {"name": "APT catalogue (aggregated public reporting)", "url": "", "kind": kind}
    return {"name": "not recorded", "url": "", "kind": kind}


def _stale(last_seen: str, today: Optional[date] = None) -> bool:
    if not last_seen:
        return True
    today = today or datetime.now(timezone.utc).date()
    try:
        return (today - date.fromisoformat(last_seen)).days > STALE_DAYS
    except ValueError:
        return True


def search(con: sqlite3.Connection, raw: str) -> dict:
    """Everything known about one indicator. URLs also match their host."""
    value, t = classify(raw)
    if not t:
        return {"query": raw, "type": "", "matches": [], "error": "not a recognised indicator"}
    candidates = [(value, t)]
    if t == "url":
        host = re.sub(r"^[a-z][a-z0-9+.-]*://", "", value, flags=re.I).split("/")[0].split(":")[0].lower()
        candidates.append(classify(host))
    rows = []
    for v, tt in candidates:
        rows += [dict(r) for r in con.execute("SELECT * FROM iocs WHERE value = ? AND type = ?", (v, tt))]
    groups = aptdb._load()["by_uuid"]
    matches = []
    for r in rows:
        g = groups.get(r["group_key"], {})
        matches.append({"value": r["value"], "type": r["type"], "kind": r["kind"], "family": r["family"],
                        "group": r["group_key"], "group_name": g.get("name", r["group_key"][5:] if r["group_key"].startswith("name:") else ""),
                        "country": g.get("country", ""), "first_seen": r["first_seen"], "last_seen": r["last_seen"],
                        "hits": r["hits"], "stale": _stale(r["last_seen"]), "url": r["url"],
                        "matched_on": "host" if r["value"] != value else "exact"})
    return {"query": raw, "value": value, "type": t, "defanged": defang(value, t), "matches": matches}


def group_iocs(con: sqlite3.Connection, group_key: str) -> list[dict]:
    rows = [dict(r) for r in con.execute(
        "SELECT value, type, kind, family, first_seen, last_seen, hits, url FROM iocs WHERE group_key = ? "
        "ORDER BY last_seen DESC, type, value", (group_key,))]
    for r in rows:
        r["stale"] = _stale(r["last_seen"])
    return rows


def sandbox_captures(con: sqlite3.Connection, limit: int = 200) -> list[dict]:
    """Indicators captured from sandbox detonations, newest detonation first.

    Grouped by sample (the url column holds the sample reference), so the
    caller can show one card per detonation rather than a flat indicator list.
    """
    rows = con.execute(
        "SELECT value, type, family, first_seen, last_seen, hits, url "
        "FROM iocs WHERE kind = 'sandbox' "
        "ORDER BY first_seen DESC, rowid DESC LIMIT ?", (limit,)).fetchall()
    samples: dict[str, dict] = {}
    for r in rows:
        d = dict(r)
        key = d["url"] or d["first_seen"]
        s = samples.setdefault(key, {
            "sample": key, "family": d["family"], "detonated_at": d["first_seen"],
            "indicators": [],
        })
        if not s["family"] and d["family"]:
            s["family"] = d["family"]
        s["indicators"].append({
            "value": defang(d["value"], d["type"]), "raw": d["value"],
            "type": d["type"], "hits": d["hits"],
        })
    out = sorted(samples.values(), key=lambda s: s["detonated_at"], reverse=True)
    for s in out:
        s["count"] = len(s["indicators"])
    return out


def summary_for_group(con: sqlite3.Connection, group_key: str) -> dict:
    counts, fresh = {}, {}
    for t, last, n in con.execute("SELECT type, last_seen, COUNT(*) FROM iocs WHERE group_key = ? GROUP BY type, last_seen",
                                  (group_key,)):
        counts[t] = counts.get(t, 0) + n
        if not _stale(last):
            fresh[t] = fresh.get(t, 0) + n
    newest = con.execute("SELECT MAX(last_seen) FROM iocs WHERE group_key = ?", (group_key,)).fetchone()[0] or ""
    return {"total": sum(counts.values()), "by_type": counts, "fresh_by_type": fresh, "fresh": sum(fresh.values()),
            "newest": newest}


# ---------------------------------------------------------------- exports --
def to_txt(rows: list[dict], types: Optional[set] = None, fresh_only: bool = False) -> str:
    vals = sorted({r["value"] for r in rows if (not types or r["type"] in types) and not (fresh_only and r["stale"])})
    return "\n".join(vals) + ("\n" if vals else "")


def to_csv(rows: list[dict], group_name: str) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["indicator", "type", "group", "malware_family", "first_seen", "last_seen", "status", "kind", "reference"])
    for r in rows:
        w.writerow([r["value"], r["type"], group_name, r["family"], r["first_seen"], r["last_seen"],
                    "historical" if r["stale"] else "fresh", r["kind"], r["url"]])
    return buf.getvalue()


def _stix_pattern(v: str, t: str) -> Optional[str]:
    esc = v.replace("\\", "\\\\").replace("'", "\\'")
    return {"ip": f"[ipv{6 if ':' in v else 4}-addr:value = '{esc}']",
            "cidr": f"[ipv{6 if ':' in v else 4}-addr:value = '{esc}']",
            "domain": f"[domain-name:value = '{esc}']", "url": f"[url:value = '{esc}']",
            "md5": f"[file:hashes.MD5 = '{esc}']", "sha1": f"[file:hashes.'SHA-1' = '{esc}']",
            "sha256": f"[file:hashes.'SHA-256' = '{esc}']", "email": f"[email-addr:value = '{esc}']"}.get(t)


def to_stix(rows: list[dict], group: dict) -> dict:
    """STIX 2.1 bundle: the intrusion set, one indicator per IOC, and an
    'indicates' relationship from each indicator to the group. IDs are
    deterministic (UUIDv5), so re-exports update rather than duplicate."""
    ns = uuidlib.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    gid = f"intrusion-set--{uuidlib.uuid5(ns, 'groundtrace:group:' + group['uuid'])}"
    objs = [{"type": "intrusion-set", "spec_version": "2.1", "id": gid, "created": now, "modified": now,
             "name": group["name"], "aliases": group.get("aliases", [])[:50]}]
    for r in rows:
        pat = _stix_pattern(r["value"], r["type"])
        if not pat:
            continue
        iid = f"indicator--{uuidlib.uuid5(ns, 'groundtrace:ioc:' + r['type'] + ':' + r['value'])}"
        valid_from = (r["first_seen"] + "T00:00:00.000Z") if r["first_seen"] else now
        ind = {"type": "indicator", "spec_version": "2.1", "id": iid, "created": now, "modified": now,
               "name": f"{r['type']}: {r['value']}"[:250], "pattern": pat, "pattern_type": "stix",
               "valid_from": valid_from, "indicator_types": ["malicious-activity"]}
        if r["family"]:
            ind["labels"] = [r["family"]]
        objs.append(ind)
        objs.append({"type": "relationship", "spec_version": "2.1",
                     "id": f"relationship--{uuidlib.uuid5(ns, iid + gid)}", "created": now, "modified": now,
                     "relationship_type": "indicates", "source_ref": iid, "target_ref": gid})
    return {"type": "bundle", "id": f"bundle--{uuidlib.uuid4()}", "objects": objs}


# ------------------------------------------------------------- correlation --
def _resolve(host: str, timeout: float = 3.0) -> list[str]:
    """Current A/AAAA records for a host (bounded wait; empty on failure)."""
    import concurrent.futures
    import socket
    def lookup():
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        try:
            return ex.submit(lookup).result(timeout=timeout)
        except Exception:
            return []


def related(con: sqlite3.Connection, raw: str, signals_db: Optional[str] = None,
            hosting: Optional[dict] = None, resolve: bool = True, limit: int = 40) -> dict:
    """What else is connected to an indicator, from our own data:
      together   other indicators in the same signals/reports
      network    other known-malicious IPs in the same /24
      hosting    the IP's provider and its threat profile (from the threat map)
      dns        what a domain (or a URL's host) resolves to now, and whether
                 those IPs are known
    Each related indicator says whether the store knows it, and its groups."""
    value, t = classify(raw)
    out = {"value": value, "type": t, "together": [], "network": [], "hosting": None, "dns": []}
    if not t:
        return out
    host = value
    if t == "url":
        host = re.sub(r"^[a-z][a-z0-9+.-]*://", "", value, flags=re.I).split("/")[0].split(":")[0].lower()
    host_type = classify(host)[1]

    def known(v, tt):
        rows = con.execute("SELECT group_key, kind, last_seen FROM iocs WHERE value = ? AND type = ?", (v, tt)).fetchall()
        groups = aptdb._load()["by_uuid"]
        names = sorted({groups.get(r[0], {}).get("name", "") for r in rows if r[0]} - {""})
        return {"known": bool(rows), "groups": names, "last_seen": max((r[2] for r in rows), default="")}

    # Seen together in the same signals.
    if signals_db and Path(signals_db).exists():
        sc = sqlite3.connect(signals_db)
        try:
            needles = {value, host}
            rows = []
            for n in needles:
                pat = '%"' + n.replace("%", "").replace("_", "\\_") + '"%'
                rows += sc.execute(
                    "SELECT signal_id, ip_addresses, domains, malware_hashes, urls, title FROM signals "
                    "WHERE ip_addresses LIKE ? ESCAPE '\\' OR domains LIKE ? ESCAPE '\\' "
                    "OR malware_hashes LIKE ? ESCAPE '\\' OR urls LIKE ? ESCAPE '\\' LIMIT 200",
                    (pat, pat, pat, pat)).fetchall()
        finally:
            sc.close()
        seen, counts = set(), {}
        for sid, ips, doms, hashes, urls, title in rows:
            if sid in seen:
                continue
            seen.add(sid)
            for col in (ips, doms, hashes, urls):
                for v in json.loads(col or "[]"):
                    nv, tt = classify(v)
                    if tt and nv not in (value, host):
                        counts[(nv, tt)] = counts.get((nv, tt), 0) + 1
        for (nv, tt), n in sorted(counts.items(), key=lambda kv: -kv[1])[:limit]:
            out["together"].append({"value": nv, "type": tt, "defanged": defang(nv, tt), "times": n, **known(nv, tt)})
        out["together_signals"] = len(seen)

    # Same /24 (IPv4).
    if host_type == "ip" and "." in host:
        prefix = host.rsplit(".", 1)[0] + "."
        for (v,) in con.execute("SELECT DISTINCT value FROM iocs WHERE type = 'ip' AND value LIKE ? AND value != ? LIMIT ?",
                                (prefix + "%", host, limit)):
            out["network"].append({"value": v, "type": "ip", "defanged": defang(v, "ip"), **known(v, "ip")})
        out["network_block"] = prefix + "0/24"

    # Hosting profile from the threat map (provider, ASN, score, dense blocks).
    if host_type == "ip" and hosting:
        for cc, c in hosting.get("countries", {}).items():
            for prov in c.get("providers", []):
                if any(i["ip"] == host for i in prov.get("ips", [])):
                    out["hosting"] = {"country": cc, "provider": prov["name"], "asn": prov["asn"], "kind": prov["kind"],
                                      "score": prov.get("score"), "malicious_ips": prov["ip_count"],
                                      "dense_blocks": [c2["cidr"] for c2 in prov.get("clusters", [])][:3]}
                    break
            if out["hosting"]:
                break

    # Same malware family: other infrastructure running the same malware
    # (most feeds report one indicator per entry, so this is the main pivot).
    fams = sorted({r[0] for r in con.execute("SELECT family FROM iocs WHERE value IN (?, ?) AND family != ''", (value, host))})
    out["families"] = fams
    out["family"] = []
    for fam in fams[:3]:
        for v, tt, last in con.execute(
                "SELECT value, type, MAX(last_seen) FROM iocs WHERE family = ? AND kind = 'telemetry' AND value NOT IN (?, ?) "
                "GROUP BY value, type ORDER BY MAX(last_seen) DESC LIMIT ?", (fam, value, host, limit)):
            out["family"].append({"value": v, "type": tt, "defanged": defang(v, tt), "family": fam, **known(v, tt)})

    # DNS pivot.
    if resolve and host_type == "domain":
        for ip in _resolve(host):
            out["dns"].append({"value": ip, "type": "ip", "defanged": defang(ip, "ip"), **known(ip, "ip")})
    return out
