"""Stage 2 -- infrastructure pivoting: one indicator -> the actor's footprint.

Complements ioc_store.related(), which pivots within our OWN data (same /24,
same signals, same family, current DNS). This module reaches OUTSIDE, to map
infrastructure we may not have seen yet:

  cert     certificate-transparency siblings (crt.sh) -- domains sharing a
           certificate / SAN set with the target. A shared cert is a strong link.
  rdns     reverse DNS (PTR) for an IP.
  hostdb   Shodan InternetDB hostnames/ports/CVEs for an IP (keyless).
  jarm     servers with the same JARM TLS fingerprint (Shodan, needs a key).

Every related host is tagged with the method that found it and a confidence,
and marked whether our store already knows it -- so the pivot carries its own
provenance. Results are cached (12h) in the shared apt.db.

Nothing here claims a server's hosting location is the operator's location.
"""
from __future__ import annotations

import json
import socket
import time
import urllib.parse
import urllib.request

from . import ioc_store
from .verify import _env, _http_json, _UA

CACHE_SECONDS = 12 * 3600
# Confidence per method: how strongly a shared signal links two hosts.
_CONF = {"cert": "high", "rdns": "medium", "hostdb": "medium", "jarm": "medium", "favicon": "low"}
_CACHE_SCHEMA = "CREATE TABLE IF NOT EXISTS infra_cache (key TEXT PRIMARY KEY, at REAL NOT NULL, result TEXT NOT NULL)"


def _host_of(value: str, t: str) -> str:
    if t == "url":
        return urllib.parse.urlsplit(value).hostname or value
    return value


# --------------------------------------------------------------------------- #
# external pivots (each returns a list of {value, type, note})
# --------------------------------------------------------------------------- #
def _crtsh_siblings(domain: str, timeout: int = 15) -> list[dict]:
    """Domains sharing a certificate with this one (crt.sh). Keyless."""
    url = f"https://crt.sh/?q={urllib.parse.quote(domain)}&output=json"
    code, body = _http_json(urllib.request.Request(url, headers={**_UA, "Accept": "application/json"}), timeout=timeout)
    if code != 200 or not isinstance(body, list):
        return []
    out, seen = [], {domain.lower()}
    for cert in body[:200]:
        issuer = (cert.get("issuer_name") or "")[:60]
        for name in str(cert.get("name_value") or "").splitlines():
            n = name.strip().lstrip("*.").lower()
            if n and n != domain.lower() and "." in n and n not in seen and not n.endswith(".local"):
                seen.add(n)
                out.append({"value": n, "type": "domain", "note": f"shares a certificate ({issuer})" if issuer else "shares a certificate"})
    return out[:60]


def _reverse_dns(ip: str, timeout: float = 3.0) -> list[dict]:
    socket.setdefaulttimeout(timeout)
    try:
        host, aliases, _ = socket.gethostbyaddr(ip)
    except (OSError, socket.herror, socket.gaierror):
        return []
    names = {host, *aliases} - {ip}
    return [{"value": n.lower().rstrip("."), "type": "domain", "note": "reverse DNS (PTR)"} for n in names if n]


def _internetdb(ip: str, timeout: int = 10) -> list[dict]:
    url = f"https://internetdb.shodan.io/{urllib.parse.quote(ip)}"
    code, body = _http_json(urllib.request.Request(url, headers={**_UA, "Accept": "application/json"}), timeout=timeout)
    if code != 200 or not isinstance(body, dict):
        return []
    out = [{"value": h.lower().rstrip("."), "type": "domain", "note": "resolves to this IP (InternetDB)"}
           for h in (body.get("hostnames") or [])]
    return out


def _shodan_jarm(ip: str, timeout: int = 15) -> list[dict]:
    """Other IPs with the same JARM fingerprint. Needs a Shodan API key."""
    key = _env("SHODAN_API_KEY")
    if not key or not ip:
        return []
    host_url = f"https://api.shodan.io/shodan/host/{urllib.parse.quote(ip)}?key={urllib.parse.quote(key)}"
    code, body = _http_json(urllib.request.Request(host_url, headers=_UA), timeout=timeout)
    if code != 200 or not isinstance(body, dict):
        return []
    jarm = ""
    for svc in body.get("data") or []:
        jarm = (svc.get("ssl") or {}).get("jarm") or jarm
    if not jarm:
        return []
    q = urllib.parse.quote(f"ssl.jarm:{jarm}")
    code, res = _http_json(urllib.request.Request(
        f"https://api.shodan.io/shodan/host/search?key={urllib.parse.quote(key)}&query={q}&minify=true",
        headers=_UA), timeout=timeout)
    if code != 200 or not isinstance(res, dict):
        return []
    out, seen = [], {ip}
    for m in (res.get("matches") or [])[:50]:
        mip = m.get("ip_str")
        if mip and mip not in seen:
            seen.add(mip)
            out.append({"value": mip, "type": "ip", "note": f"same JARM fingerprint ({jarm[:16]}…)"})
    return out


# --------------------------------------------------------------------------- #
# public
# --------------------------------------------------------------------------- #
def _known(con, v: str, t: str) -> dict:
    from . import aptdb
    rows = con.execute("SELECT group_key, last_seen FROM iocs WHERE value = ? AND type = ?", (v, t)).fetchall()
    groups = aptdb._load()["by_uuid"]
    names = sorted({groups.get(r[0], {}).get("name", "") for r in rows if r[0]} - {""})
    return {"known": bool(rows), "groups": names, "last_seen": max((r[1] for r in rows), default="")}


def pivot(indicator: str, con=None, force: bool = False) -> dict:
    """External infrastructure pivots for one indicator, grouped by method."""
    value, t = ioc_store.classify(indicator)
    if not t:
        return {"query": indicator, "type": "", "pivots": [], "error": "not a recognised indicator"}

    own = con or ioc_store.connect()
    own.executescript(_CACHE_SCHEMA)
    key = f"{t}:{value}"
    try:
        if not force:
            row = own.execute("SELECT at, result FROM infra_cache WHERE key = ?", (key,)).fetchone()
            if row and time.time() - row[0] < CACHE_SECONDS:
                return {**json.loads(row[1]), "cached": True}

        host = _host_of(value, t)
        groups: dict[str, list[dict]] = {}
        if t in ("domain", "url"):
            groups["cert"] = _crtsh_siblings(host)
        if t == "ip":
            groups["rdns"] = _reverse_dns(value)
            groups["hostdb"] = _internetdb(value)
            groups["jarm"] = _shodan_jarm(value)

        pivots = []
        for method, rels in groups.items():
            seen, enriched = set(), []
            for r in rels:
                if r["value"] in seen:
                    continue
                seen.add(r["value"])
                enriched.append({**r, "defanged": ioc_store.defang(r["value"], r["type"]), **_known(own, r["value"], r["type"])})
            if enriched:
                pivots.append({"method": method, "confidence": _CONF.get(method, "low"),
                               "count": len(enriched), "related": enriched[:60]})

        result = {"query": indicator, "value": value, "type": t,
                  "pivots": sorted(pivots, key=lambda p: {"high": 0, "medium": 1, "low": 2}[p["confidence"]]),
                  "cached": False}
        own.execute("INSERT OR REPLACE INTO infra_cache (key, at, result) VALUES (?, ?, ?)",
                    (key, time.time(), json.dumps({k: v for k, v in result.items() if k != "cached"})))
        own.commit()
        return result
    finally:
        if con is None:
            own.close()
