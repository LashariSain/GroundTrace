"""Independent verification of an indicator, on demand.

A match in the IOC store only says an indicator was *listed* somewhere.
Lists have mistakes — a benign DLL or installer that sat next to malware ends
up in a report's indicator list. This cross-checks against independent
services and turns the answers into one plain verdict:

  VirusTotal       how many engines flag it; names / threat label   (hash, ip, domain, url host)
  MalwareBazaar    is it a catalogued malware sample; family, tags    (hash)
  CIRCL hashlookup is it a KNOWN-GOOD file (NSRL / vendor software)   (hash) - the false-positive check
  ThreatFox        is it a known C2 / payload host, which family       (ip, domain, url, hash)
  URLhaus          is it distributing malware, online or offline       (url, domain, ip)
  GreyNoise        is the IP a mass scanner, or a known-benign service (ip) - the false-positive check
  Shodan           what actually runs on the IP: ports, services       (ip)

Run only when asked (VirusTotal's free tier is 4 requests/min, 500/day),
and cached for a day.
"""
from __future__ import annotations

import json
import os
import ssl
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

from . import ioc_store

CACHE_SECONDS = 24 * 3600
_UA = {"User-Agent": "groundtrace/0.1 (research tool)"}


def _env(name: str) -> str:
    return os.environ.get(name, "").strip()


def _ca_context():
    """TLS context using certifi's CA bundle when it is installed.

    Verification is always on; this only widens the set of trusted roots.
    Python on Windows validates against the local store, which does not carry
    every public CA -- urlhaus-api.abuse.ch is signed by SwissSign and failed
    to verify here while the other abuse.ch hosts (Google Trust Services)
    passed. certifi ships the Mozilla root list, which includes it.
    """
    global _CTX
    if _CTX is None:
        try:
            import certifi
            _CTX = ssl.create_default_context(cafile=certifi.where())
        except Exception:                      # noqa: BLE001 - fall back to the default roots
            _CTX = ssl.create_default_context()
    return _CTX


_CTX = None


def _http_json(req: urllib.request.Request, timeout: int = 20):
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ca_context()) as r:
            return r.status, json.loads(r.read().decode("utf-8", "replace") or "null")
    except urllib.error.HTTPError as e:
        return e.code, None
    except (OSError, ValueError) as e:
        return 0, {"error": str(e)}


def virustotal(value: str, t: str) -> dict:
    key = _env("DARKFEEDS_VT_KEY")
    if not key:
        return {"status": "not_configured"}
    from darkfeeds import virustotal as vt
    path = {"md5": "files", "sha1": "files", "sha256": "files", "ip": "ip_addresses", "domain": "domains"}.get(t)
    if t == "url":  # check the URL's host
        value, path = urllib.parse.urlsplit(value).hostname or value, "domains"
    if not path:
        return {"status": "unsupported"}
    try:
        data = vt._get(f"/{path}/{urllib.parse.quote(value)}", key)
    except RuntimeError as e:
        return {"status": "error", "error": str(e)[:200]}
    if data is None:
        return {"status": "not_found"}
    a = data.get("data", {}).get("attributes", {})
    st = a.get("last_analysis_stats", {}) or {}
    label = ((a.get("popular_threat_classification") or {}).get("suggested_threat_label")) or ""
    return {"status": "found", "malicious": st.get("malicious", 0), "suspicious": st.get("suspicious", 0),
            "engines": sum(st.values()) if st else 0, "label": label, "reputation": a.get("reputation", 0),
            "names": (a.get("names") or [])[:5], "tags": (a.get("tags") or [])[:8],
            "first_seen": time.strftime("%Y-%m-%d", time.gmtime(a["first_submission_date"])) if a.get("first_submission_date") else "",
            "link": f"https://www.virustotal.com/gui/{ {'files': 'file', 'ip_addresses': 'ip-address', 'domains': 'domain'}[path] }/{value}"}


def _why(code: int, body) -> str:
    """A reason a caller can act on, rather than a bare status number."""
    if isinstance(body, dict) and body.get("error"):
        msg = str(body["error"])
        if "CERTIFICATE_VERIFY_FAILED" in msg:
            return "TLS certificate for this service could not be verified from this machine"
        return msg[:160]
    return f"HTTP {code}"


def _transport_failed(code: int, body) -> bool:
    """True when the request never produced an answer.

    _http_json returns (0, {"error": ...}) on a transport failure, which is a
    dict -- so an isinstance(body, dict) check passes and the service's
    "not found" branch runs. That reports a network failure as evidence the
    indicator is unknown, which is a claim we have not earned.
    """
    return code != 200 or (isinstance(body, dict) and "error" in body and "query_status" not in body)


def malwarebazaar(value: str, t: str) -> dict:
    if t not in ("md5", "sha1", "sha256"):
        return {"status": "unsupported"}
    key = _env("DARKFEEDS_ABUSECH_KEY")
    if not key:
        return {"status": "not_configured"}
    req = urllib.request.Request("https://mb-api.abuse.ch/api/v1/", method="POST",
                                 data=urllib.parse.urlencode({"query": "get_info", "hash": value}).encode(),
                                 headers={**_UA, "Auth-Key": key})
    code, body = _http_json(req)
    if not isinstance(body, dict):
        return {"status": "error", "error": f"HTTP {code}"}
    if body.get("query_status") != "ok" or not body.get("data"):
        return {"status": "not_found" if body.get("query_status") in ("hash_not_found", "no_results") else "error",
                "error": body.get("query_status", "")}
    d = body["data"][0]
    return {"status": "found", "family": d.get("signature") or "", "tags": (d.get("tags") or [])[:8],
            "file_type": d.get("file_type") or "", "first_seen": (d.get("first_seen") or "")[:10],
            "link": f"https://bazaar.abuse.ch/sample/{d.get('sha256_hash', value)}/"}


def circl(value: str, t: str) -> dict:
    """CIRCL hashlookup: is this a known (mostly benign) software file?"""
    if t not in ("md5", "sha1", "sha256"):
        return {"status": "unsupported"}
    req = urllib.request.Request(f"https://hashlookup.circl.lu/lookup/{t}/{value}", headers={**_UA, "Accept": "application/json"})
    code, body = _http_json(req)
    if code == 404:
        return {"status": "not_found"}
    if not isinstance(body, dict) or code != 200:
        return {"status": "error", "error": f"HTTP {code}"}
    return {"status": "found", "file_name": body.get("FileName", ""), "product": body.get("ProductName", "") or body.get("source", ""),
            "known_malicious": bool(body.get("KnownMalicious")), "trust": body.get("hashlookup:trust")}


def _abusech(url, payload, as_json=True):
    key = _env("DARKFEEDS_ABUSECH_KEY")
    if not key:
        return -1, None
    data = json.dumps(payload).encode() if as_json else urllib.parse.urlencode(payload).encode()
    headers = {**_UA, "Auth-Key": key,
               "Content-Type": "application/json" if as_json else "application/x-www-form-urlencoded"}
    return _http_json(urllib.request.Request(url, method="POST", data=data, headers=headers))


_THREAT = {"botnet_cc": "botnet C2 server", "payload_delivery": "malware delivery host",
           "cc_skimming": "card-skimming server", "payload": "malware payload"}


def threatfox(value: str, t: str) -> dict:
    if t not in ("ip", "domain", "url", "md5", "sha1", "sha256"):
        return {"status": "unsupported"}
    code, body = _abusech("https://threatfox-api.abuse.ch/api/v1/", {"query": "search_ioc", "search_term": value})
    if code == -1:
        return {"status": "not_configured"}
    if _transport_failed(code, body) or not isinstance(body, dict):
        return {"status": "error", "error": _why(code, body)}
    if body.get("query_status") != "ok" or not isinstance(body.get("data"), list) or not body["data"]:
        return {"status": "not_found"}
    d = sorted(body["data"], key=lambda x: x.get("last_seen") or x.get("first_seen") or "", reverse=True)[0]
    family = d.get("malware_printable") or ""
    return {"status": "found", "threat": _THREAT.get(d.get("threat_type") or "", d.get("threat_type") or "malicious"),
            "family": "" if family.lower().startswith("unknown") else family, "confidence": d.get("confidence_level"),
            "first_seen": (d.get("first_seen") or "")[:10], "last_seen": (d.get("last_seen") or "")[:10],
            "records": len(body["data"]),
            "link": f"https://threatfox.abuse.ch/ioc/{d.get('id')}/" if d.get("id") else ""}


def urlhaus(value: str, t: str) -> dict:
    if t == "url":
        code, body = _abusech("https://urlhaus-api.abuse.ch/v1/url/", {"url": value}, as_json=False)
    elif t in ("domain", "ip"):
        code, body = _abusech("https://urlhaus-api.abuse.ch/v1/host/", {"host": value}, as_json=False)
    elif t in ("md5", "sha256"):
        # URLhaus indexes payloads too: which URLs distributed this sample.
        # That is an independent source for a hash, and it is what makes
        # corroboration possible for samples ThreatFox also knows. (sha1 is
        # not a lookup key in this API.)
        code, body = _abusech("https://urlhaus-api.abuse.ch/v1/payload/",
                              {f"{t}_hash": value}, as_json=False)
    else:
        return {"status": "unsupported"}
    if code == -1:
        return {"status": "not_configured"}
    if _transport_failed(code, body) or not isinstance(body, dict):
        return {"status": "error", "error": _why(code, body)}
    if body.get("query_status") != "ok":
        return {"status": "not_found"}
    if t in ("md5", "sha256"):
        urls = int(body.get("url_count") or 0)
        return {"status": "found", "urls": urls, "online": int(body.get("urlhaus_download") is not None),
                "threat": body.get("signature") or "", "file_type": body.get("file_type") or "",
                "first_seen": (body.get("firstseen") or "")[:10],
                "link": body.get("urlhaus_reference") or ""}
    if t == "url":
        return {"status": "found", "online": body.get("url_status") == "online", "threat": body.get("threat") or "",
                "tags": (body.get("tags") or [])[:6], "first_seen": (body.get("date_added") or "")[:10],
                "link": body.get("urlhaus_reference") or ""}
    urls = body.get("urls") or []
    return {"status": "found", "urls": int(body.get("url_count") or len(urls)),
            "online": sum(1 for u in urls if u.get("url_status") == "online"),
            "first_seen": (body.get("firstseen") or "")[:10], "link": body.get("urlhaus_reference") or ""}


def greynoise(value: str, t: str) -> dict:
    if t != "ip":
        return {"status": "unsupported"}
    headers = {**_UA, "Accept": "application/json"}
    if _env("GREYNOISE_API_KEY"):
        headers["key"] = _env("GREYNOISE_API_KEY")
    code, body = _http_json(urllib.request.Request(f"https://api.greynoise.io/v3/community/{value}", headers=headers))
    if code == 404:
        return {"status": "not_found"}  # GreyNoise answers "not observed scanning" with 404
    if code == 429:
        return {"status": "rate_limited"}
    if not isinstance(body, dict) or code != 200:
        return {"status": "error", "error": f"HTTP {code}"}
    if not body.get("noise") and not body.get("riot"):
        return {"status": "not_found"}
    return {"status": "found", "scanner": bool(body.get("noise")), "benign_service": bool(body.get("riot")),
            "classification": body.get("classification") or "", "name": body.get("name") or "",
            "last_seen": body.get("last_seen") or "", "link": f"https://viz.greynoise.io/ip/{value}"}


def shodan(value: str, t: str) -> dict:
    """Shodan InternetDB: open ports, hostnames, known CVEs and tags for an IP.
    Free and keyless (the full host API needs a paid Shodan membership)."""
    if t != "ip":
        return {"status": "unsupported"}
    code, body = _http_json(urllib.request.Request(f"https://internetdb.shodan.io/{value}", headers={**_UA, "Accept": "application/json"}))
    if code == 404:
        return {"status": "not_found"}
    if not isinstance(body, dict) or code != 200:
        return {"status": "error", "error": f"HTTP {code}"}
    return {"status": "found", "ports": (body.get("ports") or [])[:20], "hostnames": (body.get("hostnames") or [])[:5],
            "tags": (body.get("tags") or [])[:6], "vulns": (body.get("vulns") or [])[:10],
            "link": f"https://www.shodan.io/host/{value}"}


# A single service saying "malicious" is a lead. "Confirmed" is reserved for
# agreement between independent services, because one source cannot be checked
# against anything -- and a feed that is wrong about an indicator is wrong
# about it every time you ask.
_CORROBORATION_MIN = 2


def malicious_sources(t: str, vt: dict, mb: dict, tf: dict, uh: dict) -> list[str]:
    """Independent services that each indicate this indicator is malicious.

    VirusTotal counts only at 10+ detections: a handful of engines flagging
    something is routine noise, and VT is one source however many engines it
    aggregates.
    """
    out = []
    if tf.get("status") == "found":
        out.append("ThreatFox")
    if uh.get("status") == "found" and (uh.get("online") or uh.get("urls") or t == "url"):
        out.append("URLhaus")
    if mb.get("status") == "found":
        out.append("MalwareBazaar")
    if vt.get("status") == "found" and (vt.get("malicious") or 0) >= 10:
        out.append(f"VirusTotal ({vt['malicious']} engines)")
    return out


def verdict(t: str, vt: dict, mb: dict, ci: dict, tf=None, uh=None, gn=None) -> dict:
    tf, uh, gn = tf or {}, uh or {}, gn or {}
    srcs = malicious_sources(t, vt, mb, tf, uh)

    def _d(level, text, **extra):
        return {"level": level, "text": text, "sources": srcs,
                "corroborated": len(srcs) >= _CORROBORATION_MIN, **extra}

    def _detail():
        bits = []
        if tf.get("status") == "found":
            fam = f" ({tf['family']})" if tf.get("family") else ""
            seen = tf.get("last_seen") or tf.get("first_seen") or "unknown"
            bits.append(f"ThreatFox: {tf.get('threat') or 'malicious indicator'}{fam}, last seen {seen}")
        if "URLhaus" in srcs:
            bits.append("URLhaus: malware distribution ("
                        + ("currently online" if uh.get("online") else "now offline") + ")")
        if mb.get("status") == "found":
            fam = mb.get("family") or vt.get("label")
            bits.append("MalwareBazaar: sample listed" + (f" ({fam})" if fam else ""))
        if vt.get("status") == "found" and (vt.get("malicious") or 0) >= 10:
            bits.append(f"VirusTotal: {vt['malicious']} of {vt.get('engines', 0)} engines")
        return "; ".join(bits)

    if len(srcs) >= _CORROBORATION_MIN:
        return _d("confirmed",
                  f"Confirmed malicious — {len(srcs)} independent sources agree. {_detail()}.")
    if gn.get("benign_service"):
        name = f": {gn['name']}" if gn.get("name") else ""
        return _d("benign", f"Known-benign service{name}. Likely a false positive; do not block on this alone.")
    if gn.get("scanner"):
        return _d("likely", "Internet-wide scanner (" + (gn.get("classification") or "unclassified")
                  + "): opportunistic background noise, not evidence of a targeted attack.")
    mal = vt.get("malicious", 0) if vt.get("status") == "found" else None
    if ci.get("status") == "found" and not ci.get("known_malicious") and (mal is None or mal <= 2):
        return _d("benign", "Known-good file (software catalogue) — likely a false positive in the indicator list. Do not block on this alone.")
    if srcs:
        # Exactly one source. Say which, and say it is not corroborated --
        # this was reported as "confirmed" before, on a single feed.
        return _d("likely", f"Likely malicious, but only one source says so ({srcs[0]}). "
                            f"{_detail()}. Not corroborated: a second independent "
                            f"source is needed to confirm.")
    if mal is not None and mal >= 1:
        return _d("likely", f"Likely malicious: {mal} of {vt.get('engines', 0)} engines flag it. "
                            f"Not corroborated (VirusTotal only).")
    if mal == 0:
        return _d("clean", "No engine flags it today." if t in ("md5", "sha1", "sha256")
                  else "No engine flags it today (infrastructure is often re-used or taken down; check the dates).")
    return _d("unverified", "Not found by any verification service — unverified.")


_SCHEMA = "CREATE TABLE IF NOT EXISTS verify_cache (key TEXT PRIMARY KEY, at REAL NOT NULL, result TEXT NOT NULL)"


def check(raw: str, con: Optional[sqlite3.Connection] = None, force: bool = False) -> dict:
    value, t = ioc_store.classify(raw)
    if t not in ("md5", "sha1", "sha256", "ip", "domain", "url"):
        return {"query": raw, "type": t, "error": "verification supports hashes, IPs, domains and URLs"}
    own = con is None
    con = con or ioc_store.connect()
    try:
        con.execute(_SCHEMA)
        row = con.execute("SELECT at, result FROM verify_cache WHERE key = ?", (f"{t}:{value}",)).fetchone()
        if row and not force and time.time() - row[0] < CACHE_SECONDS:
            return {**json.loads(row[1]), "cached": True}
        vt, mb, ci = virustotal(value, t), malwarebazaar(value, t), circl(value, t)
        tf, uh, gn, sh = threatfox(value, t), urlhaus(value, t), greynoise(value, t), shodan(value, t)
        out = {"query": raw, "value": value, "type": t, "checked_at": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
               "virustotal": vt, "malwarebazaar": mb, "circl": ci, "threatfox": tf, "urlhaus": uh,
               "greynoise": gn, "shodan": sh, "verdict": verdict(t, vt, mb, ci, tf, uh, gn)}
        con.execute("INSERT OR REPLACE INTO verify_cache (key, at, result) VALUES (?, ?, ?)",
                    (f"{t}:{value}", time.time(), json.dumps(out)))
        con.commit()
        return {**out, "cached": False}
    finally:
        if own:
            con.close()
