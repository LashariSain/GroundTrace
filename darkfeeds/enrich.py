"""
IP enrichment — attribute an IOC's IP to an org/ASN/country via RDAP.

Not a `whois` subprocess: that binary isn't installed on Windows by default,
whois output format varies by registry and is painful to parse reliably, and
spawning a process per IP has no good way to rate-limit or cache. RDAP (the
IETF-standardized successor to whois, RFC 7483) is plain JSON over HTTPS —
stdlib `urllib` only, no extra dependency, and rdap.org's bootstrap service
auto-routes the query to whichever RIR (ARIN/RIPE/APNIC/...) actually holds
the record, so one endpoint covers every public IP.

Private/reserved/documentation addresses (RFC 1918, RFC 5737, loopback, …)
are skipped before any network call — they have no RIR record and querying
them would just waste a request.
"""
from __future__ import annotations

import ipaddress
import json
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

_UA = {"User-Agent": "groundtrace-darkfeeds/0.1 (research tool)"}
_TIMEOUT = 15
_RDAP_URL = "https://rdap.org/ip/{ip}"

# Be a polite citizen of a free, shared bootstrap service.
_RATE_LIMIT_SECONDS = 1.0
_last_call = 0.0

_cache: dict[str, "IPEnrichment"] = {}


@dataclass
class IPEnrichment:
    ip: str
    org: str = ""
    country: str = ""
    asn: str = ""
    as_name: str = ""
    cidr: str = ""
    skipped_reason: str = ""   # set instead of querying, for private/reserved IPs
    error: str = ""


_DOC_NETS = [ipaddress.ip_network(n) for n in
             ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]


def _is_queryable(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Return a skip reason, or "" if this IP is worth querying RDAP for.

    Checked before the general is_private/is_reserved catch-alls below,
    since those flag documentation ranges too (they ARE private) but a more
    specific label is more useful here than a generic "private".
    """
    if any(ip in net for net in _DOC_NETS):
        return "documentation range (RFC 5737/3849)"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_private:
        return "private (RFC 1918)"
    if ip.is_reserved:
        return "reserved"
    return ""


def _rate_limit() -> None:
    global _last_call
    wait = _RATE_LIMIT_SECONDS - (time.monotonic() - _last_call)
    if wait > 0:
        time.sleep(wait)
    _last_call = time.monotonic()


def _iter_entities(data: dict):
    """Entities can nest (a registrant entity containing an abuse-contact
    entity, etc.) — walk the whole tree, not just the top level."""
    for entity in data.get("entities", []):
        yield entity
        yield from _iter_entities(entity)


def _extract(data: dict, ip: str) -> IPEnrichment:
    # "org" is the actual organization name; "fn" is often just a contact's
    # role/personal name (e.g. "Abuse", "NOC") — prefer org, fall back to fn
    # only if no entity has one.
    org = fallback_fn = ""
    for entity in _iter_entities(data):
        for field_ in entity.get("vcardArray", [None, []])[1]:
            if field_[0] == "org" and field_[3]:
                org = field_[3]
            elif field_[0] == "fn" and field_[3] and not fallback_fn:
                fallback_fn = field_[3]
        if org:
            break
    org = org or fallback_fn or data.get("name", "")

    # Country can show up two ways depending on the registry: structured
    # vcard "adr" components (RIPE/APNIC-style), or just a free-text "label"
    # parameter with the country as its last line (ARIN-style — the
    # structured array is left blank). Try structured first, fall back to
    # the label's last non-empty line.
    country = ""
    for entity in _iter_entities(data):
        for addr in entity.get("vcardArray", [None, []])[1]:
            if addr[0] != "adr":
                continue
            if isinstance(addr[3], list) and len(addr[3]) >= 7 and addr[3][-1]:
                country = addr[3][-1]
                break
            label = addr[1].get("label") if isinstance(addr[1], dict) else None
            if label:
                lines = [ln.strip() for ln in label.splitlines() if ln.strip()]
                if lines:
                    country = lines[-1]
                    break
        if country:
            break

    asn = ""
    for link in data.get("links", []):
        if "autnum" in (link.get("href") or ""):
            asn = link["href"].rstrip("/").rsplit("/", 1)[-1]

    cidr = ""
    start, end = data.get("startAddress"), data.get("endAddress")
    if start:
        cidr = f"{start}" + (f" - {end}" if end and end != start else "")

    return IPEnrichment(ip=ip, org=org, country=country, asn=asn, cidr=cidr)


_CYMRU_HOST = "whois.cymru.com"
_CYMRU_PORT = 43
_CYMRU_TIMEOUT = 10


def _cymru_asn_lookup(ips: list[str]) -> dict[str, dict]:
    """Bulk ASN lookup via Team Cymru's whois service (RFC-less but a long-
    standing free/open convention; no key, no rate limit published, one TCP
    round trip for any number of IPs). IP RDAP records routinely omit ASN —
    this is the standard way to actually get it. Returns {ip: {asn, as_name,
    country, registry, allocated}}; empty dict for any IP that errors.

    Protocol: connect to port 43, send "begin\\nverbose\\n<ip>\\n...\\nend\\n",
    read pipe-delimited response lines, one per IP (plus a header line).
    """
    if not ips:
        return {}
    query = "begin\nverbose\n" + "\n".join(ips) + "\nend\n"
    try:
        with socket.create_connection((_CYMRU_HOST, _CYMRU_PORT),
                                      timeout=_CYMRU_TIMEOUT) as sock:
            sock.sendall(query.encode())
            chunks = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
        raw = b"".join(chunks).decode(errors="replace")
    except OSError:
        return {}

    lines = [ln for ln in raw.splitlines() if ln.strip()]
    if lines and lines[0].lstrip().startswith("AS"):
        lines = lines[1:]  # drop the header row

    out: dict[str, dict] = {}
    for line in lines:
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 7:
            continue
        asn, ip, prefix, cc, registry, allocated, as_name = parts[:7]
        out[ip] = {"asn": asn if asn != "NA" else "", "as_name": as_name,
                   "country": cc, "registry": registry, "allocated": allocated,
                   "prefix": prefix}
    return out


def _apply_asn(result: IPEnrichment, asn_data: dict) -> None:
    if not asn_data:
        return
    result.asn = asn_data.get("asn", "")
    result.as_name = asn_data.get("as_name", "")
    # Cymru's AS name is a consistent "SHORTNAME - Description, CC" format
    # pulled from routing registry data — prefer it over RDAP's org field,
    # which has proven unreliable across registries (see country note
    # below): it can surface a generic abuse/admin contact's name instead
    # of the actual assignee, especially for APNIC-delegated space.
    if asn_data.get("as_name"):
        result.org = asn_data["as_name"]
    # Cymru's country is a plain, consistent 2-letter ISO code pulled from
    # routing registry data. RDAP's is parsed out of free-text/vcard fields
    # whose layout differs by registry — reliable for some (ARIN, RIPE),
    # but e.g. APNIC-delegated space can put a street address where the
    # country should be. Prefer the reliable source when we have it.
    cymru_country = asn_data.get("country", "")
    if cymru_country:
        result.country = cymru_country
    elif not result.country:
        result.country = ""


def enrich_ip(ip_str: str, *, use_cache: bool = True) -> IPEnrichment:
    """RDAP + ASN-enrich one public IP. Private/reserved IPs are skipped.

    For more than one IP, prefer enrich_ips() — it does ASN lookups in a
    single bulk Team Cymru query instead of one round trip per IP.
    """
    if use_cache and ip_str in _cache:
        return _cache[ip_str]

    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError as e:
        result = IPEnrichment(ip=ip_str, error=f"invalid IP: {e}")
        _cache[ip_str] = result
        return result

    skip = _is_queryable(ip)
    if skip:
        result = IPEnrichment(ip=ip_str, skipped_reason=skip)
        _cache[ip_str] = result
        return result

    _rate_limit()
    try:
        req = urllib.request.Request(_RDAP_URL.format(ip=ip_str), headers=_UA)
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            data = json.loads(r.read().decode("utf-8"))
        result = _extract(data, ip_str)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as e:
        result = IPEnrichment(ip=ip_str, error=f"{type(e).__name__}: {e}")

    _apply_asn(result, _cymru_asn_lookup([ip_str]).get(ip_str, {}))
    _cache[ip_str] = result
    return result


def enrich_and_store_signals(signals: list, store, *, shodan_api_key: str = "") -> int:
    """Enrich every IP across a batch of ThreatSignals — RDAP/Cymru always
    (who owns it, where), plus Shodan host data if a key is configured (what
    it's actually running: open ports, services, known CVEs on them) — in
    one shared Cymru call via enrich_ips' internal batching, and persist
    each signal's result to the store. Meant to run right after
    save_signals() on a fresh collection batch — enriching in-memory
    signals we already have is one pass; re-scanning the whole DB
    afterward (store.get_unenriched_ips) is for catching up signals saved
    before this existed, not routine use.

    Returns the number of signals that had at least one IP enriched.
    """
    from dataclasses import asdict

    all_ips = sorted({ip for s in signals for ip in s.ip_addresses})
    if not all_ips:
        return 0

    by_ip = {r.ip: asdict(r) for r in enrich_ips(all_ips)}

    if shodan_api_key:
        from .shodan_client import host_lookup
        # Capped per batch (one rate-limited call per IP); the rest can be
        # filled in later with `darkfeeds enrich-ips`.
        budget = SHODAN_BATCH_BUDGET
        for ip, data in by_ip.items():
            if data.get("skipped_reason"):
                continue  # don't waste a Shodan call on a private/reserved IP
            if budget <= 0:
                break
            budget -= 1
            host = host_lookup(ip, api_key=shodan_api_key)
            data["shodan"] = asdict(host)

    count = 0
    for s in signals:
        if not s.ip_addresses:
            continue
        enrichment = {ip: by_ip[ip] for ip in s.ip_addresses if ip in by_ip}
        if enrichment:
            store.save_ip_enrichment(s.signal_id, enrichment)
            count += 1
    return count


# Per-IP RDAP is rate limited (~1-15 s each); a 2,000-IP batch took over an
# hour. Cymru's bulk lookup already gives country/ASN/provider for every IP in
# one query, so RDAP is only a capped fallback for IPs Cymru couldn't place.
RDAP_FALLBACK_BUDGET = 25
SHODAN_BATCH_BUDGET = 25
_CYMRU_CHUNK = 1000


def _rdap(ip: str) -> IPEnrichment:
    _rate_limit()
    try:
        req = urllib.request.Request(_RDAP_URL.format(ip=ip), headers=_UA)
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            data = json.loads(r.read().decode("utf-8"))
        return _extract(data, ip)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as e:
        return IPEnrichment(ip=ip, error=f"{type(e).__name__}: {e}")


def enrich_ips(ips: list[str], *, rdap_budget: int = RDAP_FALLBACK_BUDGET) -> list[IPEnrichment]:
    """Enrich several IPs, de-duplicated: one bulk Team Cymru query per 1,000
    IPs, then per-IP RDAP for at most `rdap_budget` IPs Cymru left unplaced."""
    seen: dict[str, IPEnrichment] = {}
    queryable: list[str] = []

    for ip in ips:
        if ip in seen:
            continue
        if ip in _cache:
            seen[ip] = _cache[ip]
            continue
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError as e:
            seen[ip] = _cache[ip] = IPEnrichment(ip=ip, error=f"invalid IP: {e}")
            continue
        skip = _is_queryable(addr)
        if skip:
            seen[ip] = _cache[ip] = IPEnrichment(ip=ip, skipped_reason=skip)
            continue
        seen[ip] = IPEnrichment(ip=ip)
        queryable.append(ip)

    asn_map: dict[str, dict] = {}
    for i in range(0, len(queryable), _CYMRU_CHUNK):
        asn_map.update(_cymru_asn_lookup(queryable[i:i + _CYMRU_CHUNK]))

    for ip in queryable:
        asn = asn_map.get(ip, {})
        if not asn.get("country") and rdap_budget > 0:
            rdap_budget -= 1
            seen[ip] = _rdap(ip)
        _apply_asn(seen[ip], asn)
        _cache[ip] = seen[ip]

    return [seen[ip] for ip in ips]
