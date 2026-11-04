"""
Shodan enrichment — host/service intelligence for IPs already extracted from
underground signals. Complements the RDAP/Cymru enrichment in enrich.py:
RDAP/Cymru answer "who owns this IP and where", Shodan answers "what is this
IP actually running" (open ports, exposed services, known CVEs on them).

Stdlib `urllib` only. Requires DARKFEEDS_SHODAN_KEY. Free/dev tier: 1 req/sec.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

_BASE = "https://api.shodan.io"
_TIMEOUT = 20
_RATE_LIMIT_SECONDS = 1.0
_last_call = 0.0


@dataclass
class ShodanHost:
    ip: str
    org: str = ""
    isp: str = ""
    os: str = ""
    ports: list[int] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    vulns: list[str] = field(default_factory=list)   # CVE ids Shodan flagged
    tags: list[str] = field(default_factory=list)
    not_found: bool = False
    error: str = ""


def _rate_limit() -> None:
    global _last_call
    wait = _RATE_LIMIT_SECONDS - (time.monotonic() - _last_call)
    if wait > 0:
        time.sleep(wait)
    _last_call = time.monotonic()


def host_lookup(ip: str, *, api_key: str) -> ShodanHost:
    """Everything Shodan knows about one IP: open ports, services, known CVEs."""
    if not api_key:
        return ShodanHost(ip=ip, error="No Shodan API key configured — set DARKFEEDS_SHODAN_KEY.")

    _rate_limit()
    req = urllib.request.Request(f"{_BASE}/shodan/host/{ip}?key={api_key}")
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            data = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return ShodanHost(ip=ip, not_found=True)
        body = e.read().decode(errors="replace")
        return ShodanHost(ip=ip, error=f"Shodan HTTP {e.code}: {body[:300]}")
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as e:
        return ShodanHost(ip=ip, error=f"{type(e).__name__}: {e}")

    return ShodanHost(
        ip=ip,
        org=data.get("org", "") or "",
        isp=data.get("isp", "") or "",
        os=data.get("os", "") or "",
        ports=sorted(set(data.get("ports", []))),
        hostnames=data.get("hostnames", []),
        vulns=sorted(data.get("vulns", [])) if data.get("vulns") else [],
        tags=data.get("tags", []) or [],
    )
