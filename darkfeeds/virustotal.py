"""
VirusTotal enrichment — reputation lookups for hashes, IPs, and domains
already extracted from underground signals (darkfeeds/extractors.py).

Public API v3, free tier: 4 req/min, 500/day (as published by VirusTotal;
enforced here client-side so a batch run doesn't get the key throttled/banned).
Stdlib `urllib` only, no SDK dependency. Requires DARKFEEDS_VT_KEY.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

_BASE = "https://www.virustotal.com/api/v3"
_TIMEOUT = 20

# Free tier: 4 req/min. Sleep between calls rather than burst and get 429'd.
_RATE_LIMIT_SECONDS = 15.0
_last_call = 0.0


@dataclass
class VTReputation:
    indicator: str
    kind: str = ""                 # "hash" | "ip" | "domain"
    malicious: int = 0             # # of AV engines flagging it malicious
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    total_engines: int = 0
    reputation: int = 0            # VT community reputation score
    tags: list[str] = field(default_factory=list)
    names: list[str] = field(default_factory=list)   # known filenames, for hashes
    not_found: bool = False
    error: str = ""

    @property
    def is_malicious(self) -> bool:
        return self.malicious > 0


def _rate_limit() -> None:
    global _last_call
    wait = _RATE_LIMIT_SECONDS - (time.monotonic() - _last_call)
    if wait > 0:
        time.sleep(wait)
    _last_call = time.monotonic()


def _get(path: str, api_key: str) -> Optional[dict]:
    if not api_key:
        raise RuntimeError(
            "No VirusTotal API key configured — set DARKFEEDS_VT_KEY.")
    _rate_limit()
    req = urllib.request.Request(f"{_BASE}{path}", headers={"x-apikey": api_key})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        body = e.read().decode(errors="replace")
        raise RuntimeError(f"VirusTotal HTTP {e.code}: {body[:300]}") from e


def _from_stats(indicator: str, kind: str, data: dict) -> VTReputation:
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return VTReputation(
        indicator=indicator, kind=kind,
        malicious=stats.get("malicious", 0),
        suspicious=stats.get("suspicious", 0),
        harmless=stats.get("harmless", 0),
        undetected=stats.get("undetected", 0),
        total_engines=sum(stats.values()) if stats else 0,
        reputation=attrs.get("reputation", 0),
        tags=attrs.get("tags", []),
        names=attrs.get("names", [])[:5] if "names" in attrs else [],
    )


def check_hash(file_hash: str, *, api_key: str) -> VTReputation:
    """MD5/SHA1/SHA256 reputation — AV detection count + known filenames."""
    try:
        data = _get(f"/files/{file_hash}", api_key)
    except RuntimeError as e:
        return VTReputation(indicator=file_hash, kind="hash", error=str(e))
    if data is None:
        return VTReputation(indicator=file_hash, kind="hash", not_found=True)
    return _from_stats(file_hash, "hash", data)


def check_ip(ip: str, *, api_key: str) -> VTReputation:
    try:
        data = _get(f"/ip_addresses/{ip}", api_key)
    except RuntimeError as e:
        return VTReputation(indicator=ip, kind="ip", error=str(e))
    if data is None:
        return VTReputation(indicator=ip, kind="ip", not_found=True)
    return _from_stats(ip, "ip", data)


def check_domain(domain: str, *, api_key: str) -> VTReputation:
    try:
        data = _get(f"/domains/{domain}", api_key)
    except RuntimeError as e:
        return VTReputation(indicator=domain, kind="domain", error=str(e))
    if data is None:
        return VTReputation(indicator=domain, kind="domain", not_found=True)
    return _from_stats(domain, "domain", data)
