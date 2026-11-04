"""
Clearnet API collectors — MalwareBazaar, ThreatFox, RansomLook, AlienVault OTX.

These are FREE APIs that don't require Tor. They provide high-quality
threat intelligence including malware samples, IoCs, ransomware activity,
and APT-attributed pulses.
"""
from __future__ import annotations

import hashlib
import json
import urllib.request
import urllib.error
from datetime import datetime
from typing import Optional

from .models import ThreatSignal, SignalSource, SignalType, Priority, Confidence
from . import focus
from .extractors import extract_all

_UA = {"User-Agent": "darkfeeds/0.1 (threat-intel-research)"}
_TIMEOUT = 20


def _get_json(url: str, headers: dict = None, data: bytes = None) -> Optional[dict | list]:
    """HTTP GET/POST returning parsed JSON."""
    hdrs = {**_UA, **(headers or {})}
    try:
        req = urllib.request.Request(url, headers=hdrs, data=data)
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as e:
        print(f"[!] API error: {url} — {e}")
        return None


def _post_json(url: str, payload: dict, headers: dict = None,
               content_type: str = "json") -> Optional[dict | list]:
    """HTTP POST with JSON or form data."""
    if content_type == "json":
        data = json.dumps(payload).encode("utf-8")
        ct = "application/json"
    else:
        data = urllib.parse.urlencode(payload).encode("utf-8")
        ct = "application/x-www-form-urlencoded"
    hdrs = {**_UA, "Content-Type": ct, **(headers or {})}
    try:
        req = urllib.request.Request(url, headers=hdrs, data=data)
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as e:
        print(f"[!] API error: {url} — {e}")
        return None


import os
import urllib.parse


def _abuse_ch_headers() -> Optional[dict]:
    """abuse.ch (MalwareBazaar, ThreatFox) requires a free Auth-Key since
    2024 — https://auth.abuse.ch/. Returns None (and says so once) without
    it, so callers skip cleanly instead of logging a 401 on every run."""
    key = os.environ.get("DARKFEEDS_ABUSECH_KEY")
    if not key:
        if not getattr(_abuse_ch_headers, "_warned", False):
            print("[!] abuse.ch sources skipped: set DARKFEEDS_ABUSECH_KEY "
                  "(free at https://auth.abuse.ch/)")
            _abuse_ch_headers._warned = True
        return None
    return {"Auth-Key": key}


# ─────────────────────────────────────────────────────────────────────────
# MalwareBazaar (abuse.ch) — Malware samples, hashes, APT tags
# Free, requires an abuse.ch Auth-Key (DARKFEEDS_ABUSECH_KEY)
# ─────────────────────────────────────────────────────────────────────────

def collect_malwarebazaar_recent(limit: int = 50) -> list[ThreatSignal]:
    """Get the most recent malware samples from MalwareBazaar."""
    headers = _abuse_ch_headers()
    if headers is None:
        return []
    print("[*] Collecting from MalwareBazaar (recent samples)...")
    data = _post_json(
        "https://mb-api.abuse.ch/api/v1/",
        {"query": "get_recent", "selector": "time"},
        headers=headers, content_type="form"
    )
    if not data or data.get("query_status") != "ok":
        print("[!] MalwareBazaar: no data returned")
        return []

    signals = []
    # Limit manually since API might not respect limit param here
    samples = data.get("data", [])[:limit]
    for sample in samples:
        tags = sample.get("tags") or []
        sig = sample.get("signature") or ""
        text = f"{sig} {' '.join(tags)} {sample.get('file_name', '')}"

        extraction = extract_all(text)
        focus_score = focus.relevance(text)

        signal = ThreatSignal(
            signal_id=hashlib.sha256(sample["sha256_hash"].encode()).hexdigest()[:16],
            signal_type=SignalType.MALWARE_SAMPLE,
            source=SignalSource.MALWAREBAZAAR,
            source_name="MalwareBazaar",
            source_url=f"https://bazaar.abuse.ch/sample/{sample['sha256_hash']}/",
            title=f"{sig or 'Unknown'} — {sample.get('file_type', 'unknown')}",
            raw_text=text,
            malware_hashes=[sample["sha256_hash"]],
            malware_family=sig or extraction.malware_family,
            threat_actor=extraction.threat_actor,
            target_country=focus.target(focus_score),
            relevance_score=extraction.overall_score,
            tags=tags,
            posted_at=_parse_ts(sample.get("first_seen")),
        )
        signals.append(signal)

    print(f"[+] MalwareBazaar: {len(signals)} samples collected")
    return signals


def collect_malwarebazaar_by_tag(tag: str) -> list[ThreatSignal]:
    """Search MalwareBazaar for samples with a specific tag (e.g., 'CrimsonRAT')."""
    headers = _abuse_ch_headers()
    if headers is None:
        return []
    print(f"[*] MalwareBazaar: searching tag '{tag}'...")
    data = _post_json(
        "https://mb-api.abuse.ch/api/v1/",
        {"query": "get_taginfo", "tag": tag, "limit": "50"},
        headers=headers, content_type="form"
    )
    if not data or data.get("query_status") != "ok":
        return []

    signals = []
    for sample in data.get("data", []):
        tags = sample.get("tags") or []
        sig = sample.get("signature") or tag
        text = f"{sig} {' '.join(tags)}"
        extraction = extract_all(text)

        signal = ThreatSignal(
            signal_id=hashlib.sha256(sample["sha256_hash"].encode()).hexdigest()[:16],
            signal_type=SignalType.MALWARE_SAMPLE,
            source=SignalSource.MALWAREBAZAAR,
            source_name="MalwareBazaar",
            source_url=f"https://bazaar.abuse.ch/sample/{sample['sha256_hash']}/",
            title=f"[{tag}] {sig} — {sample.get('file_type', '')}",
            malware_hashes=[sample["sha256_hash"]],
            malware_family=sig,
            threat_actor=extraction.threat_actor,
            relevance_score=extraction.overall_score,
            tags=tags,
            posted_at=_parse_ts(sample.get("first_seen")),
        )
        signals.append(signal)

    print(f"[+] MalwareBazaar [{tag}]: {len(signals)} samples")
    return signals


# ─────────────────────────────────────────────────────────────────────────
# ThreatFox (abuse.ch) — IoCs linked to malware families
# Free, requires an abuse.ch Auth-Key (DARKFEEDS_ABUSECH_KEY)
# ─────────────────────────────────────────────────────────────────────────

def collect_threatfox_recent(days: int = 3) -> list[ThreatSignal]:
    """Get recent IoCs from ThreatFox."""
    headers = _abuse_ch_headers()
    if headers is None:
        return []
    print(f"[*] Collecting from ThreatFox (last {days} days)...")
    # ThreatFox takes a JSON body (unlike MalwareBazaar's form fields).
    data = _post_json(
        "https://threatfox-api.abuse.ch/api/v1/",
        {"query": "get_iocs", "days": days},
        headers=headers, content_type="json"
    )
    if not data or data.get("query_status") != "ok":
        print("[!] ThreatFox: no data returned")
        return []

    signals = []
    for ioc in data.get("data", []):
        ioc_value = ioc.get("ioc", "")
        malware = ioc.get("malware_printable", "")
        tags = ioc.get("tags") or []
        text = f"{malware} {ioc_value} {' '.join(tags or [])}"

        extraction = extract_all(text)

        signal = ThreatSignal(
            signal_id=hashlib.sha256(f"tf:{ioc.get('id', '')}".encode()).hexdigest()[:16],
            signal_type=SignalType.C2_INFRASTRUCTURE if "c2" in str(ioc.get("threat_type", "")).lower()
                        else SignalType.MALWARE_SAMPLE,
            source=SignalSource.THREATFOX,
            source_name="ThreatFox",
            source_url=f"https://threatfox.abuse.ch/ioc/{ioc.get('id', '')}/",
            title=f"{malware} — {ioc.get('threat_type', '')} — {ioc_value[:80]}",
            raw_text=text,
            malware_family=malware,
            threat_actor=extraction.threat_actor,
            ip_addresses=extraction.ips,
            domains=extraction.domains,
            relevance_score=extraction.overall_score,
            tags=tags,
            posted_at=_parse_ts(ioc.get("first_seen_utc")),
            confidence=Confidence.HIGH,  # ThreatFox data is verified
        )
        signals.append(signal)

    print(f"[+] ThreatFox: {len(signals)} IoCs collected")
    return signals


# ─────────────────────────────────────────────────────────────────────────
# RansomLook — free ransomware leak-site claim tracker (https://www.ransomlook.io)
# Replaces ransomware.live, which moved its victim feed behind a paid API PRO
# key in 2025. RansomLook's /api endpoints are free and need no key.
# ─────────────────────────────────────────────────────────────────────────

RANSOMLOOK_RECENT_URL = "https://www.ransomlook.io/api/recent/200"


def collect_ransomlook() -> list[ThreatSignal]:
    """Get recent ransomware leak-site claims from RansomLook (free, no key)."""
    print("[*] Collecting from RansomLook...")
    data = _get_json(RANSOMLOOK_RECENT_URL)
    if not data:
        print("[!] RansomLook: no data returned")
        return []
    if isinstance(data, dict):
        data = data.get("posts") or data.get("data") or []

    signals = []
    for post in data:
        group = (post.get("group_name") or "").strip()
        title = (post.get("post_title") or "").strip()
        description = (post.get("description") or "").strip()
        link = (post.get("link") or "").strip()
        # /post/... links are relative to the site root
        if link.startswith("/"):
            link = f"https://www.ransomlook.io{link}"

        # Keep the leak-post body in raw_text so CVE mentions and focus-country
        # signals in the description are picked up downstream.
        text = f"{group} {title}\n{description}".strip()
        focus_score = focus.relevance(text)

        signal = ThreatSignal(
            signal_id=hashlib.sha256(
                f"rl:{group}:{title}".encode()
            ).hexdigest()[:16],
            signal_type=SignalType.RANSOMWARE_VICTIM,
            source=SignalSource.RANSOMLOOK,
            source_name="ransomlook.io",
            source_url=link,
            title=f"[{group}] {title}" if group else title,
            raw_text=text,
            threat_actor=group,
            target_country=focus.target(focus_score),
            relevance_score=0.5 if focus_score > focus.RELEVANT else 0.15,
            priority=Priority.HIGH if focus_score > focus.RELEVANT else Priority.LOW,
            confidence=Confidence.HIGH,
            posted_at=_parse_ts(post.get("discovered")),
        )
        signals.append(signal)

    print(f"[+] RansomLook: {len(signals)} claims")
    return signals


# ─────────────────────────────────────────────────────────────────────────
# AlienVault OTX — Threat intel pulses with IoCs, CVEs, APT attribution
# Free API key required (get from https://otx.alienvault.com)
# ─────────────────────────────────────────────────────────────────────────

_OTX_HASHES = ("FileHash-SHA256", "FileHash-MD5", "FileHash-SHA1")


def _otx_pulse_detail(pulse_id: str, headers: dict) -> Optional[dict]:
    """The full pulse. OTX's search endpoint returns pulses WITHOUT their
    indicators (and usually without targeted_countries / adversary), which is
    why every APT pulse used to arrive with no IPs or domains."""
    if not pulse_id:
        return None
    data = _get_json(f"https://otx.alienvault.com/api/v1/pulses/{pulse_id}", headers=headers)
    return data if isinstance(data, dict) and data.get("id") else None


def _otx_fields(pulse: dict, extraction) -> dict:
    """Signal fields from a full OTX pulse: IOCs, actor, family, targeting."""
    indicators = pulse.get("indicators") or []
    by_type = lambda *types: [i["indicator"] for i in indicators
                              if i.get("type") in types and i.get("indicator")]
    families = [m.get("display_name") if isinstance(m, dict) else m
                for m in pulse.get("malware_families") or []]
    targeted = [c for c in pulse.get("targeted_countries") or [] if isinstance(c, str)]
    country = focus.get().country
    in_focus = bool(country) and (extraction.focus_relevance > focus.RELEVANT
                                  or country in {c.lower() for c in targeted})
    return {
        "malware_hashes": by_type(*_OTX_HASHES)[:50],
        "ip_addresses": by_type("IPv4", "IPv6")[:100],
        "domains": by_type("domain", "hostname")[:100],
        "urls": by_type("URL")[:20],
        "threat_actor": extraction.threat_actor or (pulse.get("adversary") or "").strip(),
        "malware_family": extraction.malware_family or (families[0] if families else ""),
        "target_country": country if in_focus else (targeted[0].lower() if targeted else ""),
        # Every targeted country and family, so nothing is lost to the single
        # target_country column.
        "tags": list(dict.fromkeys((pulse.get("tags") or [])
                                   + [f"target:{c}" for c in targeted]
                                   + [f"family:{f}" for f in families if f])),
    }


def backfill_otx_indicators(api_key: str, store, limit: int = 200) -> int:
    """Re-fetch stored OTX pulses that came in without indicators, fill in
    their IOCs, actor and targeting, and queue their IPs for enrichment."""
    headers = {"X-OTX-API-KEY": api_key}
    done = 0
    for row in store.get_otx_without_indicators(limit):
        pulse = _otx_pulse_detail(row["source_url"].rstrip("/").rsplit("/", 1)[-1], headers)
        if not pulse:
            continue
        text = f"{pulse.get('name', '')} {pulse.get('description', '')} {' '.join(pulse.get('tags') or [])}"
        store.update_signal_iocs(row["signal_id"], _otx_fields(pulse, extract_all(text)))
        done += 1
    return done


def collect_otx_pulses(api_key: str, search: str = "APT",
                       limit: int = 20) -> list[ThreatSignal]:
    """Search OTX for threat intel pulses."""
    if not api_key:
        print("[!] OTX: no API key set (DARKFEEDS_OTX_KEY)")
        return []

    print(f"[*] Collecting from OTX (search: '{search}')...")
    headers = {"X-OTX-API-KEY": api_key}
    url = (f"https://otx.alienvault.com/api/v1/search/pulses"
           f"?q={urllib.parse.quote(search)}&sort=-created&limit={limit}")

    data = _get_json(url, headers=headers)
    if not data or "results" not in data:
        print("[!] OTX: no results")
        return []

    signals = []
    for pulse in data["results"]:
        name = pulse.get("name", "")
        desc = pulse.get("description", "")
        tags = pulse.get("tags", [])
        text = f"{name} {desc} {' '.join(tags)}"

        extraction = extract_all(text)
        fields = _otx_fields(_otx_pulse_detail(pulse.get("id", ""), headers) or pulse, extraction)

        signal = ThreatSignal(
            signal_id=hashlib.sha256(pulse.get("id", name).encode()).hexdigest()[:16],
            signal_type=SignalType.THREAT_ACTOR if fields["threat_actor"]
                        else SignalType.GENERAL_INTEL,
            source=SignalSource.OTX,
            source_name="AlienVault OTX",
            source_url=f"https://otx.alienvault.com/pulse/{pulse.get('id', '')}",
            title=name,
            raw_text=desc[:2000],
            cve_ids=extraction.cve_ids,
            malware_hashes=fields["malware_hashes"],
            malware_family=fields["malware_family"],
            ip_addresses=fields["ip_addresses"],
            domains=fields["domains"],
            urls=fields["urls"],
            product_names=extraction.products,
            threat_actor=fields["threat_actor"],
            target_country=fields["target_country"],
            relevance_score=extraction.overall_score,
            tags=fields["tags"],
            confidence=Confidence.MEDIUM,
            posted_at=_parse_ts(pulse.get("created")),
        )
        signals.append(signal)

    print(f"[+] OTX [{search}]: {len(signals)} pulses collected")
    return signals


# ─────────────────────────────────────────────────────────────────────────

def _parse_ts(s) -> Optional[datetime]:
    if not s:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d",
                "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(str(s)[:19], fmt[:len(str(s)[:19])+2])
        except ValueError:
            continue
    return None
