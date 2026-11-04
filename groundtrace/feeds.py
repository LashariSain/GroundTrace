"""
Threat-feed clients. Pure stdlib (urllib) so the tool runs with zero installs.

Sources:
  - NVD 2.0        : canonical CVE record, CWE, CVSS, references
  - CISA KEV       : is it *actually* being exploited?
  - EPSS (FIRST)   : probability it will be exploited in the next 30 days

All network calls are best-effort: on any failure they return None/empty so the
pipeline keeps working offline (e.g. against the bundled sample).
"""
from __future__ import annotations

import json
import re
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import date, datetime, timedelta
from typing import Optional

from .config import get_config

_UA = {"User-Agent": "groundtrace/0.1 (research tool)"}
_TIMEOUT = 20


class FeedUnavailable(RuntimeError):
    """A feed could not be *reached* (offline, timeout, rate-limited, bad
    response) — as opposed to a successful response that simply contained no
    such CVE. Callers use this to tell 'try again later' apart from 'no such
    CVE', which the old blanket `None` return could not express."""


class _RateLimiter:
    """Sliding-window token bucket — blocks (sleeps) rather than drops, so a
    free-tier budget is respected instead of getting the IP throttled/banned."""

    def __init__(self, max_calls: int, window_seconds: float):
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        self._calls: list[float] = []

    def acquire(self) -> None:
        now = time.monotonic()
        self._calls = [t for t in self._calls if now - t < self.window_seconds]
        if len(self._calls) >= self.max_calls:
            sleep_for = self.window_seconds - (now - self._calls[0])
            if sleep_for > 0:
                time.sleep(sleep_for)
            now = time.monotonic()
            self._calls = [t for t in self._calls if now - t < self.window_seconds]
        self._calls.append(time.monotonic())


_nvd_limiter: Optional[_RateLimiter] = None
# FIRST's EPSS API has no published hard limit, but it's a free shared
# service — be a polite, conservative citizen by default (2 req/s).
_epss_limiter = _RateLimiter(max_calls=2, window_seconds=1.0)

# Hard daily ceiling (config.max_daily_requests) — a circuit breaker so a
# large `recent` pull can't runaway-call a free-tier API all day.
_daily_count = 0
_daily_day: Optional[date] = None


def _nvd_rate_limit() -> None:
    global _nvd_limiter
    cfg = get_config()
    if _nvd_limiter is None:
        _nvd_limiter = _RateLimiter(cfg.nvd_tokens_per_window, cfg.nvd_window_seconds)
    _check_daily_budget()
    _nvd_limiter.acquire()


def _downgrade_nvd_to_keyless() -> None:
    """A rejected API key means we're actually on NVD's 5 req/30s public tier,
    not the 50/30s keyed tier the limiter was sized for in config. Re-size the
    limiter so follow-up pages are paced for keyless and don't get throttled."""
    global _nvd_limiter
    if _nvd_limiter is None or _nvd_limiter.max_calls > 5:
        _nvd_limiter = _RateLimiter(5, 30.0)


def _check_daily_budget() -> None:
    global _daily_count, _daily_day
    cfg = get_config()
    today = date.today()
    if _daily_day != today:
        _daily_day, _daily_count = today, 0
    if _daily_count >= cfg.max_daily_requests:
        raise RuntimeError(
            f"groundtrace: hit the daily request ceiling "
            f"({cfg.max_daily_requests}, set GROUNDTRACE_MAX_DAILY_REQUESTS to "
            f"raise it) — stopping to protect the free-tier API quota.")
    _daily_count += 1


def _get_json(url: str) -> Optional[dict]:
    try:
        req = urllib.request.Request(url, headers=_UA)
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return None


def _parse_date(s: str) -> Optional[date]:
    if not s:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s[:26] if "." in s else s[:19], fmt).date()
        except ValueError:
            continue
    try:
        return date.fromisoformat(s[:10])
    except ValueError:
        return None


def fetch_nvd(cve_id: str) -> Optional[dict]:
    """Return a normalized dict for one CVE from NVD.

    None means NVD was reachable but has no such *published* CVE (unknown id, or
    a reserved/embargoed one NVD hasn't ingested). Raises FeedUnavailable if NVD
    itself could not be reached (offline, timeout, or rate-limited) — so the two
    cases are no longer conflated into a single ambiguous None.
    """
    _nvd_rate_limit()
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    data = _get_json(url)
    if data is None:
        raise FeedUnavailable(f"could not reach NVD for {cve_id}")
    if not data.get("vulnerabilities"):
        return None
    return _normalize_cve(data["vulnerabilities"][0]["cve"])


def fetch_cve_registry(cve_id: str) -> Optional[dict]:
    """Look a CVE up in the CVE.org / MITRE registry (cveawg), which — unlike
    NVD — also carries RESERVED (allocated but not-yet-published) records.

    Returns {"state", "assigner", "title"} if the id is in the registry, None if
    it isn't (HTTP 404), or raises FeedUnavailable on a network error. Lets us
    tell a genuinely reserved/embargoed CVE apart from a non-existent id.
    """
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    try:
        req = urllib.request.Request(url, headers=_UA)
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            data = json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise FeedUnavailable(f"CVE registry returned HTTP {e.code} for {cve_id}")
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as e:
        raise FeedUnavailable(f"could not reach the CVE registry for {cve_id}: {e}")

    meta = data.get("cveMetadata", {})
    cna = data.get("containers", {}).get("cna", {})
    title = cna.get("title") or ""
    if not title:
        for d in cna.get("descriptions", []) or []:
            if d.get("value"):
                title = d["value"]
                break
    return {"state": meta.get("state"),
            "assigner": meta.get("assignerShortName"),
            "title": title}


def fetch_credits(cve_id: str) -> Optional[list[str]]:
    """CVE.org credits ("Vlad Stolyarov ... with assistance from Google Big
    Sleep"), each as "type: name". NVD drops this field, and it is where a CNA
    records who - or what - found the bug. None on failure, so it is retried."""
    data = _get_json(f"https://cveawg.mitre.org/api/cve/{cve_id}")
    if data is None:
        return None
    cna = (data.get("containers") or {}).get("cna") or {}
    return [f"{c.get('type') or 'credit'}: {c['value']}"
            for c in cna.get("credits") or [] if c.get("value")]


def fetch_credits_bulk(cve_ids: list[str], workers: int = 8) -> dict[str, list[str]]:
    """Credits for many CVEs; cveawg has no batch endpoint, so a small thread
    pool keeps a 2,000-CVE backfill to minutes. Failed lookups are left out."""
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(fetch_credits, cve_ids)
    return {c: r for c, r in zip(cve_ids, results) if r is not None}


_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")
_TITLE_MAX = 120


def _synthesize_title(cve_id: str, description: str) -> str:
    """NVD's CVE record has no separate title field — only a (often long)
    description — so without this, every live-fetched Finding shows a blank
    title. Use the first sentence, truncated, as a stand-in."""
    if not description:
        return cve_id
    first = _SENTENCE_END.split(description.strip(), maxsplit=1)[0]
    if len(first) > _TITLE_MAX:
        first = first[:_TITLE_MAX].rsplit(" ", 1)[0] + "…"
    return f"{cve_id}: {first}"


def _normalize_cve(cve: dict) -> dict:
    cve_id = cve.get("id", "CVE-UNKNOWN")
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break

    cwes = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            if d.get("value", "").startswith("CWE-"):
                cwes.append(d["value"])

    cvss = severity = None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            m = metrics[key][0]["cvssData"]
            cvss = m.get("baseScore")
            severity = m.get("baseSeverity") or metrics[key][0].get("baseSeverity")
            break

    refs = [r.get("url") for r in cve.get("references", []) if r.get("url")]

    affected = _extract_affected(cve.get("configurations", []))

    return {
        "cve_id": cve_id,
        "title": _synthesize_title(cve_id, desc),
        "description": desc,
        "cwe_ids": sorted(set(cwes)),
        "cvss": cvss,
        "cvss_severity": severity,
        "published": _parse_date(cve.get("published", "")),
        "references": refs,
        "affected": affected,
    }


def _extract_affected(configurations: list[dict]) -> list[str]:
    """Pull vulnerable CPE criteria strings out of NVD's configurations tree.

    NVD nests these as configurations -> nodes -> cpeMatch. Only entries with
    vulnerable=True describe an affected product; the rest are context
    (e.g. "running on" platform matches) and are skipped.
    """
    seen: list[str] = []
    for config in configurations or []:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", True):
                    continue
                criteria = match.get("criteria")
                if not criteria:
                    continue
                version_range = _version_range_suffix(match)
                entry = criteria + version_range
                if entry not in seen:
                    seen.append(entry)
    return seen


def _version_range_suffix(match: dict) -> str:
    parts = []
    if "versionStartIncluding" in match:
        parts.append(f">={match['versionStartIncluding']}")
    if "versionStartExcluding" in match:
        parts.append(f">{match['versionStartExcluding']}")
    if "versionEndIncluding" in match:
        parts.append(f"<={match['versionEndIncluding']}")
    if "versionEndExcluding" in match:
        parts.append(f"<{match['versionEndExcluding']}")
    return f" ({', '.join(parts)})" if parts else ""


def _nvd_get_page(url: str, api_key: Optional[str]):
    """GET one NVD page. Returns (data | None, key_to_keep_using).

    A *wrong* API key must degrade to the slower keyless free tier, never make
    the whole pull silently return nothing: NVD answers 403/404 to a bad key, so
    on that we retry the request without the key and stop sending it thereafter.
    """
    for key in ([api_key, None] if api_key else [None]):
        req = urllib.request.Request(url, headers=dict(_UA, **({"apiKey": key} if key else {})))
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
                return json.loads(r.read().decode("utf-8")), key
        except urllib.error.HTTPError as e:
            if key and e.code in (403, 404):
                print(f"[feeds] NVD rejected the API key (HTTP {e.code}); "
                      f"falling back to keyless requests — set a valid "
                      f"GROUNDTRACE_NVD_API_KEY or leave it blank.", file=sys.stderr)
                _downgrade_nvd_to_keyless()  # we're really on the 5/30s tier now
                continue  # retry this same page without the key
            return None, api_key
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
            return None, api_key
    return None, None


def fetch_nvd_range(
    start: date, end: date, *, api_key: Optional[str] = None,
    results_per_page: int = 2000, max_pages: int = 20,
    sleep_between_pages: float = 6.0,
) -> list[dict]:
    """Normalized dicts for every CVE *published* in [start, end] (inclusive).

    NVD caps a single query window at 120 days — 30 days is well within that.
    Paginates via startIndex; without an API key NVD allows 5 req/30s, so we
    sleep between pages by default (pass a shorter sleep if you have a key).
    Best-effort: returns whatever pages succeeded if a later page fails.
    """
    if (end - start).days > 120:
        raise ValueError("NVD date range is limited to 120 days per query")

    base = ("https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?pubStartDate={start.isoformat()}T00:00:00.000"
            f"&pubEndDate={end.isoformat()}T23:59:59.999"
            f"&resultsPerPage={results_per_page}")

    out: list[dict] = []
    start_index = 0
    use_key = api_key  # dropped to None below if NVD rejects it
    for page in range(max_pages):
        _nvd_rate_limit()
        url = f"{base}&startIndex={start_index}"
        data, use_key = _nvd_get_page(url, use_key)
        if data is None:
            break

        vulns = data.get("vulnerabilities", [])
        out.extend(_normalize_cve(v["cve"]) for v in vulns)

        total = data.get("totalResults", len(out))
        start_index += len(vulns)
        if not vulns or start_index >= total:
            break
        # Extra pacing between big pages, on top of the per-request rate
        # limiter — free tier is unforgiving of back-to-back large pages.
        time.sleep(sleep_between_pages)

    return out


def fetch_recent_cves(days: int = 30, *, api_key: Optional[str] = None) -> list[dict]:
    """Every CVE published in the last `days` days (default 30), up to today."""
    end = date.today()
    start = end - timedelta(days=days)
    return fetch_nvd_range(start, end, api_key=api_key)


def search_nvd(keyword: str, *, days: Optional[int] = None, limit: int = 50,
               api_key: Optional[str] = None) -> list[dict]:
    """Newest `limit` CVEs whose NVD record matches every word of `keyword`
    (NVD's keywordSearch: description, and vendor/product names), optionally
    only those published in the last `days` (max 120).

    NVD returns oldest-first with no sort option, so this reads the total from
    a first page and, if needed, fetches the last page: at most two requests.
    Raises FeedUnavailable if NVD can't be reached.
    """
    q = f"keywordSearch={urllib.parse.quote(keyword)}"
    if days:
        end = date.today()
        start = end - timedelta(days=min(days, 120))
        q += (f"&pubStartDate={start.isoformat()}T00:00:00.000"
              f"&pubEndDate={end.isoformat()}T23:59:59.999")
    base = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{q}&resultsPerPage={limit}"

    _nvd_rate_limit()
    data, key = _nvd_get_page(f"{base}&startIndex=0", api_key)
    if data is None:
        raise FeedUnavailable("NVD keyword search failed")
    total = data.get("totalResults", 0)
    if total > limit:
        _nvd_rate_limit()
        last, _ = _nvd_get_page(f"{base}&startIndex={total - limit}", key)
        if last is not None:
            data = last
    out = [_normalize_cve(v["cve"]) for v in data.get("vulnerabilities", [])]
    out.sort(key=lambda r: (r.get("published") or date.min), reverse=True)
    return out


def fetch_epss_bulk(cve_ids: list[str]) -> dict[str, float]:
    """EPSS for many CVEs at once (FIRST accepts comma-separated ids), so a
    50-CVE search costs one or two requests instead of fifty."""
    out: dict[str, float] = {}
    for i in range(0, len(cve_ids), 50):
        chunk = cve_ids[i:i + 50]
        _check_daily_budget()
        _epss_limiter.acquire()
        data = _get_json("https://api.first.org/data/v1/epss?cve=" + ",".join(chunk))
        for row in (data or {}).get("data", []):
            try:
                out[row["cve"]] = float(row["epss"])
            except (KeyError, ValueError, TypeError):
                pass
    return out


def fetch_epss_timeseries(cve_ids: list[str]) -> dict[str, list[tuple[str, float]]]:
    """Last ~30 days of EPSS per CVE, newest first, as [(date, epss)]. FIRST
    returns the current score plus a `time-series` list; both are merged."""
    out: dict[str, list[tuple[str, float]]] = {}
    for i in range(0, len(cve_ids), 50):
        chunk = cve_ids[i:i + 50]
        _check_daily_budget()
        _epss_limiter.acquire()
        data = _get_json("https://api.first.org/data/v1/epss?scope=time-series&cve=" + ",".join(chunk))
        for row in (data or {}).get("data", []):
            try:
                points = [(row["date"], float(row["epss"]))]
                points += [(p["date"], float(p["epss"])) for p in row.get("time-series", [])]
            except (KeyError, ValueError, TypeError):
                continue
            out[row.get("cve", "")] = sorted(set(points), reverse=True)
    return out


def fetch_epss(cve_id: str) -> Optional[float]:
    _check_daily_budget()
    _epss_limiter.acquire()
    data = _get_json(f"https://api.first.org/data/v1/epss?cve={cve_id}")
    if not data or not data.get("data"):
        return None
    try:
        return float(data["data"][0]["epss"])
    except (KeyError, ValueError, IndexError):
        return None


_kev_cache: Optional[set[str]] = None


_kev_entries: Optional[list[dict]] = None
_kev_fetched_at: float = 0.0


def load_kev_entries(*, force: bool = False) -> list[dict]:
    """Full CISA KEV catalog entries (cveID, vendorProject, product,
    vulnerabilityName, dateAdded, dueDate, knownRansomwareCampaignUse, ...).

    Cached, but only for `kev_sync_hours` (config) — a long-running watcher
    must see entries CISA adds while it's running. A failed refresh keeps
    serving the previous copy rather than reporting an empty catalog.
    """
    global _kev_entries, _kev_cache, _kev_fetched_at
    ttl = get_config().kev_sync_hours * 3600
    if not force and _kev_entries is not None and time.monotonic() - _kev_fetched_at < ttl:
        return _kev_entries
    _check_daily_budget()
    url = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
    data = _get_json(url)
    if data and data.get("vulnerabilities"):
        _kev_entries = data["vulnerabilities"]
        _kev_cache = {v["cveID"] for v in _kev_entries}
        _kev_fetched_at = time.monotonic()
    return _kev_entries or []


def load_kev() -> set[str]:
    """Set of CVE IDs on the CISA Known Exploited Vulnerabilities catalog."""
    load_kev_entries()
    return _kev_cache or set()
