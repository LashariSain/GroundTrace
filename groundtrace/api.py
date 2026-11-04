"""
REST API over the findings store and darkfeeds signals (stdlib only).

  python -m groundtrace serve [--host 127.0.0.1] [--port 8080]

Endpoints (all JSON):
  GET  /health
  GET  /stats
  GET  /findings?severity=&kev=1&since=YYYY-MM-DD&min_risk=&q=&limit=
  GET  /                           analyst dashboard (static page; data calls need the key)
  GET  /findings/<CVE-ID>          full record + score history + underground signals
  GET  /runs?limit=
  GET  /alerts?limit=              delivered alerts
  GET  /metrics                    store/alert counts, last watch cycle + step errors
  GET  /malware                    malware families in the collected data
  GET  /overview                   dashboard totals: families, sources, runs, indicators
  POST /analyze/<CVE-ID>           live NVD/KEV/EPSS analysis, saved to store
  POST /recent?days=&min_severity=&max_cves=&epss=   pull latest published CVEs
  GET  /websearch/<CVE-ID>         web results (DuckDuckGo) when a CVE isn't in NVD
  POST /search/nvd?q=&days=        pull newest NVD CVEs matching a keyword into the store
  GET|POST|DELETE /watchlist?term= keywords the watcher alerts on
  GET  /pocs/<CVE-ID>              public PoC links (GitHub, Exploit-DB…) with red flags; never downloaded
  GET  /signals?priority=&country=&actor=&source=&min_score=&limit=   (darkfeeds)
  GET  /geo                        threat map: per-country profiles + key findings
  GET  /radar, POST /radar         non-KEV CVEs ranked by gathered evidence; no forecast (POST recomputes)
  GET  /claims?q=&history=         every claim made about an indicator, with its
                                   evidence, measured reliability and falsifier

Auth: if GROUNDTRACE_API_KEY is set, every request except /health must send it
as `X-API-Key`. If it's not set, the server refuses to bind to anything but
localhost — an unauthenticated API must never be reachable from the network.
"""
from __future__ import annotations

import hmac
import json
from datetime import datetime, timezone
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import parse_qs, unquote, urlparse

from .config import get_config
from .store import FindingStore

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}

# MIME types for static assets served from groundtrace/static/.
_MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
    ".woff": "font/woff",
    ".ttf": "font/ttf",
    ".json": "application/json",
    ".geojson": "application/json",
    ".jpg": "image/jpeg",
}


ARCGIS_VERSION = "4.34"

# What the API never reveals: which feeds the intelligence came from. Feed
# names and credit blocks are dropped, links to the sources' own index pages
# (ETDA cards, OTX pulses, MISP, ATT&CK group pages) are removed, and the
# sightings ledger's feed codes become generic evidence kinds. References to
# reports stay. Licence notices live once, in the dashboard's "Data licences".
_HIDDEN_KEYS = {"source", "source_name", "sources", "credit"}
# Index pages of the sources and the feeds' own entry pages (not reports).
_INDEX_PAGE = re.compile(r"apt\.etda\.or\.th|otx\.alienvault\.com|misp-project\.org|attack\.mitre\.org/groups"
                         r"|threatfox\.abuse\.ch|bazaar\.abuse\.ch|urlhaus\.abuse\.ch|ransomware\.live|ransomlook\.io", re.I)
# Free-text fields (alert details, radar evidence) naming a feed -> generic.
_FEED_TEXT = [
    (re.compile(r"https?://[^\s,;)]*(feedburner|bleepingcomputer|krebsonsecurity|thehackernews|securityweek|therecord|darkreading)[^\s,;)]*", re.I), "news feed"),
    (re.compile(r"https?://[^\s,;)]*cisa\.gov[^\s,;)]*", re.I), "CISA alerts"),
    (re.compile(r"AlienVault OTX|\bOTX\b", re.I), "threat-intel pulse"),
    (re.compile(r"PoC-in-GitHub", re.I), "public PoC index"),
    (re.compile(r"\bThreatFox\b|\bURLhaus\b", re.I), "IOC feed"),
    (re.compile(r"\bMalwareBazaar\b", re.I), "malware feed"),
    (re.compile(r"ransomlook(\.io)?|ransomware\.live", re.I), "leak-site tracker"),
    (re.compile(r"\bExploit-DB\b", re.I), "exploit archive"),
]
_TEXT_KEYS = {"detail", "evidence", "title", "summary"}


def _generic_text(t: str) -> str:
    for rx, repl in _FEED_TEXT:
        t = rx.sub(repl, t)
    return t
EVIDENCE_KIND = {"otx": "pulse", "etda": "operation", "ransomware": "leak-site", "mitre": "campaign",
                 "feed": "telemetry", "news": "news"}
_ARCHIVE_KIND = {"Exploit-DB": "Exploit archive", "Packet Storm": "Exploit archive",
                 "Metasploit": "Metasploit module", "Nuclei template": "Nuclei template"}


def _hide_sources(o, key: str = ""):
    if key == "explanation":  # risk factors cite NVD / FIRST / CISA: the scoring standards
        return o
    if isinstance(o, dict):
        if "last_seen_source" in o or "by_source" in o:  # sightings ledger -> generic kinds
            o = {**o, "last_seen_kind": EVIDENCE_KIND.get(o.get("last_seen_source"), "record"),
                 "by_kind": {EVIDENCE_KIND.get(k, "record"): v for k, v in (o.get("by_source") or {}).items()}}
            o.pop("last_seen_source", None); o.pop("by_source", None)
            if o.get("last_seen_url") and _INDEX_PAGE.search(o["last_seen_url"]):
                o["last_seen_url"] = ""
        if "etda" in o:  # the operations card: neutral name, no slug
            card = {k: v for k, v in (o.get("etda") or {}).items() if k not in ("slug", "url", "title")} if o.get("etda") else None
            o = {k: v for k, v in o.items() if k != "etda"}
            o["group_card"] = card
        if o.get("kind") == "archive" and o.get("name") in _ARCHIVE_KIND:
            o = {**o, "name": _ARCHIVE_KIND[o["name"]]}
        if "source" in o and o.get("source") in EVIDENCE_KIND and "day" in o:  # ledger evidence row
            o = {**o, "kind": EVIDENCE_KIND[o["source"]]}
        out = {}
        for k, v in o.items():
            if k in _HIDDEN_KEYS:
                continue
            if k in ("url", "source_url") and isinstance(v, str) and _INDEX_PAGE.search(v):
                continue
            out[k] = _generic_text(v) if k in _TEXT_KEYS and isinstance(v, str) else _hide_sources(v, k)
        return out
    if isinstance(o, list):
        return [_hide_sources(x, key) for x in o
                if not (isinstance(x, dict) and set(x) <= {"url", "description"} and _INDEX_PAGE.search(str(x.get("url", ""))))
                and not (isinstance(x, str) and x.startswith("http") and _INDEX_PAGE.search(x))]
    return o


def _arcgis_key() -> str:
    return os.environ.get("ARCGIS_API_KEY", "").strip()


# Public-domain NASA imagery, used for the 3D globe when no Esri key is set.
_GIBS = "https://gibs.earthdata.nasa.gov"


def _map3d() -> bool:
    """Is the 3D globe enabled?

    Two ways in, both explicit: an ARCGIS_API_KEY (Esri imagery), or
    GROUNDTRACE_MAP_3D=1 for the keyless NASA Blue Marble globe. Off by default,
    because turning it on lets the browser talk to a third party -- the same
    reason the CSP below allows nothing external otherwise.
    """
    if _arcgis_key():
        return True
    return os.environ.get("GROUNDTRACE_MAP_3D", "").strip().lower() in ("1", "true", "yes", "on")


def _csp() -> str:
    """Self-hosted by default. Only when the 3D globe is enabled does the
    policy also allow Esri's SDK, tiles, fonts and its blob: web workers, plus
    NASA's GIBS tiles when running keyless."""
    esri = ""
    if _map3d():
        esri = " https://js.arcgis.com https://*.arcgis.com https://*.arcgisonline.com"
        if not _arcgis_key():
            esri += " " + _GIBS
    return ("default-src 'self'; "
            f"style-src 'self' 'unsafe-inline'{esri}; "
            # 'wasm-unsafe-eval' lets ArcGIS compile its WebAssembly modules; it does
            # not re-enable JavaScript eval ('unsafe-eval' stays off).
            f"script-src 'self' 'unsafe-inline'{" 'wasm-unsafe-eval' https://js.arcgis.com" if esri else ''}; "
            f"img-src 'self' data:{esri + ' blob:' if esri else ''}; "
            f"font-src 'self'{esri}; "
            f"connect-src 'self'{esri}; "
            + (f"worker-src 'self' blob:{esri}; " if esri else "")
            + "frame-ancestors 'none'; base-uri 'none'")


def _age_hours(ts: str) -> float:
    try:
        dt = datetime.fromisoformat(ts)
    except (TypeError, ValueError):
        return float("inf")
    return (datetime.now(timezone.utc) - dt).total_seconds() / 3600


def _q(params: dict, key: str, cast=str, default=None):
    vals = params.get(key)
    if not vals or vals[0] == "":
        return default
    try:
        return cast(vals[0])
    except ValueError:
        raise _BadRequest(f"invalid value for {key!r}")


class _BadRequest(Exception):
    pass


class Handler(BaseHTTPRequestHandler):
    server_version = "groundtrace-api/0.1"
    api_key: Optional[str] = None
    db_path: str = ""  # set in serve(); one SQLite connection per request,
    store: FindingStore = None  # since requests run on separate threads

    # --- plumbing -----------------------------------------------------------
    def _send(self, status: int, body, hide_sources: bool = True) -> None:
        if hide_sources:
            body = _hide_sources(body)
        data = json.dumps(body, indent=2, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _authorized(self) -> bool:
        if not self.api_key:
            return True
        sent = self.headers.get("X-API-Key", "")
        return hmac.compare_digest(sent, self.api_key)

    def log_message(self, fmt, *args):  # one compact line per request
        sys.stderr.write(f"[api] {self.address_string()} {fmt % args}\n")

    def _dispatch(self, method: str) -> None:
        url = urlparse(self.path)
        parts = [p for p in url.path.split("/") if p]
        params = parse_qs(url.query)

        if parts == ["health"]:
            return self._send(200, {"status": "ok"})
        if method == "GET" and parts == []:
            return self._dashboard("home.html")
        if method == "GET" and parts == ["dashboard"]:
            return self._dashboard()
        # Serve any file under static/ (css, js, fonts, svg, images).
        if method == "GET" and len(parts) >= 2 and parts[0] == "static":
            return self._static_file("/".join(parts[1:]))
        if not self._authorized():
            return self._send(401, {"error": "missing or invalid X-API-Key"})

        try:
            if method == "GET" and parts == ["stats"]:
                return self._send(200, self.store.stats())

            if method == "GET" and parts == ["runs"]:
                return self._send(200, self.store.list_runs(_q(params, "limit", int, 20)))

            if method == "GET" and parts == ["findings"]:
                limit = min(_q(params, "limit", int, 50), 500)
                since = _q(params, "since")
                if since and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", since):
                    raise _BadRequest("since must be a date like 2026-01-31")
                filters = dict(
                    severity=_q(params, "severity"),
                    kev_only=_q(params, "kev") in ("1", "true", "yes"),
                    ai_only=_q(params, "ai") in ("1", "true", "yes"),
                    since=_q(params, "since"),
                    min_risk=_q(params, "min_risk", float),
                    search=_q(params, "q"), limit=limit)
                rows, matched_on = self.store.query(**filters), "text"
                if not rows and filters["search"]:
                    rows, matched_on = self.store.query(**filters, include_refs=True), "references"
                return self._send(200, {"count": len(rows), "results": rows,
                                        "matched_on": matched_on})

            if method == "GET" and len(parts) == 2 and parts[0] == "findings":
                cve = parts[1].upper()
                if not _CVE_RE.match(cve):
                    raise _BadRequest("not a CVE id")
                d = self.store.get(cve)
                if d is None:
                    return self._send(404, {"error": f"{cve} not in store",
                                            "hint": f"POST /analyze/{cve} to fetch it"})
                # Recompute from the stored inputs so older records get the
                # breakdown too, and the number always matches its explanation.
                from .models import Scores, explain_risk
                s = d.setdefault("scores", {})
                sc = Scores(cvss=s.get("cvss"), cvss_severity=s.get("cvss_severity"),
                            epss=s.get("epss"),
                            asset_criticality=s.get("asset_criticality", 1.0),
                            in_kev=bool(s.get("in_kev") or (d.get("disclosure") or {}).get("in_kev")))
                s["risk"] = sc.risk
                s["explanation"] = explain_risk(sc, cve)
                from .classify.ai_discovery import detect_ai_discovery
                disc = d.setdefault("discovery", {})
                disc["ai_found_by"], disc["ai_evidence"] = detect_ai_discovery(
                    d.get("description", ""), d.get("references") or [], d.get("credits"))
                d["history"] = self.store.history(cve)
                d["exploited_by"] = self._exploited_by(cve)
                d["likely_groups"] = self._likely(cve, d.get("affected"), {g["group"] for g in d["exploited_by"]})
                d["underground_signals"] = self._underground(cve)
                return self._send(200, d)

            if method == "GET" and parts == ["metrics"]:
                return self._metrics()

            if method == "GET" and parts == ["malware"]:
                return self._families()

            if method == "GET" and len(parts) == 2 and parts[0] == "malware":
                return self._malware(unquote(parts[1]), params)

            if method == "GET" and parts == ["overview"]:
                return self._overview()

            if method == "GET" and parts == ["alerts"]:
                from .alert_view import feed
                rows = [(a, self.store.get(a["key"].split(":")[-1].upper()))
                        for a in self.store.list_alerts(500)]
                return self._send(200, feed(rows, min(_q(params, "limit", int, 50), 500),
                                            _q(params, "all") in ("1", "true", "yes")))

            if method == "POST" and len(parts) == 2 and parts[0] == "analyze":
                return self._analyze(parts[1].upper())

            if method == "POST" and parts == ["recent"]:
                return self._recent(params)

            if method == "GET" and len(parts) == 2 and parts[0] == "websearch":
                cve = parts[1].upper()
                if not _CVE_RE.match(cve):
                    raise _BadRequest("not a CVE id")
                from .websearch import search_web
                return self._send(200, {"cve": cve, "results": search_web(cve)})

            if method == "GET" and len(parts) == 2 and parts[0] == "pocs":
                cve = parts[1].upper()
                if not _CVE_RE.match(cve):
                    raise _BadRequest("not a CVE id")
                from .poc import find_pocs
                stored = self.store.get(cve) or {}
                return self._send(200, find_pocs(cve, stored.get("references") or []))

            if method == "POST" and parts == ["search", "nvd"]:
                return self._search_nvd(params)

            if parts == ["watchlist"]:
                return self._watchlist(method, params)

            if method == "GET" and parts == ["radar"]:
                rows = self.store.get_radar(min(_q(params, "limit", int, 50), 200))
                for r in rows:  # documented past exploitation, labelled as such in the UI
                    r["likely_groups"] = self._likely(r["cve_id"])[:3]
                return self._send(200, {"count": len(rows), "results": rows,
                                        "computed_at": rows[0]["computed_at"] if rows else None})

            if method == "POST" and parts == ["radar"]:
                # Recompute now instead of waiting for the next watcher cycle.
                from .radar import compute_radar
                from darkfeeds.config import Config as DFConfig
                rows = compute_radar(self.store, DFConfig().db_path)
                return self._send(200, {"count": len(rows), "results": rows[:50]})

            if method == "GET" and parts == ["signals"]:
                return self._signals(params)

            if method == "GET" and parts == ["geo"]:
                from .geo import slim
                return self._send(200, slim(self._geo()))

            if method == "GET" and parts == ["config", "map"]:
                # Behind the API key like every endpoint. The ArcGIS key is a
                # browser key by design (Esri "public application" credential,
                # basemap privileges only, ideally referrer-restricted).
                key = _arcgis_key()
                return self._send(200, {"arcgis": bool(key), "arcgis_key": key or None,
                                        "three_d": _map3d(),
                                        "arcgis_version": ARCGIS_VERSION})

            if method == "GET" and parts == ["iocs", "search"]:
                from . import ioc_store
                q = (_q(params, "q") or "").strip()
                if not q or len(q) > 2048:
                    raise _BadRequest("give an indicator: IP, domain, URL, hash, email (defanged is fine)")
                con = ioc_store.connect()
                try:
                    res = ioc_store.search(con, q)
                finally:
                    con.close()
                status = {g["uuid"]: g for g in self._apts().get("groups", [])}
                for m in res["matches"]:
                    s_ = status.get(m["group"], {})
                    m.update({"status": s_.get("status", ""), "group_last_seen": s_.get("last_seen", "")})
                return self._send(200, res)

            if method == "GET" and parts == ["iocs", "related"]:
                # Correlation from our own data: same malware family, same
                # signals, same /24, hosting provider profile, DNS pivot.
                from . import ioc_store
                from darkfeeds.config import Config as DFConfig
                q = (_q(params, "q") or "").strip()
                if not q or len(q) > 2048:
                    raise _BadRequest("give an indicator")
                con = ioc_store.connect()
                try:
                    return self._send(200, ioc_store.related(con, q, DFConfig().db_path, self._geo()))
                finally:
                    con.close()

            if method == "GET" and parts == ["sandbox", "recent"]:
                # Fresh detonations (newest first). Freshness is the point.
                from . import anyrun
                limit = min(_q(params, "limit", int, 30), 100)
                res = anyrun.recent(limit)
                for r in res.get("runs", []):
                    r["age_hours"] = anyrun.hours_since(r.get("detonated_at", ""))
                return self._send(200, _hide_sources(res))

            if method == "GET" and parts == ["sandbox", "captured"]:
                # What we have already captured and kept: the sandbox-sourced
                # indicators in our own store, grouped per detonation.
                from . import anyrun, ioc_store
                limit = min(_q(params, "limit", int, 200), 500)
                con = ioc_store.connect()
                try:
                    samples = ioc_store.sandbox_captures(con, limit)
                finally:
                    con.close()
                for s in samples:
                    s["age_hours"] = anyrun.hours_since(s.get("detonated_at", ""))
                return self._send(200, _hide_sources({
                    "samples": samples,
                    "indicators": sum(s["count"] for s in samples),
                }))

            if method == "GET" and parts == ["sandbox", "capture"]:
                # Network indicators a single sample touched when it ran.
                from . import anyrun
                q = (_q(params, "q") or "").strip()
                if not q or len(q) > 128:
                    raise _BadRequest("give a file hash or sandbox task id")
                cap = anyrun.capture(q)
                if cap is None:
                    return self._send(404, {"error": "no detonation data for that sample",
                                            "hint": "needs a configured sandbox backend"})
                cap["age_hours"] = anyrun.hours_since(cap.get("detonated_at", ""))
                return self._send(200, _hide_sources(cap))

            if method == "GET" and parts == ["infra", "pivot"]:
                # External pivots: cert-transparency siblings, reverse DNS,
                # InternetDB, JARM -- the actor's footprint beyond our data.
                from . import infra
                q = (_q(params, "q") or "").strip()
                if not q or len(q) > 2048:
                    raise _BadRequest("give an indicator to pivot from")
                return self._send(200, _hide_sources(infra.pivot(q)))

            if method == "GET" and parts == ["infra", "match"]:
                # Which known group's infrastructure habits this indicator fits.
                from . import aptdb, fingerprint, ioc_store
                q = (_q(params, "q") or "").strip()
                if not q or len(q) > 2048:
                    raise _BadRequest("give an indicator")
                value, t = ioc_store.classify(q)
                if not t:
                    raise _BadRequest("not a recognised indicator")
                # strict by default: a named group needs two independent
                # habits. broad accepts one rare habit as a hunting lead and
                # says so in each result's verdict/reliability.
                mode = (_q(params, "mode") or "strict").strip().lower()
                if mode not in ("strict", "broad"):
                    raise _BadRequest("mode must be 'strict' or 'broad'")
                prints = self._footprints()
                hits = fingerprint.match(value, t, prints,
                                         aptdb._load()["by_uuid"], mode=mode)
                # Record what we told the caller. match() stays pure -- it takes
                # no connection and writes nothing -- so the ledger entry is
                # made here, where there is a database to write to.
                self._record_match_claims(value, t, hits)
                return self._send(200, _hide_sources(
                    {"value": value, "type": t, "defanged": ioc_store.defang(value, t),
                     "mode": mode, "matches": hits,
                     # So an empty result can say what was checked rather than
                     # rendering as a blank panel. Abstention is an answer and
                     # has to look like one.
                     "groups_checked": len(prints),
                     "threshold": (fingerprint.MIN_SCORE_STRICT if mode == "strict"
                                   else fingerprint.MIN_SCORE_BROAD),
                     "reliability": fingerprint.RELIABILITY[mode]["precision"],
                     "reliability_basis": fingerprint.RELIABILITY[mode]["basis"]}))

            if method == "GET" and parts == ["claims"]:
                # Everything the tool has claimed about one indicator, with the
                # evidence, the measured reliability, and what would disprove it.
                from . import claims, ioc_store
                q = (_q(params, "q") or "").strip()
                if not q or len(q) > 2048:
                    raise _BadRequest("give an indicator")
                value, t = ioc_store.classify(q)
                if not t:
                    raise _BadRequest("not a recognised indicator")
                history = str(_q(params, "history") or "").lower() in ("1", "true", "yes")
                con = ioc_store.connect()
                rows = claims.for_subject(con, value, t, include_superseded=history,
                                          limit=min(_q(params, "limit", int, 100), 500))
                return self._send(200, _hide_sources(
                    {"value": value, "type": t, "defanged": ioc_store.defang(value, t),
                     "include_superseded": history, "claims": rows}))

            if method == "GET" and parts == ["iocs", "verify"]:
                # Independent cross-check (VirusTotal, MalwareBazaar, CIRCL);
                # on demand only, cached for a day.
                from . import verify
                q = (_q(params, "q") or "").strip()
                if not q or len(q) > 2048:
                    raise _BadRequest("give a hash, IP, domain or URL")
                return self._send(200, verify.check(q, force=_q(params, "force") in ("1", "true")))

            if method == "GET" and len(parts) == 3 and parts[:2] == ["iocs", "group"]:
                return self._group_iocs(unquote(parts[2]).lower(), params)

            if method == "GET" and parts == ["apts", "graph"]:
                from . import aptdb
                g = aptdb.graph()
                return self._send(200, {"nodes": g["nodes"], "links": g["links"]}, hide_sources=False)

            if method == "GET" and parts == ["apts", "malware"]:
                from . import malware_stats
                s = malware_stats.summary()
                if s is None:
                    return self._send(404, {"error": "malware statistics not built yet; the watcher builds them"})
                return self._send(200, s)

            if method == "GET" and len(parts) == 3 and parts[:2] == ["apts", "sample"]:
                from . import malware_stats
                try:
                    hit = malware_stats.lookup(parts[2])
                except ValueError as e:
                    raise _BadRequest(str(e))
                return self._send(200, {"hash": parts[2].lower(), "known_apt_sample": bool(hit), **(hit or {})})

            if method == "GET" and parts == ["apts"]:
                return self._send(200, self._apts())

            if method == "GET" and len(parts) == 2 and parts[0] == "apts":
                from . import aptdb
                from darkfeeds.config import Config as DFConfig
                key = unquote(parts[1])
                if not re.fullmatch(r"[0-9a-fA-F-]{36}|name:[a-z0-9]{3,64}", key):
                    raise _BadRequest("not a group id")
                p = aptdb.profile(key.lower(), DFConfig().db_path)
                if p is None:
                    return self._send(404, {"error": "no such group in the catalog"})
                p["cves"] = self._group_cves(key.lower())
                fp = self._prints().get(key.lower())
                from . import apt_behavior
                p["behavior"] = apt_behavior.public(fp) if fp else None
                from . import ioc_store
                con = ioc_store.connect()
                try:
                    p["ioc_summary"] = ioc_store.summary_for_group(con, key.lower())
                finally:
                    con.close()
                return self._send(200, p)

            if method == "GET" and len(parts) == 2 and parts[0] == "geo":
                cc = parts[1].upper()
                if not re.fullmatch(r"[A-Z]{2}", cc):
                    raise _BadRequest("not a 2-letter country code")
                country = self._geo()["countries"].get(cc)
                if country is None:
                    return self._send(404, {"error": f"no infrastructure recorded for {cc}"})
                return self._send(200, {"cc": cc, **country})

            return self._send(404, {"error": "no such endpoint"})
        except _BadRequest as e:
            return self._send(400, {"error": str(e)})
        except Exception as e:
            return self._send(500, {"error": f"{type(e).__name__}: {e}"})

    def _handle(self, method: str):
        url = urlparse(self.path)
        parts = [p for p in url.path.split("/") if p]
        if parts == ["health"]:
            return self._send(200, {"status": "ok"})
        if method == "GET" and parts == []:
            return self._dashboard("home.html")
        if method == "GET" and parts == ["dashboard"]:
            return self._dashboard()
        # Serve any file under static/ (css, js, fonts, svg, images) without hitting DB
        if method == "GET" and len(parts) >= 2 and parts[0] == "static":
            return self._static_file("/".join(parts[1:]))

        db = self.db_path or get_config().db_path
        self.store = FindingStore(db)
        try:
            self._dispatch(method)
        finally:
            self.store.close()

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def do_DELETE(self):
        self._handle("DELETE")

    # --- endpoints with more logic -----------------------------------------
    def _analyze(self, cve: str):
        if not _CVE_RE.match(cve):
            raise _BadRequest("not a CVE id")
        from .pipeline import analyze_cve, missing_cve_reason
        from .feeds import FeedUnavailable
        try:
            finding = analyze_cve(cve)  # rate-limited + daily-capped in feeds.py
        except FeedUnavailable:
            return self._send(503, {"error": f"NVD is unreachable right now — "
                                    f"could not fetch {cve}. Please try again shortly."})
        if finding is None:
            # NVD was reachable but has no published record for this id.
            return self._send(404, {"error": missing_cve_reason(cve)})
        run_id = self.store.start_run("api", {"target": cve})
        self.store.save_findings([finding], run_id)
        self.store.finish_run(run_id, 1)
        return self._send(200, finding.to_dict())

    @staticmethod
    def _term(params: dict) -> str:
        term = " ".join((_q(params, "q", str, "") or _q(params, "term", str, "") or "").split())
        if not 2 <= len(term) <= 60 or not term.isprintable():
            raise _BadRequest("keyword must be 2-60 printable characters")
        return term

    def _search_nvd(self, params: dict):
        """Pull the newest NVD CVEs matching a keyword into the store, so the
        local search also covers CVEs nobody has fetched yet."""
        term = self._term(params)
        days = _q(params, "days", int, 0) or None
        if days is not None and not 1 <= days <= 120:
            raise _BadRequest("days must be between 1 and 120")
        from .pipeline import analyze_keyword
        from .feeds import FeedUnavailable
        resolved = None
        try:
            findings = analyze_keyword(term, days=days, limit=50)
            if not findings and not _CVE_RE.match(term.upper()):
                # A nickname ("PHP2Shell", "Log4Shell") is rarely in NVD's text.
                from .pipeline import analyze_cve, resolve_nickname
                resolved = resolve_nickname(term)
                findings = [f for f in (analyze_cve(c) for c in resolved["cves"]) if f]
        except FeedUnavailable:
            return self._send(503, {"error": "NVD is unreachable right now. Please try again shortly."})
        if findings:
            run_id = self.store.start_run("search", {"q": term, "days": days})
            new = self.store.save_findings(findings, run_id)
            self.store.finish_run(run_id, len(findings))
        else:
            new = 0
        return self._send(200, {"q": term, "fetched": len(findings), "new": new,
                                "cves": [f.cve_id for f in findings], "resolved": resolved})

    def _watchlist(self, method: str, params: dict):
        from .watch import baseline_watch_term
        if method == "GET":
            return self._send(200, {"terms": self.store.watch_terms()})
        if method == "POST":
            term = self._term(params)
            if len(self.store.watch_terms()) >= 25:
                raise _BadRequest("watchlist is limited to 25 terms")
            added = self.store.add_watch(term)
            seen = baseline_watch_term(self.store, term) if added else 0
            return self._send(200, {"term": term, "added": added, "already_matching": seen,
                                    "terms": self.store.watch_terms()})
        if method == "DELETE":
            removed = self.store.remove_watch(self._term(params))
            return self._send(200, {"removed": removed, "terms": self.store.watch_terms()})
        raise _BadRequest("use GET, POST or DELETE")

    _SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def _recent(self, params: dict):
        """Pull CVEs *published* in the last N days from NVD, analyze, save, and
        return a summary. Bounded (days/max_cves) so a UI click can't kick off
        an unbounded free-tier pull."""
        days = _q(params, "days", int, 7)
        if not 1 <= days <= 30:
            raise _BadRequest("days must be between 1 and 30")
        max_cves = _q(params, "max_cves", int, 50)
        if not 1 <= max_cves <= 200:
            raise _BadRequest("max_cves must be between 1 and 200")
        # Empty / "ALL" means no severity filter. This matters for a "latest
        # CVEs" pull: newly published CVEs are usually still "Awaiting Analysis"
        # with no CVSS yet, so any severity filter would drop the newest ones.
        sev_raw = (_q(params, "min_severity", str, "") or "").upper()
        min_severity = None
        if sev_raw and sev_raw != "ALL":
            if sev_raw not in self._SEVERITIES:
                raise _BadRequest(f"min_severity must be one of {', '.join(self._SEVERITIES)} or ALL")
            min_severity = sev_raw
        # EPSS adds one request per CVE; let the caller skip it for a faster pass.
        epss = _q(params, "epss", str, "1") not in ("0", "false", "no")

        from .pipeline import analyze_recent
        from .feeds import FeedUnavailable
        try:
            findings = analyze_recent(days=days, min_severity=min_severity,
                                      max_cves=max_cves, fetch_epss=epss)
        except FeedUnavailable:
            return self._send(503, {"error": "NVD is unreachable right now — "
                                    "could not pull recent CVEs. Please try again shortly."})
        run_id = self.store.start_run("api-recent",
                                      {"days": days, "min_severity": min_severity or "ALL",
                                       "max_cves": max_cves, "epss": epss})
        new = self.store.save_findings(findings, run_id)
        self.store.finish_run(run_id, len(findings))
        return self._send(200, {"pulled": len(findings), "new": new, "days": days,
                                "min_severity": min_severity or "ALL", "max_cves": max_cves,
                                "cves": [f.cve_id for f in findings]})

    def _static_file(self, rel_path: str):
        """Serve a file from the static/ directory.

        Path-traversal is blocked by resolving the path and checking it stays
        inside the static root.  Only known MIME types are served.
        """
        from pathlib import Path
        static_root = (Path(__file__).parent / "static").resolve()
        target = (static_root / rel_path).resolve()
        # is_relative_to, not a string prefix: "static_old/" also starts with "static".
        if not target.is_relative_to(static_root):
            return self._send(403, {"error": "forbidden"})
        if not target.is_file():
            return self._send(404, {"error": "not found"})
        suffix = target.suffix.lower()
        mime = _MIME_TYPES.get(suffix)
        if not mime:
            return self._send(403, {"error": "file type not served"})
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        # Cache fonts and images aggressively; CSS/JS for a short time.
        if suffix in (".woff2", ".woff", ".ttf", ".svg", ".png", ".ico", ".jpg", ".geojson")                 or "/vendor/" in rel_path.replace("\\", "/"):
            self.send_header("Cache-Control", "public, max-age=604800")
        else:
            self.send_header("Cache-Control", "public, max-age=60")
        self.end_headers()
        self.wfile.write(data)

    def _dashboard(self, name: str = "dashboard.html"):
        from pathlib import Path
        page = (Path(__file__).parent / "static" / name).read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        # Everything is self-hosted (Tailwind and fonts are vendored under
        # static/), so nothing may load from another origin. 'unsafe-inline'
        # is needed for the page's inline script and Tailwind's injected
        # styles; allowing https: here would let any website's script run.
        self.send_header("Content-Security-Policy", _csp())
        self.send_header("X-Content-Type-Options", "nosniff")
        # Always revalidate: a cached page kept showing removed buttons.
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(page)

    def _underground(self, cve: str) -> list[dict]:
        """darkfeeds signals mentioning this CVE: the CVE/dark-web join."""
        from darkfeeds.config import Config as DFConfig
        from .unified import _signals_for_cve
        try:
            rows = _signals_for_cve(cve, DFConfig().db_path)
        except Exception:
            return []
        keep = ("signal_id", "signal_type", "priority", "source", "source_name", "source_url",
                "title", "threat_actor", "target_country", "price", "collected_at")
        return [{k: r.get(k) for k in keep} for r in rows]

    @staticmethod
    def _alert_channels() -> dict:
        from . import notify
        chans = notify.channels()
        return {"configured": chans,
                "note": ("alerts are recorded and visible here, but no channel is "
                         "configured so none are sent anywhere" if not chans else "")}

    def _families(self):
        from darkfeeds.config import Config as DFConfig
        from darkfeeds.store import Store as DFStore
        df = DFStore(DFConfig().db_path)
        try:
            return self._send(200, {"families": df.families()})
        finally:
            df.close()

    def _malware(self, family: str, params: dict):
        """One family's page; format=txt downloads its network blocklist."""
        from datetime import date, timedelta
        from darkfeeds.config import Config as DFConfig
        from darkfeeds.store import Store as DFStore
        df = DFStore(DFConfig().db_path)
        try:
            p = df.family_profile(family)
        finally:
            df.close()
        if p is None:
            return self._send(404, {"error": f"no malware family profile for {family!r}"})
        ind = p["indicators"]
        if _q(params, "format") == "txt":
            # Older infrastructure is often reassigned to someone innocent.
            cutoff = (date.today() - timedelta(days=90)).isoformat()
            values = [i["value"] for t in ("ip", "domain", "url") for i in ind[t]
                      if i["last_seen"] >= cutoff]
            stem = re.sub(r"[^a-z0-9]+", "_", family.lower()).strip("_")
            head = f"# {family}: IPs, domains and URLs seen in the last 90 days. Review before blocking.\n"
            return self._send_file(head + "\n".join(values) + "\n",
                                   "text/plain; charset=utf-8", f"{stem}_blocklist.txt")
        p["indicator_counts"] = {t: len(v) for t, v in ind.items()}
        p["indicators"] = {t: v[:100] for t, v in ind.items()}
        from . import family_intel
        p["intel"] = family_intel.build(DFConfig().db_path, p)
        return self._send(200, p)

    def _overview(self):
        """Everything the dashboard's first screen needs that /geo doesn't cover."""
        from darkfeeds.config import Config as DFConfig
        from darkfeeds.store import Store as DFStore
        from . import aptdb, fingerprint, ioc_store
        df = DFStore(DFConfig().db_path)
        try:
            signals = df.overview()
        finally:
            df.close()
        con = ioc_store.connect()
        try:
            by_type = dict(con.execute("SELECT type, COUNT(*) FROM iocs GROUP BY type").fetchall())
        finally:
            con.close()
        hashes = sum(by_type.get(t, 0) for t in ("sha256", "sha1", "md5"))
        known = {t: by_type.get(t, 0) for t in ("domain", "url", "ip")}
        total = sum(by_type.values())
        return self._send(200, {
            "findings": self.store.stats(),
            "top_cves": self.store.query(limit=5),
            "signals": signals,
            "threat_groups": len(aptdb._load()["groups"]),
            "indicators": {**known, "hash": hashes, "total": total,
                           "other": total - hashes - sum(known.values())},
            "precision": {m: {"precision": fingerprint.RELIABILITY[m]["precision"],
                              **fingerprint.MEASURED_RATES[m]}
                          for m in fingerprint.RELIABILITY},
            "alert_volume": self.store.alert_volume(),
            "alert_channels": self._alert_channels(),
        })

    def _metrics(self):
        from darkfeeds.config import Config as DFConfig
        from darkfeeds.store import Store as DFStore
        cycle = self.store.last_run("watch-cycle", finished=True)
        if cycle:
            cycle["params"] = json.loads(cycle.get("params") or "{}")
        # An unfinished cycle newer than the last finished one is in progress,
        # unless it's so old the watcher must have died mid-cycle.
        running = self.store.last_run("watch-cycle")
        if running and (running.get("finished_at") or _age_hours(running["started_at"]) > 6):
            running = None
        try:
            df = DFStore(DFConfig().db_path)
            dark = df.get_stats()
            df.close()
        except Exception as e:
            dark = {"error": f"{type(e).__name__}: {e}"}
        return self._send(200, {
            "findings": self.store.stats(),
            "alerts_delivered": self.store.alert_counts(),
            # Delivered beside baselined: the alerts table is mostly rows that
            # were recorded on first sight and never sent, so its row count is
            # not alert volume and must not be read as such.
            "alert_volume": self.store.alert_volume(),
            # Which destinations are configured. Empty means alerts are
            # recorded and shown here but never leave the machine -- worth
            # stating plainly, because it looks identical to a quiet week.
            "alert_channels": self._alert_channels(),
            "last_watch_cycle": cycle,
            "running_watch_cycle": running,
            "last_cve_pull": self.store.last_run("watch") or self.store.last_run("recent"),
            "darkfeeds": dark,
        })

    _geo_cache: tuple[float, dict] = (0.0, {})

    def _geo(self) -> dict:
        """geo_summary scans every signal (~1 s); the map and the country it
        opens next ask within moments, so share one computation for a minute."""
        import time
        ts, data = Handler._geo_cache
        if time.time() - ts > 60 or not data:
            from .geo import geo_summary
            from darkfeeds.config import Config as DFConfig
            data = geo_summary(DFConfig().db_path)
            Handler._geo_cache = (time.time(), data)
        return data

    def _send_file(self, body: str, mime: str, filename: str) -> None:
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _group_iocs(self, key: str, params: dict):
        """A group's indicators as JSON, or as a download: txt (blocklist),
        csv, or stix (STIX 2.1 bundle). ?types=ip,domain  ?fresh=1"""
        from . import aptdb, ioc_store
        if not re.fullmatch(r"[0-9a-f-]{36}|name:[a-z0-9]{3,64}", key):
            raise _BadRequest("not a group id")
        fmt = (_q(params, "format") or "json").lower()
        types = {t for t in (_q(params, "types") or "").split(",") if t} or None
        fresh = _q(params, "fresh") in ("1", "true", "yes")
        con = ioc_store.connect()
        try:
            rows = ioc_store.group_iocs(con, key)
        finally:
            con.close()
        for r in rows:  # references to the feeds' own pages are not exported
            if r["url"] and _INDEX_PAGE.search(r["url"]):
                r["url"] = ""
        rows = [r for r in rows if (not types or r["type"] in types) and not (fresh and r["stale"])]
        g = aptdb._load()["by_uuid"].get(key) or {"uuid": key, "name": key[5:] if key.startswith("name:") else key, "aliases": []}
        stem = re.sub(r"[^A-Za-z0-9]+", "_", g["name"]).strip("_") or "group"
        if fmt == "txt":
            return self._send_file(ioc_store.to_txt(rows), "text/plain; charset=utf-8", f"{stem}_iocs.txt")
        if fmt == "csv":
            return self._send_file(ioc_store.to_csv(rows, g["name"]), "text/csv; charset=utf-8", f"{stem}_iocs.csv")
        if fmt == "stix":
            return self._send_file(json.dumps(ioc_store.to_stix(rows, g), indent=1), "application/stix+json", f"{stem}_iocs.stix.json")
        if fmt != "json":
            raise _BadRequest("format must be json, txt, csv or stix")
        return self._send(200, {"group": key, "count": len(rows), "results": rows[:1000]})

    _prints_cache: tuple[float, dict] = (0.0, {})

    def _prints(self) -> dict:
        """Behaviour fingerprints for every group with CVE links (10 min cache)."""
        import time
        ts, data = Handler._prints_cache
        if time.time() - ts > 600 or not data:
            from . import apt_behavior, apt_cve, aptdb, mitre
            con = apt_cve.connect()
            try:
                keys = [r[0] for r in con.execute("SELECT DISTINCT group_key FROM cve_links")]
                by = aptdb._load()["by_uuid"]

                def techniques(gk):
                    g = by.get(gk)
                    m = mitre.group_for([g["name"], *g["aliases"]]) if g else None
                    return m["techniques"] if m else []
                data = apt_behavior.build_all(con, self._kev_index(), keys, techniques)
            finally:
                con.close()
            Handler._prints_cache = (time.time(), data)
        return data

    _footprints_cache: tuple[float, dict] = (0.0, {})

    def _footprints(self) -> dict:
        """Infrastructure footprints for every attributed group (10 min cache)."""
        import time
        ts, data = Handler._footprints_cache
        if time.time() - ts > 600 or not data:
            from . import fingerprint, ioc_store
            con = ioc_store.connect()
            try:
                keys = [r[0] for r in con.execute("SELECT DISTINCT group_key FROM iocs WHERE group_key != ''")]
                data = fingerprint.build_all(con, keys)
            finally:
                con.close()
            Handler._footprints_cache = (time.time(), data)
        return data

    @staticmethod
    def _record_match_claims(value: str, t: str, hits: list[dict]) -> None:
        """Log footprint matches to the append-only ledger.

        Best-effort: a ledger write must never cost the caller their answer,
        so failures are logged and swallowed. Each claim carries a falsifier,
        which for a habit match is concrete -- the habits it rests on are
        named in the basis, and finding another group with them disproves it.
        """
        if not hits:
            return
        from . import claims, ioc_store
        con = None
        try:
            con = ioc_store.connect()
            for h in hits:
                shared = "; ".join(h.get("basis") or [])
                claims.record(
                    con, subject=value, subject_type=t, claim="resembles",
                    object=h["group"], object_label=h.get("group_name") or "",
                    basis=h.get("basis") or [], method="footprint",
                    score=h.get("score"), reliability=h.get("reliability"),
                    verdict=h.get("verdict") or "lead",
                    falsifier=(f"another group is found sharing these habits ({shared}), "
                               f"or this group is observed abandoning them; the match is "
                               f"habit similarity only and names no operator"))
        except Exception as e:                      # noqa: BLE001 - never block the response
            print(f"[claims] not recorded for {value}: {e}", file=sys.stderr)
        finally:
            if con is not None:
                con.close()

    def _likely(self, cve: str, cpes: Optional[list] = None, exclude: set = frozenset()) -> list[dict]:
        """Groups with documented CVEs against this CVE's vendor or product.

        A record of what these groups have exploited before, with the count in
        each result's `why`. It is not a forecast about this CVE: nothing here
        estimates whether any group will use it, and no reliability figure is
        attached because no such claim is being made.
        """
        from . import apt_behavior
        if cpes is None:
            stored = self.store.get(cve) or {}
            cpes = stored.get("affected")
        targets = apt_behavior.cve_products(cve, self._kev_index(), cpes)
        status = {g["uuid"]: g for g in self._apts().get("groups", [])}
        out = apt_behavior.likely_groups(self._prints(), targets, set(exclude))
        for x in out:
            s_ = status.get(x["group"], {})
            x.update({"name": s_.get("name", x["group"]), "country": s_.get("country", ""), "status": s_.get("status", "catalog")})
        return out

    def _kev_index(self) -> dict:
        try:
            from .feeds import load_kev_entries
            return {e.get("cveID"): e for e in load_kev_entries()}
        except Exception:
            return {}

    def _exploited_by(self, cve: str) -> list[dict]:
        """APT groups with evidence of exploiting this CVE, with how active
        each group is now (last seen, regions hit in the last 90 days)."""
        from . import apt_cve
        con = apt_cve.connect()
        try:
            groups = apt_cve.groups_for_cve(con, cve)
        finally:
            con.close()
        status = {g["uuid"]: g for g in self._apts().get("groups", [])}
        for g in groups:
            s = status.get(g["group"], {})
            g.update({"status": s.get("status", "catalog"), "last_seen": s.get("last_seen", ""),
                      "recent_ccs": s.get("recent_ccs", [])})
        return groups

    def _group_cves(self, group_key: str) -> list[dict]:
        """A group's CVEs with KEV status (and ransomware use) and, when the
        CVE is in our findings, its scores."""
        from . import apt_cve
        con = apt_cve.connect()
        try:
            cves = apt_cve.cves_for_group(con, group_key)
        finally:
            con.close()
        kev = self._kev_index()
        stored = {r["cve_id"]: r for r in self.store.conn.execute(
            f"SELECT cve_id, cvss, cvss_severity, epss, risk FROM findings WHERE cve_id IN ({','.join('?' * len(cves))})",
            [c["cve"] for c in cves]).fetchall()} if cves else {}
        for c in cves:
            k, f = kev.get(c["cve"]), stored.get(c["cve"])
            c.update({"in_kev": bool(k), "ransomware": bool(k and str(k.get("knownRansomwareCampaignUse", "")).lower() == "known"),
                      "product": f"{k.get('vendorProject', '')} {k.get('product', '')}".strip() if k else "",
                      "in_findings": bool(f), **({k2: f[k2] for k2 in ("cvss", "cvss_severity", "epss", "risk")} if f else {})})
        return cves

    _apts_cache: tuple[float, dict] = (0.0, {})

    def _apts(self) -> dict:
        import time
        ts, data = Handler._apts_cache
        if time.time() - ts > 60 or not data:
            from . import aptdb
            from darkfeeds.config import Config as DFConfig
            data = aptdb.summary(DFConfig().db_path)
            Handler._apts_cache = (time.time(), data)
        return data

    def _signals(self, params):
        from darkfeeds.config import Config as DFConfig
        from darkfeeds.store import Store as DFStore
        df = DFStore(DFConfig().db_path)
        try:
            rows = df.get_signals(
                priority=_q(params, "priority"), country=_q(params, "country"),
                actor=_q(params, "actor"), source=_q(params, "source"),
                known_actor=_q(params, "known_actor") in ("1", "true", "yes"),
                min_score=_q(params, "min_score", float, 0.0),
                limit=min(_q(params, "limit", int, 50), 500))
        finally:
            df.close()
        for r in rows:  # decode JSON-in-TEXT columns for API consumers
            for k in ("cve_ids", "malware_hashes", "ip_addresses", "domains", "urls",
                      "product_names", "tags", "ip_enrichment", "hash_enrichment"):
                if isinstance(r.get(k), str):
                    try:
                        r[k] = json.loads(r[k])
                    except json.JSONDecodeError:
                        pass
        return self._send(200, {"count": len(rows), "results": rows})


def serve(host: str = "127.0.0.1", port: int = 8080) -> None:
    api_key = os.environ.get("GROUNDTRACE_API_KEY")
    if not api_key and host not in _LOCAL_HOSTS:
        raise SystemExit(
            f"refusing to bind to {host} without auth — set GROUNDTRACE_API_KEY, "
            f"or bind to 127.0.0.1")

    Handler.api_key = api_key
    Handler.db_path = get_config().db_path
    FindingStore(Handler.db_path).close()  # create schema up front
    httpd = ThreadingHTTPServer((host, port), Handler)

    def _warm():
        # The first APT click after a restart otherwise pays ~5 s loading the
        # catalog, ETDA cards, the ATT&CK index and the signals scan.
        try:
            from . import aptdb, mitre
            from darkfeeds.config import Config as DFConfig
            aptdb.summary(DFConfig().db_path)
            aptdb.etda_card("")
            mitre._load()
            from . import apt_cve, ioc_store
            con = apt_cve.connect()
            if not con.execute("SELECT 1 FROM cve_links LIMIT 1").fetchone():
                apt_cve.rebuild(con, apt_cve.collect(DFConfig().db_path))
            con.close()
            con = ioc_store.connect()
            if not con.execute("SELECT 1 FROM iocs LIMIT 1").fetchone():
                ioc_store.rebuild(con, ioc_store.collect(signals_db=DFConfig().db_path))
            con.close()
        except Exception as e:  # warming is best effort
            print(f"[!] cache warm-up: {type(e).__name__}: {e}", file=sys.stderr)
    def _refs():
        try:
            from . import family_refs
            family_refs.refresh()
        except Exception as e:  # reference data is optional
            print(f"[!] family references: {type(e).__name__}: {e}", file=sys.stderr)
    import threading
    threading.Thread(target=_warm, daemon=True).start()
    threading.Thread(target=_refs, daemon=True).start()
    auth = "X-API-Key required" if api_key else "NO AUTH (localhost only)"
    print(f"[+] groundtrace API on http://{host}:{port}  ({auth})", file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
