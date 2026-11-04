"""Sandbox-detonation capture: fresh C2 / network indicators from malware runs.

Stage 1 of the capture -> pivot -> OPSEC-leak pipeline. When a sample detonates
in a sandbox, the run records every host it talks to. We pull that network set
and store it as indicators tagged ``kind="sandbox"`` with ``first_seen`` set to
the detonation time -- that timestamp is the freshness signal the rest of the
tool ranks on ("time since first seen in the wild").

Two backends, both optional and keyed, so the module degrades gracefully:
  * VirusTotal  (DARKFEEDS_VT_KEY) -- per-sample contacted IPs/domains/URLs.
    Works today; no "recent detonations" feed on the public tier, so recent()
    returns not_configured for VT.
  * ANY.RUN     (ANYRUN_API_KEY)   -- public task feed + per-task report, which
    gives a near-real-time stream of fresh detonations. API access is paid-tier
    only; a free Community account issues no key, so this backend stays dark
    for most users.
  * Hybrid Analysis (HYBRIDANALYSIS_API_KEY) -- Falcon Sandbox. A free key on a
    registered account, and the best of the three for this stage: it returns a
    real detonation's own network set (hosts, domains, DNS) plus a 24h feed of
    recent submissions, so it serves both discovery and capture.
  * MalwareBazaar (DARKFEEDS_ABUSECH_KEY) -- discovery fallback for recent():
    newest submitted samples (hash + family + first_seen). It has no network
    data of its own, so each hash is handed to the VirusTotal path above to get
    the contacted hosts. Free Auth-Key from auth.abuse.ch.

Nothing here claims the C2's hosting location is the operator's location; this
stage only captures what the sample touched. Attribution lives in Stage 3.
"""
from __future__ import annotations

import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Optional

from .verify import _env, _http_json

_UA = {"User-Agent": "groundtrace/0.1 (research tool)"}
_ANYRUN = "https://api.any.run/v1"
_HA = "https://www.hybrid-analysis.com/api/v2"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _ts_to_day(ts) -> str:
    """Epoch seconds or ISO string -> YYYY-MM-DD (UTC); '' when unparseable."""
    if not ts:
        return ""
    try:
        if isinstance(ts, (int, float)):
            return time.strftime("%Y-%m-%d", time.gmtime(ts))
        s = str(ts).replace("Z", "+00:00")
        return datetime.fromisoformat(s).astimezone(timezone.utc).strftime("%Y-%m-%d")
    except (ValueError, OSError):
        return ""


def hours_since(day_or_iso: str) -> Optional[float]:
    """Age in hours of a first_seen value; None when it can't be parsed."""
    d = _ts_to_day(day_or_iso) if "T" in (day_or_iso or "") else (day_or_iso or "")
    if not d:
        return None
    try:
        then = datetime.strptime(d, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return round((datetime.now(timezone.utc) - then).total_seconds() / 3600, 1)


# --------------------------------------------------------------------------- #
# VirusTotal backend
# --------------------------------------------------------------------------- #
def _vt_get(path: str):
    key = _env("DARKFEEDS_VT_KEY")
    if not key:
        return None
    from darkfeeds import virustotal as vt
    try:
        return vt._get(path, key)
    except RuntimeError:
        return None


def _capture_vt(sample_hash: str) -> Optional[dict]:
    meta = _vt_get(f"/files/{urllib.parse.quote(sample_hash)}")
    if meta is None:
        return None
    a = (meta.get("data") or {}).get("attributes") or {}
    cls = a.get("popular_threat_classification") or {}
    family = cls.get("suggested_threat_label") or ""
    detonated = _ts_to_day(a.get("first_submission_date"))
    c2: list[dict] = []

    def _pull(rel: str, t: str, field: str = "id"):
        data = _vt_get(f"/files/{urllib.parse.quote(sample_hash)}/{rel}?limit=40")
        for item in (data or {}).get("data", []) or []:
            val = item.get(field) if field == "id" else (item.get("attributes") or {}).get(field)
            if val:
                c2.append({"value": val, "type": t})

    _pull("contacted_ips", "ip")
    _pull("contacted_domains", "domain")
    _pull("contacted_urls", "url", field="url")
    return {
        "hash": sample_hash.lower(),
        "family": family,
        "verdict": "malicious" if (a.get("last_analysis_stats") or {}).get("malicious") else "",
        "detonated_at": detonated,
        "source": "sandbox",
        "c2": _dedupe(c2),
        "payloads": [],
    }


# --------------------------------------------------------------------------- #
# ANY.RUN backend
# --------------------------------------------------------------------------- #
def _anyrun_get(path: str, timeout: int = 20):
    key = _env("ANYRUN_API_KEY")
    if not key:
        return None
    req = urllib.request.Request(_ANYRUN + path, headers={**_UA, "Authorization": f"API-Key {key}"})
    status, data = _http_json(req, timeout=timeout)
    return data if status == 200 else None


def _parse_anyrun_report(report: dict, task_id: str = "") -> dict:
    d = report.get("data") or report
    net = d.get("network") or {}
    c2: list[dict] = []
    for conn in net.get("connections") or []:
        ip = conn.get("ip") or conn.get("destinationIp")
        if ip:
            c2.append({"value": ip, "type": "ip"})
    for dns in net.get("dns") or net.get("dnsRequests") or []:
        dom = dns.get("domain") or dns.get("reversedIp")
        if dom:
            c2.append({"value": dom, "type": "domain"})
    for http in net.get("httpRequests") or net.get("http") or []:
        url = http.get("url")
        if url:
            c2.append({"value": url, "type": "url"})
    analysis = d.get("analysis") or {}
    threat = (analysis.get("scores") or {}).get("verdict") or {}
    detonated = _ts_to_day(analysis.get("creation") or analysis.get("date") or d.get("date"))
    fam = ""
    for inc in d.get("incidents") or []:
        if inc.get("mitre") or inc.get("threatLevel"):
            fam = inc.get("title", "") or fam
    return {
        "hash": (d.get("sample") or {}).get("hashes", {}).get("sha256", "").lower(),
        "family": (threat.get("threatLevelText") or fam or "")[:80],
        "verdict": (threat.get("threatLevelText") or "").lower(),
        "detonated_at": detonated,
        "source": "sandbox",
        "task_id": task_id,
        "c2": _dedupe(c2),
        "payloads": [],
    }


def recent(limit: int = 30) -> dict:
    """Newest detonations/submissions, newest-first.

    ANY.RUN's task feed is the richest source but needs a paid-tier key. When
    that is absent we fall back to MalwareBazaar's recent submissions, which
    gives the same thing the dashboard needs -- fresh hashes to capture from.
    VT has no public "recent" feed of its own.
    """
    if not _env("ANYRUN_API_KEY"):
        for backend, name in ((_ha_recent, "hybridanalysis"), (_mb_recent, "malwarebazaar")):
            runs = backend(limit)
            if runs:
                return {"status": "ok", "source": name, "runs": runs}
            if runs == []:                      # configured but empty: not an outage
                return {"status": "ok", "source": name, "runs": []}
        return {"status": "not_configured", "runs": []}
    data = _anyrun_get(f"/analysis?limit={int(limit)}")
    if data is None:
        for backend, name in ((_ha_recent, "hybridanalysis"), (_mb_recent, "malwarebazaar")):
            runs = backend(limit)
            if runs:
                return {"status": "ok", "source": name, "runs": runs}
        return {"status": "error", "runs": []}
    runs = []
    for task in (data.get("data") or {}).get("tasks") or data.get("tasks") or []:
        tid = task.get("uuid") or task.get("id") or ""
        runs.append({
            "task_id": tid,
            "name": (task.get("name") or task.get("file") or "")[:120],
            "verdict": ((task.get("verdict") or {}).get("threatLevelText")
                        if isinstance(task.get("verdict"), dict) else task.get("verdict")) or "",
            "detonated_at": _ts_to_day(task.get("date") or task.get("creation")),
        })
    return {"status": "ok", "source": "anyrun", "runs": runs}


# --------------------------------------------------------------------------- #
# Hybrid Analysis backend (Falcon Sandbox)
# --------------------------------------------------------------------------- #
def _ha_req(path: str, form: Optional[dict] = None):
    """Falcon Sandbox demands the literal User-Agent below; without it the API
    rejects the request regardless of the key."""
    key = _env("HYBRIDANALYSIS_API_KEY")
    if not key:
        return None
    headers = {"api-key": key, "User-Agent": "Falcon Sandbox", "Accept": "application/json"}
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(_HA + path, data=data, headers=headers,
                                 method="POST" if form is not None else "GET")
    status, body = _http_json(req, timeout=25)
    return body if status == 200 else None


def _ha_hosts(rep: dict) -> list[dict]:
    """Network set from a report. Field names vary across report shapes, so
    every known spelling is tried and the result de-duplicated."""
    c2: list[dict] = []
    for ip in rep.get("hosts") or []:
        if isinstance(ip, str):
            c2.append({"value": ip, "type": "ip"})
    for host in rep.get("compromised_hosts") or []:
        if isinstance(host, str):
            c2.append({"value": host, "type": "ip" if host.count(".") == 3 else "domain"})
    for dom in rep.get("domains") or []:
        if isinstance(dom, str):
            c2.append({"value": dom, "type": "domain"})
    for d in rep.get("dns_requests") or []:
        dom = d.get("domain") if isinstance(d, dict) else d
        if dom:
            c2.append({"value": dom, "type": "domain"})
    for h in rep.get("http_requests") or []:
        if isinstance(h, dict):
            url = h.get("url") or ""
            host = h.get("host") or ""
            if url:
                c2.append({"value": url, "type": "url"})
            if host:
                c2.append({"value": host, "type": "domain"})
    return _dedupe(c2)


def _report_ids(rep: dict) -> list[str]:
    """Job ids for a sample's detonations. The API returns these as bare
    strings in `reports` / `related_reports`, not objects."""
    out: list[str] = []
    for key in ("reports", "related_reports"):
        for r in rep.get(key) or []:
            rid = r if isinstance(r, str) else (r.get("job_id") or r.get("id") or "")
            if rid and rid not in out:
                out.append(str(rid))
    return out


def _capture_ha(sample_hash: str) -> Optional[dict]:
    """Network set for one sample.

    /overview carries the verdict and family but never the network data; that
    lives on each detonation's /report/{job_id}/summary. A sample can have
    several detonations (different OS images) and only some will have touched
    the network, so each is tried until one yields hosts.
    """
    rep = _ha_req(f"/overview/{urllib.parse.quote(sample_hash)}")
    if not isinstance(rep, dict) or not rep:
        return None
    c2: list[dict] = []
    for rid in _report_ids(rep)[:4]:
        sub = _ha_req(f"/report/{urllib.parse.quote(rid)}/summary")
        if isinstance(sub, dict) and sub:
            c2 = _ha_hosts(sub)
            if c2:
                break
    return {
        "hash": (rep.get("sha256") or sample_hash).lower(),
        "family": (rep.get("vx_family") or "")[:80],
        "verdict": rep.get("verdict") or "",
        "detonated_at": _ts_to_day(rep.get("analysis_start_time") or rep.get("submitted_at")),
        "source": "hybridanalysis",
        "c2": c2,
        "payloads": [],
    }


def _ha_recent(limit: int) -> Optional[list[dict]]:
    """Hybrid Analysis feed of the last 24h. None when unconfigured/failing."""
    body = _ha_req("/feed/latest")
    if not isinstance(body, dict):
        return None
    runs = []
    for s in (body.get("data") or [])[:limit]:
        h = (s.get("sha256") or "").lower()
        if not h:
            continue
        runs.append({
            "task_id": s.get("job_id") or "",
            "hash": h,
            "name": (s.get("submit_name") or s.get("last_file_name") or h[:16])[:120],
            "family": s.get("vx_family") or "",
            "verdict": s.get("threat_level_human") or s.get("verdict") or "",
            "detonated_at": _ts_to_day(s.get("analysis_start_time")),
            "source": "hybridanalysis",
            "url": f"https://www.hybrid-analysis.com/sample/{h}",
        })
    return runs


# --------------------------------------------------------------------------- #
# MalwareBazaar backend (discovery only)
# --------------------------------------------------------------------------- #
def _mb_recent(limit: int) -> Optional[list[dict]]:
    """Newest MalwareBazaar submissions. None when unconfigured or failing.

    MalwareBazaar records that a sample exists, not what it talked to; the
    hashes it returns are the input to capture(), which pulls the network set.
    """
    from .verify import _abusech
    code, body = _abusech("https://mb-api.abuse.ch/api/v1/",
                          {"query": "get_recent", "selector": "time"}, as_json=False)
    if code == -1:
        return None
    if not isinstance(body, dict) or body.get("query_status") != "ok":
        return []
    runs = []
    for s in (body.get("data") or [])[:limit]:
        h = (s.get("sha256_hash") or "").lower()
        if not h:
            continue
        runs.append({
            "task_id": "",
            "hash": h,
            "name": (s.get("file_name") or h[:16])[:120],
            "family": s.get("signature") or "",
            "verdict": s.get("signature") or "",
            "detonated_at": _ts_to_day(s.get("first_seen")),
            "source": "malwarebazaar",
            "url": f"https://bazaar.abuse.ch/sample/{h}/",
        })
    return runs


# --------------------------------------------------------------------------- #
# public API
# --------------------------------------------------------------------------- #
def _dedupe(rows: list[dict]) -> list[dict]:
    seen, out = set(), []
    for r in rows:
        k = (r["value"], r["type"])
        if k not in seen:
            seen.add(k)
            out.append(r)
    return out


def capture(sample_or_task: str) -> Optional[dict]:
    """Network indicators from one detonation.

    Accepts a file hash (VT, or ANY.RUN search) or an ANY.RUN task id.
    Returns None when neither backend is configured or has the sample.
    """
    sample_or_task = (sample_or_task or "").strip()
    if not sample_or_task:
        return None
    # ANY.RUN task id (uuid-ish, not a hash length)
    if _env("ANYRUN_API_KEY") and "-" in sample_or_task and len(sample_or_task) not in (32, 40, 64):
        rep = _anyrun_get(f"/analysis/{urllib.parse.quote(sample_or_task)}")
        if rep:
            return _parse_anyrun_report(rep, sample_or_task)
    # Hybrid Analysis first: its network set is one real detonation's, whereas
    # VT aggregates every submission's contacts (benign CDN/OS noise included).
    cap = _capture_ha(sample_or_task)
    if cap and cap["c2"]:
        return cap
    return _capture_vt(sample_or_task) or cap


def to_rows(cap: dict, group_key: str = "", keep_benign: bool = False) -> list[dict]:
    """A capture -> ioc_store rows (kind='sandbox'). first_seen = detonation day.

    Provider-operated infrastructure (OS update checks, OCSP responders, public
    resolvers, CDN edges) is dropped by default -- see groundtrace.benign for why
    and for what is deliberately kept. The dropped rows are recorded on the
    capture as ``cap["benign"]`` so a caller can show what was filtered rather
    than silently losing it. Pass keep_benign=True to disable the filter.
    """
    if not cap:
        return []
    day = cap.get("detonated_at") or _today()
    fam = cap.get("family") or ""
    ref = (f"https://www.virustotal.com/gui/file/{cap['hash']}"
           if cap.get("hash") else "")
    rows = []
    for ind in cap.get("c2") or []:
        rows.append({
            "value": ind["value"], "type": ind["type"],
            "group_key": group_key, "kind": "sandbox",
            "family": fam, "first_seen": day, "last_seen": day,
            "hits": 1, "url": ref,
        })
    if keep_benign:
        return rows
    from . import benign
    kept, dropped = benign.split(rows)
    cap["benign"] = dropped
    return kept


_UPSERT = """
INSERT INTO iocs (value, type, group_key, kind, family, first_seen, last_seen, hits, url)
VALUES (:value, :type, :group_key, :kind, :family, :first_seen, :last_seen, :hits, :url)
ON CONFLICT(value, type, group_key, kind) DO UPDATE SET
    hits       = hits + 1,
    last_seen  = MAX(last_seen, excluded.last_seen),
    first_seen = MIN(NULLIF(first_seen, ''), NULLIF(excluded.first_seen, '')),
    family     = CASE WHEN iocs.family = '' THEN excluded.family ELSE iocs.family END,
    url        = CASE WHEN iocs.url = '' THEN excluded.url ELSE iocs.url END
"""


def upsert(con, rows: list[dict]) -> int:
    """Insert sandbox rows incrementally (no wipe); bumps hits on repeat sightings."""
    n = 0
    for r in rows:
        con.execute(_UPSERT, r)
        n += 1
    con.commit()
    return n
