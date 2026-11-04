"""
Scheduled collection + alerting.

  python -m groundtrace watch                 # loop forever, every 6h
  python -m groundtrace watch --once          # one cycle (for Task Scheduler / cron)

Each cycle:
  1. CISA KEV catalog  -> alert on newly added entries               (kev:<CVE>)
  2. NVD recent CVEs   -> saved to the findings store; optional alert on
                          new CRITICAL CVEs (--alert-critical)        (critical:<CVE>)
  3. watchlist terms   -> NVD keyword search; alert on new matches   (watch:<term>:<CVE>)
  4. darkfeeds collect -> alert on any CVE mentioned underground     (underground:<CVE>)
                          and on P1 signals                           (signal:<id>)
  5. radar             -> alert once on a checkable fact about a non-KEV CVE:
                          a PoC predating publication, EPSS at/above 0.9, or a
                          rise in EPSS this week                     (radar:<CVE>)

Alerts are deduplicated by key in the store's `alerts` table, so restarts
and overlapping windows never re-alert. The very first cycle is a baseline:
everything currently visible is recorded as seen and nothing is sent —
otherwise the first run would fire ~1,500 KEV alerts.
"""
from __future__ import annotations

import sys
import time
from datetime import date, datetime, timedelta, timezone

from .config import get_config
from .notify import Alert, send
from .store import FindingStore

# Delivery order when a cycle has more alerts than fit in one digest.
_KIND_ORDER = {"kev": 0, "exploitdb": 1, "sandbox": 2, "radar": 3, "geo": 4, "underground": 5, "watch": 6, "signal": 7, "critical": 8}
# KEV entries older than this that we somehow never saw (e.g. the watcher was
# offline for months) are recorded silently rather than alerted as "new".
_KEV_FRESH_DAYS = 30


def _log(msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"[watch {ts}Z] {msg}", file=sys.stderr)


def _kev_alerts() -> tuple[list[Alert], list[Alert], set[str]]:
    """Returns (fresh alerts, stale-but-unseen, set of all KEV CVE ids)."""
    from . import feeds
    entries = feeds.load_kev_entries(force=True)
    cutoff = date.today() - timedelta(days=_KEV_FRESH_DAYS)
    fresh, stale = [], []
    for e in entries:
        cve = e.get("cveID", "")
        added = e.get("dateAdded", "")
        ransomware = e.get("knownRansomwareCampaignUse", "") == "Known"
        a = Alert(
            key=f"kev:{cve}", kind="kev",
            title=f"{cve} added to CISA KEV (actively exploited)",
            detail=(f"{e.get('vendorProject', '')} {e.get('product', '')}: "
                    f"{e.get('vulnerabilityName', '')}; added {added}, "
                    f"federal due date {e.get('dueDate', '?')}"
                    + ("; used in ransomware campaigns" if ransomware else "")),
            url=f"https://nvd.nist.gov/vuln/detail/{cve}",
            data={"cve": cve, "dateAdded": added, "ransomware": ransomware})
        try:
            is_fresh = date.fromisoformat(added) >= cutoff
        except ValueError:
            is_fresh = True
        (fresh if is_fresh else stale).append(a)
    return fresh, stale, {e.get("cveID", "") for e in entries}


def backfill_epss(store: FindingStore) -> int:
    """Fill in EPSS for stored CVEs that lack it. The NVD pull skips per-CVE
    EPSS (one request each); without it risk falls back to the 0.1 default and
    an exploited CVE scores ~10 instead of ~100. FIRST's bulk endpoint makes
    this ~1 request per 50 CVEs. CVEs FIRST hasn't scored yet stay NULL and are
    retried next cycle."""
    from . import feeds
    return store.set_epss(feeds.fetch_epss_bulk(store.missing_epss()))


def backfill_credits(store: FindingStore, limit: int = 1000) -> int:
    """Fetch CVE.org credits (who/what found the bug) for stored CVEs lacking
    them; the AI-Found view relies on these. One request per CVE, so capped
    per cycle - a large store catches up over a few cycles."""
    from . import feeds
    return store.set_credits(feeds.fetch_credits_bulk(store.missing_credits(limit)))


def _cve_step(store: FindingStore, days: int, min_severity: str,
              alert_critical: bool) -> list[Alert]:
    from .pipeline import analyze_recent
    findings = analyze_recent(days=days, min_severity=min_severity, fetch_epss=False)
    run_id = store.start_run("watch", {"days": days, "min_severity": min_severity})
    new = store.save_findings(findings, run_id)
    store.finish_run(run_id, len(findings))
    _log(f"CVE pull: {len(findings)} {min_severity}+ CVE(s) in last {days}d, {new} new to store")
    _log(f"EPSS: filled in for {backfill_epss(store)} stored CVE(s)")
    _log(f"Credits: fetched for {backfill_credits(store)} stored CVE(s)")
    from . import exploitdb
    if exploitdb.refresh():  # daily; keeps the 10 MB download off the UI click path
        _log("Exploit-DB: index refreshed")
    from . import family_refs
    if family_refs.refresh():  # weekly
        _log("malware family references updated")
    from . import aptdb
    if aptdb.refresh():  # weekly, ~70 MB
        _log("APT catalog: refreshed from APTmap")
        from . import malware_stats
        _log(f"APT malware statistics: {malware_stats.refresh()}")  # only re-downloads if APTmap changed
    from darkfeeds.config import Config as DFConfig
    from . import apt_sightings
    df = DFConfig()
    _log(f"APT sightings: {apt_sightings.refresh_all(df.db_path, df.otx_api_key)}")
    from . import apt_cve
    con = apt_cve.connect()
    try:
        _log(f"APT-CVE links: {apt_cve.rebuild(con, apt_cve.collect(df.db_path))}")
    finally:
        con.close()
    from . import ioc_store
    con = ioc_store.connect()
    try:
        _log(f"IOC store: {ioc_store.rebuild(con, ioc_store.collect(signals_db=df.db_path))} indicators")
    finally:
        con.close()
    if not alert_critical:
        return []
    return [Alert(key=f"critical:{f.cve_id}", kind="critical",
                  title=f"New CRITICAL CVE {f.cve_id} (CVSS {f.scores.cvss})",
                  detail=(f.title or f.description)[:160],
                  url=f"https://nvd.nist.gov/vuln/detail/{f.cve_id}")
            for f in findings if (f.scores.cvss_severity or "").upper() == "CRITICAL"]


_MAX_WATCH_TERMS = 25  # each term costs 1-2 NVD requests per cycle


def _watch_alert(term: str, cve_id: str, title: str, severity, cvss, in_kev) -> Alert:
    sev = (severity or "severity pending") + (f" {cvss}" if cvss is not None else "")
    return Alert(key=f"watch:{term.lower()}:{cve_id}", kind="watch",
                 title=f"Watchlist '{term}': {cve_id} ({sev}{', on CISA KEV' if in_kev else ''})",
                 detail=(title or "")[:160],
                 url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                 data={"cve": cve_id, "term": term})


def baseline_watch_term(store: FindingStore, term: str) -> int:
    """Record what a new term already matches as seen, so adding 'microsoft'
    doesn't fire an alert for every Microsoft CVE in the store."""
    rows = store.query(search=term, limit=5000)
    alerts = [_watch_alert(term, r["cve_id"], r["title"], r["cvss_severity"], r["cvss"], r["in_kev"])
              for r in rows]
    store.record_alerts(alerts, None)
    return len(alerts)


def _watchlist_step(store: FindingStore, days: int) -> list[Alert]:
    from .pipeline import analyze_keyword
    terms = [t["term"] for t in store.watch_terms()][:_MAX_WATCH_TERMS]
    alerts: list[Alert] = []
    for term in terms:
        findings = analyze_keyword(term, days=max(days, 1), limit=50)
        if findings:
            run_id = store.start_run("watchlist", {"term": term, "days": days})
            store.save_findings(findings, run_id)
            store.finish_run(run_id, len(findings))
        alerts += [_watch_alert(term, f.cve_id, f.title, f.scores.cvss_severity,
                                f.scores.cvss, f.disclosure.in_kev) for f in findings]
    if terms:
        _log(f"watchlist: {len(terms)} term(s), {len(alerts)} match(es) in last {days}d")
    return alerts


def _exploitdb_step(store: FindingStore) -> tuple[list[Alert], list[Alert]]:
    """New exploits on exploit-db.com for CVEs we track (stored, or matching a
    watchlist term). Returns (fresh, silent): the step's first run only records
    the current listing as seen, so it doesn't alert on 50 old exploits."""
    from . import exploitdb
    rows = exploitdb.recent()
    if rows is None:
        raise RuntimeError("exploit-db.com listing unavailable")
    tracked = store.existing_cves(sorted({c for e in rows for c in e["cves"]}))
    terms = [t["term"].lower().split() for t in store.watch_terms()]
    alerts = []
    for e in rows:
        cves = [c for c in e["cves"] if c in tracked]
        title = e["title"].lower()
        term = next((" ".join(t) for t in terms if all(w in title for w in t)), None)
        if not cves and not term:
            continue
        why = f"for {', '.join(cves)}" if cves else f"matches watchlist '{term}'"
        alerts.append(Alert(
            key=f"exploitdb:{e['id']}", kind="exploitdb",
            title=f"New public exploit {why}"
                  + (" (verified)" if e["verified"] else ""),
            detail=f"{e['title']} · {e['type']} · {e['platform']} · {e['date']}"[:300],
            url=e["url"], data={"edb_id": e["id"], "cves": e["cves"]}))
    _log(f"Exploit-DB: {len(rows)} newest exploit(s), {len(alerts)} for tracked CVEs/terms")
    if not store.has_alerts("exploitdb"):
        return [], alerts
    return alerts, []


# Each capture costs ~4 VirusTotal calls and the free tier allows 4/min and
# 500/day, so only this many of the newest runs are enriched per cycle.
_SANDBOX_PER_CYCLE = 6


def _sandbox_step(store: FindingStore) -> tuple[list[Alert], list[Alert]]:
    """Fresh sandbox detonations: capture the network indicators each sample
    touched, store them (kind='sandbox', first_seen=detonation day), and alert
    when a run matches a watchlist term. Needs a sandbox backend with a live
    feed; a no-op (and silent) otherwise. First run records current runs only."""
    from . import anyrun, ioc_store
    feed = anyrun.recent(40)
    if feed.get("status") != "ok":
        _log(f"sandbox: {feed.get('status', 'unavailable')}")
        return [], []
    runs = feed["runs"]
    # Feeds are dominated by test uploads and clean binaries. When the backend
    # states a verdict (Hybrid Analysis does), spend the capture budget on the
    # samples it calls malicious first; runs without a verdict keep their place.
    _rank = {"malicious": 0, "suspicious": 1}
    runs = sorted(runs, key=lambda r: _rank.get((r.get("verdict") or "").lower(), 2))
    terms = [t["term"].lower().split() for t in store.watch_terms()]
    con = ioc_store.connect()
    alerts, captured = [], 0
    try:
        for r in runs[:_SANDBOX_PER_CYCLE]:
            # ANY.RUN gives a task id; the MalwareBazaar fallback gives a hash.
            cap = anyrun.capture(r.get("task_id") or r.get("hash") or "")
            if not cap:
                continue
            captured += anyrun.upsert(con, anyrun.to_rows(cap))
            name = (r.get("name", "") + " " + cap.get("family", "")).lower()
            term = next((" ".join(t) for t in terms if t and all(w in name for w in t)), None)
            if not term:
                continue
            c2 = ", ".join(i["value"] for i in cap.get("c2", [])[:4]) or "no network indicators"
            alerts.append(Alert(
                key=f"sandbox:{r.get('task_id') or r.get('hash', '')}", kind="sandbox",
                title=f"Fresh detonation matches watchlist '{term}'"
                      + (f" ({cap['family']})" if cap.get("family") else ""),
                detail=f"{r.get('name', 'sample')} · {r.get('detonated_at', '')} · C2: {c2}"[:300],
                data={"c2": [i["value"] for i in cap.get("c2", [])[:12]]}))
    finally:
        con.close()
    _log(f"sandbox: {len(runs)} recent run(s), {captured} indicator(s) captured, {len(alerts)} matched")
    if not store.has_alerts("sandbox"):
        return [], alerts
    return alerts, []


_GEO_SPIKE = 10  # new malicious IPs on one provider within a week


def _geo_step(store: FindingStore) -> tuple[list[Alert], list[Alert]]:
    """A hosting provider that gained many new malicious IPs this week: a
    campaign standing up infrastructure. One alert per provider per ISO week;
    the step's first run records the current state silently."""
    from datetime import date
    from darkfeeds.config import Config as DFConfig
    from .geo import geo_summary
    g = geo_summary(DFConfig().db_path)
    if not g.get("as_of"):
        return [], []
    year, week, _ = date.fromisoformat(g["as_of"]).isocalendar()
    alerts = []
    for cc, c in g["countries"].items():
        for p in c["providers"]:
            if p["new_7d"] < _GEO_SPIKE:
                continue
            what = ("likely a botnet wave on hijacked devices" if p["kind"] == "isp"
                    else "attacker infrastructure being stood up")
            biggest = p["clusters"][0] if p["clusters"] else None
            alerts.append(Alert(
                key=f"geo:{p['asn'] or p['name']}:{cc}:{year}-W{week:02d}", kind="geo",
                title=f"Hosting spike: {p['name']} (AS{p['asn']}, {cc}) gained {p['new_7d']} "
                      f"new malicious IPs this week (score {p['score']}/100)",
                detail=(f"{what}; " + ", ".join(p["families"])
                        + (f"; densest block {biggest['cidr']} ({biggest['ips']} IPs)" if biggest else ""))[:300],
                data={"asn": p["asn"], "cc": cc, "new_7d": p["new_7d"]}))
    _log(f"geo: {len(alerts)} provider(s) with {_GEO_SPIKE}+ new malicious IPs this week")
    if not store.has_alerts("geo"):
        return [], alerts
    return alerts, []


# Facts that justify waking someone, each independently checkable. A score
# threshold is not on this list: the old gate fired on score >= 60, which was
# unreachable, so this step had never produced an alert. An alert must name
# something that happened, not a number we invented.
_EPSS_ALERT = 0.9
# A rise only counts if it is big enough to mean something. Without a line
# here the trigger fired on changes of 0.0001 and alerted on 23 of 40
# candidates, which is the noise this tool is supposed to remove.
_EPSS_RISE_ALERT = 0.05


def _radar_triggers(e: dict) -> list[str]:
    """Why this entry is worth an alert, in plain terms. Empty means no alert."""
    why = []
    if e.get("poc_before_publication"):
        why.append("a public PoC existed before NVD published the CVE")
    epss = next((c for c in e["components"] if c["name"] == "EPSS level"), None)
    if epss and epss.get("available") and epss["points"] >= 35 * _EPSS_ALERT:
        why.append(f"FIRST puts exploitation probability at or above {_EPSS_ALERT:.0%}, "
                   f"and CISA has not listed it")
    mom = next((c for c in e["components"] if c["name"] == "EPSS momentum"), None)
    if mom and mom.get("available") and (mom.get("rise") or 0) >= _EPSS_RISE_ALERT:
        why.append(f"its exploitation probability rose {mom['rise']:+.3f} "
                   f"in the last 7 days")
    return why


def _radar_step(store: FindingStore) -> list[Alert]:
    from darkfeeds.config import Config as DFConfig
    from .radar import compute_radar
    entries = compute_radar(store, DFConfig().db_path)
    thin = sum(1 for e in entries if e["level"] == "insufficient")
    out = []
    for e in entries:
        why = _radar_triggers(e)
        if not why:
            continue
        out.append(Alert(
            key=f"radar:{e['cve_id']}", kind="radar",
            title=f"{e['cve_id']}: {why[0]} (not yet on CISA KEV)",
            detail=("; ".join(why) + ". Evidence: "
                    + "; ".join(c["evidence"] for c in e["components"]
                                if c["available"] and c["points"] > 0))[:300],
            url=f"https://nvd.nist.gov/vuln/detail/{e['cve_id']}",
            data={"cve": e["cve_id"], "score": e["score"],
                  "coverage": e["coverage"], "triggers": why}))
    _log(f"radar: {len(entries)} candidate(s) ranked, {thin} with insufficient "
         f"coverage, {len(out)} alert(s) on factual triggers")
    return out


def _darkweb_step(store: FindingStore, kev: set[str]) -> list[Alert]:
    from darkfeeds.cli import run_collection
    from darkfeeds.config import Config as DFConfig
    from darkfeeds.store import Store as DFStore

    df_cfg = DFConfig()
    df = DFStore(df_cfg.db_path)
    try:
        signals = run_collection(df_cfg, df, enrich=True)
    finally:
        df.close()

    # A CVE being discussed/sold underground is exactly when we want its full
    # record: fetch any we don't have yet (rate-limited in feeds.py), so the
    # alert carries real severity/EPSS and the CVE becomes queryable.
    mentioned = sorted({c for s in signals for c in s.cve_ids})
    missing = [c for c in mentioned if store.get(c) is None]
    if missing:
        from .pipeline import analyze_cve
        from .feeds import FeedUnavailable

        def _try(c):
            try:
                return analyze_cve(c)
            except FeedUnavailable:
                return None  # NVD down this cycle — don't abort the whole step

        fetched = [f for f in (_try(c) for c in missing) if f is not None]
        if fetched:
            run_id = store.start_run("watch-underground", {"cves": missing})
            store.save_findings(fetched, run_id)
            store.finish_run(run_id, len(fetched))

    alerts: list[Alert] = []
    for s in signals:
        for cve in s.cve_ids:
            known = store.get(cve) or {}
            scores = known.get("scores", {})
            sev = scores.get("cvss_severity") or "severity unknown"
            if scores.get("cvss") is not None:
                sev += f" {scores['cvss']}"
            if scores.get("epss") is not None:
                sev += f", EPSS {scores['epss']:.2f}"
            context = [sev]
            if cve in kev or known.get("disclosure", {}).get("in_kev"):
                context.append("on CISA KEV")
            if s.threat_actor:
                context.append(f"actor: {s.threat_actor}")
            alerts.append(Alert(
                key=f"underground:{cve}", kind="underground",
                title=f"{cve} seen in threat-intel telemetry ({s.signal_type.value})",
                detail=f"{s.title[:100]} [{', '.join(context)}]",
                url=s.source_url if s.source_url.startswith("http") else "",
                data={"cve": cve, "signal_id": s.signal_id}))
        if s.priority.value == "P1":
            alerts.append(Alert(
                key=f"signal:{s.signal_id}", kind="signal",
                title=f"P1 signal: {s.title[:100]}",
                detail=s.signal_type.value + (f", actor {s.threat_actor}" if s.threat_actor else ""),
                data={"signal_id": s.signal_id}))
    _log(f"dark-web collection: {len(signals)} signal(s), "
         f"{sum(1 for a in alerts if a.kind == 'underground')} CVE mention(s)")
    return alerts


def run_cycle(*, days: int = 2, min_severity: str = "HIGH", darkweb: bool = True,
              alert_critical: bool = False, max_alerts: int = 20,
              dry_run: bool = False) -> dict:
    store = FindingStore(get_config().db_path)
    baseline = not store.has_alerts()
    candidates: list[Alert] = []
    silent: list[Alert] = []
    errors: dict[str, str] = {}
    kev: set[str] = set()
    # Record the cycle as "running" up front so the dashboard can show a cycle
    # in progress (a full one takes 20+ min on free tiers), not just the last
    # finished one.
    cycle_id = None if dry_run else store.start_run("watch-cycle", {"baseline": baseline})

    try:
        fresh, stale, kev = _kev_alerts()
        candidates += fresh
        silent += stale
        _log(f"KEV catalog: {len(kev)} entries")
    except Exception as e:
        errors["kev"] = f"{type(e).__name__}: {e}"

    try:
        candidates += _cve_step(store, days, min_severity, alert_critical)
    except Exception as e:
        errors["cve"] = f"{type(e).__name__}: {e}"

    try:
        candidates += _watchlist_step(store, days)
    except Exception as e:
        errors["watchlist"] = f"{type(e).__name__}: {e}"

    try:
        fresh, stale = _exploitdb_step(store)
        candidates += fresh
        silent += stale
    except Exception as e:
        errors["exploitdb"] = f"{type(e).__name__}: {e}"

    if darkweb:
        try:
            candidates += _darkweb_step(store, kev)
        except Exception as e:
            errors["darkweb"] = f"{type(e).__name__}: {e}"

    # After collection, so this cycle's threat-intel mentions count.
    try:
        candidates += _radar_step(store)
    except Exception as e:
        errors["radar"] = f"{type(e).__name__}: {e}"

    try:
        fresh, stale = _sandbox_step(store)
        candidates += fresh
        silent += stale
    except Exception as e:
        errors["sandbox"] = f"{type(e).__name__}: {e}"

    try:
        fresh, stale = _geo_step(store)
        candidates += fresh
        silent += stale
    except Exception as e:
        errors["geo"] = f"{type(e).__name__}: {e}"

    for step, err in errors.items():
        _log(f"[!] step '{step}' failed: {err}")

    # Dedup within the cycle (same CVE mentioned by several signals) and
    # against everything already recorded.
    unique = {a.key: a for a in candidates}
    new_keys = store.new_alert_keys(list(unique))
    new = sorted((unique[k] for k in new_keys), key=lambda a: (_KIND_ORDER.get(a.kind, 9), a.key))
    unseen_stale = store.new_alert_keys([a.key for a in silent])
    stale_new = [a for a in silent if a.key in unseen_stale]

    summary = {"baseline": baseline, "new_alerts": len(new), "errors": errors, "sent": {}}
    if cycle_id is not None:
        # One row per cycle so /metrics can show "last cycle" and failing steps.
        store.finish_run(cycle_id, len(new), status="partial" if errors else "done",
                         params={"errors": errors, "baseline": baseline})
    if dry_run:
        _log(f"dry run: {len(new)} alert(s) would be sent" + (" (baseline)" if baseline else ""))
        summary["preview"] = [a.line() for a in new[:max_alerts]]
        store.close()
        return summary

    store.record_alerts(stale_new, None)
    if baseline:
        store.record_alerts(new, None)
        _log(f"first run: recorded {len(new)} current item(s) as baseline, nothing sent. "
             f"From the next cycle on, only new events alert.")
    elif new:
        shown, overflow = new[:max_alerts], max(0, len(new) - max_alerts)
        result = send(shown, overflow=overflow)
        # An empty result means no channel is configured. Recording a
        # placeholder here would mark the row delivered and inflate the only
        # number that says how many alerts actually reached anyone.
        store.record_alerts(new, result or None)
        summary["sent"] = result
        if result:
            _log(f"{len(new)} new alert(s) delivered via {', '.join(result)}")
        else:
            _log(f"{len(new)} new alert(s) recorded but NOT sent: no alert channel "
                 f"is configured. They are in the dashboard and GET /alerts.")
    else:
        _log("no new alerts")
    store.close()
    return summary


def watch(*, interval_hours: float = 6.0, once: bool = False, **cycle_kwargs) -> None:
    while True:
        started = time.monotonic()
        try:
            run_cycle(**cycle_kwargs)
        except Exception as e:  # never let one bad cycle kill the loop
            _log(f"[!] cycle crashed: {type(e).__name__}: {e}")
        if once:
            return
        sleep_for = max(60.0, interval_hours * 3600 - (time.monotonic() - started))
        _log(f"next cycle in {sleep_for / 3600:.1f}h")
        try:
            time.sleep(sleep_for)
        except KeyboardInterrupt:
            _log("stopped")
            return
