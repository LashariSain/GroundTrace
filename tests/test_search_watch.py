from datetime import date

from groundtrace import feeds, watch
from groundtrace.models import Finding, Scores
from groundtrace.store import FindingStore


def _f(cve, title, desc="", affected=(), refs=(), sev="HIGH"):
    return Finding(cve_id=cve, title=title, description=desc, affected=list(affected),
                   references=list(refs), scores=Scores(cvss=8.0, cvss_severity=sev))


def _store(tmp_path, findings):
    s = FindingStore(str(tmp_path / "f.db"))
    s.save_findings(findings, s.start_run("test"))
    return s


def test_search_ignores_reference_urls_and_requires_every_word(tmp_path):
    s = _store(tmp_path, [
        _f("CVE-2026-0001", "FortiOS SSL-VPN heap overflow",
           affected=["cpe:2.3:o:fortinet:fortios:7.4.0"]),
        _f("CVE-2026-0002", "Ivanti gateway bug", refs=["https://fortinet.com/blog/x"]),
        _f("CVE-2026-0003", "Fortinet FortiWeb path traversal"),
    ])
    ids = lambda q: sorted(r["cve_id"] for r in s.query(search=q))  # noqa: E731
    assert ids("fortinet") == ["CVE-2026-0001", "CVE-2026-0003"]   # CPE + title, not the URL
    assert ids("fortinet ssl-vpn") == ["CVE-2026-0001"]
    assert ids("cve-2026-0002") == ["CVE-2026-0002"]
    assert ids("100%") == [] and ids("a_b") == []                   # LIKE wildcards escaped


def test_reference_fallback_finds_nicknames(tmp_path):
    s = _store(tmp_path, [_f("CVE-2026-109618", "PHP longjmp OOM flaw",
                             refs=["https://www.wiz.io/blog/php2shell-php-rce"])])
    assert s.query(search="php2shell") == []
    assert [r["cve_id"] for r in s.query(search="php2shell", include_refs=True)] == ["CVE-2026-109618"]


def test_set_epss_recomputes_risk(tmp_path):
    s = _store(tmp_path, [_f("CVE-2026-0001", "x")])        # CVSS 8.0, no EPSS
    assert s.missing_epss() == ["CVE-2026-0001"]
    assert s.query()[0]["risk"] == 8.0                      # 0.1 default
    assert s.set_epss({"CVE-2026-0001": 0.9998, "CVE-2026-9999": 0.5}) == 1
    assert s.query()[0]["risk"] == 80.0 and s.get("CVE-2026-0001")["scores"]["risk"] == 80.0
    assert s.missing_epss() == []


def test_resolve_nickname_needs_agreement(monkeypatch):
    from groundtrace import pipeline
    results = [
        {"title": "PHP2Shell (CVE-2026-109618 and CVE-2026-109619)", "url": "https://a.com/1", "snippet": ""},
        {"title": "PHP2Shell advisory", "url": "https://b.org/x", "snippet": "CVE-2026-109618, CVE-2026-109619"},
        {"title": "blog", "url": "https://c.net/y", "snippet": "unrelated CVE-2020-0001"},
    ]
    monkeypatch.setattr("groundtrace.websearch.search_web", lambda q, max_results: results)
    r = pipeline.resolve_nickname("php2shell")
    assert sorted(r["cves"]) == ["CVE-2026-109618", "CVE-2026-109619"]


def test_watchlist_is_case_insensitive(tmp_path):
    s = _store(tmp_path, [])
    assert s.add_watch("GeoServer") and not s.add_watch("geoserver")
    assert [t["term"] for t in s.watch_terms()] == ["GeoServer"]
    assert s.remove_watch("GEOSERVER") and s.watch_terms() == []


def test_new_term_baselines_existing_matches(tmp_path):
    s = _store(tmp_path, [_f("CVE-2026-0001", "GeoServer RCE")])
    s.add_watch("geoserver")
    assert watch.baseline_watch_term(s, "geoserver") == 1
    assert s.new_alert_keys(["watch:geoserver:CVE-2026-0001"]) == set()
    assert s.list_alerts() == []                      # baseline: recorded, not sent


def test_watchlist_step_alerts_only_on_unseen_matches(tmp_path, monkeypatch):
    s = _store(tmp_path, [_f("CVE-2026-0001", "GeoServer RCE")])
    s.add_watch("geoserver")
    watch.baseline_watch_term(s, "geoserver")
    monkeypatch.setattr("groundtrace.pipeline.analyze_keyword", lambda term, days, limit: [
        _f("CVE-2026-0001", "GeoServer RCE"), _f("CVE-2026-0009", "GeoServer XXE", sev="CRITICAL")])
    alerts = watch._watchlist_step(s, days=2)
    new = s.new_alert_keys([a.key for a in alerts])
    assert new == {"watch:geoserver:CVE-2026-0009"}
    assert s.get("CVE-2026-0009") is not None        # matches are saved to the store


def test_search_nvd_reads_the_newest_page(monkeypatch):
    def cve(n, day):
        return {"cve": {"id": f"CVE-2026-{n:04d}", "published": f"2026-10-{day:02d}T00:00:00",
                        "descriptions": [{"lang": "en", "value": "x"}]}}
    calls = []

    def page(url, key):
        calls.append(url)
        if url.endswith("startIndex=0"):
            return {"totalResults": 120, "vulnerabilities": [cve(1, 1), cve(2, 2)]}, key
        return {"totalResults": 120, "vulnerabilities": [cve(119, 20), cve(120, 25)]}, key

    monkeypatch.setattr(feeds, "_nvd_get_page", page)
    monkeypatch.setattr(feeds, "_nvd_rate_limit", lambda: None)
    out = feeds.search_nvd("geo server", limit=2)
    assert [r["cve_id"] for r in out] == ["CVE-2026-0120", "CVE-2026-0119"]
    assert "keywordSearch=geo%20server" in calls[0] and calls[1].endswith("startIndex=118")
    assert out[0]["published"] == date(2026, 10, 25)


def test_sandbox_step_captures_and_matches(tmp_path, monkeypatch):
    from groundtrace import ioc_store
    dbfile = str(tmp_path / "apt.db")
    orig = ioc_store.connect
    monkeypatch.setattr(ioc_store, "connect", lambda path=None: orig(dbfile))
    s = _store(tmp_path, [])
    s.add_watch("remcos")
    feed = {"status": "ok", "runs": [
        {"task_id": "t-1", "name": "invoice.exe", "detonated_at": "2026-10-28"},
        {"task_id": "t-2", "name": "benign.pdf", "detonated_at": "2026-10-28"}]}
    caps = {
        "t-1": {"hash": "a" * 64, "family": "remcos", "detonated_at": "2026-10-28",
                "c2": [{"value": "91.213.50.7", "type": "ip"},
                       {"value": "gate.ddns.net", "type": "domain"}]},
        "t-2": {"hash": "b" * 64, "family": "", "detonated_at": "2026-10-28",
                "c2": [{"value": "1.1.1.1", "type": "ip"}]}}
    monkeypatch.setattr("groundtrace.anyrun.recent", lambda n=40: feed)
    monkeypatch.setattr("groundtrace.anyrun.capture", lambda tid: caps.get(tid))
    fresh, silent = watch._sandbox_step(s)              # first run: baseline (silent)
    assert fresh == [] and len(silent) == 1 and silent[0].key == "sandbox:t-1"
    # indicators from BOTH runs were captured, regardless of watchlist match --
    # minus t-2's lone 1.1.1.1, which groundtrace.benign drops as a public resolver
    con = orig(dbfile)
    try:
        stored = {r[0] for r in con.execute(
            "select value from iocs where kind='sandbox'").fetchall()}
    finally:
        con.close()
    assert stored == {"91.213.50.7", "gate.ddns.net"}


def test_sandbox_step_noop_without_feed(tmp_path, monkeypatch):
    s = _store(tmp_path, [])
    monkeypatch.setattr("groundtrace.anyrun.recent", lambda n=40: {"status": "not_configured", "runs": []})
    assert watch._sandbox_step(s) == ([], [])


def test_unsent_alerts_are_not_recorded_as_delivered(tmp_path, monkeypatch):
    """No channel configured means nothing was sent. Say so in the data.

    watch.py previously recorded {"stderr": "ok"} when send() returned
    nothing, which marked the row delivered. On the real store that made 30
    alerts look sent when they had only been printed to a terminal.
    """
    from groundtrace import notify
    from groundtrace.store import FindingStore

    for var in ("GROUNDTRACE_WEBHOOK_URL", "GROUNDTRACE_TELEGRAM_BOT_TOKEN",
                "GROUNDTRACE_TELEGRAM_CHAT_ID"):
        monkeypatch.delenv(var, raising=False)
    assert notify.channels() == []

    s = FindingStore(str(tmp_path / "f.db"))
    s.conn.execute(
        "INSERT INTO alerts (key, kind, title, detail, url, created_at, delivered) "
        "VALUES ('k1','kev','t','','','2026-01-01','')")
    s.conn.commit()
    v = s.alert_volume()
    assert v["delivered_total"] == 0 and v["baselined_total"] == 1


def test_channels_reports_what_is_configured(monkeypatch):
    from groundtrace import notify

    for var in ("GROUNDTRACE_WEBHOOK_URL", "GROUNDTRACE_TELEGRAM_BOT_TOKEN",
                "GROUNDTRACE_TELEGRAM_CHAT_ID"):
        monkeypatch.delenv(var, raising=False)
    assert notify.channels() == []

    monkeypatch.setenv("GROUNDTRACE_WEBHOOK_URL", "https://hooks.slack.com/services/x")
    assert notify.channels() == ["webhook"]

    # a bot token without a chat id cannot send, so it does not count
    monkeypatch.setenv("GROUNDTRACE_TELEGRAM_BOT_TOKEN", "t")
    assert notify.channels() == ["webhook"]
    monkeypatch.setenv("GROUNDTRACE_TELEGRAM_CHAT_ID", "c")
    assert notify.channels() == ["webhook", "telegram"]
