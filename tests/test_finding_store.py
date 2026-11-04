"""FindingStore round-trips: upsert dedup, history, EPSS backfill, queries, alerts."""
from types import SimpleNamespace

from groundtrace.models import Finding, Scores
from groundtrace.store import FindingStore


def _store(tmp_path):
    return FindingStore(str(tmp_path / "t.db"))


def _finding(cve="CVE-2024-1000", cvss=9.0, epss=0.5, kev=False):
    f = Finding(cve_id=cve, title="RCE", scores=Scores(cvss=cvss, epss=epss))
    f.disclosure.in_kev = kev
    return f


def test_save_and_get_roundtrip(tmp_path):
    s = _store(tmp_path)
    run = s.start_run("cve")
    new = s.save_findings([_finding()], run)
    s.finish_run(run, 1)

    assert new == 1
    got = s.get("CVE-2024-1000")
    assert got["cve_id"] == "CVE-2024-1000"
    assert got["scores"]["risk"] == Scores(cvss=9.0, epss=0.5).risk
    s.close()


def test_upsert_dedups_but_appends_history(tmp_path):
    s = _store(tmp_path)
    r1 = s.start_run("cve")
    assert s.save_findings([_finding(epss=0.5)], r1) == 1
    r2 = s.start_run("cve")
    # Same CVE again -> not counted as new, but a second history row.
    assert s.save_findings([_finding(epss=0.6)], r2) == 0

    rows = s.query()
    assert len(rows) == 1
    assert len(s.history("CVE-2024-1000")) == 2
    s.close()


def test_no_epss_rerun_backfills_last_known(tmp_path):
    s = _store(tmp_path)
    r1 = s.start_run("cve")
    s.save_findings([_finding(epss=0.8)], r1)
    risk_before = s.get("CVE-2024-1000")["scores"]["risk"]

    # A --no-epss re-run (epss=None): must reuse the stored 0.8, not fall to 0.1.
    r2 = s.start_run("cve")
    s.save_findings([_finding(epss=None)], r2)
    after = s.get("CVE-2024-1000")
    assert after["scores"]["epss"] == 0.8
    assert after["scores"]["risk"] == risk_before
    s.close()


def test_query_filters(tmp_path):
    s = _store(tmp_path)
    r = s.start_run("recent")
    s.save_findings([
        _finding("CVE-2024-1", cvss=9.9, epss=0.9, kev=True),
        _finding("CVE-2024-2", cvss=4.0, epss=0.1, kev=False),
    ], r)

    assert {x["cve_id"] for x in s.query(kev_only=True)} == {"CVE-2024-1"}
    assert {x["cve_id"] for x in s.query(min_risk=50)} == {"CVE-2024-1"}
    # KEV sorts first regardless of raw risk ordering.
    assert s.query()[0]["cve_id"] == "CVE-2024-1"
    s.close()


def test_stats_counts(tmp_path):
    s = _store(tmp_path)
    r = s.start_run("recent")
    f_crit = _finding("CVE-2024-9", cvss=9.9, kev=True)
    f_crit.scores.cvss_severity = "CRITICAL"
    s.save_findings([f_crit], r)
    st = s.stats()
    assert st["total"] == 1 and st["kev"] == 1 and st["critical"] == 1
    s.close()


def test_alert_dedup_via_new_alert_keys(tmp_path):
    s = _store(tmp_path)
    alert = SimpleNamespace(key="kev:CVE-2024-1", kind="kev", title="t",
                            detail="", url="")
    assert s.new_alert_keys(["kev:CVE-2024-1"]) == {"kev:CVE-2024-1"}
    s.record_alerts([alert], {"webhook": "ok"})
    # Once recorded, it's no longer "new".
    assert s.new_alert_keys(["kev:CVE-2024-1"]) == set()
    assert s.alert_counts().get("kev") == 1
    s.close()


def test_query_ai_only(tmp_path):
    from groundtrace.store import FindingStore
    from groundtrace.pipeline import analyze
    store = FindingStore(str(tmp_path / "f.db"))
    ai = analyze({"cve_id": "CVE-2025-0001", "description": "Overflow discovered by Big Sleep."})
    plain = analyze({"cve_id": "CVE-2025-0002", "description": "Overflow reported by a researcher."})
    run = store.start_run("test")
    store.save_findings([ai, plain], run)
    rows = store.query(ai_only=True)
    assert [r["cve_id"] for r in rows] == ["CVE-2025-0001"]
    assert rows[0]["ai_found_by"] == "Google Big Sleep"
    assert "_desc" not in rows[0]
    assert len(store.query()) == 2


def test_credits_survive_repull_and_drive_ai_filter(tmp_path):
    from groundtrace.store import FindingStore
    from groundtrace.pipeline import analyze
    store = FindingStore(str(tmp_path / "f.db"))
    raw = {"cve_id": "CVE-2025-0003", "description": "Overflow."}
    store.save_findings([analyze(raw)], store.start_run("test"))
    assert store.missing_credits() == ["CVE-2025-0003"]
    store.set_credits({"CVE-2025-0003": ["finder: XBOW"]})
    # A later NVD re-pull has no credits; the fetched ones must be kept.
    store.save_findings([analyze(raw)], store.start_run("test"))
    assert store.missing_credits() == []
    assert store.query(ai_only=True)[0]["ai_found_by"] == "XBOW"


def test_alert_volume_separates_delivered_from_baselined(tmp_path):
    """Row count is not alert volume.

    Most rows in `alerts` are baseline: recorded on first sight so the watcher
    does not alert on a backlog it has only just loaded. On the real store that
    is 1,793 baselined against 30 delivered, so counting the table overstates
    what was actually sent by sixty times.
    """
    from groundtrace.store import FindingStore

    s = FindingStore(str(tmp_path / "f.db"))
    s.conn.executemany(
        "INSERT INTO alerts (key, kind, title, detail, url, created_at, delivered) "
        "VALUES (?,?,?,?,?,?,?)",
        [("a1", "kev", "t", "", "", "2026-01-01", '{"webhook": "ok"}'),
         ("a2", "kev", "t", "", "", "2026-01-01", ""),
         ("a3", "kev", "t", "", "", "2026-01-01", ""),
         ("a4", "radar", "t", "", "", "2026-01-01", '{"webhook": "ok"}')])
    s.conn.commit()

    v = s.alert_volume()
    assert v["delivered_total"] == 2 and v["baselined_total"] == 2
    assert v["rows_total"] == 4
    assert v["delivered"] == {"kev": 1, "radar": 1}
    assert v["baselined"] == {"kev": 2}
    assert "only delivered_total is alert volume" in v["note"]
    # the older count stays delivered-only, so nothing that read it changes
    assert s.alert_counts() == {"kev": 1, "radar": 1}
