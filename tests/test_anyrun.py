"""Sandbox-detonation capture (Stage 1). External backends are stubbed."""
import darkfeeds.virustotal as vt
from groundtrace import anyrun, ioc_store

_FILE = {"data": {"attributes": {
    "first_submission_date": 1_760_000_000,  # 2025-10-09
    "popular_threat_classification": {"suggested_threat_label": "trojan.remcos/agent"},
    "last_analysis_stats": {"malicious": 12, "harmless": 50},
}}}
_IPS = {"data": [{"id": "91.213.50.7"}, {"id": "45.9.148.3"}]}
_DOMS = {"data": [{"id": "update-sync.ddns.net"}]}
_URLS = {"data": [{"attributes": {"url": "http://update-sync.ddns.net/gate.php"}}]}


def _fake_vt_get(path, key):
    if path.endswith("/contacted_ips?limit=40"):
        return _IPS
    if path.endswith("/contacted_domains?limit=40"):
        return _DOMS
    if path.endswith("/contacted_urls?limit=40"):
        return _URLS
    return _FILE


def test_capture_and_rows(monkeypatch):
    monkeypatch.setenv("DARKFEEDS_VT_KEY", "x")
    monkeypatch.setenv("ANYRUN_API_KEY", "")
    monkeypatch.setattr(vt, "_get", _fake_vt_get)
    cap = anyrun.capture("a" * 64)
    assert cap["family"] == "trojan.remcos/agent"
    assert cap["detonated_at"] == "2025-10-09"
    vals = {c["value"] for c in cap["c2"]}
    assert "91.213.50.7" in vals and "update-sync.ddns.net" in vals
    assert "http://update-sync.ddns.net/gate.php" in vals
    rows = anyrun.to_rows(cap, group_key="")
    assert len(rows) == 4 and all(r["kind"] == "sandbox" for r in rows)
    assert all(r["first_seen"] == "2025-10-09" for r in rows)


def test_upsert_is_incremental(tmp_path, monkeypatch):
    monkeypatch.setenv("DARKFEEDS_VT_KEY", "x")
    monkeypatch.setattr(vt, "_get", _fake_vt_get)
    con = ioc_store.connect(str(tmp_path / "apt.db"))
    rows = anyrun.to_rows(anyrun.capture("b" * 64))
    assert anyrun.upsert(con, rows) == 4
    anyrun.upsert(con, rows)                       # same run seen again
    hits = con.execute("select hits from iocs where value='91.213.50.7' and kind='sandbox'").fetchone()[0]
    assert hits == 2                               # bumped, not duplicated
    assert con.execute("select count(*) from iocs where kind='sandbox'").fetchone()[0] == 4


def test_no_key_is_graceful(monkeypatch):
    monkeypatch.setenv("DARKFEEDS_VT_KEY", "")
    monkeypatch.setenv("ANYRUN_API_KEY", "")
    monkeypatch.setenv("DARKFEEDS_ABUSECH_KEY", "")
    assert anyrun.capture("c" * 64) is None
    assert anyrun.recent()["status"] == "not_configured"


_MB_OK = {"query_status": "ok", "data": [
    {"sha256_hash": "D" * 64, "file_name": "invoice.exe", "signature": "RemcosRAT",
     "first_seen": "2026-10-29 07:14:02"},
    {"sha256_hash": "E" * 64, "file_name": "", "signature": "", "first_seen": ""},
]}


def test_recent_falls_back_to_malwarebazaar(monkeypatch):
    """No ANY.RUN key (the free-plan case) -> discovery still works."""
    monkeypatch.setenv("ANYRUN_API_KEY", "")
    monkeypatch.setenv("DARKFEEDS_ABUSECH_KEY", "k")
    from groundtrace import verify
    monkeypatch.setattr(verify, "_abusech", lambda *a, **k: (200, _MB_OK))
    feed = anyrun.recent(10)
    assert feed["status"] == "ok" and feed["source"] == "malwarebazaar"
    first = feed["runs"][0]
    assert first["hash"] == "d" * 64            # lowercased for the VT lookup
    assert first["family"] == "RemcosRAT" and first["detonated_at"] == "2026-10-29"
    assert first["url"].endswith(f"/sample/{'d' * 64}/")
    assert len(feed["runs"]) == 2               # a bare hash with no metadata still counts


def test_recent_fallback_tolerates_bad_response(monkeypatch):
    monkeypatch.setenv("ANYRUN_API_KEY", "")
    monkeypatch.setenv("DARKFEEDS_ABUSECH_KEY", "k")
    from groundtrace import verify
    monkeypatch.setattr(verify, "_abusech", lambda *a, **k: (200, {"query_status": "no_results"}))
    assert anyrun.recent()["runs"] == []
    monkeypatch.setattr(verify, "_abusech", lambda *a, **k: (-1, None))
    assert anyrun.recent()["status"] == "not_configured"


def test_hours_since_parses():
    assert anyrun.hours_since("") is None
    assert anyrun.hours_since("2020-01-01") > 0


def test_anyrun_report_parse():
    rep = {"data": {
        "network": {
            "connections": [{"ip": "5.230.252.84"}],
            "dns": [{"domain": "avupdate.servehttp.com"}],
            "httpRequests": [{"url": "http://avupdate.servehttp.com/a"}],
        },
        "analysis": {"creation": "2026-09-24T10:00:00Z",
                     "scores": {"verdict": {"threatLevelText": "Malicious"}}},
        "sample": {"hashes": {"sha256": "D" * 64}},
    }}
    cap = anyrun._parse_anyrun_report(rep, "task-1")
    vals = {c["value"] for c in cap["c2"]}
    assert "5.230.252.84" in vals and "avupdate.servehttp.com" in vals
    assert cap["detonated_at"] == "2026-09-24" and cap["verdict"] == "malicious"


_HA_OVERVIEW = {
    "sha256": "F" * 64, "vx_family": "Ransom.HiddenTears.Generic",
    "verdict": "malicious", "analysis_start_time": "2026-10-30T06:07:02+00:00",
    # the API returns job ids as bare strings, not objects
    "reports": ["job-1"], "related_reports": ["job-1"],
}
_HA_SUMMARY = {"hosts": ["85.17.56.34"], "domains": ["ryuk.com"],
               "compromised_hosts": [], "dns_requests": [{"domain": "trickbot.com"}],
               "http_requests": [{"url": "http://ryuk.com/g.php", "host": "ryuk.com"}]}


def test_ha_capture_reads_network_from_report_summary(monkeypatch):
    """The overview never carries the network set; the per-report summary does."""
    monkeypatch.setenv("HYBRIDANALYSIS_API_KEY", "k")
    seen = []

    def fake(path, form=None):
        seen.append(path)
        return _HA_OVERVIEW if path.startswith("/overview/") else _HA_SUMMARY

    monkeypatch.setattr(anyrun, "_ha_req", fake)
    cap = anyrun._capture_ha("f" * 64)
    assert any(p.startswith("/report/job-1/summary") for p in seen)
    assert cap["family"] == "Ransom.HiddenTears.Generic"
    assert cap["verdict"] == "malicious" and cap["detonated_at"] == "2026-10-30"
    vals = {c["value"] for c in cap["c2"]}
    assert {"85.17.56.34", "ryuk.com", "trickbot.com", "http://ryuk.com/g.php"} <= vals


def test_ha_recent_uses_feed_field_names(monkeypatch):
    monkeypatch.setenv("ANYRUN_API_KEY", "")
    monkeypatch.setenv("HYBRIDANALYSIS_API_KEY", "k")
    feed = {"data": [{"sha256": "A" * 64, "job_id": "j1", "submit_name": "x.exe",
                      "vx_family": "Gen:Variant.Lazy", "threat_level_human": "malicious",
                      "analysis_start_time": "2026-10-30 06:07:02"}]}
    monkeypatch.setattr(anyrun, "_ha_req", lambda path, form=None: feed)
    out = anyrun.recent(5)
    assert out["source"] == "hybridanalysis"
    r = out["runs"][0]
    assert r["verdict"] == "malicious" and r["family"] == "Gen:Variant.Lazy"
    assert r["detonated_at"] == "2026-10-30" and r["task_id"] == "j1"
