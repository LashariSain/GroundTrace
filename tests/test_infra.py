"""Stage 2 external infrastructure pivoting. Network calls are stubbed."""
from groundtrace import infra, ioc_store


def _seed(con):
    con.execute("INSERT INTO iocs (value,type,group_key,kind,family,first_seen,last_seen,hits,url) "
                "VALUES ('sibling.example','domain','u-1','catalog','',' ',' ',1,'')")
    con.commit()


def test_pivot_groups_methods_and_marks_known(tmp_path, monkeypatch):
    monkeypatch.setattr("groundtrace.aptdb._load", lambda: {"by_uuid": {"u-1": {"name": "APT-Test"}}})
    monkeypatch.setattr(infra, "_crtsh_siblings", lambda d, timeout=15: [
        {"value": "sibling.example", "type": "domain", "note": "shares a certificate"},
        {"value": "other-evil.example", "type": "domain", "note": "shares a certificate"}])
    con = ioc_store.connect(str(tmp_path / "apt.db"))
    _seed(con)
    r = infra.pivot("evil.example", con=con)
    assert r["type"] == "domain" and not r["cached"]
    cert = next(p for p in r["pivots"] if p["method"] == "cert")
    assert cert["confidence"] == "high" and cert["count"] == 2
    known = {x["value"]: x["known"] for x in cert["related"]}
    assert known["sibling.example"] is True and known["other-evil.example"] is False
    assert {"APT-Test"} == set(next(x for x in cert["related"] if x["value"] == "sibling.example")["groups"])
    # second call is served from cache; force bypasses it
    assert infra.pivot("evil.example", con=con)["cached"] is True
    assert infra.pivot("evil.example", con=con, force=True)["cached"] is False


def test_pivot_ip_uses_rdns_hostdb_jarm(tmp_path, monkeypatch):
    monkeypatch.setattr("groundtrace.aptdb._load", lambda: {"by_uuid": {}})
    monkeypatch.setattr(infra, "_reverse_dns", lambda ip, timeout=3.0: [{"value": "ptr.example", "type": "domain", "note": "reverse DNS (PTR)"}])
    monkeypatch.setattr(infra, "_internetdb", lambda ip, timeout=10: [{"value": "vhost.example", "type": "domain", "note": "resolves to this IP (InternetDB)"}])
    monkeypatch.setattr(infra, "_shodan_jarm", lambda ip, timeout=15: [{"value": "45.9.148.3", "type": "ip", "note": "same JARM fingerprint (abc…)"}])
    con = ioc_store.connect(str(tmp_path / "apt.db"))
    r = infra.pivot("91.213.50.7", con=con)
    methods = {p["method"] for p in r["pivots"]}
    assert methods == {"rdns", "hostdb", "jarm"}


def test_pivot_rejects_junk(tmp_path):
    con = ioc_store.connect(str(tmp_path / "apt.db"))
    assert infra.pivot("hello world", con=con)["error"]


def test_no_shodan_key_means_no_jarm(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "")
    assert infra._shodan_jarm("1.2.3.4") == []
