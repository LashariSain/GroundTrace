"""Verification verdicts from independent services (services stubbed)."""
from groundtrace import ioc_store, verify


def test_verdicts():
    nf = {"status": "not_found"}
    assert verify.verdict("sha1", {"status": "found", "malicious": 0, "engines": 70}, nf,
                          {"status": "found", "known_malicious": False})["level"] == "benign"
    # MalwareBazaar alone (VT at 3 is below the 10-engine bar) is one source:
    # strong, but nothing to check it against, so a lead rather than confirmed.
    one_src = verify.verdict("sha256", {"status": "found", "malicious": 3, "engines": 70},
                             {"status": "found", "family": "Emotet"}, nf)
    assert one_src["level"] == "likely" and one_src["corroborated"] is False
    assert one_src["sources"] == ["MalwareBazaar"]
    # With VirusTotal above the bar as well, two independent sources agree.
    two_src = verify.verdict("sha256", {"status": "found", "malicious": 44, "engines": 70},
                             {"status": "found", "family": "Emotet"}, nf)
    assert two_src["level"] == "confirmed" and two_src["corroborated"] is True
    assert len(two_src["sources"]) == 2
    assert verify.verdict("ip", {"status": "found", "malicious": 2, "engines": 90}, {"status": "unsupported"}, {"status": "unsupported"})["level"] == "likely"
    assert verify.verdict("domain", {"status": "found", "malicious": 0, "engines": 90}, nf, nf)["level"] == "clean"
    assert verify.verdict("md5", nf, nf, nf)["level"] == "unverified"
    # a known-good catalogue file that many engines flag is NOT called benign
    many = verify.verdict("sha1", {"status": "found", "malicious": 40, "engines": 70}, nf, {"status": "found"})
    assert many["level"] == "likely" and many["sources"] == ["VirusTotal (40 engines)"]


def test_check_caches_and_validates(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(verify, "virustotal", lambda v, t: calls.append(v) or {"status": "found", "malicious": 12, "engines": 70})
    monkeypatch.setattr(verify, "malwarebazaar", lambda v, t: {"status": "not_found"})
    monkeypatch.setattr(verify, "circl", lambda v, t: {"status": "not_found"})
    for name in ("threatfox", "urlhaus", "greynoise", "shodan"):   # never hit live services in tests
        monkeypatch.setattr(verify, name, lambda v, t: {"status": "not_found"})
    con = ioc_store.connect(str(tmp_path / "apt.db"))
    r1 = verify.check("1.2.3[.]4", con)
    r2 = verify.check("1.2.3.4", con)
    # VirusTotal is a single source, however many engines it aggregates.
    assert r1["verdict"]["level"] == "likely" and r1["verdict"]["corroborated"] is False
    assert not r1["cached"] and r2["cached"] and calls == ["1.2.3.4"]
    verify.check("1.2.3.4", con, force=True)
    assert len(calls) == 2
    assert "error" in verify.check("bad@x.example", con)       # emails aren't verifiable here


def test_infrastructure_verdicts():
    nf, na = {"status": "not_found"}, {"status": "unsupported"}
    vt_low = {"status": "found", "malicious": 1, "engines": 90}
    # a specialised C2 feed outranks a low antivirus count
    tf = {"status": "found", "threat": "botnet C2 server", "family": "Hermes", "last_seen": "2026-10-23"}
    v = verify.verdict("ip", vt_low, na, na, tf, nf, nf)
    assert v["level"] == "likely" and "botnet C2 server (Hermes)" in v["text"]
    assert v["sources"] == ["ThreatFox"] and v["corroborated"] is False
    assert "second independent" in v["text"]
    # ThreatFox plus URLhaus is corroboration.
    both = verify.verdict("url", nf, na, na, tf, {"status": "found", "online": True}, na)
    assert both["level"] == "confirmed" and both["corroborated"] is True
    assert verify.verdict("url", nf, na, na, nf, {"status": "found", "online": True}, na)["level"] == "likely"
    assert verify.verdict("ip", vt_low, na, na, nf, nf, {"status": "found", "benign_service": True, "name": "Google"})["level"] == "benign"
    assert "scanner" in verify.verdict("ip", vt_low, na, na, nf, nf, {"status": "found", "scanner": True, "classification": "malicious"})["text"]


def test_confirmed_is_impossible_from_one_source():
    """Phase 2.3's gate: no single service can produce "confirmed"."""
    nf, na = {"status": "not_found"}, {"status": "unsupported"}
    singles = [
        dict(tf={"status": "found", "threat": "C2"}),
        dict(uh={"status": "found", "online": True}),
        dict(mb={"status": "found", "family": "Emotet"}),
        dict(vt={"status": "found", "malicious": 70, "engines": 70}),
    ]
    for kw in singles:
        v = verify.verdict("url", kw.get("vt", nf), kw.get("mb", na), na,
                           kw.get("tf", nf), kw.get("uh", nf), na)
        assert len(v["sources"]) == 1, v["sources"]
        assert v["level"] != "confirmed", (kw, v["level"])
        assert v["corroborated"] is False


def test_every_verdict_reports_its_sources():
    nf, na = {"status": "not_found"}, {"status": "unsupported"}
    for v in (verify.verdict("md5", nf, nf, nf),
              verify.verdict("domain", {"status": "found", "malicious": 0, "engines": 9}, nf, nf),
              verify.verdict("ip", {"status": "found", "malicious": 1, "engines": 9}, na, na),
              verify.verdict("ip", {"status": "found", "malicious": 1, "engines": 9}, na, na,
                             nf, nf, {"status": "found", "benign_service": True})):
        assert "sources" in v and "corroborated" in v
        assert isinstance(v["sources"], list)


# --- a failed lookup is not a "not found" ----------------------------------

def test_transport_failure_is_reported_as_an_error_not_not_found(monkeypatch):
    """_http_json returns (0, {"error": ...}) when the request never landed.

    That is a dict, so the old isinstance() check passed and the service's
    "not found" branch ran -- reporting a network failure as evidence the
    indicator is unknown. Measured live: every URLhaus lookup on this machine
    failed TLS verification and reported "not found".
    """
    fail = (0, {"error": "<urlopen error [SSL: CERTIFICATE_VERIFY_FAILED] ...>"})
    monkeypatch.setattr(verify, "_abusech", lambda *a, **k: fail)
    for v, t in (("gate.ddns.net", "domain"), ("http://x.example/a", "url"),
                 ("a" * 64, "sha256")):
        r = verify.urlhaus(v, t)
        assert r["status"] == "error", (v, t, r)
        assert "certificate" in r["error"].lower()
    tf = verify.threatfox("1.2.3.4", "ip")
    assert tf["status"] == "error" and "certificate" in tf["error"].lower()


def test_http_error_is_also_an_error(monkeypatch):
    monkeypatch.setattr(verify, "_abusech", lambda *a, **k: (503, None))
    assert verify.urlhaus("gate.ddns.net", "domain")["status"] == "error"
    assert verify.threatfox("1.2.3.4", "ip")["status"] == "error"


def test_genuine_not_found_is_still_not_found(monkeypatch):
    monkeypatch.setattr(verify, "_abusech", lambda *a, **k: (200, {"query_status": "no_results"}))
    assert verify.urlhaus("gate.ddns.net", "domain")["status"] == "not_found"
    assert verify.threatfox("1.2.3.4", "ip")["status"] == "not_found"


def test_urlhaus_looks_up_payload_hashes(monkeypatch):
    """URLhaus indexes payloads, so a hash has a second independent source."""
    seen = {}

    def fake(url, payload, as_json=True):
        seen["url"], seen["payload"] = url, payload
        return 200, {"query_status": "ok", "url_count": "3", "signature": "Agent Tesla",
                     "file_type": "exe", "firstseen": "2026-10-01 11:22:33",
                     "urlhaus_reference": "https://urlhaus.abuse.ch/x/"}

    monkeypatch.setattr(verify, "_abusech", fake)
    r = verify.urlhaus("b" * 64, "sha256")
    assert seen["url"].endswith("/payload/") and "sha256_hash" in seen["payload"]
    assert r["status"] == "found" and r["urls"] == 3
    assert r["threat"] == "Agent Tesla" and r["file_type"] == "exe"
    assert r["first_seen"] == "2026-10-01"

    verify.urlhaus("c" * 32, "md5")
    assert "md5_hash" in seen["payload"]
    # sha1 is not a lookup key in this API, so it stays unsupported.
    assert verify.urlhaus("d" * 40, "sha1")["status"] == "unsupported"


def test_urlhaus_payload_counts_toward_corroboration(monkeypatch):
    nf, na = {"status": "not_found"}, {"status": "unsupported"}
    uh = {"status": "found", "urls": 3, "threat": "Agent Tesla"}
    tf = {"status": "found", "threat": "C2"}
    srcs = verify.malicious_sources("sha256", nf, nf, tf, uh)
    assert srcs == ["ThreatFox", "URLhaus"]
    v = verify.verdict("sha256", nf, na, na, tf, uh, na)
    assert v["level"] == "confirmed" and v["corroborated"] is True
