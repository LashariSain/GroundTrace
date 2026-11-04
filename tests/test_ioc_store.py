"""IOC store: typing, both sources, search, freshness, exports."""
import json
import sqlite3
from datetime import date

import pytest

from groundtrace import aptdb, ioc_store as I
from darkfeeds.store import Store


@pytest.mark.parametrize("raw,expect", [
    ("1.2.3[.]4", ("1.2.3.4", "ip")), ("10.0.0.0/8", ("10.0.0.0/8", "cidr")),
    ("hxxps://evil[.]example/a", ("https://evil.example/a", "url")), ("Evil.Example.", ("evil.example", "domain")),
    ("A" * 32, ("a" * 32, "md5")), ("b" * 40, ("b" * 40, "sha1")), ("C" * 64, ("c" * 64, "sha256")),
    ("bad[@]actor.example", ("bad@actor.example", "email")), ("not an indicator", ("not an indicator", "")),
])
def test_classify_and_refang(raw, expect):
    assert I.classify(raw) == expect


def test_defang():
    assert I.defang("1.2.3.4", "ip") == "1[.]2[.]3[.]4"
    assert I.defang("https://a.example/x", "url") == "hxxps://a[.]example/x"


@pytest.fixture
def store(tmp_path, monkeypatch):
    raw = tmp_path / "aptmap.json"
    raw.write_text(json.dumps({"features": [{"properties": {"uuid": "u-1", "otx_iocs": [
        {"type": "domain", "value": "C2.Example"}, {"type": "FileHash-MD5", "value": "A" * 32},
        {"type": "YARA", "value": "rule x {}"}]}}]}), encoding="utf-8")
    db = str(tmp_path / "s.db")
    Store(db).close()
    con = sqlite3.connect(db)
    con.execute("INSERT INTO signals (signal_id, signal_type, priority, source, source_name, title, threat_actor, "
                "malware_family, ip_addresses, domains, collected_at, source_url) VALUES "
                "('s1', 'x', 'P3', 'otx', 'OTX', 't', 'APT36', 'CrimsonRAT', '[\"9.9.9.9\"]', '[\"c2.example\"]', "
                "'2026-10-20T00:00:00', 'https://report.example/1')")
    con.commit()
    con.close()
    monkeypatch.setattr(aptdb, "resolve", lambda n: {"uuid": "u-1"} if n == "APT36" else None)
    monkeypatch.setattr(aptdb, "groups_for_tool", lambda f: [])
    monkeypatch.setattr(aptdb, "_load", lambda: {"by_uuid": {"u-1": {"name": "Transparent Tribe", "country": "PK"}}})
    led = I.connect(str(tmp_path / "apt.db"))
    I.rebuild(led, I.collect(raw, db))
    return led


def test_both_sources_and_search(store):
    rows = {(r["value"], r["kind"]) for r in store.execute("SELECT * FROM iocs")}
    assert ("c2.example", "catalog") in rows and ("c2.example", "telemetry") in rows   # normalised + merged by kind
    assert ("9.9.9.9", "telemetry") in rows and not any("rule" in v for v, _ in rows)  # YARA not an indicator here
    r = I.search(store, "hxxp://C2[.]example/path")
    assert r["type"] == "url" and {m["matched_on"] for m in r["matches"]} == {"host"}
    tele = next(m for m in r["matches"] if m["kind"] == "telemetry")
    assert tele["group_name"] == "Transparent Tribe" and tele["last_seen"] == "2026-10-20" and tele["family"] == "CrimsonRAT"
    assert I.search(store, "not an indicator")["type"] == ""


def test_freshness_and_exports(store):
    assert I._stale("", date(2026, 10, 28)) and I._stale("2026-01-01", date(2026, 10, 28))
    assert not I._stale("2026-10-01", date(2026, 10, 28))
    rows = I.group_iocs(store, "u-1")
    assert I.to_txt(rows, {"ip"}) == "9.9.9.9\n"
    csv_text = I.to_csv(rows, "Transparent Tribe")
    assert csv_text.splitlines()[0].startswith("indicator,type,group") and "c2.example" in csv_text
    b1 = I.to_stix(rows, {"uuid": "u-1", "name": "Transparent Tribe", "aliases": ["APT36"]})
    b2 = I.to_stix(rows, {"uuid": "u-1", "name": "Transparent Tribe", "aliases": ["APT36"]})
    inds = [o for o in b1["objects"] if o["type"] == "indicator"]
    assert {o["pattern"] for o in inds} >= {"[ipv4-addr:value = '9.9.9.9']", "[domain-name:value = 'c2.example']",
                                            f"[file:hashes.MD5 = '{'a' * 32}']"}
    assert sorted(o["id"] for o in inds) == sorted(o["id"] for o in b2["objects"] if o["type"] == "indicator")  # stable ids
    assert all(o["relationship_type"] == "indicates" for o in b1["objects"] if o["type"] == "relationship")


def test_related_family_network_and_together(store, tmp_path):
    store.executemany("INSERT INTO iocs (value, type, group_key, kind, family, last_seen) VALUES (?, ?, ?, ?, ?, ?)", [
        ("9.9.9.10", "ip", "", "telemetry", "CrimsonRAT", "2026-10-21"),   # same family + same /24
        ("8.8.8.8", "ip", "", "telemetry", "Other", "2026-10-21")])
    store.commit()
    hosting = {"countries": {"NL": {"providers": [{"name": "Host BV", "asn": "1", "kind": "hosting", "score": 70,
                                                    "ip_count": 2, "clusters": [], "ips": [{"ip": "9.9.9.9"}]}]}}}
    r = I.related(store, "9.9.9[.]9", None, hosting, resolve=False)
    # c2.example came from the same CrimsonRAT signal, so it is same-family too
    assert r["families"] == ["CrimsonRAT"] and sorted(x["value"] for x in r["family"]) == ["9.9.9.10", "c2.example"]
    assert [x["value"] for x in r["network"]] == ["9.9.9.10"] and r["network_block"] == "9.9.9.0/24"
    assert r["hosting"]["provider"] == "Host BV" and r["hosting"]["score"] == 70
    assert "8.8.8.8" not in {x["value"] for x in r["family"] + r["network"]}


def test_source_of_names_every_origin():
    """Every indicator can say where it came from, without a schema change."""
    from groundtrace import ioc_store

    tf = ioc_store.source_of({"url": "https://threatfox.abuse.ch/ioc/1956146/", "kind": "telemetry"})
    assert tf["name"] == "ThreatFox (abuse.ch)" and tf["url"].endswith("/1956146/")

    otx = ioc_store.source_of({"url": "https://otx.alienvault.com/pulse/abc", "kind": "telemetry"})
    assert otx["name"] == "AlienVault OTX"

    # Catalogue rows carry no permalink; saying so is accurate, inventing one is not.
    cat = ioc_store.source_of({"url": "", "kind": "catalog"})
    assert "APT catalogue" in cat["name"] and cat["url"] == ""

    # A leak site is named generically rather than echoing an onion address.
    onion = ioc_store.source_of(
        {"url": "http://krybitqsdzwmhnitvwuhvsntfgf2wrhxveyxroxpc44c6gkft2cqldyd.onion/x", "kind": "telemetry"})
    assert onion["name"] == "Dark-web leak site" and ".onion" not in onion["name"]

    # An unknown host still names itself rather than returning nothing.
    other = ioc_store.source_of({"url": "https://example.org/report/1", "kind": "telemetry"})
    assert other["name"] == "example.org"

    assert ioc_store.source_of({"url": "", "kind": "telemetry"})["name"] == "not recorded"
