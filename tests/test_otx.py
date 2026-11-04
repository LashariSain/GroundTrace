"""OTX: pulses are fetched in full (search results carry no indicators), and
stored indicator-less pulses can be backfilled."""
import json

from darkfeeds import collectors
from darkfeeds.store import Store

FULL = {
    "id": "abc123", "name": "Operation RapidRust: new Rust backdoors", "description": "",
    "tags": ["apt"], "adversary": "Operation C-Major",
    "targeted_countries": ["Afghanistan", "India"],
    "malware_families": [{"display_name": "RUSTYSHADE"}],
    "indicators": [{"type": "IPv4", "indicator": "45.1.2.3"},
                   {"type": "hostname", "indicator": "c2.example.net"},
                   {"type": "domain", "indicator": "example.org"},
                   {"type": "FileHash-SHA256", "indicator": "a" * 64}],
}


def _fake_get(url, headers=None):
    if "/search/pulses" in url:
        return {"results": [{"id": "abc123", "name": FULL["name"], "indicators": []}]}
    if url.endswith("/pulses/abc123"):
        return FULL
    return None


def test_collect_fetches_full_pulse(monkeypatch):
    monkeypatch.setattr(collectors, "_get_json", _fake_get)
    s = collectors.collect_otx_pulses("key", search="apt36")[0]
    assert s.ip_addresses == ["45.1.2.3"]
    assert s.domains == ["c2.example.net", "example.org"]       # hostnames count as domains
    assert s.malware_family == "RUSTYSHADE"
    assert s.target_country == "afghanistan"
    assert "target:India" in s.tags and "family:RUSTYSHADE" in s.tags


def test_backfill_fills_stored_pulse_and_requeues_enrichment(tmp_path, monkeypatch):
    store = Store(str(tmp_path / "s.db"))
    store.conn.execute(
        "INSERT INTO signals (signal_id, signal_type, priority, source, source_name, source_url, title, "
        "ip_enrichment) VALUES ('s1', 'threat_actor', 'P3', 'otx', 'AlienVault OTX', "
        "'https://otx.alienvault.com/pulse/abc123', 'APT36', '{}')")
    store.conn.commit()
    assert [r["signal_id"] for r in store.get_otx_without_indicators()] == ["s1"]
    monkeypatch.setattr(collectors, "_get_json", _fake_get)
    assert collectors.backfill_otx_indicators("key", store) == 1
    row = store.conn.execute("SELECT * FROM signals WHERE signal_id = 's1'").fetchone()
    assert json.loads(row["ip_addresses"]) == ["45.1.2.3"]
    assert row["threat_actor"] == "Operation C-Major"
    assert store.get_otx_without_indicators() == []
    assert [r["signal_id"] for r in store.get_unenriched_ips()] == ["s1"]
