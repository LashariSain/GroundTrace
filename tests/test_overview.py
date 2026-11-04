"""The dashboard's aggregates stay honest and never name a feed."""
import json

from groundtrace import fingerprint
from groundtrace.api import _hide_sources
from darkfeeds.models import ThreatSignal
from darkfeeds.store import Store


def _store(tmp_path):
    store = Store(str(tmp_path / "df.db"))
    for i in range(25):
        store.save_signal(ThreatSignal(signal_id=f"m{i}", source_name="ThreatFox", title=f"m{i}",
                                       malware_family="Mirai", ip_addresses=[f"10.0.0.{i}"]))
        store.save_ip_enrichment(f"m{i}", {f"10.0.0.{i}": {"country": "DE"}})
    store.save_signal(ThreatSignal(signal_id="u", source_name="ThreatFox", title="u",
                                   malware_family="Unknown Loader"))
    store.save_signal(ThreatSignal(signal_id="n", source_name="https://news.example/feed", title="n"))
    store.save_signal(ThreatSignal(signal_id="r", source_name="ransomlook.io", title="r"))
    return store


def test_overview_counts_families_hosting_and_feed_kinds(tmp_path):
    store = _store(tmp_path)
    try:
        o = store.overview()
    finally:
        store.close()
    assert o["total"] == 28
    assert [f["family"] for f in o["families"]] == ["Mirai"]     # unlabelled families are left out
    assert o["top_hosted"] == [{"family": "Mirai", "signals": 25, "ips": 25, "country": "DE"}]
    assert {k["kind"]: k["n"] for k in o["feed_kinds"]} == {
        "Malware telemetry": 26, "News and advisories": 1, "Ransomware leak sites": 1}
    assert sum(r["n"] for r in o["runs"]) == 28


def test_overview_survives_source_hiding_and_names_no_feed(tmp_path):
    store = _store(tmp_path)
    try:
        out = _hide_sources(store.overview())
    finally:
        store.close()
    assert out["feed_kinds"] and out["latest"] and out["top_hosted"]
    text = json.dumps(out).lower()
    assert "threatfox" not in text and "ransomlook" not in text and "news.example" not in text


def test_hosting_needs_enough_ips_to_mean_anything(tmp_path):
    store = Store(str(tmp_path / "df.db"))
    try:
        store.save_signal(ThreatSignal(signal_id="a", source_name="ThreatFox", title="a",
                                       malware_family="Rare", ip_addresses=["10.0.0.1"]))
        store.save_ip_enrichment("a", {"10.0.0.1": {"country": "DE"}})
        assert store.overview()["top_hosted"] == []
    finally:
        store.close()


def test_every_mode_has_measured_rates():
    assert set(fingerprint.MEASURED_RATES) == set(fingerprint.RELIABILITY)
