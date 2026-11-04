from darkfeeds import enrich
from darkfeeds.models import ThreatSignal
from darkfeeds.store import Store


def test_duplicate_signal_is_not_reported_new(tmp_path):
    store = Store(str(tmp_path / "s.db"))
    a = ThreatSignal(signal_id="sig-a", source_name="t", title="a", raw_text="a")
    b = ThreatSignal(signal_id="sig-b", source_name="t", title="b", raw_text="b")
    assert store.save_signal(a) is True
    assert store.save_signal(b) is True
    # Before the fix, total_changes (cumulative) made duplicates look new.
    assert store.save_signal(a) is False
    assert store.save_signals([a, b]) == 0


def test_cymru_covers_bulk_and_rdap_is_capped(monkeypatch):
    enrich._cache.clear()
    ips = [f"8.8.{i // 250}.{i % 250 + 1}" for i in range(60)]
    placed = {ip: {"asn": "15169", "as_name": "GOOGLE", "country": "US"} for ip in ips[:50]}
    cymru_calls, rdap_calls = [], []
    monkeypatch.setattr(enrich, "_cymru_asn_lookup", lambda batch: cymru_calls.append(batch) or placed)
    monkeypatch.setattr(enrich, "_rdap", lambda ip: rdap_calls.append(ip) or enrich.IPEnrichment(ip=ip))

    out = enrich.enrich_ips(ips + ["10.0.0.1"], rdap_budget=4)
    assert len(cymru_calls) == 1 and "10.0.0.1" not in cymru_calls[0]   # private IPs skipped
    assert rdap_calls == ips[50:54]           # only unplaced IPs, and only up to the budget
    assert {r.country for r in out[:50]} == {"US"}
    assert out[-1].skipped_reason
