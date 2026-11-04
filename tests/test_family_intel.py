"""Family facts are evidence with a source; a name alone is not evidence."""
from darkfeeds.extractors import extract_threat_actor
from darkfeeds.models import ThreatSignal
from darkfeeds.store import Store
from groundtrace import family_intel as fi


def test_family_name_alone_does_not_link_a_group():
    assert not fi.names_actor("Akira", "Akira Stealer", "Akira Stealer abc123")
    assert not fi.names_actor("Rhysida", "Rhysida", "Rhysida abc123")
    assert not fi.names_actor("APT36 (Transparent Tribe)", "Crimsonrat", "Crimsonrat sample")
    assert fi.names_actor("APT36 (Transparent Tribe)", "RUSTYSHADE", "APT36 deploys RUSTYSHADE")
    assert fi.names_actor("APT36 (Transparent Tribe)", "Crimsonrat", "Transparent Tribe used Crimsonrat")


def test_akira_stealer_is_not_attributed_to_the_akira_group():
    assert extract_threat_actor("Akira Stealer abc") == ""
    assert extract_threat_actor("Akira ransomware hit a hospital") == "Akira"


def test_reported_groups_keep_only_supported_rows_and_newest_report():
    rows = [("APT36 (Transparent Tribe)", "APT36 uses X", "", "2026-10-01", "https://a"),
            ("APT36 (Transparent Tribe)", "APT36 again with X", "", "2026-10-09", "https://b"),
            ("Akira", "X sample", "", "2026-11-01", "https://c")]
    assert fi.reported_groups(rows, "X") == [{"group": "APT36 (Transparent Tribe)", "reports": 2,
                                              "last_reported": "2026-10-09", "url": "https://b"}]


def test_activity_is_relative_to_the_latest_collection():
    assert fi.activity("2026-11-04", "2026-11-04")["status"] == "active"
    assert fi.activity("2026-10-10", "2026-11-04")["status"] == "recent"
    assert fi.activity("2026-01-01", "2026-11-04")["status"] == "quiet"


def test_type_needs_the_name_or_a_majority_of_tags():
    assert fi.family_type("Mirai", [])["type"] == "Botnet / DDoS"
    assert fi.family_type("Zzz", [["stealer"], ["stealer"], []]) == {"type": "Infostealer", "basis": "feed tags"}
    assert fi.family_type("Zzz", [["stealer"], [], []])["type"] == ""


def test_threatfox_hashes_and_urls_in_text_are_counted(tmp_path):
    sha = "a" * 64
    store = Store(str(tmp_path / "df.db"))
    store.save_signal(ThreatSignal(signal_id="h", source_name="ThreatFox", title="t",
                                   malware_family="Fam", raw_text=f"Fam {sha} elf"))
    store.save_signal(ThreatSignal(signal_id="u", source_name="ThreatFox", title="t",
                                   malware_family="Fam", raw_text="Fam http://bad.example/x.bin elf"))
    store.save_signal(ThreatSignal(signal_id="x", source_name="ThreatFox", title="t",
                                   malware_family="Fam", raw_text=f"Fam http://bad.example/{'c' * 32} elf"))
    store.save_signal(ThreatSignal(signal_id="o", source_name="AlienVault OTX", title="t",
                                   malware_family="Fam", raw_text="b" * 64))
    try:
        ind = store.family_profile("Fam")["indicators"]
    finally:
        store.close()
    assert [i["value"] for i in ind["hash"]] == [sha]
    assert {i["value"] for i in ind["url"]} == {"http://bad.example/x.bin", f"http://bad.example/{'c' * 32}"}
