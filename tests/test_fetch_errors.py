"""The /analyze path must tell three outcomes apart: NVD unreachable (offline),
NVD reachable but no such published CVE, and a reserved CVE present only in the
CVE.org registry. Before, all three collapsed into one ambiguous None / "offline
or unknown CVE" message. These tests pin the distinction without any network."""
import pytest

from groundtrace import feeds
from groundtrace.pipeline import missing_cve_reason


def test_fetch_nvd_offline_raises(monkeypatch):
    # _get_json returns None on any network/parse failure.
    monkeypatch.setattr(feeds, "_get_json", lambda url: None)
    with pytest.raises(feeds.FeedUnavailable):
        feeds.fetch_nvd("CVE-2021-44228")


def test_fetch_nvd_reachable_but_unknown_returns_none(monkeypatch):
    # NVD answered, but with no matching CVE — that's "not found", not "offline".
    monkeypatch.setattr(feeds, "_get_json", lambda url: {"vulnerabilities": []})
    assert feeds.fetch_nvd("CVE-2026-109619") is None


def test_missing_reason_reserved(monkeypatch):
    monkeypatch.setattr(feeds, "fetch_cve_registry",
                        lambda cve: {"state": "RESERVED", "assigner": "php", "title": ""})
    msg = missing_cve_reason("CVE-2026-109619")
    assert "RESERVED" in msg and "php" in msg


def test_missing_reason_absent(monkeypatch):
    monkeypatch.setattr(feeds, "fetch_cve_registry", lambda cve: None)
    msg = missing_cve_reason("CVE-2026-109619")
    assert "not found" in msg.lower()


def test_missing_reason_registry_unreachable_falls_back(monkeypatch):
    def boom(cve):
        raise feeds.FeedUnavailable("down")
    monkeypatch.setattr(feeds, "fetch_cve_registry", boom)
    # Must not raise — degrade to the generic (still accurate) message.
    msg = missing_cve_reason("CVE-2026-109619")
    assert "CVE-2026-109619" in msg
