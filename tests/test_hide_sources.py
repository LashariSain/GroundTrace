"""The API never reveals which feeds intelligence came from."""
from groundtrace.api import _hide_sources


def test_feed_names_credits_and_index_pages_are_removed():
    out = _hide_sources({
        "source": "ThreatFox", "source_name": "ThreatFox", "source_url": "https://report.example/1",
        "credit": {"name": "x"}, "sources": [{"name": "MISP"}],
        "links": [{"url": "https://apt.etda.or.th/cgi-bin/showcard.cgi?u=1", "description": ""},
                  {"url": "https://vendor.example/report.pdf", "description": "report"}],
        "mitre": {"url": "https://attack.mitre.org/groups/G0134/", "techniques": [{"url": "https://attack.mitre.org/techniques/T1566/"}]},
    })
    assert out["source_url"] == "https://report.example/1"               # references stay
    assert not {"source", "source_name", "credit", "sources"} & set(out)
    assert [l["url"] for l in out["links"]] == ["https://vendor.example/report.pdf"]
    assert "url" not in out["mitre"] and out["mitre"]["techniques"][0]["url"].endswith("T1566/")


def test_ledger_feed_codes_become_generic_kinds():
    out = _hide_sources({"last_seen_source": "otx", "by_source": {"etda": 3, "ransomware": 1},
                         "evidence": [{"day": "2026-01-01", "source": "mitre", "title": "t"}]})
    assert out["last_seen_kind"] == "pulse" and out["by_kind"] == {"operation": 3, "leak-site": 1}
    assert out["evidence"][0]["kind"] == "campaign" and "source" not in out["evidence"][0]
    assert "last_seen_source" not in out and "by_source" not in out


def test_scoring_standards_and_archive_kinds():
    out = _hide_sources({"scores": {"explanation": {"factors": [{"source": "NVD"}]}},
                         "archives": [{"kind": "archive", "name": "Exploit-DB", "url": "u"}]})
    assert out["scores"]["explanation"]["factors"][0]["source"] == "NVD"  # CVSS/EPSS/KEV cite standards
    assert out["archives"][0]["name"] == "Exploit archive"


def test_feed_entry_pages_and_free_text_are_genericised():
    out = _hide_sources({
        "source_url": "https://threatfox.abuse.ch/ioc/1981964/",
        "refs": ["https://apt.etda.or.th/cgi-bin/listgroups.cgi?t=x", "https://vendor.example/a.pdf"],
        "detail": "AlienVault OTX: Attack from 1.2.3.4",
        "evidence": "2 source(s): https://feeds.feedburner.com/TheHackersNews, 682 repo(s) in PoC-in-GitHub",
    })
    assert "source_url" not in out and out["refs"] == ["https://vendor.example/a.pdf"]
    assert out["detail"] == "threat-intel pulse: Attack from 1.2.3.4"
    assert out["evidence"] == "2 source(s): news feed, 682 repo(s) in public PoC index"


def test_operations_card_gets_a_neutral_name():
    out = _hide_sources({"etda": {"slug": "x", "url": "https://apt.etda.or.th/x", "title": "T", "operations": [1]}})
    assert "etda" not in out and out["group_card"] == {"operations": [1]}


def test_dispatch_has_no_local_unquote_import():
    # A function-local `from urllib.parse import unquote` makes the name local
    # to all of _dispatch, so any earlier branch using it raises
    # UnboundLocalError (the IOC export endpoint did, with HTTP 500).
    import inspect
    from groundtrace.api import Handler
    assert "import unquote" not in inspect.getsource(Handler._dispatch)
