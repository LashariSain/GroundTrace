"""Alerts explain themselves, and stale ones are hidden rather than deleted."""
import json
from datetime import date

from groundtrace.alert_view import describe, feed

TODAY = date(2026, 11, 4)


def _alert(**kw):
    base = {"key": "kev:CVE-2026-1111", "kind": "kev", "title": "t", "detail": "", "url": "",
            "created_at": "2026-10-26T12:00:00+00:00", "delivered": '{"stderr": "ok"}'}
    return {**base, **kw}


def test_kev_alert_carries_due_date_and_cve_facts():
    d = describe(_alert(detail="X: flaw; added 2026-10-23, federal due date 2026-10-26"),
                 {"published": "2026-10-01", "affected": ["cpe:2.3:a:acme_co:gateway:1:*"],
                  "scores": {"cvss_severity": "HIGH", "cvss": 8.8, "epss": 0.5, "risk": 40.0}},
                 TODAY)
    assert (d["kev_added"], d["due_date"]) == ("2026-10-23", "2026-10-26")
    assert d["severity"] == "HIGH" and d["product"] == "acme co gateway"
    assert d["cve_id"] == "CVE-2026-1111" and not d["hidden"]
    assert d["headline"] == "flaw"


def test_mention_of_an_old_cve_is_hidden_with_a_reason():
    d = describe(_alert(key="underground:CVE-2015-3306", kind="underground",
                        detail="https://www.cisa.gov/uscert/ncas/alerts.xml: Advisory [HIGH 9.8]"),
                 {"published": "2015-05-18"}, TODAY)
    assert d["hidden"] and "old CVE" in d["hidden_reason"]


def test_public_advisory_is_not_called_underground_and_feed_is_not_named():
    d = describe(_alert(key="underground:CVE-2026-2222", kind="underground",
                        title="CVE-2026-2222 seen in underground source (vuln_discussion)",
                        detail="https://feeds.feedburner.com/TheHackersNews: Big flaw [HIGH 8.1]"),
                 {"published": "2026-10-20"}, TODAY)
    assert d["source_kind"] == "Security news" and "underground" not in d["title"]
    assert d["detail"] == "Big flaw" and "feedburner" not in json.dumps(d)
    assert not d["hidden"]


def test_old_alert_is_hidden_and_delivery_is_stated_plainly():
    d = describe(_alert(created_at="2026-08-01T00:00:00+00:00"), None, TODAY)
    assert d["hidden"] and d["delivery"] == "Printed on this machine only"
    d = describe(_alert(delivered='{"slack": "ok"}'), None, TODAY)
    assert d["delivery"] == "Sent to slack"


def test_small_limit_is_not_used_up_by_hidden_alerts():
    old = [(_alert(key=f"underground:CVE-2015-{1000 + i}", kind="underground"),
            {"published": "2015-01-01"}) for i in range(5)]
    d = feed(old + [(_alert(), None)], limit=5, today=TODAY)
    assert [a["key"] for a in d["results"]] == ["kev:CVE-2026-1111"]
    assert (d["relevant"], d["hidden"]) == (1, 5)
