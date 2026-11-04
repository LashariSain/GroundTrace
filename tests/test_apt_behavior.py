"""Behaviour fingerprints and likely-interest predictions."""
from groundtrace import apt_behavior as B

KEV = {
    "CVE-2018-13379": {"vendorProject": "Fortinet", "product": "FortiOS", "cwes": ["CWE-22"], "knownRansomwareCampaignUse": "Known"},
    "CVE-2022-40684": {"vendorProject": "Fortinet", "product": "FortiOS", "cwes": ["CWE-287"], "knownRansomwareCampaignUse": "Unknown"},
    "CVE-2021-26855": {"vendorProject": "Microsoft", "product": "Exchange Server", "cwes": ["CWE-918"], "knownRansomwareCampaignUse": "Known"},
}


def _link(cve, conf="high", day=""):
    return {"cve": cve, "confidence": conf, "evidence": [{"day": day}] if day else []}


def test_fingerprint_uses_strong_links_only():
    fp = B.fingerprint([_link("CVE-2018-13379", day="2019-06-01"), _link("CVE-2022-40684"),
                        _link("CVE-2021-26855", conf="low")], KEV,
                       [{"name": "Exploit Public-Facing Application", "tactics": ["initial-access"]}, {"name": "X", "tactics": ["execution"]}])
    assert fp["cves"] == 2 and fp["vendors"] == [["Fortinet", 2]]          # the low-confidence Exchange link is ignored
    assert [w[0] for w in fp["weaknesses"]] == ["CWE-22", "CWE-287"] and fp["weaknesses"][0][1] == "path traversal"
    assert fp["initial_access"] == ["Exploit Public-Facing Application"]
    assert fp["ransomware_share"] == 0.5 and fp["median_cve_age_years"] == 1


def test_likely_groups_product_and_vendor_rules():
    prints = {
        "fortinet-fan": B.fingerprint([_link("CVE-2018-13379"), _link("CVE-2022-40684")], KEV),
        "exchange-only": B.fingerprint([_link("CVE-2021-26855")], KEV),
    }
    # new FortiOS CVE via its CPE: product match for the Fortinet group only
    fortios = B.cve_products("CVE-2099-0001", KEV, ["cpe:2.3:o:fortinet:fortios:7.0.0:*:*:*:*:*:*:*"])
    hits = B.likely_groups(prints, fortios)
    assert [h["group"] for h in hits] == ["fortinet-fan"] and "this product" in hits[0]["why"]
    # another Fortinet product: vendor rule needs at least 2 CVEs from the vendor
    fortiweb = B.cve_products("CVE-2099-0002", {}, ["cpe:2.3:a:fortinet:fortiweb:7.0:*:*:*:*:*:*:*"])
    assert [h["group"] for h in B.likely_groups(prints, fortiweb)] == ["fortinet-fan"]
    assert "2 vulnerabilities from this vendor" in B.likely_groups(prints, fortiweb)[0]["why"]
    # a generic word ("server") must not make Exchange match another Microsoft server product
    sharepoint = B.cve_products("CVE-2099-0003", {}, ["cpe:2.3:a:microsoft:sharepoint_server:2019:*:*:*:*:*:*:*"])
    assert B.likely_groups(prints, sharepoint) == []
    # documented exploiters are excluded from predictions
    assert B.likely_groups(prints, fortios, exclude={"fortinet-fan"}) == []


def test_previously_exploited_is_a_record_not_a_forecast():
    """Groups named from past exploitation must not be framed as a prediction.

    Every other surface that names an actor carries a measured reliability.
    This one carries none, because it asserts no probability -- it reports
    documented past CVEs with a count. If it is ever reworded as a forecast it
    becomes a claim with no measured accuracy behind it, which is the thing the
    README promises the tool does not do.
    """
    from pathlib import Path

    from groundtrace import apt_behavior

    prints = {"g1": {"_products": [("fortinet", {"fortios"}, 3)],
                     "_vendor_counts": {"fortinet": 4}}}
    out = apt_behavior.likely_groups(prints, [("fortinet", {"fortios"})])
    assert out and out[0]["group"] == "g1"
    # The reason is a checkable count of past CVEs, not a likelihood.
    assert "has exploited" in out[0]["why"] and "3" in out[0]["why"]
    assert not {"probability", "likelihood", "confidence", "reliability"} & set(out[0])

    # No user-facing surface may call it a prediction.
    for path in (Path("groundtrace/apt_behavior.py"), Path("groundtrace/static/dashboard.html")):
        text = path.read_text(encoding="utf-8").lower()
        for phrase in ("likely interest (prediction)", "prediction from past behaviour",
                       "likely interest · prediction"):
            assert phrase not in text, (path.name, phrase)
