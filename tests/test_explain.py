from groundtrace.models import Scores, explain_risk


def _product(ex):
    v = 100.0
    for f in ex["factors"]:
        v *= f["value"]
    return round(v, 1)


def test_factors_multiply_to_the_score():
    s = Scores(cvss=7.5, cvss_severity="HIGH", epss=0.42)
    ex = explain_risk(s, "CVE-2024-0001")
    assert ex["result"] == s.risk == _product(ex)
    assert [f["source"] for f in ex["factors"]] == ["NVD", "FIRST EPSS", "your config"]
    assert ex["factors"][0]["url"] == "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"


def test_kev_floor_is_explained_and_cited():
    s = Scores(cvss=9.8, epss=0.02, in_kev=True)
    ex = explain_risk(s, "CVE-2024-0002")
    lik = ex["factors"][1]
    assert lik["value"] == 0.9 and lik["source"] == "CISA KEV"
    assert "floor" in lik["basis"]
    assert ex["result"] == s.risk == _product(ex)


def test_missing_epss_uses_stated_default():
    ex = explain_risk(Scores(cvss=5.0), "CVE-2024-0003")
    assert ex["factors"][1]["value"] == 0.1 and ex["factors"][1]["source"] == "default"


def test_unscored_cve_says_why():
    ex = explain_risk(Scores(), "CVE-2024-0004")
    assert ex["result"] is None and ex["factors"] == [] and "CVSS" in ex["note"]
