"""Risk scoring math and the derived fields on Finding/Scores/Disclosure."""
from datetime import date

import pytest

from groundtrace.models import Disclosure, Finding, Scores, explain_risk


def test_risk_combines_severity_exploitability_and_asset():
    # (cvss/10) * epss * asset_criticality * 100
    s = Scores(cvss=9.8, epss=0.5, asset_criticality=1.0)
    assert s.risk == round((9.8 / 10) * 0.5 * 1.0 * 100, 1)  # 49.0


def test_risk_uses_epss_fallback_when_missing():
    # EPSS absent -> 0.1 default, not treated as zero.
    assert Scores(cvss=10.0, epss=None).risk == 10.0


def test_risk_is_none_without_cvss():
    assert Scores(cvss=None, epss=0.9).risk is None


def test_kev_floors_exploit_likelihood():
    # KEV = observed in-the-wild exploitation, so a low EPSS must not sink an
    # actively-exploited CVE. Floor lifts a 9.8/EPSS-0.022 CVE from ~2 to ~88.
    low = Scores(cvss=9.8, epss=0.022, in_kev=False).risk
    kev = Scores(cvss=9.8, epss=0.022, in_kev=True).risk
    assert low < 5 and kev > 80


def test_kev_does_not_lower_an_already_high_risk():
    # A KEV CVE that already has high EPSS keeps its (higher) EPSS, not the floor.
    assert Scores(cvss=9.8, epss=0.99, in_kev=True).risk == Scores(cvss=9.8, epss=0.99).risk


def test_asset_criticality_scales_risk_down():
    full = Scores(cvss=8.0, epss=0.4, asset_criticality=1.0).risk
    half = Scores(cvss=8.0, epss=0.4, asset_criticality=0.5).risk
    assert half == round(full / 2, 1)


def test_to_dict_injects_derived_risk():
    f = Finding(cve_id="CVE-2024-0001", scores=Scores(cvss=7.5, epss=0.2))
    d = f.to_dict()
    assert d["scores"]["risk"] == Scores(cvss=7.5, epss=0.2).risk


def test_patch_available_and_leaked_before_fix():
    patched_first = Disclosure(disclosure_date=date(2024, 1, 10),
                               patch_date=date(2024, 1, 5))
    assert patched_first.patch_available_at_disclosure is True
    assert patched_first.leaked_before_fix is False

    leaked_first = Disclosure(disclosure_date=date(2024, 1, 5),
                              patch_date=date(2024, 1, 10))
    assert leaked_first.patch_available_at_disclosure is False
    assert leaked_first.leaked_before_fix is True


def test_disclosure_derivations_none_without_both_dates():
    only_disclosure = Disclosure(disclosure_date=date(2024, 1, 1))
    assert only_disclosure.patch_available_at_disclosure is None
    assert only_disclosure.leaked_before_fix is None


# --- bounds: a risk score the tool cannot justify is worse than no score ----

def test_risk_cannot_exceed_100_for_a_valid_input():
    # The worst real case tops out below 100, not above it.
    assert Scores(cvss=9.8, epss=0.95, asset_criticality=1.0, in_kev=True).risk == 93.1
    assert Scores(cvss=10.0, epss=1.0, asset_criticality=1.0).risk == 100.0


@pytest.mark.parametrize("bad", [3.0, 1.01, -0.5, -0.0001])
def test_out_of_range_criticality_is_rejected(bad):
    with pytest.raises(ValueError, match="asset_criticality"):
        Scores(cvss=9.8, asset_criticality=bad)


@pytest.mark.parametrize("ok", [0.0, 0.5, 1.0])
def test_in_range_criticality_is_accepted(ok):
    assert Scores(cvss=9.8, epss=0.5, asset_criticality=ok).risk is not None


def test_clamp_is_a_second_line_of_defence_and_is_disclosed():
    # CVSS is not range-validated (it comes from NVD), so the clamp still
    # has to hold -- and say when it applied, rather than quietly cap.
    bad = Scores(cvss=20.0, epss=1.0)
    assert bad.risk == 100.0
    assert bad.risk_clamped is True
    note = explain_risk(bad, "CVE-2021-44228")["note"]
    assert note and "200.0" in note and "capped" in note


def test_normal_scores_are_not_flagged_as_clamped():
    s = Scores(cvss=9.8, epss=0.95, in_kev=True)
    assert s.risk_clamped is False
    assert explain_risk(s, "CVE-2021-44228")["note"] is None


def test_cli_rejects_out_of_range_criticality_as_a_usage_error():
    # argparse type -> exit 2 with a usage message, not a traceback.
    from groundtrace.__main__ import main
    with pytest.raises(SystemExit) as e:
        main(["cve", "CVE-2021-44228", "--criticality", "3"])
    assert e.value.code == 2
