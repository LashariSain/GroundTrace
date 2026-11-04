from datetime import date

from groundtrace import radar
from groundtrace.models import Finding, Scores
from groundtrace.store import FindingStore

TODAY = date(2026, 10, 26)
PHP2SHELL = {"cve_id": "CVE-2026-109618", "title": "PHP OOM flaw", "published": "2026-10-21",
             "cvss": 9.8, "cvss_severity": "CRITICAL", "epss": 0.9998}
# Real FIRST time-series for PHP2Shell, newest first.
SERIES = [("2026-10-25", 0.99981), ("2026-10-24", 0.11841), ("2026-10-23", 0.1162), ("2026-10-22", 0.05307)]


def test_php2shell_shape_scores_high_with_evidence():
    mentions = {"sources": {"BleepingComputer", "The Hacker News"}, "items": []}
    repos = [{"created_at": "2026-10-18T00:00:00Z"}] + [{"created_at": "2026-10-22T00:00:00Z"}] * 20
    e = radar.score_entry(PHP2SHELL, SERIES, mentions, repos, TODAY)
    pts = {c["name"]: c["points"] for c in e["components"]}
    assert pts["EPSS level"] == 35.0
    assert pts["EPSS momentum"] == 25.0                      # +0.947 in a week, capped
    assert pts["Chatter"] == 14.0                            # 2 sources × 7
    assert pts["Public PoCs"] == 20.0
    assert e["score"] == 94.0
    # Full data: the whole scale applied, and the entry is ranked -- but no
    # band is assigned, because nothing has been calibrated to predict.
    assert e["level"] == "ranked"
    assert e["points_available"] == 100 and e["coverage"] == 1.0
    assert e["unmeasured"] == []
    assert e["score_of_available"] == 94.0
    assert e["poc_before_publication"] is True               # PoC dated 18th, published 21st
    momentum = next(c for c in e["components"] if c["name"] == "EPSS momentum")
    assert "0.0531 on 2026-10-22" in momentum["evidence"]


def test_quiet_cve_ranks_low_without_a_band():
    quiet = dict(PHP2SHELL, cve_id="CVE-2026-0001", epss=0.01)
    e = radar.score_entry(quiet, [("2026-10-25", 0.01), ("2026-10-19", 0.01)], {}, [], TODAY)
    assert e["score"] < 5 and e["level"] == "ranked"
    assert not e["poc_before_publication"]


def test_short_history_is_unmeasured_not_zero():
    """A missing measurement must never be scored as a zero measurement."""
    e = radar.score_entry(PHP2SHELL, [], {}, [], TODAY)
    momentum = next(c for c in e["components"] if c["name"] == "EPSS momentum")
    assert momentum["available"] is False and momentum["points"] == 0
    assert "not measurable" in momentum["evidence"]
    # 25 of the 100 points could not be assessed, so they leave the scale.
    assert "EPSS momentum" in e["unmeasured"]
    assert e["points_available"] == 75 and e["coverage"] == 0.75


def test_failed_poc_lookup_is_not_evidence_of_absence():
    """repos=None means the lookup failed, which is not "no PoC exists"."""
    e = radar.score_entry(PHP2SHELL, SERIES, {}, None, TODAY)
    poc = next(c for c in e["components"] if c["name"] == "Public PoCs")
    assert poc["available"] is False and poc["points"] == 0
    assert "unknown" in poc["evidence"]
    assert e["poc_before_publication"] is False       # unknown, so not claimed
    assert e["points_available"] == 80 and "Public PoCs" in e["unmeasured"]
    # An empty list is different: the index answered and listed none.
    e2 = radar.score_entry(PHP2SHELL, SERIES, {}, [], TODAY)
    poc2 = next(c for c in e2["components"] if c["name"] == "Public PoCs")
    assert poc2["available"] is True and "no public PoC indexed" in poc2["evidence"]


def test_too_little_coverage_is_insufficient_not_low():
    e = radar.score_entry(dict(PHP2SHELL, epss=None), [], {}, None, TODAY)
    assert e["level"] == "insufficient"
    assert e["coverage"] < radar.MIN_COVERAGE
    assert sorted(e["unmeasured"]) == ["EPSS level", "EPSS momentum", "Public PoCs"]


def test_the_prediction_claim_is_gone():
    """The plan's exit test for Phase 4.1.

    The module docstring still explains why the band was removed -- that is
    documentation, not a claim. What must not exist is code that assigns one.
    """
    assert not hasattr(radar, "HOT") and not hasattr(radar, "WARMING")
    levels = {radar._level(c / 100) for c in range(0, 101)}
    assert levels == {"ranked", "insufficient"}
    # No scoring path may emit a band, whatever the inputs.
    for epss in (None, 0.01, 0.5, 0.9998):
        for repos in (None, [], [{"created_at": "2026-10-18T00:00:00Z"}] * 30):
            e = radar.score_entry(dict(PHP2SHELL, epss=epss), SERIES,
                                  {"sources": {"a", "b", "c"}}, repos, TODAY)
            assert e["level"] in ("ranked", "insufficient"), e["level"]


def test_candidates_exclude_kev_and_include_mentioned_old_cves(tmp_path):
    s = FindingStore(str(tmp_path / "f.db"))
    old = Finding(cve_id="CVE-2020-1111", published=date(2020, 1, 1), scores=Scores(cvss=7.0))
    new = Finding(cve_id="CVE-2026-2222", published=date(2026, 10, 20), scores=Scores(cvss=7.0))
    kev = Finding(cve_id="CVE-2026-3333", published=date(2026, 10, 20), scores=Scores(cvss=7.0))
    kev.disclosure.in_kev = True
    s.save_findings([old, new, kev], s.start_run("t"))
    ids = lambda extra: sorted(r["cve_id"] for r in s.radar_candidates("2026-09-26", extra))  # noqa: E731
    assert ids([]) == ["CVE-2026-2222"]
    assert ids(["CVE-2020-1111", "CVE-2026-3333"]) == ["CVE-2020-1111", "CVE-2026-2222"]


# --- alert triggers: facts, not thresholds on an invented score -------------

def _entry(**over):
    e = radar.score_entry(PHP2SHELL, SERIES, {}, [], TODAY)
    e.update(over)
    return e


def test_alert_triggers_require_a_checkable_fact():
    from groundtrace.watch import _radar_triggers
    # High score alone is not a reason: the old gate was score >= 60.
    quiet = radar.score_entry(dict(PHP2SHELL, epss=0.5), [("2026-10-25", 0.5)], {}, [], TODAY)
    assert quiet["score"] > 0 and _radar_triggers(quiet) == []

    # A PoC predating publication is a fact.
    early = radar.score_entry(PHP2SHELL, [("2026-10-25", 0.5)], {},
                              [{"created_at": "2026-10-18T00:00:00Z"}], TODAY)
    assert any("before NVD published" in w for w in _radar_triggers(early))

    # EPSS at or above 0.9 while absent from KEV is a fact.
    hot_epss = radar.score_entry(PHP2SHELL, [("2026-10-25", 0.99)], {}, [], TODAY)
    assert any("90%" in w for w in _radar_triggers(hot_epss))


def test_small_epss_rise_does_not_alert():
    from groundtrace.watch import _radar_triggers, _EPSS_RISE_ALERT
    tiny = radar.score_entry(dict(PHP2SHELL, epss=0.01),
                             [("2026-10-25", 0.0102), ("2026-10-20", 0.01)], {}, [], TODAY)
    mom = next(c for c in tiny["components"] if c["name"] == "EPSS momentum")
    assert mom["available"] and 0 < mom["rise"] < _EPSS_RISE_ALERT
    assert _radar_triggers(tiny) == []        # a rise of 0.0002 is not news

    big = radar.score_entry(dict(PHP2SHELL, epss=0.3),
                            [("2026-10-25", 0.30), ("2026-10-20", 0.10)], {}, [], TODAY)
    assert any("rose" in w for w in _radar_triggers(big))


def test_unmeasured_momentum_never_triggers():
    from groundtrace.watch import _radar_triggers
    e = radar.score_entry(dict(PHP2SHELL, epss=0.1), [], {}, None, TODAY)
    mom = next(c for c in e["components"] if c["name"] == "EPSS momentum")
    assert mom["available"] is False and mom["rise"] is None
    assert not any("rose" in w for w in _radar_triggers(e))
