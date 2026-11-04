"""The accuracy harness itself.

README.md quotes this script's output as the tool's headline claim, so its
logic needs the same protection as the code it measures. These tests cover the
parts that do not need a catalogue: the fit/report split, the metric
arithmetic, and the macro average that keeps one large group from setting the
figure.
"""
import importlib.util
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "validate_footprints", Path(__file__).resolve().parents[1] / "scripts" / "validate_footprints.py")
V = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)


def test_split_is_deterministic_and_covers_both_halves():
    keys = [f"group-{i}" for i in range(400)]
    first = [V.half(k, 20261030, 0.7) for k in keys]
    again = [V.half(k, 20261030, 0.7) for k in keys]
    assert first == again                      # same seed, same partition
    assert set(first) == {"fit", "report"}
    fit = first.count("fit") / len(first)
    assert 0.6 < fit < 0.8                     # roughly the requested fraction


def test_a_different_seed_gives_a_different_split():
    keys = [f"group-{i}" for i in range(200)]
    a = [V.half(k, 1, 0.7) for k in keys]
    b = [V.half(k, 2, 0.7) for k in keys]
    assert a != b


def test_summarise_arithmetic():
    s = {"n": 100, "surfaced": 40, "correct": 30, "wrong": 10,
         "per_group": {"g1": [20, 15], "g2": [20, 15]}}
    m = V.summarise(s)
    assert m["tests"] == 100 and m["surfaced"] == 40
    assert m["precision"] == 0.75              # 30 of 40 surfaced
    assert m["wrong_group_rate"] == 0.10       # 10 of 100 tests
    assert m["abstention"] == 0.60             # 60 of 100 never surfaced
    assert m["correct_matches"] == 30
    assert m["macro_precision"] == 0.75
    assert m["groups_scored"] == 2


def test_macro_average_is_not_dominated_by_one_large_group():
    """The LabHost lesson, as a test.

    One group holding most of the catalogue must not set the headline. The big
    group is right 20% of the time and the two small ones 80%. Pooling drags
    the figure to 0.26; the macro average weights each group equally and
    reports 0.60, which is what the catalogue actually supports.
    """
    s = {"n": 1000, "surfaced": 1000, "correct": 260, "wrong": 740,
         "per_group": {"huge": [900, 180], "a": [50, 40], "b": [50, 40]}}
    m = V.summarise(s)
    assert m["precision"] == 0.26
    assert round(m["macro_precision"], 2) == 0.60


def test_summarise_handles_a_total_abstention():
    m = V.summarise({"n": 50, "surfaced": 0, "correct": 0, "wrong": 0, "per_group": {}})
    assert m["precision"] is None and m["macro_precision"] is None
    assert m["abstention"] == 1.0 and m["groups_scored"] == 0


def test_thresholds_match_the_shipped_scoring():
    from groundtrace import fingerprint
    assert V.STRICT == fingerprint.MIN_SCORE_STRICT
    assert V.BROAD == fingerprint.MIN_SCORE_BROAD


def test_published_defaults_are_the_ones_readme_quotes():
    """The documented command must reproduce the documented numbers.

    README.md tells a reader to run the script with no arguments. If the
    defaults drift from the values the published figures were measured with,
    that reader gets different numbers and reasonably concludes the README is
    dishonest.
    """
    root = Path(__file__).resolve().parents[1]
    src = (root / "scripts" / "validate_footprints.py").read_text(encoding="utf-8")
    assert '"--sample", type=int, default=1500' in src
    assert '"--per-group", type=int, default=15' in src
    readme = (root / "README.md").read_text(encoding="utf-8")
    assert "max 15/group" in readme and "867 tests" in readme
