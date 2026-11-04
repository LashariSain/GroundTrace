"""The focus country is opt-in, local, and safe when misconfigured."""
import json

from darkfeeds import focus


def _file(tmp_path, monkeypatch, body):
    path = tmp_path / "focus.json"
    path.write_text(body, encoding="utf-8")
    monkeypatch.setenv("GROUNDTRACE_FOCUS_FILE", str(path))


def test_off_without_a_file(tmp_path, monkeypatch):
    monkeypatch.setenv("GROUNDTRACE_FOCUS_FILE", str(tmp_path / "missing.json"))
    assert focus.get().country == ""
    assert focus.relevance("anything at all") == 0
    assert focus.target(1.0) == ""


def test_scores_and_labels_from_the_file(tmp_path, monkeypatch):
    _file(tmp_path, monkeypatch, json.dumps({"country": "Exampleland", "code": "ex",
                                             "signals": [["(?i)exampleland", 0.4], ["capital", 0.9]]}))
    assert focus.get().code == "EX"
    assert focus.relevance("EXAMPLELAND") == 0.4
    assert focus.relevance("exampleland capital") == 1.0
    assert focus.target(0.4) == "exampleland"
    assert focus.target(0.1) == ""


def test_broken_file_is_ignored(tmp_path, monkeypatch):
    for body in ("{not json", json.dumps({"country": "x", "signals": [["(", 1]]})):
        _file(tmp_path, monkeypatch, body)
        assert focus.get().country == ""
