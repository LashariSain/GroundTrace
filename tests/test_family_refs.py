"""Reference data: exact names only, credited, and never fetched on a page view."""
import json

from groundtrace import family_refs as fr

MALPEDIA = {
    "elf.mirai": {"common_name": "Mirai", "alt_names": ["Katana"], "description": "A botnet.",
                  "attribution": [], "urls": ["https://a.example/1", "javascript:alert(1)"]},
    "win.quiet": {"common_name": "Quiet", "alt_names": [], "description": "",
                  "attribution": ["APT1"], "urls": []},
    "win.other": {"common_name": "Other", "alt_names": ["Mirai"], "description": "Not it.",
                  "attribution": [], "urls": []},
}
MISP = {"tool": {"values": [
    {"value": "Quiet", "description": "From MISP.", "meta": {"refs": ["https://b.example"]}},
    {"value": "OnlyMisp", "description": "Misp only.", "meta": {"synonyms": ["OM"]}},
]}}


def _use(tmp_path, monkeypatch, malpedia=MALPEDIA, clusters=MISP):
    path = tmp_path / "family_index.json"
    path.write_text(json.dumps(fr.build_index(malpedia, clusters)), encoding="utf-8")
    monkeypatch.setattr(fr, "_index_path", lambda: path)
    monkeypatch.setattr(fr, "_index_mtime", None)
    monkeypatch.delenv("GROUNDTRACE_MALPEDIA", raising=False)


def test_own_name_beats_another_familys_alias(tmp_path, monkeypatch):
    _use(tmp_path, monkeypatch)
    assert fr.lookup("MIRAI")["description"] == "A botnet."
    assert fr.lookup("Katana")["name"] == "Mirai"


def test_only_web_links_are_kept_and_platform_comes_from_the_key(tmp_path, monkeypatch):
    _use(tmp_path, monkeypatch)
    entry = fr.lookup("Mirai")
    assert entry["refs"] == ["https://a.example/1"]
    assert entry["platforms"] == ["Linux"]
    assert entry["url"].endswith("/details/elf.mirai")


def test_misp_fills_a_missing_description_and_both_sources_are_credited(tmp_path, monkeypatch):
    _use(tmp_path, monkeypatch)
    entry = fr.lookup("Quiet")
    assert entry["description"] == "From MISP." and entry["description_source"] == "MISP Galaxy"
    assert entry["attribution"] == ["APT1"]
    assert {c["name"].split(",")[0] for c in entry["credits"]} == {"Malpedia (Fraunhofer FKIE)", "MISP Galaxy"}


def test_unknown_name_and_no_index_return_nothing(tmp_path, monkeypatch):
    _use(tmp_path, monkeypatch)
    assert fr.lookup("Nonexistent") is None
    monkeypatch.setattr(fr, "_index_path", lambda: tmp_path / "missing.json")
    assert fr.lookup("Mirai") is None


def test_malpedia_can_be_switched_off(tmp_path, monkeypatch):
    _use(tmp_path, monkeypatch)
    monkeypatch.setenv("GROUNDTRACE_MALPEDIA", "0")
    assert fr.lookup("Mirai") is None
    assert fr.lookup("OnlyMisp")["source"] == "MISP Galaxy"
    quiet = fr.lookup("Quiet")  # also in Malpedia: still served, from the open data alone
    assert quiet["description"] == "From MISP." and quiet["attribution"] == []
    assert {c["name"] for c in quiet["credits"]} == {"MISP Galaxy, CC0 / BSD"}


def test_refresh_keeps_the_old_index_when_downloads_fail(tmp_path, monkeypatch):
    _use(tmp_path, monkeypatch)
    before = (tmp_path / "family_index.json").read_text(encoding="utf-8")
    monkeypatch.setattr(fr, "_fetch", lambda url: None)
    assert fr.refresh(force=True) is False
    # One source failing is enough: Malpedia's data must not vanish for a week.
    monkeypatch.setattr(fr, "_fetch", lambda url: None if url == fr.MALPEDIA_URL else {"values": []})
    assert fr.refresh(force=True) is False
    assert (tmp_path / "family_index.json").read_text(encoding="utf-8") == before
