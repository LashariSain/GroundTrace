from datetime import datetime, timezone

from groundtrace import poc

NOW = datetime(2026, 10, 26, tzinfo=timezone.utc)
CVE = "CVE-2024-36401"


def _repo(name, desc="PoC for CVE-2024-36401", stars=10, created="2024-07-04T00:00:00Z", fork=False):
    return {"full_name": name, "html_url": f"https://github.com/{name}", "description": desc,
            "stargazers_count": stars, "forks_count": 0, "created_at": created,
            "pushed_at": created, "fork": fork}


def test_clean_repo_has_no_flags():
    assert poc.red_flags(_repo("a/CVE-2024-36401"), CVE, NOW) == []


def test_lure_is_flagged_and_newness_is_only_a_note():
    r = _repo("x/exploit", desc="Working 0day, get the .rar, password inside",
              stars=0, created="2026-10-24T00:00:00Z")
    flags = poc.red_flags(r, CVE, NOW)
    assert any("malware-lure" in f for f in flags)
    assert any("may be unrelated" in f for f in flags)
    assert not any("new" in f for f in flags)
    assert any("not yet vetted" in n for n in poc.notes(r, NOW))


def test_legitimate_patch_and_lab_repos_are_not_called_lures():
    for desc in ["Patched PHP 7.4 RPMs for CentOS 7 fixing CVE-2024-36401; download from releases",
                 "Educational lab demonstrating HTTP upload handling and password reset for CVE-2024-36401",
                 "Setup script and installer for the CVE-2024-36401 mitigation"]:
        assert poc.red_flags(_repo("a/CVE-2024-36401-x", desc=desc), CVE, NOW) == [], desc


def test_archive_links_only_match_known_hosts():
    refs = ["https://www.exploit-db.com/exploits/52000", "https://example.com/exploit-db.com",
            "http://packetstormsecurity.com/files/1/x.html", "https://nvd.nist.gov/x"]
    out = poc.archive_links(refs)
    assert [o["name"] for o in out] == ["Exploit-DB"]


def test_find_pocs_merges_dedups_and_ranks(monkeypatch):
    poc._cache.clear()
    good = _repo("a/CVE-2024-36401", stars=5)
    popular_flagged = _repo("b/CVE-2024-36401", stars=500, fork=True)

    def fake_get(url, headers):
        if "nomi-sec" in url:
            return [good]
        return {"items": [good, popular_flagged, {"html_url": "javascript:alert(1)"}]}

    monkeypatch.setattr(poc, "_get", fake_get)
    r = poc.find_pocs(CVE.lower())
    names = [x["name"] for x in r["repos"]]
    assert names == ["a/CVE-2024-36401", "b/CVE-2024-36401"]   # unflagged first, deduped
    assert r["repos"][0]["source"] == "PoC-in-GitHub"
    assert "nothing was downloaded" in r["warning"]


def test_search_failure_is_reported_not_cached(monkeypatch):
    poc._cache.clear()
    monkeypatch.setattr(poc, "_get", lambda url, headers: None)
    r = poc.find_pocs(CVE)
    assert r["repos"] == [] and r["errors"]
    assert CVE not in poc._cache


import pytest


@pytest.fixture(autouse=True)
def _no_exploitdb(monkeypatch):
    # find_pocs also queries Exploit-DB; keep these tests offline.
    from groundtrace import exploitdb
    monkeypatch.setattr(exploitdb, "exploits_for", lambda cve, live=False: [])
