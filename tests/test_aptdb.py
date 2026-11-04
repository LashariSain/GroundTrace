"""APT catalog: compaction, alias resolution, tool attribution, live layer."""
import json
import sqlite3

import pytest

from groundtrace import aptdb
from darkfeeds.store import Store


def _feature(uuid, name, aliases, country, targets, tools, related=()):
    return {"type": "Feature", "geometry": {"type": "Point", "coordinates": [70.0, 30.0]},
            "properties": {
                "uuid": uuid, "name": name, "other-names": aliases, "country": country,
                "location": country, "sponsor": "", "motivations": ["Espionage"], "first-seen": "2013",
                "description": f"{name} description", "targets": targets,
                "target-category": ["Military"], "TTP": [{"techniqueID": "T1566"}],
                "tools": [{"value": t, "category": c, "description": "No description available yet.",
                           "refs": []} for t, c in tools],
                "ext-links": [{"url": "https://example.com/report.pdf", "description": ""},
                              {"url": "javascript:alert(1)"}],
                "sources": [{"name": "MISP", "url": "https://www.misp-project.org/"}],
                "related": [{"dest-uuid": r, "type": "similar",
                             "tags": ['estimative-language:likelihood-probability="likely"']} for r in related],
                "otx_iocs": [{"type": "IPv4", "value": "45.1.2.3"}],
                "attribution-confidence": "50"}}


APT36 = "acbb5cad-ffe7-4b0e-a57a-2dbc916e8905"
SIDE = "11111111-2222-3333-4444-555555555555"


@pytest.fixture
def catalog(tmp_path, monkeypatch):
    raw, idx = tmp_path / "aptmap.json", tmp_path / "apt_index.json"
    raw.write_text(json.dumps({"type": "FeatureCollection", "features": [
        _feature(APT36, "Operation C-Major", ["APT36", "Transparent Tribe", "Mythic Leopard"], "PK",
                 ["India", "Afghanistan", "Korea (Republic of)", "NATO"],
                 [("CrimsonRAT", "Malware"), ("Vidar", "Malware"), ("Mimikatz", "Tools")], related=[SIDE]),
        _feature(SIDE, "RAZOR TIGER", ["SideWinder"], "IN", ["Pakistan"],
                 [("Vidar", "Malware"), ("WarHawk", "Malware")]),
    ]}), encoding="utf-8")
    aptdb.build_index(raw, idx)
    monkeypatch.setattr(aptdb, "_index_path", lambda: idx)
    monkeypatch.setattr(aptdb, "_index_mtime", None)
    return idx


def test_compact_profile_fields(catalog):
    g = aptdb.resolve("APT36")
    assert g["name"] == "Operation C-Major" and g["country"] == "PK"
    assert g["target_ccs"] == ["AF", "IN", "KR"]            # NATO stays text-only
    assert "NATO" in g["targets"] and g["ttps"] == ["T1566"]
    assert [l["url"] for l in g["links"]] == ["https://example.com/report.pdf"]  # no javascript:
    assert g["related"] == [{"uuid": SIDE, "type": "similar", "likelihood": "likely", "name": "RAZOR TIGER"}]
    assert g["otx_ips"] == ["45.1.2.3"] and g["attribution_confidence"] == 50
    assert g["tools"][0]["description"] == ""               # placeholder text dropped


def test_alias_resolution_handles_combined_labels(catalog):
    for name in ("Transparent Tribe", "mythic leopard", "APT36 (Transparent Tribe)", "Operation “C-Major”"):
        assert aptdb.resolve(name)["uuid"] == APT36
    assert aptdb.resolve("SideWinder / Rattlesnake")["uuid"] == SIDE
    assert aptdb.resolve("nobody") is None


def test_only_exclusive_non_commodity_malware_attributes(catalog):
    assert [g["uuid"] for g in aptdb.groups_for_tool("crimsonrat")] == [APT36]
    assert aptdb.groups_for_tool("Vidar") == []      # shared and commodity
    assert aptdb.groups_for_tool("Mimikatz") == []   # a tool, not malware


def test_live_activity_direct_and_via_tooling(catalog, tmp_path):
    db = str(tmp_path / "s.db")
    Store(db).close()
    con = sqlite3.connect(db)
    rows = [("s1", "APT36 (Transparent Tribe)", "", '["CVE-2024-1"]', "pakistan", "2026-10-26T10:00:00",
             json.dumps({"9.9.9.9": {"country": "nl", "asn": "1", "org": "Host"}})),
            ("s2", "", "CrimsonRAT", "[]", "", "2026-10-01T10:00:00", "{}"),
            ("s3", "", "Vidar", "[]", "", "2026-10-26T10:00:00", "{}")]
    for sid, actor, fam, cves, tc, ts, enr in rows:
        con.execute("INSERT INTO signals (signal_id, signal_type, priority, source, source_name, title, "
                    "threat_actor, malware_family, cve_ids, target_country, collected_at, ip_enrichment) "
                    "VALUES (?, 'x', 'P3', 'otx', 'OTX', 't', ?, ?, ?, ?, ?, ?)",
                    (sid, actor, fam, cves, tc, ts, enr))
    con.commit()
    con.close()
    live = aptdb.live_activity(db)
    a = live[APT36]
    assert (a["signals"], a["direct"], a["via_tooling"], a["last_7d"]) == (2, 1, 1, 1)
    assert a["status"] == "active" and a["cves"] == ["CVE-2024-1"]
    assert a["infra"][0]["cc"] == "NL" and a["targets"] == [("Pakistan", 1)]
    assert SIDE not in live                           # Vidar attributed to nobody
    from groundtrace import apt_sightings
    ledger = str(tmp_path / "apt.db")
    con = apt_sightings.connect(ledger)
    assert apt_sightings.collect_feeds(con, db) == 2      # s1 direct + s2 via CrimsonRAT; Vidar dropped
    con.close()
    s = aptdb.summary(db, ledger=ledger)
    top = s["groups"][0]
    assert top["uuid"] == APT36 and top["last_seen"] == "2026-10-26" and top["sightings"] == 2
    assert s["origins"] == {"PK": 1, "IN": 1}


def test_activity_last_seen_regions_and_status(catalog, tmp_path):
    from datetime import date
    from groundtrace import apt_sightings as S
    con = S.connect(str(tmp_path / "apt.db"))
    S.record(con, [
        {"key": "a", "group_key": APT36, "day": "2026-10-20", "source": "otx", "countries": ["IN"],
         "sectors": ["Defense"], "title": "new pulse", "url": "https://otx.alienvault.com/pulse/1"},
        {"key": "b", "group_key": APT36, "day": "2026-10-25", "source": "feed", "countries": ["AF"],
         "inferred": True, "title": "CrimsonRAT C2"},
        {"key": "c", "group_key": APT36, "day": "2024-01-10", "source": "mitre", "title": "old campaign"},
        {"key": "a", "group_key": APT36, "day": "2026-10-20", "source": "otx"},          # duplicate key
    ])
    a = S.activity(con, APT36, today=date(2026, 10, 28))
    assert a["sightings"] == 3
    assert a["last_seen"] == "2026-10-20" and a["last_seen_source"] == "otx"   # named beats inferred
    assert a["first_seen"] == "2024-01-10"
    assert dict(a["regions_recent"]) == {"IN": 1, "AF": 1} and a["sectors_recent"] == [("Defense", 1)]
    assert a["by_source"] == {"otx": 1, "feed": 1, "mitre": 1}
    assert aptdb.status_for(8) == "active" and aptdb.status_for(100) == "recent"
    assert aptdb.status_for(400) == "dormant" and aptdb.status_for(None) == "catalog"


def test_news_matching_ignores_company_aliases_and_countries(catalog, tmp_path):
    from groundtrace import apt_sightings as S
    db = str(tmp_path / "s.db")
    Store(db).close()
    con = sqlite3.connect(db)
    for sid, title in (("n1", "Transparent Tribe hits India and Afghanistan"),
                       ("n2", "transparent tribe of words in lowercase prose")):
        con.execute("INSERT INTO signals (signal_id, signal_type, priority, source, source_name, title, "
                    "collected_at) VALUES (?, 'general_intel', 'P4', 'rss', "
                    "'https://www.bleepingcomputer.com/feed/', ?, '2026-10-26T00:00:00')", (sid, title))
    con.commit()
    con.close()
    led = S.connect(str(tmp_path / "apt.db"))
    assert S.collect_feeds(led, db) == 1                     # case-sensitive: only n1
    row = led.execute("SELECT * FROM sightings").fetchone()
    assert row["source"] == "news" and json.loads(row["countries"]) == []   # news never sets regions


def test_graph_merges_tools_and_dedups_relations(catalog):
    g = aptdb.graph()
    kinds = {n["id"]: n for n in g["nodes"]}
    vidar = kinds["tool:vidar"]
    assert vidar["users"] == 2 and vidar["kind"] == "tool"          # shared tool = one hub node
    uses = [l for l in g["links"] if l["type"] == "uses"]
    assert len(uses) == 5                                           # 3 tools + 2 tools
    rel = [l for l in g["links"] if l["type"] != "uses"]
    assert len(rel) == 1 and rel[0]["likelihood"] == "likely"       # A->B listed once


def test_apt_cve_links_from_every_source(catalog, tmp_path):
    from groundtrace import apt_cve
    attack = tmp_path / "attack.json"
    attack.write_text(json.dumps({"objects": [
        {"type": "intrusion-set", "id": "intrusion-set--1", "name": "Transparent Tribe", "aliases": ["APT36"],
         "description": "Group profile."},
        {"type": "attack-pattern", "id": "attack-pattern--1",
         "external_references": [{"source_name": "mitre-attack", "url": "https://attack.mitre.org/techniques/T1203/"}]},
        {"type": "relationship", "id": "relationship--1", "relationship_type": "uses", "source_ref": "intrusion-set--1", "target_ref": "attack-pattern--1",
         "description": "[Transparent Tribe](https://attack.mitre.org/groups/G0134) has exploited CVE-2012-0158 in documents.(Citation: X)"},
    ]}), encoding="utf-8")
    cards = [{"title": "Transparent Tribe, APT 36", "names": [], "operations": [
        {"day": "2020-03-01", "text": "Spear-phishing using CVE-2017-0199 against Indian targets.", "url": "https://r.example/1"}]}]
    links = apt_cve.collect(None, str(attack), cards)
    by = {(l["cve"], l["kind"]): l for l in links}
    t = by[("CVE-2012-0158", "technique")]
    assert t["confidence"] == "high" and t["evidence"] == "Transparent Tribe has exploited CVE-2012-0158 in documents."
    assert t["url"].endswith("T1203/")                                  # citation and markdown link removed
    assert by[("CVE-2017-0199", "operation")]["day"] == "2020-03-01"
    con = apt_cve.connect(str(tmp_path / "apt.db"))
    assert apt_cve.rebuild(con, links) == len(links)
    g = apt_cve.groups_for_cve(con, "cve-2017-0199")[0]
    assert g["group"] == APT36 and g["confidence"] == "high" and g["last_dated"] == "2020-03-01"
    assert {c["cve"] for c in apt_cve.cves_for_group(con, APT36)} == {"CVE-2012-0158", "CVE-2017-0199"}


def test_sentence_window_centres_on_the_cve():
    from groundtrace.apt_cve import _sentence
    long = "Intro sentence. " + "word " * 80 + "the group exploited CVE-2021-26855 in Exchange " + "tail " * 80 + ". Next."
    s = _sentence(long, "CVE-2021-26855")
    assert "CVE-2021-26855" in s and s.startswith("…") and len(s) <= 245 and not s[1].isspace()


def test_otx_sweep_backs_off_when_unreachable(catalog, tmp_path, monkeypatch):
    from groundtrace import apt_sightings as S
    calls = []
    monkeypatch.setattr(S, "_otx_search", lambda term, key, limit=20: calls.append(term))  # None = unreachable
    monkeypatch.setattr(S.time, "sleep", lambda s: None)
    con = S.connect(str(tmp_path / "apt.db"))
    assert S.sweep_otx(con, "key", groups_per_run=2) == 0
    assert len(calls) == 1                                   # stopped at the first failure, not every term
    pos = con.execute("SELECT value FROM sweep_state WHERE name = 'otx_pos'").fetchone()
    assert pos is None or pos[0] == "0"                      # nothing skipped: resumes from the same group
    monkeypatch.setattr(S, "_otx_search", lambda term, key, limit=20: [])   # reachable, no hits
    S.sweep_otx(con, "key", groups_per_run=1)
    assert con.execute("SELECT value FROM sweep_state WHERE name = 'otx_pos'").fetchone()[0] == "1"


def test_concurrent_first_runs_download_once(tmp_path, monkeypatch):
    """Two first-run callers shared one temp file, which fails on Windows."""
    import io
    import threading
    import time
    from groundtrace import aptdb as a
    calls = []

    class Slow(io.BytesIO):
        def __enter__(self):
            calls.append(1)
            time.sleep(0.05)
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(a, "_raw_path", lambda: tmp_path / "raw.json")
    monkeypatch.setattr(a, "_index_path", lambda: tmp_path / "idx.json")
    monkeypatch.setattr(a.urllib.request, "urlopen", lambda *x, **k: Slow(b"{}"))
    monkeypatch.setattr(a, "build_index", lambda raw, idx: idx.write_text("{}", encoding="utf-8"))
    threads = [threading.Thread(target=a.refresh) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(calls) == 1 and not list(tmp_path.glob("*.tmp"))
