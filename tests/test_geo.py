"""Geographic threat intel: country profiles, ISP-vs-attacker-hosting logic,
actor-origin layer and auto-written findings — built from a throwaway signals DB."""
import json
import sqlite3

from groundtrace.geo import actor_origin, geo_summary
from darkfeeds.store import Store


def _db(tmp_path, rows):
    path = str(tmp_path / "signals.db")
    Store(path).close()  # create the real schema
    con = sqlite3.connect(path)
    for i, r in enumerate(rows):
        con.execute(
            "INSERT INTO signals (signal_id, signal_type, priority, source, source_name, "
            "title, malware_family, tags, threat_actor, target_country, cve_ids, ip_enrichment) "
            "VALUES (?, ?, 'P4', 'threatfox', 'ThreatFox', ?, ?, ?, ?, ?, ?, ?)",
            (f"s{i}", r.get("type", "malware_sample"), r.get("title", ""), r.get("family", ""),
             json.dumps(r.get("tags", [])), r.get("actor", ""), r.get("target", ""),
             json.dumps(r.get("cves", [])), json.dumps(r.get("ips", {}))))
    con.commit()
    con.close()
    return path


def _ip(n, cc, org):
    return {f"10.0.{cc and ord(cc[0])}.{n}": {"country": cc, "org": org}}


def test_attacker_hosting_vs_consumer_isp(tmp_path):
    rows = []
    # RU: 10 C2s all on one hosting provider -> "block the ASN" advice.
    for n in range(10):
        rows.append({"family": "Cobalt Strike", "ips": _ip(n, "RU", "GCS - GLOBAL CONNECTIVITY SOLUTIONS LLP, GB")})
    # PK: 10 bots on a consumer ISP -> victims, "notify, don't block".
    for n in range(10):
        rows.append({"family": "Mozi", "tags": ["Mozi", "botnet"],
                     "ips": _ip(n, "PK", "CYBERNET-AP - Cyber Internet Services (Pvt) Ltd., PK")})
    g = geo_summary(_db(tmp_path, rows))

    ru, pk = g["countries"]["RU"], g["countries"]["PK"]
    assert ru["categories"][0][0] == "Post-exploitation C2"
    assert "blocking at the ASN level" in ru["summary"]
    assert pk["isp_pct"] == 100
    assert "don't block" in pk["summary"]
    joined = " ".join(g["findings"])
    assert "Concentrated attacker hosting" in joined and "[[RU]]" in joined
    assert "Compromised-device hotspots" in joined and "[[PK]]" in joined


def test_unknown_family_is_not_a_family(tmp_path):
    rows = [{"family": "Unknown malware", "ips": _ip(1, "US", "DIGITALOCEAN-ASN - DigitalOcean, LLC, US")}]
    g = geo_summary(_db(tmp_path, rows))
    assert g["countries"]["US"]["families"] == []
    assert g["countries"]["US"]["cloud_pct"] == 100


def test_actor_origin_layer_and_targeting(tmp_path):
    rows = [{"actor": "APT36 (Transparent Tribe)", "target": "pakistan"},
            {"actor": "SideWinder", "target": "pakistan"},
            {"actor": "qilin"}]
    g = geo_summary(_db(tmp_path, rows))
    assert g["origin"] == {"PK": 1, "IN": 1, "RU": 1}
    assert g["targets"]["pakistan"]["signals"] == 2
    assert actor_origin("Some Unknown Crew") is None


def test_empty_db_has_a_finding_not_a_crash(tmp_path):
    g = geo_summary(_db(tmp_path, []))
    assert g["infra"] == {} and len(g["findings"]) == 1


def test_hosting_profile_lists_ips_per_provider(tmp_path):
    ip = {"1.2.3.4": {"country": "US", "org": "DIGITALOCEAN-ASN, US", "asn": "14061", "cidr": "1.2.0.0/16"}}
    rows = [{"family": "Sliver", "ips": ip, "cves": ["CVE-2024-1"]},
            {"family": "Mirai", "tags": ["botnet"], "ips": ip},
            {"family": "Vidar", "ips": {"5.6.7.8": {"country": "US", "org": "COMCAST-7922, US", "asn": "7922"}}}]
    provs = geo_summary(_db(tmp_path, rows))["countries"]["US"]["providers"]
    do = next(p for p in provs if p["asn"] == "14061")
    assert do["kind"] == "cloud" and do["ip_count"] == 1
    e = do["ips"][0]
    assert e["ip"] == "1.2.3.4" and e["signals"] == 2 and e["cidr"] == "1.2.0.0/16"
    assert set(e["families"]) == {"Sliver", "Mirai"} and e["cves"] == ["CVE-2024-1"]
    assert next(p for p in provs if p["asn"] == "7922")["kind"] == "isp"


def test_clusters_and_density_raise_score():
    from groundtrace.geo import ip_clusters, provider_score
    ips = [{"ip": f"91.193.233.{n}", "category": "Botnet / DDoS", "last_seen": "2026-10-26"}
           for n in range(1, 11)]
    ips.append({"ip": "8.8.8.8", "category": "Botnet / DDoS", "last_seen": "2026-10-26"})
    clusters = ip_clusters(ips)
    assert [(c["cidr"], c["ips"]) for c in clusters] == [("91.193.233.0/24", 10)]
    assert clusters[0]["members"][:3] == ["91.193.233.1", "91.193.233.2", "91.193.233.3"]  # numeric order
    dense = provider_score(ips, families=1, ref_day="2026-10-26", clustered=10)
    spread = provider_score(ips, families=1, ref_day="2026-10-26", clustered=0)
    assert dense["score"] > spread["score"] and dense["parts"]["density"] == 14


def test_recency_is_relative_to_latest_collection():
    from groundtrace.geo import provider_score
    ips = [{"ip": "1.1.1.1", "category": "RAT C2", "last_seen": "2026-01-01"}]
    assert provider_score(ips, 1, "2026-01-03")["parts"]["recency"] == 25
    assert provider_score(ips, 1, "2026-03-01")["parts"]["recency"] == 0


def test_slim_drops_ip_lists_and_leaderboard_merges_asns(tmp_path):
    from groundtrace.geo import slim
    ips_us = {f"5.5.5.{n}": {"country": "US", "org": "DIGITALOCEAN-ASN, US", "asn": "14061"} for n in range(3)}
    ips_sg = {"6.6.6.6": {"country": "SG", "org": "DIGITALOCEAN-ASN, SG", "asn": "14061"}}
    g = geo_summary(_db(tmp_path, [{"family": "Sliver", "ips": ips_us}, {"family": "Sliver", "ips": ips_sg}]))
    assert "ips" not in slim(g)["countries"]["US"]["providers"][0]
    assert "ips" in g["countries"]["US"]["providers"][0]  # slim() must not mutate the original
    top = g["leaderboard"][0]
    assert top["asn"] == "14061" and sorted(top["countries"]) == ["SG", "US"] and top["ip_count"] == 4


def test_focus_country_collects_targeting(tmp_path, monkeypatch):
    path = tmp_path / "focus.json"
    path.write_text('{"country": "pakistan", "code": "PK"}', encoding="utf-8")
    monkeypatch.setenv("GROUNDTRACE_FOCUS_FILE", str(path))
    g = geo_summary(_db(tmp_path, [{"actor": "APT36 (Transparent Tribe)", "target": "pakistan", "title": "CrimsonRAT"},
                                   {"actor": "SideWinder", "target": "pakistan"}, {"actor": "x"}]))
    pk = g["focus"]
    assert pk["targeting_count"] == 2 and {a for a, _ in pk["actors"]} == {"APT36 (Transparent Tribe)", "SideWinder"}


def test_geo_spike_alert_after_baseline(tmp_path, monkeypatch):
    from groundtrace import watch
    from groundtrace.notify import Alert
    from groundtrace.store import FindingStore
    ips = {f"7.7.7.{n}": {"country": "NL", "org": "EVILHOST, NL", "asn": "666"} for n in range(12)}
    path = _db(tmp_path, [{"family": "Cobalt Strike", "ips": ips}])
    import sqlite3
    con = sqlite3.connect(path)
    con.execute("UPDATE signals SET collected_at = '2026-10-26T00:00:00'")
    con.commit(); con.close()
    monkeypatch.setenv("DARKFEEDS_DB_PATH", path)
    store = FindingStore(str(tmp_path / "f.db"))
    fresh, silent = watch._geo_step(store)
    assert fresh == [] and [a.key for a in silent] == ["geo:666:NL:2026-W44"]
    store.record_alerts([Alert(key="geo:x", kind="geo", title="t")], None)
    fresh, _ = watch._geo_step(store)
    assert "gained 12 new malicious IPs" in fresh[0].title and "7.7.7.0/24" in fresh[0].detail
