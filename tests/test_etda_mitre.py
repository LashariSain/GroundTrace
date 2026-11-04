"""ETDA Threat Group Cards parsing + ledger rules, and ATT&CK group matching."""
import json

from groundtrace import etda, mitre

CARD = """<html><head><title>Transparent Tribe, APT 36 - Threat Group Cards: A Threat Actor Encyclopedia</title></head><body>
<table>
<tr><td class="tshaded">Names</td><td>Transparent Tribe (Proofpoint)<br>APT 36 (Mandiant)<br>Mythic Leopard (CrowdStrike)</td></tr>
<tr><td class="tshaded">Country</td><td>Pakistan</td></tr>
<tr><td class="tshaded">First seen</td><td>2013</td></tr>
<tr><td class="tshaded">Observed</td><td>Sectors: Defense, Government.<br>Countries: Afghanistan, India, Pakistan.</td></tr>
<tr><td class="tshaded">Operations performed</td><td><table>
  <tr><td>Mar 2016</td><td>Pakistani officials collected data on Indian troop movements &lt;<a href="https://example.com/smesh">https://example.com/smesh</a>&gt;</td></tr>
  <tr><td>Early 2020</td><td>New USBWorm module seen in Afghanistan &lt;<a href="https://example.com/usb">https://example.com/usb</a>&gt;</td></tr>
  <tr><td>Mar 2025</td><td>ClickFix attack spoofs Indian Ministry of Defence</td></tr>
</table></td></tr>
<tr><td class="tshaded">Counter operations</td><td><table>
  <tr><td>Jun 2021</td><td>Domains seized &lt;<a href="https://example.com/seized">x</a>&gt;</td></tr>
</table></td></tr>
<tr><td class="tshaded">MITRE ATT&amp;CK</td><td><a href="https://attack.mitre.org/groups/G0134/">x</a></td></tr>
</table></body></html>"""


def test_parse_date_keeps_precision():
    assert etda.parse_date("Mar 2016") == ("2016-03-01", "month")
    assert etda.parse_date("Early 2020") == ("2020-02-01", "approx")
    assert etda.parse_date("Q3 2022") == ("2022-08-01", "approx")
    assert etda.parse_date("2019") == ("2019-01-01", "year")
    assert etda.parse_date("unknown") == (None, "")


def test_parse_card():
    c = etda.parse_card(CARD, "Transparent Tribe, APT 36")
    assert c["title"] == "Transparent Tribe, APT 36" and c["country"] == "Pakistan"
    assert c["names"][1] == {"name": "APT 36", "vendor": "Mandiant"}
    assert c["observed_sectors"] == ["Defense", "Government"]
    assert c["observed_countries"] == ["Afghanistan", "India", "Pakistan"]
    assert [o["day"] for o in c["operations"]] == ["2016-03-01", "2020-02-01", "2025-03-01"]
    assert c["operations"][0]["url"] == "https://example.com/smesh"
    assert "https://" not in c["operations"][0]["text"]
    assert c["counter_operations"][0]["text"] == "Domains seized" and c["mitre"] == ["G0134"]


def test_etda_ledger_excludes_own_country(tmp_path, monkeypatch):
    from groundtrace import apt_sightings as S, aptdb
    card = etda.parse_card(CARD, "Transparent Tribe, APT 36")
    monkeypatch.setattr(aptdb, "resolve", lambda n: {"uuid": "u-apt36"} if "Transparent" in n else None)
    con = S.connect(str(tmp_path / "apt.db"))
    assert S.collect_etda(con, [card]) == 4
    rows = {r["day"]: r for r in con.execute("SELECT * FROM sightings")}
    assert json.loads(rows["2016-03-01"]["countries"]) == ["IN"]          # not PK (own country)
    assert json.loads(rows["2020-02-01"]["countries"]) == ["AF"]
    assert json.loads(rows["2025-03-01"]["countries"]) == ["IN"]          # via "Indian"
    assert rows["2021-06-01"]["title"].startswith("Counter-operation:")
    assert json.loads(rows["2021-06-01"]["countries"]) == []


def test_mitre_prefers_primary_name(tmp_path, monkeypatch):
    idx = tmp_path / "attack_index.json"
    idx.write_text(json.dumps({"groups": [
        {"id": "G0082", "name": "APT38", "aliases": ["BeagleBoyz"], "url": "", "description": "",
         "modified": "", "techniques": [], "software": []},
        {"id": "G0032", "name": "Lazarus Group", "aliases": ["HIDDEN COBRA"], "url": "", "description": "",
         "modified": "", "techniques": [{"id": "T1566"}], "software": []},
    ]}), encoding="utf-8")
    monkeypatch.setattr(mitre, "_index_path", lambda: idx)
    monkeypatch.setattr(mitre, "_index_mtime", None)
    assert mitre.group_for(["Lazarus Group", "APT38", "HIDDEN COBRA"])["id"] == "G0032"
    assert mitre.group_for(["Some Name", "BeagleBoyz"])["id"] == "G0082"
    assert mitre.group_for(["Nobody"]) is None
