"""Actor footprints and candidate matching (Stage 2). Pure, no network."""
from datetime import date

import pytest

from groundtrace import fingerprint as fp


def test_ddns_and_registrable():
    assert fp.ddns_provider("office-server365.ddns.net") == "ddns.net"
    assert fp.ddns_provider("itsupport.apps-sco-gov-pk.workers.dev") == "workers.dev"
    assert fp.ddns_provider("example.com") == ""
    assert fp.registrable("a.b.theprints.org") == "theprints.org"
    assert fp.registrable("foo.bar.com.pk") == "bar.com.pk"
    assert fp.registrable("sub.office-server365.ddns.net") == "office-server365.ddns.net"


def _rows(pairs, family="", last_seen=""):
    return [{"value": v, "type": t, "family": family, "last_seen": last_seen}
            for v, t in pairs]


TODAY = date(2026, 10, 30)
RECENT = "2026-10-20"      # inside FRESH_DAYS of TODAY


def test_footprint_captures_habits():
    rows = _rows([
        ("office-server365.ddns.net", "domain"),
        ("avupdate.servehttp.com", "domain"),
        ("myftpservlet.servehttp.com", "domain"),
        ("5.230.252.84", "ip"), ("5.230.252.99", "ip"),
    ], family="SideWinderRAT")
    f = fp.footprint_for(rows)
    assert f["ddns"]["servehttp.com"] == 2 and f["ddns"]["ddns.net"] == 1
    # exact tokens only (no fuzzy splitting), to stay conservative
    assert "office" in f["tokens"] and "avupdate" in f["tokens"]
    assert f["blocks"]["5.230.252.0/24"] == 2        # two IPs in one /24
    assert f["families"]["SideWinderRAT"] == 5


def test_match_domain_by_ddns_and_token():
    prints = {"u-sw": fp.footprint_for(_rows([
        ("office-server365.ddns.net", "domain"),
        ("avupdate.servehttp.com", "domain"),
        ("updates-server.serveftp.com", "domain")]))}
    names = {"u-sw": {"name": "SideWinder"}}
    # shares the servehttp.com ddns base AND the exact token 'office'
    hits = fp.match("office-portal.servehttp.com", "domain", prints, names)
    assert hits and hits[0]["group"] == "u-sw" and hits[0]["group_name"] == "SideWinder"
    assert any("servehttp.com" in b for b in hits[0]["basis"])
    assert any("office" in b for b in hits[0]["basis"])
    # No pseudo-confidence derived from the score: a match carries the mode's
    # measured precision and is labelled a lead, never an attribution.
    assert hits[0]["verdict"] == "lead"
    # The fixture is undated, which is not the same as stale: the measured
    # precision was taken on a catalogue that is 99% undated, so it stands.
    assert hits[0]["footprint_freshness"] == "undated"
    assert hits[0]["reliability"] == fp.RELIABILITY["strict"]["precision"]
    assert "capped" not in hits[0]["reliability_basis"]
    assert "confidence" not in hits[0]
    # a domain sharing nothing scores nothing
    assert fp.match("totally-unrelated.example", "domain", prints) == []


def test_match_ignores_ubiquitous_provider_coincidence():
    # 25 groups all use ddns.net -> it's ubiquitous, so sharing ONLY ddns.net
    # (plus the .net TLD) must not name any of them.
    prints = {f"u-{i}": fp.footprint_for(_rows(
        [(f"host{i}.ddns.net", "domain"), (f"alt{i}.ddns.net", "domain"), (f"x{i}.ddns.net", "domain")]))
        for i in range(25)}
    assert fp.match("random-c2.ddns.net", "domain", prints) == []
    # but a group that also shares a distinctive token still surfaces
    prints["u-tok"] = fp.footprint_for(_rows(
        [("payroll-a.ddns.net", "domain"), ("payroll-b.ddns.net", "domain"), ("payroll-c.ddns.net", "domain")]))
    # A rare token plus a ubiquitous provider is a lead, not a confirmation.
    assert fp.match("payroll-new.ddns.net", "domain", prints) == []
    hits = fp.match("payroll-new.ddns.net", "domain", prints, mode="broad")
    assert hits and hits[0]["group"] == "u-tok" and any("payroll" in b for b in hits[0]["basis"])


def test_match_ip_by_block():
    prints = {"u-x": fp.footprint_for(_rows([("5.230.252.84", "ip"), ("5.230.252.99", "ip")]))}
    hits = fp.match("5.230.252.200", "ip", prints)
    assert hits and hits[0]["group"] == "u-x" and "5.230.252.0/24" in hits[0]["basis"][0]
    assert fp.match("8.8.8.8", "ip", prints) == []    # unrelated IP: no match


def test_build_all_needs_minimum_indicators(tmp_path, monkeypatch):
    from groundtrace import ioc_store
    con = ioc_store.connect(str(tmp_path / "apt.db"))
    for i, v in enumerate(["a.ddns.net", "b.ddns.net", "c.ddns.net"]):
        con.execute("INSERT INTO iocs (value,type,group_key,kind,family,first_seen,last_seen,hits,url) "
                    "VALUES (?,?,?,?,?,?,?,?,?)", (v, "domain", "u-big", "catalog", "", "", "", 1, ""))
    con.execute("INSERT INTO iocs (value,type,group_key,kind,family,first_seen,last_seen,hits,url) "
                "VALUES ('only.one','domain','u-small','catalog','','','',1,'')")
    con.commit()
    prints = fp.build_all(con, ["u-big", "u-small"])
    assert "u-big" in prints and "u-small" not in prints     # u-small has <3 indicators


def test_tld_alone_never_matches():
    # Three .xyz domains give the group a .xyz TLD habit, but a TLD is shared
    # by thousands of groups and must never name one on its own.
    prints = {"u-tld": fp.footprint_for(_rows(
        [("alpha.xyz", "domain"), ("bravo.xyz", "domain"), ("charlie.xyz", "domain")]))}
    assert fp.match("unrelated-site.xyz", "domain", prints) == []


def test_token_rarity_beats_ubiquitous_token():
    """A token's weight must come from how many groups use it.

    Flat per-token scoring is what let 'com' -- present in 86% of catalogue
    groups -- contribute a full point and name a group.
    """
    # 30 groups all favour 'update': sharing it says almost nothing.
    prints = {f"u-{i}": fp.footprint_for(_rows(
        [(f"update-{i}a.xyz", "domain"), (f"update-{i}b.xyz", "domain"),
         (f"update-{i}c.xyz", "domain")])) for i in range(30)}
    assert fp.match("update-fresh.xyz", "domain", prints) == []

    # One group uses 'payroll' and nobody else does: that is a real tell.
    prints["u-rare"] = fp.footprint_for(_rows(
        [("payroll-a.xyz", "domain"), ("payroll-b.xyz", "domain"), ("payroll-c.xyz", "domain")]))
    # One rare habit is a broad-mode lead; strict waits for corroboration.
    assert fp.match("payroll-new.xyz", "domain", prints) == []
    hits = fp.match("payroll-new.xyz", "domain", prints, mode="broad")
    assert hits and hits[0]["group"] == "u-rare"
    assert any("payroll" in b and "rare" in b for b in hits[0]["basis"])


def test_ubiquitous_token_plus_shared_tld_does_not_surface():
    """The 1.3-1.5 band regression.

    One shared token plus a shared TLD used to total exactly 1.3 and clear the
    floor; that band carried most of the wrong-group answers. Neither signal
    may create a match on its own now.
    """
    prints = {f"u-{i}": fp.footprint_for(_rows(
        [(f"update-{i}a.xyz", "domain"), (f"update-{i}b.xyz", "domain"),
         (f"update-{i}c.xyz", "domain")])) for i in range(30)}
    # shares the ubiquitous 'update' token AND the .xyz TLD -- still not enough
    assert fp.match("update-portal.xyz", "domain", prints) == []


def test_token_cap_keeps_the_informative_tokens():
    """The four-token cap must sort by weight, not alphabetically."""
    prints = {f"u-{i}": fp.footprint_for(_rows(
        [(f"alpha-beta-gamma-{i}.xyz", "domain"), (f"alpha-beta-delta-{i}.xyz", "domain"),
         (f"alpha-beta-epsilon-{i}.xyz", "domain")])) for i in range(20)}
    prints["u-tgt"] = fp.footprint_for(_rows(
        [("alpha-beta-zephyr-one.xyz", "domain"), ("alpha-beta-zephyr-two.xyz", "domain"),
         ("alpha-beta-zephyr-three.xyz", "domain")]))
    hits = fp.match("alpha-beta-zephyr-new.xyz", "domain", prints, mode="broad")
    assert hits and hits[0]["group"] == "u-tgt"
    # 'zephyr' is unique to u-tgt; it must appear in the basis, ahead of the
    # ubiquitous 'alpha'/'beta' which sort earlier alphabetically.
    assert "zephyr" in hits[0]["basis"][0]


def test_mode_must_be_valid():
    with pytest.raises(ValueError, match="mode"):
        fp.match("a.ddns.net", "domain", {}, mode="loose")


def test_broad_surfaces_at_least_as_much_as_strict():
    prints = {f"u-{i}": fp.footprint_for(_rows(
        [(f"zephyr-{i}a.xyz", "domain"), (f"zephyr-{i}b.xyz", "domain"),
         (f"zephyr-{i}c.xyz", "domain")])) for i in range(3)}
    strict = fp.match("zephyr-0new.xyz", "domain", prints)
    broad = fp.match("zephyr-0new.xyz", "domain", prints, mode="broad")
    assert len(broad) >= len(strict)
    assert all(h["mode"] == "broad" for h in broad)


def test_reliability_is_measured_and_plausible():
    """The published numbers must stay in range and name their method.

    They may only be changed from scripts/validate_footprints.py output.
    """
    for mode in ("strict", "broad"):
        r = fp.RELIABILITY[mode]
        assert 0.5 < r["precision"] < 1.0, mode
        for token in ("leave-one-out", "held-out groups", "macro"):
            assert token in r["basis"], (mode, token)
    # Strict demands corroboration, so it cannot be the less reliable mode.
    assert fp.RELIABILITY["strict"]["precision"] >= fp.RELIABILITY["broad"]["precision"]


def test_gates_from_the_plan_hold():
    assert fp.RELIABILITY["strict"]["precision"] >= 0.60
    assert fp.RELIABILITY["broad"]["precision"] >= 0.55
    # One rare token must clear broad alone, but never strict.
    assert fp.MIN_SCORE_BROAD <= fp._TOKEN_MAX_W < fp.MIN_SCORE_STRICT


def test_no_match_is_returned_without_its_reliability():
    prints = {"u-sw": fp.footprint_for(_rows(
        [("office-a.servehttp.com", "domain"), ("office-b.servehttp.com", "domain"),
         ("office-c.servehttp.com", "domain")]))}
    for mode in ("strict", "broad"):
        for h in fp.match("office-new.servehttp.com", "domain", prints, mode=mode):
            assert h["reliability"] > 0 and h["reliability_basis"]
            assert h["verdict"] == "lead"


# --- freshness: a stale footprint cannot carry a fresh reliability ----------

def test_freshness_bands():
    assert fp._freshness("2026-10-20", 1, 1, TODAY) == "fresh"
    assert fp._freshness("2026-07-02", 1, 1, TODAY) == "aging"
    assert fp._freshness("2025-09-25", 1, 1, TODAY) == "historical"
    # Undated is NOT historical: no dates means unknown recency, not old.
    assert fp._freshness("", 0, 3, TODAY) == "undated"
    assert fp._freshness("not-a-date", 1, 1, TODAY) == "undated"


def test_fresh_footprint_keeps_the_measured_reliability():
    prints = {"u-sw": fp.footprint_for(_rows(
        [("office-a.servehttp.com", "domain"), ("office-b.servehttp.com", "domain"),
         ("office-c.servehttp.com", "domain")], last_seen=RECENT), today=TODAY)}
    hits = fp.match("office-new.servehttp.com", "domain", prints)
    assert hits and hits[0]["footprint_freshness"] == "fresh"
    assert hits[0]["reliability"] == fp.RELIABILITY["strict"]["precision"]
    assert "capped" not in hits[0]["reliability_basis"]
    assert hits[0]["footprint_last_seen"] == RECENT


def test_historical_footprint_caps_reliability_and_says_so():
    prints = {"u-old": fp.footprint_for(_rows(
        [("office-a.servehttp.com", "domain"), ("office-b.servehttp.com", "domain"),
         ("office-c.servehttp.com", "domain")], last_seen="2024-01-05"), today=TODAY)}
    hits = fp.match("office-new.servehttp.com", "domain", prints)
    assert hits and hits[0]["footprint_freshness"] == "historical"
    assert hits[0]["reliability"] <= fp.HISTORICAL_RELIABILITY_CAP
    assert "capped" in hits[0]["reliability_basis"]
    # The uncapped measurement stays visible, so the cap is auditable.
    assert "leave-one-out" in hits[0]["reliability_basis"]


def test_cap_never_raises_reliability():
    assert fp.HISTORICAL_RELIABILITY_CAP < fp.RELIABILITY["broad"]["precision"]


def test_undated_footprint_is_not_capped():
    """The measured figure was taken on a 99%-undated catalogue; it applies."""
    prints = {"u-u": fp.footprint_for(_rows(
        [("office-a.servehttp.com", "domain"), ("office-b.servehttp.com", "domain"),
         ("office-c.servehttp.com", "domain")]), today=TODAY)}
    hits = fp.match("office-new.servehttp.com", "domain", prints)
    assert hits and hits[0]["footprint_freshness"] == "undated"
    assert hits[0]["reliability"] == fp.RELIABILITY["strict"]["precision"]


def test_historical_cap_is_labelled_a_judgement():
    prints = {"u-old": fp.footprint_for(_rows(
        [("office-a.servehttp.com", "domain"), ("office-b.servehttp.com", "domain"),
         ("office-c.servehttp.com", "domain")], last_seen="2024-01-05"), today=TODAY)}
    hits = fp.match("office-new.servehttp.com", "domain", prints)
    assert "judgement, not measurement" in hits[0]["reliability_basis"]
