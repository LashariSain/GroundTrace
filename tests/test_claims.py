"""The claim ledger: append-only, evidence required, falsifier required."""
import sqlite3

import pytest

from groundtrace import claims


def _con():
    con = sqlite3.connect(":memory:")
    claims.ensure(con)
    return con


def _claim(**over):
    base = dict(subject="evil.ddns.net", subject_type="domain", claim="resembles",
                object="u-sw", object_label="SideWinder",
                basis=["uses ddns.net dynamic DNS (rare, 1 group)"],
                method="footprint", reliability=0.722,
                falsifier="the group is observed abandoning ddns.net, or another "
                          "group is found using the same token")
    base.update(over)
    return base


def test_record_returns_an_id_and_round_trips():
    con = _con()
    cid = claims.record(con, **_claim())
    rows = claims.for_subject(con, "evil.ddns.net")
    assert len(rows) == 1
    r = rows[0]
    assert r["id"] == cid and r["object_label"] == "SideWinder"
    assert r["basis"] == ["uses ddns.net dynamic DNS (rare, 1 group)"]
    assert r["reliability"] == 0.722 and r["method"] == "footprint"
    assert r["verdict"] == "lead" and r["superseded"] is False
    assert r["claim_means"]                      # the claim type explains itself
    assert r["retrieved_at"]


def test_a_claim_without_evidence_is_refused():
    con = _con()
    for bad in ([], [""], ["   "], None):
        with pytest.raises(ValueError, match="basis"):
            claims.record(con, **_claim(basis=bad))


def test_a_claim_without_a_falsifier_is_refused():
    """Something that nothing could disprove is an opinion, not a finding."""
    con = _con()
    for bad in ("", "   "):
        with pytest.raises(ValueError, match="prove it wrong"):
            claims.record(con, **_claim(falsifier=bad))


def test_unknown_claim_types_and_methods_are_refused():
    con = _con()
    with pytest.raises(ValueError, match="claim type"):
        claims.record(con, **_claim(claim="is_definitely"))
    with pytest.raises(ValueError, match="method"):
        claims.record(con, **_claim(method="vibes"))


def test_no_confidence_field_exists():
    """The score/(score+3) pseudo-confidence must not come back."""
    con = _con()
    cols = {r[1] for r in con.execute("PRAGMA table_info(claims)")}
    assert "confidence" not in cols
    assert {"score", "reliability"} <= cols


# --- append-only, enforced by the database ---------------------------------

def test_evidence_cannot_be_edited_in_place():
    con = _con()
    cid = claims.record(con, **_claim())
    for col, val in (("basis", '["rewritten"]'), ("object", "u-other"),
                     ("reliability", 0.99), ("falsifier", "nothing"),
                     ("score", 99.0), ("method", "pivot"),
                     ("subject", "other.example"), ("retrieved_at", "1999-01-01")):
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            con.execute(f"UPDATE claims SET {col} = ? WHERE id = ?", (val, cid))
    # the row is untouched
    assert claims.for_subject(con, "evil.ddns.net")[0]["object"] == "u-sw"


def test_claims_cannot_be_deleted():
    con = _con()
    claims.record(con, **_claim())
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        con.execute("DELETE FROM claims")
    assert len(claims.for_subject(con, "evil.ddns.net")) == 1


def test_writing_the_same_value_is_not_an_edit():
    """The trigger fires on change, so a no-op update must not abort."""
    con = _con()
    cid = claims.record(con, **_claim())
    con.execute("UPDATE claims SET object = 'u-sw' WHERE id = ?", (cid,))


def test_a_correction_produces_two_rows_and_a_chain():
    con = _con()
    first = claims.record(con, **_claim())
    second = claims.correct(con, first, **_claim(
        object="u-apt36", object_label="APT36",
        basis=["shares the /24 185.225.17.0/24 (seen 4x)"]))

    # Current view shows only the correction.
    live = claims.for_subject(con, "evil.ddns.net")
    assert [r["id"] for r in live] == [second]
    assert live[0]["object_label"] == "APT36"

    # Both rows survive, and the original keeps its original evidence.
    allrows = claims.for_subject(con, "evil.ddns.net", include_superseded=True)
    assert len(allrows) == 2
    old = next(r for r in allrows if r["id"] == first)
    assert old["superseded"] is True and old["superseded_by"] == second
    assert old["object_label"] == "SideWinder"
    assert old["basis"] == ["uses ddns.net dynamic DNS (rare, 1 group)"]


def test_history_reads_the_chain_oldest_first():
    con = _con()
    a = claims.record(con, **_claim())
    b = claims.correct(con, a, **_claim(object="u-b"))
    c = claims.correct(con, b, **_claim(object="u-c"))
    chain = claims.history(con, a)
    assert [r["id"] for r in chain] == [a, b, c]
    assert [r["object"] for r in chain] == ["u-sw", "u-b", "u-c"]


def test_supersede_validates_its_arguments():
    con = _con()
    cid = claims.record(con, **_claim())
    with pytest.raises(ValueError, match="itself"):
        claims.supersede(con, cid, cid)
    with pytest.raises(ValueError, match="no such claim"):
        claims.supersede(con, cid, 9999)


def test_subject_type_filters_and_ensure_is_idempotent():
    con = _con()
    claims.record(con, **_claim())
    claims.record(con, **_claim(subject="evil.ddns.net", subject_type="url"))
    assert len(claims.for_subject(con, "evil.ddns.net")) == 2
    assert len(claims.for_subject(con, "evil.ddns.net", "domain")) == 1
    claims.ensure(con)          # re-running must not fail or duplicate
    assert len(claims.for_subject(con, "evil.ddns.net")) == 2
