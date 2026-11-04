"""Append-only ledger of every claim the tool has made.

A claim is a statement about an indicator: that it resembles a group's
habits, that it was seen alongside another host, that a service called it
malicious. Each one records what was claimed, the evidence behind it, how
reliable that class of claim is measured to be, and -- the part that is
usually missing -- what would prove it wrong.

Nothing here is ever edited. A correction inserts a new row and points the old
one at it with `superseded_by`, so the history of what the tool believed, and
when, stays readable. That is enforced by SQLite triggers rather than by
convention: UPDATE of any evidence column and DELETE of any row both abort.
An analyst who finds a wrong actor call needs to see what the tool knew at the
time, and a ledger that can be quietly rewritten cannot answer that.

`confidence` is deliberately absent. The old footprint matcher derived one
from its own score, which read as authoritative while measuring nothing. A
claim carries `score` (the raw evidence weight, meaningful only within its
method) and `reliability` (the measured precision of that method, or NULL when
it has not been measured).
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Optional

# The claims this ledger knows how to express. Keeping it closed means a new
# kind of assertion has to be named and thought about, not smuggled in.
CLAIM_TYPES = {
    "resembles": "the subject's infrastructure habits resemble the object's",
    "operates_in": "the subject is hosted in the object (a network or country)",
    "seen_with": "the subject and object appeared in the same infrastructure",
    "verified_as": "a verification service classified the subject as the object",
}

METHODS = {"footprint", "pivot", "corroboration", "verification"}

# Columns that may never change once written. superseded_by is excluded: that
# is how a correction is recorded, and it is the only permitted update.
_IMMUTABLE = ("subject", "subject_type", "claim", "object", "basis", "score",
              "reliability", "method", "retrieved_at", "falsifier")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS claims (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    subject       TEXT NOT NULL,              -- indicator value
    subject_type  TEXT NOT NULL,              -- ip | domain | url | sha256 | ...
    claim         TEXT NOT NULL,              -- one of CLAIM_TYPES
    object        TEXT NOT NULL,              -- group key, network, family, host
    object_label  TEXT NOT NULL DEFAULT '',   -- human name, for display only
    basis         TEXT NOT NULL,              -- JSON list of evidence strings
    score         REAL,                       -- raw evidence weight, per method
    reliability   REAL,                       -- measured precision, NULL if unmeasured
    method        TEXT NOT NULL,              -- one of METHODS
    verdict       TEXT NOT NULL DEFAULT 'lead',
    retrieved_at  TEXT NOT NULL,              -- when the evidence was gathered
    falsifier     TEXT NOT NULL,              -- what would prove this wrong
    superseded_by INTEGER REFERENCES claims(id)
);
CREATE INDEX IF NOT EXISTS idx_claims_subject ON claims(subject, subject_type);
CREATE INDEX IF NOT EXISTS idx_claims_object ON claims(object);
CREATE INDEX IF NOT EXISTS idx_claims_live ON claims(superseded_by);
"""

# Immutability, enforced by the database. A trigger cannot be bypassed by a
# future caller who forgets the rule, which is the point.
_TRIGGERS = """
CREATE TRIGGER IF NOT EXISTS claims_are_append_only
BEFORE UPDATE ON claims
FOR EACH ROW WHEN ({changed})
BEGIN
    SELECT RAISE(ABORT, 'claims are append-only: record a new claim and set superseded_by on the old one');
END;

CREATE TRIGGER IF NOT EXISTS claims_are_never_deleted
BEFORE DELETE ON claims
BEGIN
    SELECT RAISE(ABORT, 'claims are append-only: rows are superseded, not deleted');
END;
""".format(changed=" OR ".join(
    f"OLD.{c} IS NOT NEW.{c}" for c in _IMMUTABLE))


def ensure(con: sqlite3.Connection) -> None:
    """Create the ledger and its guard triggers if they are not there."""
    con.executescript(_SCHEMA)
    con.executescript(_TRIGGERS)
    con.commit()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def record(con: sqlite3.Connection, *, subject: str, subject_type: str, claim: str,
           object: str, basis: list[str], method: str, falsifier: str,
           object_label: str = "", score: Optional[float] = None,
           reliability: Optional[float] = None, verdict: str = "lead",
           retrieved_at: str = "") -> int:
    """Write one claim. Returns its id.

    `basis` and `falsifier` are required and must be non-empty: a claim whose
    evidence is not written down cannot be checked, and one that nothing could
    disprove is not a finding but an opinion.
    """
    if claim not in CLAIM_TYPES:
        raise ValueError(f"unknown claim type {claim!r}; expected one of {sorted(CLAIM_TYPES)}")
    if method not in METHODS:
        raise ValueError(f"unknown method {method!r}; expected one of {sorted(METHODS)}")
    if not subject or not subject_type or not object:
        raise ValueError("subject, subject_type and object are all required")
    basis = [b for b in (basis or []) if b and b.strip()]
    if not basis:
        raise ValueError("a claim must record the evidence behind it in `basis`")
    if not (falsifier or "").strip():
        raise ValueError("a claim must record what would prove it wrong in `falsifier`")

    ensure(con)
    cur = con.execute(
        "INSERT INTO claims (subject, subject_type, claim, object, object_label, basis, "
        "score, reliability, method, verdict, retrieved_at, falsifier) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (subject, subject_type, claim, object, object_label, json.dumps(basis),
         score, reliability, method, verdict, retrieved_at or _now(), falsifier.strip()))
    con.commit()
    return int(cur.lastrowid)


def supersede(con: sqlite3.Connection, old_id: int, new_id: int) -> None:
    """Mark `old_id` as replaced by `new_id`. The old row's evidence is kept."""
    if old_id == new_id:
        raise ValueError("a claim cannot supersede itself")
    rows = {r[0] for r in con.execute(
        "SELECT id FROM claims WHERE id IN (?, ?)", (old_id, new_id))}
    missing = {old_id, new_id} - rows
    if missing:
        raise ValueError(f"no such claim(s): {sorted(missing)}")
    con.execute("UPDATE claims SET superseded_by = ? WHERE id = ?", (new_id, old_id))
    con.commit()


def correct(con: sqlite3.Connection, old_id: int, **new_claim) -> int:
    """Record a replacement for `old_id` and link the two. Returns the new id."""
    new_id = record(con, **new_claim)
    supersede(con, old_id, new_id)
    return new_id


def _row(r: sqlite3.Row) -> dict:
    d = dict(r)
    try:
        d["basis"] = json.loads(d["basis"])
    except (ValueError, TypeError):
        d["basis"] = []
    d["claim_means"] = CLAIM_TYPES.get(d["claim"], "")
    d["superseded"] = d.get("superseded_by") is not None
    return d


def for_subject(con: sqlite3.Connection, subject: str, subject_type: str = "",
                include_superseded: bool = False, limit: int = 100) -> list[dict]:
    """Claims about one indicator, newest first. Current claims only by default."""
    ensure(con)
    con.row_factory = sqlite3.Row
    sql = "SELECT * FROM claims WHERE subject = ?"
    args: list = [subject]
    if subject_type:
        sql += " AND subject_type = ?"
        args.append(subject_type)
    if not include_superseded:
        sql += " AND superseded_by IS NULL"
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    return [_row(r) for r in con.execute(sql, args)]


def history(con: sqlite3.Connection, claim_id: int) -> list[dict]:
    """A claim and the chain of replacements that followed it, oldest first."""
    ensure(con)
    con.row_factory = sqlite3.Row
    out, seen, cur = [], set(), claim_id
    while cur is not None and cur not in seen:
        seen.add(cur)
        r = con.execute("SELECT * FROM claims WHERE id = ?", (cur,)).fetchone()
        if r is None:
            break
        out.append(_row(r))
        cur = r["superseded_by"]
    return out
