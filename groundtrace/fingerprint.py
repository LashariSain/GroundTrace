"""Actor footprints -- match a new, unattributed indicator to a known group.

A "footprint" is the set of reusable infrastructure habits a group shows across
its indicators, computed from what the IOC store already holds (keyless, no
external calls):

  ddns       dynamic-DNS / free-hosting providers it favours (a strong tell:
             e.g. SideWinder's heavy use of *.servehttp.com / *.ddns.net)
  tokens     recurring words in its domains ("office", "update", "server", "av")
  tlds       the TLDs it registers under
  blocks     the /24 IPv4 blocks it operates in
  families   the malware families tied to its infrastructure

match() scores a candidate indicator against every footprint and returns a
ranked list, each with the exact features that matched (basis). This is a
SIMILARITY of habits, never attribution -- the caller must present it as a lead.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from datetime import date

from .ioc_store import STALE_DAYS as _STALE_DAYS

# Dynamic-DNS and free-hosting bases commonly abused for C2 / phishing.
_DDNS = {
    "ddns.net", "hopto.org", "sytes.net", "zapto.org", "servehttp.com", "serveftp.com",
    "serveblog.net", "servegame.com", "serveminecraft.net", "myftp.biz", "myftp.org",
    "no-ip.org", "no-ip.biz", "no-ip.info", "redirectme.net", "onthewifi.com", "accesscam.org",
    "myds.me", "synology.me", "duckdns.org", "freedns.afraid.org", "mooo.com", "chickenkiller.com",
    "hosthampster.com", "work.gd", "workers.dev", "pages.dev", "r2.dev", "glitch.me",
    "herokuapp.com", "firebaseapp.com", "web.app", "000webhostapp.com", "cloudfront.net",
}
# Multi-label public suffixes we must not treat as the registrable domain.
_TWO_LEVEL = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.pk", "gov.pk", "edu.pk", "org.pk",
              "com.au", "com.br", "co.in", "gov.in", "co.jp", "com.cn", "gov.cn", "com.tr"}
_GENERIC = {"www", "mail", "web", "server", "cloud", "online", "secure", "login", "cdn", "api",
            "app", "net", "host", "the", "and", "for", "info", "home", "live", "site", "page"}


def ddns_provider(domain: str) -> str:
    d = (domain or "").lower().rstrip(".")
    for base in _DDNS:
        if d == base or d.endswith("." + base):
            return base
    return ""


def registrable(domain: str) -> str:
    d = (domain or "").lower().rstrip(".").lstrip("*.")
    base = ddns_provider(d)
    if base:  # the provider IS the registrable part; the label under it is the actor's
        labels = d[: -len(base)].rstrip(".").split(".")
        return (labels[-1] + "." + base) if labels and labels[0] else base
    parts = d.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _TWO_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else d


def _tokens(domain: str) -> set[str]:
    """Words the actor chose, with the public suffix removed.

    The suffix has to go before splitting, or the TLD becomes a full-weight
    "habit": tokenising the whole domain made 'com' the most widespread token
    in the catalogue (86% of groups), worth 1.0 -- ten times the TLD signal it
    duplicates -- with 'org', 'xyz', 'top' and 'club' close behind. Only the
    labels the actor actually registered are evidence of anything.
    """
    d = (domain or "").lower().rstrip(".")
    base = ddns_provider(d)
    if base:
        head = d[: -len(base)]
    else:
        parts = d.split(".")
        n = 2 if len(parts) >= 3 and ".".join(parts[-2:]) in _TWO_LEVEL else 1
        head = ".".join(parts[:-n]) if len(parts) > n else ""
    return {w for w in re.split(r"[^a-z0-9]+", head) if len(w) > 2 and not w.isdigit() and w not in _GENERIC}


def _slash24(ip: str) -> str:
    return ip.rsplit(".", 1)[0] + ".0/24" if ip.count(".") == 3 else ""


# A footprint built from indicators nobody has seen for years describes an
# actor's old habits. Matching against it is the commonest cause of a confident
# wrong actor call, so freshness is computed here and caps reliability in
# match().
FRESH_DAYS = 90


def _freshness(newest: str, dated: int, total: int, today: date | None = None) -> str:
    """fresh | aging | historical | undated, from the newest last_seen.

    "undated" is kept apart from "historical" deliberately. 99% of catalogue
    footprints carry no dates at all, because the write-ups they come from do
    not publish them -- not because the infrastructure is old. Calling that
    "historical" would assert staleness we have not observed, the same error
    as reading a failed lookup as an absent PoC.
    """
    if not newest or not dated:
        return "undated"
    try:
        age = ((today or date.today()) - date.fromisoformat(newest)).days
    except ValueError:
        return "undated"
    if age <= FRESH_DAYS:
        return "fresh"
    return "aging" if age <= _STALE_DAYS else "historical"


def footprint_for(rows: list[dict], today: date | None = None) -> dict:
    """rows: ioc_store rows for one group (value, type, family, ...)."""
    ddns, tokens, tlds, blocks, fams = Counter(), Counter(), Counter(), Counter(), Counter()
    n_dom = n_ip = 0
    newest, dated = "", 0
    for r in rows:
        seen = (r.get("last_seen") or "").strip()
        if seen:
            dated += 1
            newest = max(newest, seen)
        if r["family"]:
            fams[r["family"]] += 1
        if r["type"] == "domain":
            n_dom += 1
            prov = ddns_provider(r["value"])
            if prov:
                ddns[prov] += 1
            for tok in _tokens(r["value"]):
                tokens[tok] += 1
            tld = r["value"].rsplit(".", 1)[-1]
            if tld:
                tlds[tld] += 1
        elif r["type"] == "ip":
            n_ip += 1
            b = _slash24(r["value"])
            if b:
                blocks[b] += 1
    return {
        "domains": n_dom, "ips": n_ip,
        "ddns": dict(ddns), "tokens": dict(tokens.most_common(25)),
        "tlds": dict(tlds), "blocks": {b: n for b, n in blocks.items() if n >= 2},
        "families": dict(fams.most_common(10)),
        "last_seen": newest, "dated": dated, "indicators": len(rows),
        "freshness": _freshness(newest, dated, len(rows), today),
    }


def features_of(value: str, t: str) -> dict:
    """Footprint-comparable features of a single candidate indicator."""
    if t in ("domain", "url"):
        from .ioc_store import classify
        host = value if t == "domain" else (re.sub(r"^[a-z]+://", "", value).split("/")[0])
        host = classify(host)[0]
        return {"kind": "domain", "ddns": ddns_provider(host), "tokens": _tokens(host),
                "tld": host.rsplit(".", 1)[-1] if "." in host else ""}
    if t == "ip":
        return {"kind": "ip", "block": _slash24(value)}
    return {"kind": t}


def _provider_df(footprints: dict[str, dict]) -> dict[str, int]:
    """How many groups use each dynamic-DNS provider (document frequency)."""
    df: Counter = Counter()
    for fp in footprints.values():
        for prov in fp.get("ddns", {}):
            df[prov] += 1
    return df


def _ddns_weight(df: int) -> tuple[float, str]:
    """A provider shared by few groups is a strong tell; a ubiquitous one
    (ddns.net, duckdns.org, workers.dev used by dozens of groups) is weak."""
    if df <= 2:
        return 3.0, "rare"
    if df <= 6:
        return 1.5, "uncommon"
    if df <= 20:
        return 0.6, "common"
    return 0.3, "ubiquitous"


def _token_df(footprints: dict[str, dict]) -> Counter:
    """How many distinct groups use each domain token (document frequency)."""
    df: Counter = Counter()
    for fp in footprints.values():
        for tok in fp.get("tokens", {}):
            df[tok] += 1
    return df


# Weight of the rarest possible token (used by exactly one group). Fitted on
# the fit half of the catalogue; see scripts/validate_footprints.py.
_TOKEN_MAX_W = 2.5


def _token_weight(df: int, n_groups: int) -> tuple[float, str]:
    """A token one group uses is a real tell; one that 86% of groups use is not.

    Inverse document frequency, normalised so the rarest token scores
    _TOKEN_MAX_W and a near-universal one rounds to almost nothing. Flat
    per-token scoring was what let 'com' name a group.
    """
    if n_groups < 2:
        return _TOKEN_MAX_W, "rare"
    df = max(1, min(df, n_groups))
    span = math.log((n_groups + 1) / 2.0)
    w = _TOKEN_MAX_W * math.log((n_groups + 1) / (df + 1.0)) / span if span > 0 else 0.0
    w = max(0.0, round(w, 3))
    frac = df / n_groups
    label = ("rare" if df <= 2 else "uncommon" if frac <= 0.05
             else "common" if frac <= 0.25 else "ubiquitous")
    return w, label


# Two operating points, both fitted on the fit half of the catalogue and
# measured on the held-out half by scripts/validate_footprints.py.
#
# The boundary that matters sits at _TOKEN_MAX_W: below it a single rare token
# can name a group on its own, above it a match needs two independent habits.
#
#   strict  needs corroboration -- two habits, or one habit plus a /24
#   broad   accepts one rare habit as a lead, and must be labelled as such
#
# Broad sits at _TOKEN_MAX_W exactly, so a token unique to one group clears it
# alone. 2.5 was chosen over 2.0 on the fit half (66.8% vs 60.4% precision for
# 16% less coverage), not on the held-out half.
MIN_SCORE_STRICT = 3.0
MIN_SCORE_BROAD = 2.5
_MIN_SCORE = MIN_SCORE_STRICT     # retained for callers that pass no mode

# Measured precision of each mode, and the exact method behind the number.
# These are the ONLY reliability figures the product may show. They are
# produced by scripts/validate_footprints.py on the held-out half of the
# catalogue and must be updated only from its output -- never estimated, and
# never derived from a match's own score.
_BASIS = ("leave-one-out, 867 tests, {g} held-out groups, max 15/group, "
          "macro-averaged over groups, 2026-10-30")
RELIABILITY = {
    "strict": {"precision": 0.722, "basis": _BASIS.format(g=29)},
    "broad": {"precision": 0.695, "basis": _BASIS.format(g=51)},
}
# Same run, same rule: from scripts/validate_footprints.py output only.
MEASURED_RATES = {
    "strict": {"wrong_group": 0.020, "abstains": 0.894},
    "broad": {"wrong_group": 0.068, "abstains": 0.667},
}

# Ceiling on reliability when the matched group's footprint is *historical*:
# it carries dates, and the newest is older than STALE_DAYS. Matching against
# infrastructure an actor demonstrably stopped using is the commonest cause of
# a confident wrong actor call.
#
# This cap is a judgement, not a measurement -- too few dated footprints exist
# to measure precision on stale ones separately -- and results say so.
#
# It deliberately does NOT apply to "undated" footprints. The precision in
# RELIABILITY was measured by leave-one-out over this catalogue, in which 99%
# of footprints are undated, so that number already describes them. Capping
# them too would discount a figure measured on exactly that population.
HISTORICAL_RELIABILITY_CAP = 0.45


def match(value: str, t: str, footprints: dict[str, dict], names: dict | None = None,
          limit: int = 6, mode: str = "strict") -> list[dict]:
    """Rank groups whose footprint this candidate indicator resembles.

    mode="strict" (default) only surfaces a group when two independent habits
    agree; mode="broad" accepts a single rare habit, which is a hunting lead
    and must be presented as one. Each result carries the mode's measured
    precision in `reliability`, so no caller can quote a number we have not
    measured.
    """
    if mode not in ("strict", "broad"):
        raise ValueError(f"mode must be 'strict' or 'broad', got {mode!r}")
    floor = MIN_SCORE_STRICT if mode == "strict" else MIN_SCORE_BROAD
    f = features_of(value, t)
    prov_df = _provider_df(footprints)
    tok_df = _token_df(footprints)
    n_groups = len(footprints)
    out = []
    for gk, fp in footprints.items():
        score, basis = 0.0, []
        if f["kind"] == "domain":
            if f["ddns"] and f["ddns"] in fp.get("ddns", {}):
                w, rarity = _ddns_weight(prov_df.get(f["ddns"], 1))
                score += w
                basis.append(f"uses {f['ddns']} dynamic DNS ({rarity}, {fp['ddns'][f['ddns']]}x)")
            shared = set(f["tokens"]) & set(fp.get("tokens", {}))
            # Sort by weight, not alphabetically: the cap must keep the
            # informative tokens, not the first four in the alphabet.
            weighted = sorted(((_token_weight(tok_df.get(tok, 1), n_groups), tok)
                               for tok in shared), key=lambda x: (-x[0][0], x[1]))
            for (w, rarity), tok in weighted[:4]:
                score += w
                n = tok_df.get(tok, 1)
                basis.append(f"domain token '{tok}' ({rarity}, "
                             f"{n} group{'' if n == 1 else 's'})")
            # A shared TLD is the weakest signal there is -- thousands of
            # groups register under .com. Measured on held-out groups, one
            # shared domain token (1.0) plus a TLD at the old 0.3 cleared the
            # 1.3 floor, and that band held most of the wrong-group answers.
            # At 0.1 a TLD can colour a match but can never create one.
            if f["tld"] and f["tld"] in fp.get("tlds", {}) and fp["tlds"][f["tld"]] >= 3:
                score += 0.1
                basis.append(f".{f['tld']} TLD")
        elif f["kind"] == "ip":
            if f["block"] and f["block"] in fp.get("blocks", {}):
                score += 3
                basis.append(f"operates in {f['block']} (seen {fp['blocks'][f['block']]}x)")
        if score >= floor:
            nm = (names or {}).get(gk, {}).get("name", "") if names else ""
            fresh = fp.get("freshness") or "undated"
            rel = RELIABILITY[mode]["precision"]
            rel_basis = RELIABILITY[mode]["basis"]
            if fresh == "historical":
                rel = min(rel, HISTORICAL_RELIABILITY_CAP)
                rel_basis = (f"capped at {HISTORICAL_RELIABILITY_CAP} by judgement, not "
                             f"measurement: this group's newest indicator is "
                             f"{fp.get('last_seen')}, older than {_STALE_DAYS} days. "
                             f"Measured precision for the catalogue as a whole: "
                             f"{rel_basis}")
            out.append({"group": gk, "group_name": nm, "score": round(score, 1),
                        "basis": basis, "verdict": "lead",
                        "reliability": rel,
                        "reliability_basis": rel_basis,
                        "footprint_freshness": fresh,
                        "footprint_last_seen": fp.get("last_seen") or "",
                        "mode": mode})
    return sorted(out, key=lambda x: -x["score"])[:limit]


def build_all(con, group_keys: list[str]) -> dict[str, dict]:
    from . import ioc_store
    prints = {}
    for gk in group_keys:
        rows = ioc_store.group_iocs(con, gk)
        if len(rows) >= 3:                       # need a few indicators to generalise
            prints[gk] = footprint_for(rows)
    return prints
