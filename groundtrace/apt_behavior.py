"""APT behaviour fingerprints, and which groups have exploited a vendor before.

This module makes no prediction. `likely_groups()` reports documented past
exploitation -- "has exploited this product before (3 CVEs)" -- which is a
checkable record, not a forecast about the CVE being viewed. Presenting it as a
prediction would be a claim with no measured accuracy behind it, which is
exactly what the rest of the tool refuses to do.

From each group's documented CVEs (high/medium confidence links only) and
its ATT&CK techniques:
  targets     vendors and products it exploits (CISA KEV product data)
  weaknesses  vulnerability classes (CWE) it exploits
  access      its ATT&CK initial-access techniques
  ransomware  share of its CVEs CISA flags as used in ransomware campaigns
  age         how old a vulnerability typically is when the group is seen
              exploiting it (evidence date minus CVE year) — n-day vs fresh

"Previously exploited": a CVE whose product a group has exploited before, or
whose vendor it has exploited repeatedly, with the count of prior CVEs given as
the reason. It is a record, never attribution, and never a statement that the
group will use the CVE being viewed.
"""
from __future__ import annotations

import re
import statistics
from collections import Counter
from typing import Optional

CWE_NAMES = {
    "CWE-20": "improper input validation", "CWE-22": "path traversal", "CWE-77": "command injection",
    "CWE-78": "OS command injection", "CWE-79": "cross-site scripting", "CWE-89": "SQL injection",
    "CWE-94": "code injection", "CWE-119": "memory corruption", "CWE-120": "buffer overflow",
    "CWE-121": "stack buffer overflow", "CWE-122": "heap buffer overflow", "CWE-125": "out-of-bounds read",
    "CWE-190": "integer overflow", "CWE-200": "information exposure", "CWE-269": "privilege management",
    "CWE-284": "access control", "CWE-287": "authentication bypass", "CWE-288": "authentication bypass",
    "CWE-306": "missing authentication", "CWE-352": "CSRF", "CWE-400": "resource exhaustion",
    "CWE-416": "use-after-free", "CWE-434": "unrestricted file upload", "CWE-502": "unsafe deserialization",
    "CWE-611": "XXE", "CWE-668": "exposure to wrong sphere", "CWE-787": "out-of-bounds write",
    "CWE-798": "hard-coded credentials", "CWE-843": "type confusion", "CWE-862": "missing authorization",
    "CWE-863": "incorrect authorization", "CWE-918": "SSRF", "CWE-917": "expression injection",
}
# Words too generic to say two products are the same one.
_GENERIC = {"server", "windows", "microsoft", "software", "system", "systems", "the", "and", "for", "web",
            "enterprise", "edition", "management", "manager", "platform", "client", "service", "services",
            "multiple", "products", "product", "office", "suite", "application", "app", "core", "secure"}


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def _tokens(s: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9]+", (s or "").lower().replace("_", " ")) if len(w) > 2 and w not in _GENERIC}


def fingerprint(cves: list[dict], kev: dict, techniques: Optional[list] = None) -> dict:
    """cves: the group's links (apt_cve.cves_for_group rows)."""
    strong = [c for c in cves if c["confidence"] in ("high", "medium")]
    vendors, products, cwes, ages = Counter(), Counter(), Counter(), []
    ransomware = 0
    for c in strong:
        k = kev.get(c["cve"])
        if k:
            vendors[k.get("vendorProject", "")] += 1
            products[(k.get("vendorProject", ""), k.get("product", ""))] += 1
            for w in k.get("cwes") or []:
                cwes[w] += 1
            ransomware += str(k.get("knownRansomwareCampaignUse", "")).lower() == "known"
        year = int(c["cve"][4:8])
        for e in c.get("evidence") or []:
            if e.get("day"):
                ages.append(max(0, int(e["day"][:4]) - year))
                break
    access = sorted({t["name"] for t in techniques or [] if "initial-access" in (t.get("tactics") or [])})
    tactics = Counter(tac for t in techniques or [] for tac in t.get("tactics") or [])
    kev_n = sum(1 for c in strong if c["cve"] in kev)
    return {
        "cves": len(strong), "cves_in_kev": kev_n,
        "vendors": [[v, n] for v, n in vendors.most_common(6) if v],
        "products": [[f"{v} {p}".strip(), n] for (v, p), n in products.most_common(8) if v or p],
        "weaknesses": [[w, CWE_NAMES.get(w, ""), n] for w, n in cwes.most_common(6)],
        "initial_access": access,
        "tactics": tactics.most_common(6),
        "ransomware_share": round(ransomware / kev_n, 2) if kev_n else None,
        "median_cve_age_years": statistics.median(ages) if ages else None,
        "_vendor_counts": {_norm(v): n for v, n in vendors.items() if v},
        "_products": [(_norm(v), _tokens(p), n) for (v, p), n in products.items()],
    }


def cve_products(cve: str, kev: dict, cpes: Optional[list[str]] = None) -> list[tuple[str, set]]:
    """(normalised vendor, product tokens) for a CVE, from KEV and/or CPEs."""
    out, seen = [], set()
    k = kev.get(cve)
    if k:
        out.append((_norm(k.get("vendorProject", "")), _tokens(k.get("product", ""))))
    for cpe in cpes or []:
        parts = cpe.split(":")
        if len(parts) > 4 and (parts[3], parts[4]) not in seen:
            seen.add((parts[3], parts[4]))
            out.append((_norm(parts[3]), _tokens(parts[4])))
    return out


def likely_groups(prints: dict[str, dict], targets: list[tuple[str, set]], exclude: set = frozenset(),
                  limit: int = 6) -> list[dict]:
    """Groups whose past exploitation matches this CVE's vendor/product."""
    out = []
    for gk, fp in prints.items():
        if gk in exclude or not targets:
            continue
        best = None
        for vendor, ptoks in targets:
            if not vendor:
                continue
            same_product = sum(n for v, t, n in fp["_products"] if v == vendor and t and ptoks and (t & ptoks))
            same_vendor = fp["_vendor_counts"].get(vendor, 0)
            if same_product:
                cand = (3 * same_product + same_vendor, f"has exploited this product before ({same_product} CVE{'s' if same_product > 1 else ''})")
            elif same_vendor >= 2:
                cand = (same_vendor, f"has exploited {same_vendor} vulnerabilities from this vendor")
            else:
                continue
            best = max(best or cand, cand)
        if best:
            out.append({"group": gk, "score": best[0], "why": best[1]})
    return sorted(out, key=lambda x: -x["score"])[:limit]


def build_all(links_con, kev: dict, group_keys: list[str], techniques_for) -> dict[str, dict]:
    from . import apt_cve
    prints = {}
    for gk in group_keys:
        cves = apt_cve.cves_for_group(links_con, gk)
        if cves:
            prints[gk] = fingerprint(cves, kev, techniques_for(gk))
    return prints


def public(fp: dict) -> dict:
    return {k: v for k, v in fp.items() if not k.startswith("_")}
