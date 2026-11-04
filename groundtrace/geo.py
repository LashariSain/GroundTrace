"""Geographic threat intelligence — the data behind the Threat map tab.

CVEs carry no inherent geography, so we derive it from the darkfeeds signals:
  - infrastructure: the country/ASN/hosting provider of each IOC IP
    (RDAP/Cymru) — where C2 servers, payload hosts and botnet nodes live;
  - actor origin: a curated threat-actor -> origin-country attribution;
  - targeting: who a signal says is being targeted.

Beyond counts, every country gets a profile (what malware, what kind of
infrastructure, which hosting providers, which actors, sample IOCs) and the
whole dataset gets auto-written key findings, so the map answers "so what?"
rather than just "where?". Country codes are ISO-3166-1 alpha-2; findings embed
them as [[CC]] tokens that the dashboard renders as flag + country name.
"""
from __future__ import annotations

import json
import re
import sqlite3
from collections import Counter, defaultdict
from typing import Optional

# Best-effort attribution of known actors to an origin ISO-3166-1 alpha-2
# country. Matched as a case-insensitive substring of the signal's threat_actor.
# Ransomware brands are frequently Russia-nexus (criminal, not state); where an
# origin is genuinely unknown we leave the actor off the origin layer rather
# than guess. Extend freely — this is a lookup, not a model.
ACTOR_ORIGIN = {
    # South Asia APTs
    "apt36": "PK", "transparent tribe": "PK", "sidecopy": "PK",
    "sidewinder": "IN", "bitter": "IN", "patchwork": "IN", "donot": "IN",
    # DPRK
    "lazarus": "KP", "kimsuky": "KP", "andariel": "KP", "bluenoroff": "KP",
    # Russia (state)
    "apt28": "RU", "fancy bear": "RU", "apt29": "RU", "cozy bear": "RU",
    "sandworm": "RU", "turla": "RU", "gamaredon": "RU",
    # China
    "apt41": "CN", "mustang panda": "CN", "apt10": "CN", "volt typhoon": "CN",
    "apt31": "CN", "winnti": "CN",
    # Iran
    "apt34": "IR", "oilrig": "IR", "muddywater": "IR", "charming kitten": "IR",
    "apt35": "IR",
    # Ransomware brands (Russia-nexus criminal, best-effort)
    "lockbit": "RU", "qilin": "RU", "akira": "RU", "blackcat": "RU",
    "alphv": "RU", "clop": "RU", "play": "RU", "royal": "RU",
    "black basta": "RU", "blackbasta": "RU", "safepay": "RU",
    "inc ransom": "RU", "incransom": "RU", "medusa": "RU",
}

# Commercial cloud / mass-hosting providers. Infrastructure on these says
# "rented", not "attacker lives here" — the single most important caveat when
# reading an infrastructure map, so we measure it explicitly.
_CLOUD = ("amazon", "aws", "digitalocean", "akamai", "linode", "hetzner", "ovh",
          "tencent", "alibaba", "aliyun", "google", "microsoft", "azure", "vultr",
          "choopa", "oracle", "contabo", "cloudflare", "m247", "leaseweb",
          "hostinger", "ionos", "scaleway", "upcloud", "kamatera", "cloudvalley")

_POST_EXPLOIT = ("cobaltstrike", "cobalt strike", "sliver", "brute ratel", "vshell",
                 "metasploit", "havoc", "mythic", "covenant", "supershell")
_STEALERS = ("stealer", "vidar", "lumma", "redline", "stealc", "raccoon", "rhadamanthys",
             "formbook", "agenttesla", "agent tesla", "snake")
_LOADERS = ("loader", "amadey", "smokeloader", "gootloader", "icedid", "bumblebee", "pikabot",
            "latrodectus", "guloader", "privateloader")
_BOTNETS = ("mirai", "botnet", "ddos", "iot", "gafgyt", "mozi", "bashlite", "drb-ra")
_RATS = ("rat", "asyncrat", "remcos", "njrat", "quasar", "dcrat", "xworm",
         "purerat", "purehvnc", "venomrat", "nanocore", "crimsonrat")


# Consumer / telecom ISPs. Malicious IPs here are usually *compromised devices*
# (infected routers, IoT, home PCs acting as bots) — victims, not rented attack
# servers — so the right action is notify/report, never "block the ASN".
_ISP = ("telecom", "telekom", "telecommunication", "internet services", "broadband",
        "mobile", "cable", "wireless", "ptcl", "cmpak", "airnet", "jio", "airtel",
        "vodafone", "comcast", "verizon", "charter", "spectrum", "telmex", "chinanet",
        "unicom", "china mobile", "maroc telecom", "turk telekom", "rostelecom",
        "orange", "telefonica", "deutsche telekom", "bsnl", "viettel", "vnpt", "kt corp",
        "postes et telecommunications")

_NO_FAMILY = {"", "unknown", "unknown malware", "n/a", "none"}


def actor_origin(actor: str) -> Optional[str]:
    a = (actor or "").lower()
    for key, cc in ACTOR_ORIGIN.items():
        if key in a:
            return cc
    return None


def _category(signal_type: str, family: str, tags: list, title: str) -> str:
    """Human-readable kind of infrastructure, from family/tags/ThreatFox type."""
    words = {t.lower() for t in tags} | {(family or "").lower()}
    blob = " ".join(words)
    if signal_type == "ransomware_victim" or "ransomware" in blob:
        return "Ransomware"
    if any(k in blob for k in _POST_EXPLOIT):
        return "Post-exploitation C2"
    if any(k in blob for k in _STEALERS):
        return "Infostealer"
    if any(k in blob for k in _LOADERS):
        return "Loader"
    if any(k in blob for k in _BOTNETS):
        return "Botnet / DDoS"
    if any(k == w or w.endswith(k) for w in words for k in _RATS):
        return "RAT C2"
    if "payload_delivery" in (title or ""):
        return "Payload delivery"
    if "botnet_cc" in (title or ""):
        return "Botnet / DDoS"
    return (signal_type or "other").replace("_", " ").capitalize()


def _host_name(org: str) -> str:
    """'DTAG - Deutsche Telekom AG, DE' -> 'Deutsche Telekom AG'."""
    org = (org or "").strip()
    if " - " in org:
        org = org.split(" - ", 1)[1]
    return re.sub(r",\s*[A-Z]{2}$", "", org).strip() or "unknown"


def _is_cloud(org: str) -> bool:
    o = (org or "").lower()
    return any(k in o for k in _CLOUD)


def _is_isp(org: str) -> bool:
    o = (org or "").lower()
    return not _is_cloud(org) and any(k in o for k in _ISP)


def _loads(s, default):
    try:
        v = json.loads(s or "")
        return v if isinstance(v, type(default)) else default
    except (json.JSONDecodeError, TypeError):
        return default


def _new_country() -> dict:
    return {"signals": 0, "ips": set(), "families": Counter(), "categories": Counter(),
            "hosts": Counter(), "cloud": 0, "isp": 0, "actors": Counter(), "cves": Counter(),
            "samples": [], "providers": {}}


def geo_summary(db_path: str) -> dict:
    """Aggregate signal geography into map layers, country profiles and findings."""
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(
            "SELECT signal_type, source_name, source_url, title, malware_family, tags, "
            "threat_actor, target_country, cve_ids, ip_enrichment, collected_at "
            "FROM signals ORDER BY collected_at DESC").fetchall()
    finally:
        con.close()

    per_country: dict = defaultdict(_new_country)
    actors: dict = defaultdict(lambda: {"count": 0, "cves": Counter(), "origin": None,
                                        "families": Counter()})
    family_countries: dict = defaultdict(set)
    family_total: Counter = Counter()
    targets: dict = defaultdict(lambda: {"signals": 0, "actors": Counter()})
    total_cloud = total_geo_ips = 0

    for r in rows:
        enr = _loads(r["ip_enrichment"], {})
        cves = _loads(r["cve_ids"], [])
        tags = _loads(r["tags"], [])
        family = (r["malware_family"] or "").strip()
        if family.lower() in _NO_FAMILY:
            family = ""
        actor = (r["threat_actor"] or "").strip()
        cat = _category(r["signal_type"], family, tags, r["title"] or "")

        # Group this signal's IPs by country; count a country once per signal
        # (so one botnet with 40 IPs doesn't swamp the map), IPs individually.
        by_cc: dict = defaultdict(list)
        for ip, d in enr.items():
            d = d or {}
            cc = (d.get("country") or "").upper()
            if len(cc) == 2 and cc.isalpha():
                by_cc[cc].append((ip, d.get("org") or d.get("as_name") or "", d))

        for cc, ips in by_cc.items():
            pc = per_country[cc]
            pc["signals"] += 1
            pc["categories"][cat] += 1
            if family:
                pc["families"][family] += 1
                family_countries[family].add(cc)
            if actor:
                pc["actors"][actor] += 1
            for c in cves:
                pc["cves"][c] += 1
            for ip, org, d in ips:
                _add_provider_ip(pc["providers"], ip, org, d, r, family, cat, cves)
                if ip in pc["ips"]:
                    continue
                pc["ips"].add(ip)
                host = _host_name(org)
                pc["hosts"][host] += 1
                cloud = _is_cloud(org)
                pc["cloud"] += cloud
                pc["isp"] += _is_isp(org)
                total_cloud += cloud
                total_geo_ips += 1
            if len(pc["samples"]) < 6:
                ip, org, _ = ips[0]
                pc["samples"].append({
                    "ioc": ip, "family": family or "—", "category": cat,
                    "host": _host_name(org), "date": (r["collected_at"] or "")[:10],
                    "url": r["source_url"] or "", "source": r["source_name"] or ""})

        if family:
            family_total[family] += 1
        if actor:
            a = actors[actor]
            a["count"] += 1
            a["origin"] = actor_origin(actor)
            if family:
                a["families"][family] += 1
            for c in cves:
                a["cves"][c] += 1

        tc = (r["target_country"] or "").strip()
        if tc:
            t = targets[tc]
            t["signals"] += 1
            if actor:
                t["actors"][actor] += 1

    # ---- country profiles -------------------------------------------------
    ref_day = (rows[0]["collected_at"] or "")[:10] if rows else ""  # latest collection
    countries = {}
    for cc, v in per_country.items():
        n_ips = len(v["ips"])
        countries[cc] = {
            "signals": v["signals"],
            "ips": n_ips,
            "cloud_pct": round(100 * v["cloud"] / n_ips) if n_ips else 0,
            "isp_pct": round(100 * v["isp"] / n_ips) if n_ips else 0,
            "families": v["families"].most_common(8),
            "categories": v["categories"].most_common(6),
            "hosts": v["hosts"].most_common(5),
            "actors": [a for a, _ in v["actors"].most_common(8)],
            "cves": [c for c, _ in v["cves"].most_common(12)],
            "samples": v["samples"],
            "providers": _provider_list(v["providers"], ref_day),
            "summary": _country_summary(cc, v, n_ips),
        }

    # ---- actor-origin layer -----------------------------------------------
    origin: Counter = Counter()
    origin_actors: dict = defaultdict(Counter)
    for name, a in actors.items():
        if a["origin"]:
            origin[a["origin"]] += a["count"]
            origin_actors[a["origin"]][name] += a["count"]

    actor_list = sorted(
        ({"actor": a, "count": v["count"], "origin": v["origin"],
          "families": [f for f, _ in v["families"].most_common(4)],
          "cves": [c for c, _ in v["cves"].most_common(6)]}
         for a, v in actors.items()),
        key=lambda x: x["count"], reverse=True)

    infra = {cc: v["signals"] for cc, v in per_country.items()}
    ranking = sorted(infra, key=infra.get, reverse=True)
    return {
        "infra": infra,
        "max": max(infra.values()) if infra else 0,
        "origin": dict(origin),
        "origin_max": max(origin.values()) if origin else 0,
        "origin_actors": {cc: [a for a, _ in c.most_common(8)] for cc, c in origin_actors.items()},
        "ranking": [{"cc": cc, "signals": infra[cc],
                     "top_family": (countries[cc]["families"] or [["—"]])[0][0],
                     "top_host": (countries[cc]["hosts"] or [["—"]])[0][0],
                     "cloud_pct": countries[cc]["cloud_pct"],
                     "isp_pct": countries[cc]["isp_pct"]}
                    for cc in ranking[:15]],
        "countries": countries,
        "actors": actor_list[:30],
        "targets": {k: {"signals": v["signals"],
                        "actors": [a for a, _ in v["actors"].most_common(5)]}
                    for k, v in targets.items()},
        "findings": _findings(infra, countries, total_cloud, total_geo_ips,
                              family_total, family_countries, origin, origin_actors,
                              targets),
        "leaderboard": _leaderboard(countries),
        "focus": _focus(rows, countries),
        "as_of": ref_day,
        "total_signals": len(rows),
        "geolocated_signals": sum(infra.values()),
    }


_MAX_PROVIDER_IPS = 1000  # served per country on demand (/geo/<CC>)


def _kind(org: str) -> str:
    return "cloud" if _is_cloud(org) else "isp" if _is_isp(org) else "hosting"


def _add_provider_ip(providers: dict, ip: str, org: str, d: dict, row, family: str,
                     cat: str, cves: list) -> None:
    """Hosting profile: provider -> its malicious IPs, with what each was seen
    doing. Rows arrive newest first, so the first sighting is the last seen."""
    asn = str(d.get("asn") or "")
    key = asn or _host_name(org)
    p = providers.setdefault(key, {"name": _host_name(org), "asn": asn, "kind": _kind(org),
                                   "ips": {}, "families": Counter()})
    if family:
        p["families"][family] += 1
    e = p["ips"].get(ip)
    if e is None:
        e = p["ips"][ip] = {"ip": ip, "cidr": d.get("cidr") or "", "families": [],
                            "category": cat, "signals": 0, "cves": [],
                            "last_seen": (row["collected_at"] or "")[:10],
                            "first_seen": (row["collected_at"] or "")[:10],
                            "source": row["source_name"] or "", "url": row["source_url"] or ""}
    e["signals"] += 1
    if row["collected_at"]:
        e["first_seen"] = row["collected_at"][:10]  # older rows come later
    if family and family not in e["families"]:
        e["families"].append(family)
    for c in cves:
        if c not in e["cves"]:
            e["cves"].append(c)


# How dangerous each kind of hosted infrastructure is: operator-run C2 and
# ransomware outrank botnet nodes (mostly hijacked devices).
_CATEGORY_WEIGHT = {"Post-exploitation C2": 1.0, "Ransomware": 1.0, "RAT C2": 0.9,
                    "Infostealer": 0.8, "Loader": 0.8, "Payload delivery": 0.7,
                    "Botnet / DDoS": 0.5}
_NEW_DAYS = 7
_CLUSTER_MIN = 3


def _days_before(ref: str, day: str) -> int:
    from datetime import date
    try:
        return (date.fromisoformat(ref) - date.fromisoformat(day)).days
    except ValueError:
        return 10 ** 6


def provider_score(ips: list[dict], families: int, ref_day: str,
                   clustered: int = 0) -> dict:
    """0-100 threat score for a hosting provider, with its parts so the number
    explains itself. Volume (40) on a log scale, recency (25) = share of IPs
    seen in the last week, severity (20) = what the IPs run, and 15 for the
    higher of malware diversity or density (share of IPs packed into /24s
    with several malicious hosts: a dedicated attacker block). Recency is measured against the latest
    collection, so a paused watcher doesn't make everything look stale."""
    import math
    n = len(ips)
    if not n:
        return {"score": 0, "parts": {}}
    volume = min(1.0, math.log10(1 + n) / 2) * 40              # 100 IPs -> full marks
    fresh = sum(_days_before(ref_day, i["last_seen"]) <= _NEW_DAYS for i in ips)
    recency = fresh / n * 25
    severity = sum(_CATEGORY_WEIGHT.get(i["category"], 0.4) for i in ips) / n * 20
    diversity = min(1.0, families / 5) * 15
    density = clustered / n * 15
    parts = {"volume": round(volume), "recency": round(recency), "severity": round(severity),
             "diversity": round(diversity), "density": round(density)}
    return {"score": round(volume + recency + severity + max(diversity, density)), "parts": parts}


def ip_clusters(ips: list[dict]) -> list[dict]:
    """IPv4 /24s holding several malicious IPs: attackers renting neighbouring
    servers. Blocking the /24 is far narrower than blocking the whole ASN."""
    groups: dict = defaultdict(list)
    for i in ips:
        parts = i["ip"].split(".")
        if len(parts) == 4:
            groups[".".join(parts[:3]) + ".0/24"].append(i["ip"])
    return sorted(({"cidr": c, "ips": len(v),
                    "members": sorted(v, key=lambda ip: int(ip.rsplit(".", 1)[1]))[:20]}
                   for c, v in groups.items() if len(v) >= _CLUSTER_MIN),
                  key=lambda c: -c["ips"])


def _provider_list(providers: dict, ref_day: str) -> list[dict]:
    out = []
    for p in providers.values():
        ips = sorted(p["ips"].values(), key=lambda e: (-e["signals"], e["ip"]))
        new = [i for i in ips if _days_before(ref_day, i["first_seen"]) <= _NEW_DAYS]
        for i in ips:
            i["new"] = i in new
        clusters = ip_clusters(ips)
        out.append({"name": p["name"], "asn": p["asn"], "kind": p["kind"],
                    "ip_count": len(ips), "new_7d": len(new),
                    "families": [f for f, _ in p["families"].most_common(3)],
                    **provider_score(ips, len(p["families"]), ref_day,
                                     sum(c["ips"] for c in clusters)),
                    "clusters": clusters,
                    "ips": ips[:_MAX_PROVIDER_IPS]})
    return sorted(out, key=lambda p: (-p["score"], -p["ip_count"]))


def _leaderboard(countries: dict, limit: int = 15) -> list[dict]:
    """Worst hosting networks across all countries; one ASN can span several."""
    merged: dict = {}
    for cc, c in countries.items():
        for p in c["providers"]:
            m = merged.setdefault(p["asn"] or p["name"], {
                "name": p["name"], "asn": p["asn"], "kind": p["kind"], "countries": [],
                "ip_count": 0, "new_7d": 0, "score": 0, "families": [], "clusters": 0})
            m["countries"].append(cc)
            m["ip_count"] += p["ip_count"]
            m["new_7d"] += p["new_7d"]
            m["score"] = max(m["score"], p["score"])
            m["clusters"] += len(p["clusters"])
            m["families"] = list(dict.fromkeys(m["families"] + p["families"]))[:4]
    return sorted(merged.values(), key=lambda m: (-m["score"], -m["ip_count"]))[:limit]


def _focus(rows, countries: dict) -> Optional[dict]:
    """The optional focus country: infrastructure hosted there plus signals targeting it."""
    from darkfeeds import focus
    chosen = focus.get()
    if not chosen.country:
        return None
    targeting = [{"title": r["title"] or "", "actor": r["threat_actor"] or "",
                  "family": r["malware_family"] or "", "date": (r["collected_at"] or "")[:10],
                  "source": r["source_name"] or "", "url": r["source_url"] or "",
                  "cves": _loads(r["cve_ids"], [])}
                 for r in rows if (r["target_country"] or "").strip().lower() in (chosen.country, chosen.code.lower())]
    pk = countries.get(chosen.code) or {}
    actors = Counter(t["actor"] for t in targeting if t["actor"])
    return {"targeting": targeting[:100], "targeting_count": len(targeting),
            "actors": actors.most_common(10),
            "hosted_ips": pk.get("ips", 0), "isp_pct": pk.get("isp_pct", 0),
            "providers": [{k: p[k] for k in ("name", "asn", "kind", "ip_count", "new_7d", "score")}
                          for p in pk.get("providers", [])[:10]]}


def slim(summary: dict) -> dict:
    """The map payload without per-IP lists (~1.3 MB -> a fraction); the
    dashboard fetches a country's IPs with /geo/<CC> when it is opened."""
    out = dict(summary)
    out["countries"] = {cc: {**c, "providers": [{k: v for k, v in p.items() if k != "ips"}
                                                for p in c["providers"]]}
                        for cc, c in summary["countries"].items()}
    return out


def _country_summary(cc: str, v: dict, n_ips: int) -> str:
    parts = [f"{v['signals']} signal(s) on {n_ips} IP(s) hosted in [[{cc}]]"]
    cats = v["categories"].most_common(2)
    if cats:
        parts.append("mostly " + " and ".join(c.lower() for c, _ in cats))
    fams = [f for f, _ in v["families"].most_common(3)]
    if fams:
        parts.append("(" + ", ".join(fams) + ")")
    s = " — ".join(parts[:2]) + (" " + parts[2] if len(parts) > 2 else "") + "."
    hosts = v["hosts"].most_common(1)
    if n_ips and v["isp"] / n_ips >= 0.5:
        # Consumer-ISP addresses: infected devices acting as bots — victims.
        s += (f" {round(100 * v['isp'] / n_ips)}% is on consumer/telecom ISPs "
              f"({hosts[0][0] if hosts else 'local ISPs'}) — likely compromised routers/IoT "
              f"in [[{cc}]] being used as bots. Notify the ISP / national CERT; don't block the ASN.")
    elif hosts and n_ips:
        share = round(100 * hosts[0][1] / n_ips)
        if share >= 40 and n_ips >= 5:
            s += (f" {share}% sits on a single provider ({hosts[0][0]}) — concentrated "
                  f"attacker infrastructure worth blocking at the ASN level.")
    if n_ips and v["cloud"] / n_ips >= 0.5:
        s += (" Most of it is rented commercial cloud, so this marks where attackers "
              "host, not where they are.")
    return s


def _findings(infra, countries, total_cloud, total_geo_ips, family_total,
              family_countries, origin, origin_actors, targets) -> list[str]:
    out: list[str] = []
    total = sum(infra.values())
    if not total:
        return ["No geolocated infrastructure yet — run a darkfeeds collection with IP enrichment."]

    top = sorted(infra, key=infra.get, reverse=True)
    t1 = top[0]
    c1 = countries[t1]
    fam1 = c1["families"][0][0] if c1["families"] else "mixed malware"
    out.append(f"[[{t1}]] hosts the most threat infrastructure: {infra[t1]} signals "
               f"({round(100 * infra[t1] / total)}% of all geolocated), led by {fam1}. "
               f"Top 3 ([[{top[0]}]], " + ", ".join(f"[[{c}]]" for c in top[1:3])
               + f") account for {round(100 * sum(infra[c] for c in top[:3]) / total)}%.")

    if total_geo_ips:
        pct = round(100 * total_cloud / total_geo_ips)
        out.append(f"{pct}% of malicious IPs sit on commercial cloud / mass-hosting providers. "
                   "Infrastructure country reflects where attackers rent servers, not their "
                   "nationality — read the map as 'where to block', not 'who attacked'.")

    # Single-provider concentration: the most actionable infra finding.
    # Skip consumer ISPs here — concentration there means infected devices, not
    # an attacker-run host, and "block the ASN" would cut off a country's users.
    best = None
    for cc, c in countries.items():
        if c["ips"] >= 8 and c["hosts"] and c["isp_pct"] < 50:
            share = c["hosts"][0][1] / c["ips"]
            if share >= 0.4 and (best is None or c["hosts"][0][1] > best[2]):
                best = (cc, c["hosts"][0][0], c["hosts"][0][1], round(100 * share))
    if best:
        cc, host, n, share = best
        out.append(f"Concentrated attacker hosting: {share}% of [[{cc}]]'s malicious IPs ({n}) are "
                   f"on one provider — {host}. A single ASN block would cut a large slice of this activity.")

    bots = sorted((cc for cc, c in countries.items() if c["ips"] >= 8 and c["isp_pct"] >= 50),
                  key=lambda cc: -countries[cc]["ips"])
    if bots:
        out.append("Compromised-device hotspots (malicious IPs on consumer ISPs — infected routers/IoT, "
                   "i.e. victims): " + ", ".join(
                       f"[[{cc}]] {countries[cc]['ips']} IPs ({countries[cc]['families'][0][0] if countries[cc]['families'] else 'bots'})"
                       for cc in bots[:4]) + ". Report to the local CERT rather than block.")

    if family_total:
        fam = max(family_countries, key=lambda f: (len(family_countries[f]), family_total[f]))
        n = family_total[fam]
        spread = sorted(family_countries[fam], key=lambda c: -infra.get(c, 0))[:4]
        out.append(f"{fam} is the most geographically widespread family: {n} signals across "
                   f"{len(family_countries[fam])} countries (" + ", ".join(f"[[{c}]]" for c in spread) + ").")

    if origin:
        ranked = origin.most_common(3)
        bits = []
        for cc, n in ranked:
            names = ", ".join(a for a, _ in origin_actors[cc].most_common(3))
            bits.append(f"[[{cc}]] {n} signals ({names})")
        out.append("Attributed actor activity by origin: " + "; ".join(bits) + ".")

    for tc, t in sorted(targets.items(), key=lambda kv: -kv[1]["signals"])[:2]:
        who = ", ".join(a for a, _ in t["actors"].most_common(3)) or "unattributed actors"
        out.append(f"{t['signals']} signals explicitly reference targeting of {tc.title()} — "
                   f"linked to {who}.")
    return out
