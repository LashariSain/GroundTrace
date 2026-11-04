"""
DarkFeeds CLI — command-line interface for threat intelligence collection.

Usage:
  python -m darkfeeds collect                    # collect from all API sources
  python -m darkfeeds collect --source bazaar    # collect from MalwareBazaar only
  python -m darkfeeds hunt-apt                   # search for APT malware samples
  python -m darkfeeds crawl                      # crawl .onion forums (requires Tor)
  python -m darkfeeds focus-threats              # show signals for the focus country
  python -m darkfeeds stats                      # collection statistics
"""
from __future__ import annotations
from . import focus

import argparse
import sys
from datetime import datetime, timedelta

from .config import Config
from .store import Store


VT_SIGNALS_PER_BATCH = 8  # ~2 min at the free-tier rate


def _enrich_batch(args, config: Config, signals: list, store: Store) -> None:
    if getattr(args, "no_enrich", False) or not signals:
        return
    from .enrich import enrich_and_store_signals
    n = enrich_and_store_signals(signals, store, shodan_api_key=config.shodan_api_key)
    if n:
        extra = " + Shodan" if config.shodan_api_key else ""
        print(f"[+] IP-enriched {n} signal(s) (org/ASN/country via RDAP + Cymru{extra})")

    if config.vt_api_key:
        from .virustotal import check_hash
        from dataclasses import asdict
        # Free tier is ~15 s per lookup, so a few hundred hashes would stall
        # the watcher for over an hour. Check a capped number per batch; the
        # rest stay pending for `darkfeeds enrich-hashes`.
        hash_signals = [s for s in signals if s.malware_hashes][:VT_SIGNALS_PER_BATCH]
        if hash_signals:
            print(f"[*] Checking {sum(len(s.malware_hashes) for s in hash_signals)} "
                 f"hash(es) against VirusTotal (free tier: ~15s/lookup)...")
            for s in hash_signals:
                enrichment = {}
                for h in s.malware_hashes:
                    rep = check_hash(h, api_key=config.vt_api_key)
                    enrichment[h] = asdict(rep)
                    if rep.is_malicious:
                        print(f"    {h[:16]}... flagged malicious by "
                             f"{rep.malicious}/{rep.total_engines} engines")
                store.save_hash_enrichment(s.signal_id, enrichment)


def run_collection(config: Config, store: Store, *, source: str | None = None,
                   limit: int = 50, enrich: bool = True) -> list:
    """Collect from the API sources, save, and (optionally) enrich. Shared by
    the `collect` command and the groundtrace watcher. Returns the signals."""
    from .collectors import (
        collect_malwarebazaar_recent,
        collect_threatfox_recent,
        collect_ransomlook,
        collect_otx_pulses,
    )
    from .news import collect_news_feeds

    all_signals = []

    if source in (None, "bazaar"):
        all_signals.extend(collect_malwarebazaar_recent(limit=limit))

    if source in (None, "threatfox"):
        all_signals.extend(collect_threatfox_recent(days=3))

    if source in (None, "ransomware", "ransomlook"):
        all_signals.extend(collect_ransomlook())

    if source in (None, "otx") and config.otx_api_key:
        for search in focus.get().otx_searches or ["APT", "ransomware"]:
            all_signals.extend(collect_otx_pulses(config.otx_api_key, search, limit=10))

    if source in (None, "news"):
        all_signals.extend(collect_news_feeds(limit=limit))

    # Feeds return overlapping windows (ThreatFox: last 3 days every run), so
    # most signals are already stored and enriched. Enrich only the new ones;
    # re-enriching duplicates made one watcher cycle take over an hour.
    fresh = [s for s in all_signals if store.save_signal(s)]
    print(f"\n{'='*60}")
    print(f"[+] Collection complete: {len(all_signals)} signals, {len(fresh)} new")
    _enrich_batch(argparse.Namespace(no_enrich=not enrich), config, fresh, store)
    return all_signals


def cmd_collect(args, config: Config, store: Store):
    """Collect threat intelligence from API sources."""
    run_collection(config, store, source=args.source, limit=args.limit,
                   enrich=not args.no_enrich)


def cmd_hunt_apt(args, config: Config, store: Store):
    """Hunt for malware samples from APT tooling."""
    from .collectors import collect_malwarebazaar_by_tag

    apt_malware_tags = focus.get().hunt_tags or ["PlugX", "ShadowPad", "CobaltStrike"]

    all_signals = []
    for tag in apt_malware_tags:
        signals = collect_malwarebazaar_by_tag(tag)
        all_signals.extend(signals)

    new = store.save_signals(all_signals)
    print(f"\n{'='*60}")
    print(f"[+] APT hunt complete: {len(all_signals)} samples, {new} new")
    _enrich_batch(args, config, all_signals, store)


def cmd_news(args, config: Config, store: Store):
    """Collect RSS/Atom threat news and persist the resulting signals."""
    from .news import collect_news_feeds

    signals = collect_news_feeds(limit=args.limit)
    new = store.save_signals(signals)
    print(f"\n{'='*60}")
    print(f"[+] News collection complete: {len(signals)} stories, {new} new")


def cmd_crawl(args, config: Config, store: Store):
    """Crawl .onion forums via Tor (passive, read-only)."""
    from .onion_crawler import OnionCrawler

    crawler = OnionCrawler(config)

    # Check Tor connectivity first
    if not crawler.check_tor():
        print("\n[!] Tor is not running. Start Tor first:")
        print("    Windows: tor.exe (from Tor Expert Bundle)")
        print("    Linux:   sudo systemctl start tor")
        print("    Mac:     brew services start tor")
        sys.exit(1)

    # For demo/testing — crawl Ahmia (Tor search engine, .onion but simple)
    from .models import ForumTarget
    targets = [
        ForumTarget(
            name="Ahmia Search",
            base_url="http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion",
            forum_type="custom",
            requires_tor=True,
            sections=[
                {"path": f"/search/?q={q}", "name": f"Search: {q}", "pages": 1}
                for q in ["exploit CVE 2026", "0day RCE", "fortinet exploit", *focus.get().crawl_queries]
            ],
            max_pages=1,
        ),
    ]

    all_signals = []
    for target in targets:
        signals = crawler.crawl_forum(target)
        all_signals.extend(signals)

    new = store.save_signals(all_signals)
    print(f"\n{'='*60}")
    print(f"[+] Crawl complete: {len(all_signals)} signals, {new} new")
    _enrich_batch(args, config, all_signals, store)


def cmd_focus_threats(args, config: Config, store: Store):
    """Show threat signals for the focus country."""
    country = focus.get().country
    if not country:
        print("[*] No focus country configured (see GROUNDTRACE_FOCUS_FILE).")
        return
    since = None
    if args.since:
        hours = int(args.since.rstrip("hdm"))
        since = datetime.utcnow() - timedelta(hours=hours)

    signals = store.get_focus_signals(country, since=since, limit=args.limit)

    if not signals:
        print(f"[*] No signals found for {country}.")
        return

    print(f"\n{'='*60}")
    print(f"  {country.upper()} THREAT SIGNALS ({len(signals)} results)")
    print(f"{'='*60}\n")

    for s in signals:
        pri = s["priority"]
        icon = {"P1": "🔴", "P2": "🟠", "P3": "🟡", "P4": "🟢"}.get(pri, "⚪")
        print(f"  {icon} [{pri}] {s['title'][:70]}")
        print(f"     Source: {s['source_name']} | Score: {s['relevance_score']:.2f}")
        if s["threat_actor"]:
            print(f"     APT: {s['threat_actor']}")
        if s["cve_ids"] and s["cve_ids"] != "[]":
            print(f"     CVEs: {s['cve_ids']}")
        if s["malware_family"]:
            print(f"     Malware: {s['malware_family']}")
        print()


def cmd_enrich_ips(args, config: Config, store: Store):
    """RDAP/Shodan-enrich IPs on stored signals that haven't been enriched yet."""
    import json as _json
    from dataclasses import asdict
    from .enrich import enrich_ips
    from .shodan_client import host_lookup

    pending = store.get_unenriched_ips(limit=args.limit)
    if not pending:
        print("[*] No unenriched signals with IPs found.")
        return

    # One enrich_ips call for the whole batch: Team Cymru takes 1,000 IPs per
    # query, so per-signal calls left a 2,000-IP backlog that never cleared.
    by_ip = {r.ip: r for r in enrich_ips(sorted({
        ip for row in pending for ip in _json.loads(row["ip_addresses"] or "[]")}))}

    total_ips = 0
    for row in pending:
        ips = _json.loads(row["ip_addresses"] or "[]")
        if not ips:
            continue
        results = [by_ip[ip] for ip in ips if ip in by_ip]
        enrichment = {r.ip: asdict(r) for r in results}
        if config.shodan_api_key:
            for ip, data in enrichment.items():
                if not data.get("skipped_reason"):
                    data["shodan"] = asdict(host_lookup(ip, api_key=config.shodan_api_key))
        store.save_ip_enrichment(row["signal_id"], enrichment)
        total_ips += len(ips)
        for r in results:
            if r.skipped_reason:
                print(f"  {r.ip:16} skipped ({r.skipped_reason})")
            elif r.error:
                print(f"  {r.ip:16} error: {r.error}")
            else:
                print(f"  {r.ip:16} {r.org or '?':30} {r.country or '?':4} AS{r.asn or '?'}")

    print(f"\n[+] Enriched {len(pending)} signal(s), {total_ips} IP(s).")


def cmd_otx_backfill(args, config: Config, store: Store):
    """Older OTX signals were saved from search results, which carry no
    indicators; fetch each pulse in full and fill them in."""
    from .collectors import backfill_otx_indicators
    if not config.otx_api_key:
        print("[!] OTX: no API key set (DARKFEEDS_OTX_KEY)")
        return
    n = backfill_otx_indicators(config.otx_api_key, store, limit=args.limit)
    print(f"[+] OTX: filled in indicators for {n} pulse(s); run enrich-ips to geolocate their IPs")


def cmd_enrich_hashes(args, config: Config, store: Store):
    """VirusTotal-check hashes on stored signals that haven't been checked yet."""
    import json as _json
    from dataclasses import asdict
    from .virustotal import check_hash

    if not config.vt_api_key:
        print("[!] No VirusTotal key configured — set DARKFEEDS_VT_KEY.")
        return

    pending = store.get_unenriched_hashes(limit=args.limit)
    if not pending:
        print("[*] No unchecked signals with hashes found.")
        return

    total = 0
    for row in pending:
        hashes = _json.loads(row["malware_hashes"] or "[]")
        if not hashes:
            continue
        enrichment = {}
        for h in hashes:
            rep = check_hash(h, api_key=config.vt_api_key)
            enrichment[h] = asdict(rep)
            total += 1
            if rep.is_malicious:
                print(f"  {h[:16]}... MALICIOUS ({rep.malicious}/{rep.total_engines} engines)")
            elif rep.not_found:
                print(f"  {h[:16]}... not found in VirusTotal")
            elif rep.error:
                print(f"  {h[:16]}... error: {rep.error}")
            else:
                print(f"  {h[:16]}... clean (0/{rep.total_engines})")
        store.save_hash_enrichment(row["signal_id"], enrichment)

    print(f"\n[+] Checked {total} hash(es) across {len(pending)} signal(s).")


def cmd_stats(args, config: Config, store: Store):
    """Show collection statistics."""
    stats = store.get_stats()
    print(f"\n{'='*40}")
    print("  DarkFeeds Statistics")
    print(f"{'='*40}")
    print(f"  Total signals:     {stats['total']}")
    print(f"  🔴 Critical (P1):  {stats['critical']}")
    print(f"  🟠 High (P2):      {stats['high']}")
    print(f"  🎯 With attribution: {stats['with_attribution']}")
    print(f"  📡 Sources active:  {stats['sources']}")
    print(f"{'='*40}\n")


def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

    p = argparse.ArgumentParser(
        prog="darkfeeds",
        description="Passive threat intelligence collector — dark web & underground sources",
    )
    sub = p.add_subparsers(dest="command", required=True)

    # collect
    c_collect = sub.add_parser("collect", help="Collect from API sources")
    c_collect.add_argument("--source", choices=["bazaar", "threatfox", "ransomware", "ransomlook", "otx", "news"])
    c_collect.add_argument("--limit", type=int, default=50)
    c_collect.add_argument("--no-enrich", action="store_true",
                           help="skip automatic IP enrichment (org/ASN/country) of new signals")

    # news
    c_news = sub.add_parser("news", help="Collect RSS/Atom threat news")
    c_news.add_argument("--limit", type=int, default=20)

    # hunt-apt
    c_hunt = sub.add_parser("hunt-apt", help="Hunt for PK-targeting APT malware")
    c_hunt.add_argument("--no-enrich", action="store_true",
                        help="skip automatic IP enrichment of new signals")

    # crawl
    c_crawl = sub.add_parser("crawl", help="Crawl .onion forums (requires Tor)")
    c_crawl.add_argument("--no-enrich", action="store_true",
                         help="skip automatic IP enrichment of new signals")

    # focus-threats
    c_pk = sub.add_parser("focus-threats", help="Show signals for the focus country")
    c_pk.add_argument("--since", help="Time window, e.g. 24h, 48h, 168h")
    c_pk.add_argument("--limit", type=int, default=50)

    # enrich-ips
    c_enrich = sub.add_parser("enrich-ips", help="RDAP/Shodan-enrich IPs on stored signals")
    c_enrich.add_argument("--limit", type=int, default=200)

    # otx-backfill
    c_otxb = sub.add_parser("otx-backfill", help="Fetch indicators/targeting for stored OTX pulses that lack them")
    c_otxb.add_argument("--limit", type=int, default=200)

    # enrich-hashes
    c_enrich_vt = sub.add_parser("enrich-hashes", help="VirusTotal-check hashes on stored signals")
    c_enrich_vt.add_argument("--limit", type=int, default=50)

    # stats
    sub.add_parser("stats", help="Show collection statistics")

    args = p.parse_args(argv)
    config = Config()
    store = Store(config.db_path)

    try:
        if args.command == "collect":
            cmd_collect(args, config, store)
        elif args.command == "news":
            cmd_news(args, config, store)
        elif args.command == "hunt-apt":
            cmd_hunt_apt(args, config, store)
        elif args.command == "crawl":
            cmd_crawl(args, config, store)
        elif args.command == "focus-threats":
            cmd_focus_threats(args, config, store)
        elif args.command == "enrich-ips":
            cmd_enrich_ips(args, config, store)
        elif args.command == "otx-backfill":
            cmd_otx_backfill(args, config, store)
        elif args.command == "enrich-hashes":
            cmd_enrich_hashes(args, config, store)
        elif args.command == "stats":
            cmd_stats(args, config, store)
    finally:
        store.close()


if __name__ == "__main__":
    main()
