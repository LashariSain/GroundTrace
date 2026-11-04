"""
SQLite storage for DarkFeeds threat signals.
"""
from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from .models import ThreatSignal

_SCHEMA = """
CREATE TABLE IF NOT EXISTS signals (
    signal_id       TEXT PRIMARY KEY,
    signal_type     TEXT NOT NULL,
    priority        TEXT NOT NULL,
    confidence      TEXT NOT NULL DEFAULT 'low',
    source          TEXT NOT NULL,
    source_name     TEXT NOT NULL,
    source_url      TEXT,
    source_section  TEXT,
    title           TEXT,
    raw_text        TEXT,
    language        TEXT DEFAULT 'en',
    posted_at       TIMESTAMP,
    collected_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    cve_ids         TEXT DEFAULT '[]',
    malware_hashes  TEXT DEFAULT '[]',
    malware_family  TEXT DEFAULT '',
    ip_addresses    TEXT DEFAULT '[]',
    domains         TEXT DEFAULT '[]',
    urls            TEXT DEFAULT '[]',
    product_names   TEXT DEFAULT '[]',
    exploit_type    TEXT DEFAULT '',
    price           TEXT DEFAULT '',
    threat_actor    TEXT DEFAULT '',
    target_country  TEXT DEFAULT '',
    target_sector   TEXT DEFAULT '',
    relevance_score REAL DEFAULT 0.0,
    evidence_snippet TEXT DEFAULT '',
    tags            TEXT DEFAULT '[]',
    processed       INTEGER DEFAULT 0,
    ip_enrichment   TEXT DEFAULT '{}',
    hash_enrichment TEXT DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_signals_priority ON signals(priority);
CREATE INDEX IF NOT EXISTS idx_signals_source ON signals(source_name);
CREATE INDEX IF NOT EXISTS idx_signals_collected ON signals(collected_at);
CREATE INDEX IF NOT EXISTS idx_signals_relevance ON signals(relevance_score);
CREATE INDEX IF NOT EXISTS idx_signals_country ON signals(target_country);
CREATE INDEX IF NOT EXISTS idx_signals_actor ON signals(threat_actor);
CREATE INDEX IF NOT EXISTS idx_signals_processed ON signals(processed);

CREATE TABLE IF NOT EXISTS crawl_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source_name     TEXT NOT NULL,
    started_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    finished_at     TIMESTAMP,
    signals_found   INTEGER DEFAULT 0,
    pages_crawled   INTEGER DEFAULT 0,
    errors          INTEGER DEFAULT 0,
    status          TEXT DEFAULT 'running'
);
"""


_TF_HASH = re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")
_TF_URL = re.compile(r"https?://\S+")


def _feed_kind(name: str) -> str:
    """Sources are reported by kind: the API never names its feeds."""
    low = (name or "").lower()
    return ("Malware telemetry" if low in ("threatfox", "malwarebazaar")
            else "Ransomware leak sites" if "ransom" in low
            else "Community reports" if "otx" in low or "alienvault" in low
            else "News and advisories")


class Store:
    """SQLite storage for threat signals."""

    def __init__(self, db_path: str):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        # Shared with the groundtrace API/watcher processes: wait on locks, use WAL.
        self.conn = sqlite3.connect(db_path, check_same_thread=False, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=30000")
        self.conn.executescript(_SCHEMA)
        self.conn.commit()
        self._migrate()

    def _migrate(self) -> None:
        """Add columns introduced after the initial schema to existing DBs."""
        cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(signals)")}
        if "ip_enrichment" not in cols:
            self.conn.execute(
                "ALTER TABLE signals ADD COLUMN ip_enrichment TEXT DEFAULT '{}'")
            self.conn.commit()
        if "hash_enrichment" not in cols:
            self.conn.execute(
                "ALTER TABLE signals ADD COLUMN hash_enrichment TEXT DEFAULT '{}'")
            self.conn.commit()

    def save_signal(self, signal: ThreatSignal) -> bool:
        """Save a signal. Returns True if new, False if duplicate."""
        try:
            cur = self.conn.execute("""
                INSERT OR IGNORE INTO signals (
                    signal_id, signal_type, priority, confidence,
                    source, source_name, source_url, source_section,
                    title, raw_text, language,
                    posted_at, collected_at,
                    cve_ids, malware_hashes, malware_family,
                    ip_addresses, domains, urls, product_names,
                    exploit_type, price,
                    threat_actor, target_country, target_sector,
                    relevance_score, evidence_snippet, tags
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                signal.signal_id, signal.signal_type.value, signal.priority.value,
                signal.confidence.value,
                signal.source.value, signal.source_name, signal.source_url,
                signal.source_section,
                signal.title, signal.raw_text, signal.language,
                signal.posted_at.isoformat() if signal.posted_at else None,
                signal.collected_at.isoformat(),
                json.dumps(signal.cve_ids), json.dumps(signal.malware_hashes),
                signal.malware_family,
                json.dumps(signal.ip_addresses), json.dumps(signal.domains),
                json.dumps(signal.urls), json.dumps(signal.product_names),
                signal.exploit_type, signal.price,
                signal.threat_actor, signal.target_country, signal.target_sector,
                signal.relevance_score, signal.evidence_snippet,
                json.dumps(signal.tags),
            ))
            self.conn.commit()
            # rowcount is this statement only; total_changes is cumulative for
            # the connection, so it reported every duplicate after the first
            # insert as "new".
            return cur.rowcount == 1
        except sqlite3.Error as e:
            print(f"[!] DB error saving signal: {e}")
            return False

    def save_signals(self, signals: list[ThreatSignal]) -> int:
        """Save multiple signals. Returns count of new signals."""
        new_count = sum(1 for s in signals if self.save_signal(s))
        return new_count

    def get_signals(
        self, *,
        since: Optional[datetime] = None,
        priority: Optional[str] = None,
        source: Optional[str] = None,
        country: Optional[str] = None,
        actor: Optional[str] = None,
        known_actor: bool = False,
        min_score: float = 0.0,
        limit: int = 100,
    ) -> list[dict]:
        """Query signals with filters. known_actor drops signals with no
        attributed actor (NULL, empty, or a placeholder like "unknown")."""
        query = "SELECT * FROM signals WHERE relevance_score >= ?"
        params: list = [min_score]

        if since:
            query += " AND collected_at >= ?"
            params.append(since.isoformat())
        if priority:
            query += " AND priority = ?"
            params.append(priority)
        if source:
            query += " AND source_name = ?"
            params.append(source)
        if country:
            query += " AND target_country = ?"
            params.append(country)
        if actor:
            query += " AND threat_actor LIKE ?"
            params.append(f"%{actor}%")
        if known_actor:
            query += (" AND LOWER(TRIM(COALESCE(threat_actor, ''))) NOT IN "
                      "('', 'unknown', 'null', 'none', 'n/a')")

        query += " ORDER BY relevance_score DESC, collected_at DESC LIMIT ?"
        params.append(limit)

        rows = self.conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_focus_signals(self, country: str, since: Optional[datetime] = None,
                          limit: int = 50) -> list[dict]:
        """Get signals relevant to the focus country."""
        return self.get_signals(country=country, since=since, limit=limit)

    def get_stats(self) -> dict:
        """Get collection statistics."""
        row = self.conn.execute("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN priority = 'P1' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN priority = 'P2' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN threat_actor != '' THEN 1 ELSE 0 END) as with_attribution,
                COUNT(DISTINCT source_name) as sources
            FROM signals
        """).fetchone()
        return dict(row)

    def overview(self) -> dict:
        """Aggregates for the dashboard: families, sources, collection runs,
        where the top families are hosted, and the newest IP indicators."""
        q = self.conn.execute
        families = [{"family": r[0], "n": r[1]} for r in q(
            "SELECT malware_family, COUNT(*) FROM signals "
            "WHERE malware_family != '' AND malware_family NOT LIKE 'Unknown%' "
            "GROUP BY 1 ORDER BY 2 DESC")]
        # The API never names its feeds, so sources are reported by kind.
        kinds: dict[str, int] = {}
        for name, n in q("SELECT source_name, COUNT(*) FROM signals GROUP BY 1"):
            kind = _feed_kind(name)
            kinds[kind] = kinds.get(kind, 0) + n
        runs =[{"day": r[0], "n": r[1]} for r in q(
            "SELECT substr(collected_at, 1, 10), COUNT(*) FROM signals GROUP BY 1 ORDER BY 1")]

        hosted: dict[str, dict] = {}
        for fam, raw in q("SELECT malware_family, ip_enrichment FROM signals "
                          "WHERE malware_family != '' AND malware_family NOT LIKE 'Unknown%' "
                          "AND ip_enrichment NOT IN ('', '{}')"):
            try:
                enrich = json.loads(raw)
            except ValueError:
                continue
            h = hosted.setdefault(fam, {"ips": set(), "cc": {}})
            for ip, info in enrich.items():
                if info.get("country") and ip not in h["ips"]:
                    h["ips"].add(ip)
                    h["cc"][info["country"]] = h["cc"].get(info["country"], 0) + 1
        counts = {f["family"]: f["n"] for f in families}
        # Twenty IPs is the least that makes "most hosted in" mean anything.
        top_hosted = [{"family": fam, "signals": counts[fam], "ips": len(h["ips"]),
                       "country": max(h["cc"], key=h["cc"].get)}
                      for fam, h in hosted.items() if len(h["ips"]) >= 20]
        top_hosted.sort(key=lambda x: -x["signals"])

        latest = []
        for fam, ips, at in q(
                "SELECT malware_family, ip_addresses, collected_at "
                "FROM signals WHERE ip_addresses NOT IN ('', '[]') "
                "ORDER BY collected_at DESC LIMIT 5"):
            try:
                ip = json.loads(ips)[0]
            except (ValueError, IndexError):
                continue
            latest.append({"type": "IP", "indicator": ip, "family": fam or "unknown",
                           "collected_at": at})
        return {"total": q("SELECT COUNT(*) FROM signals").fetchone()[0],
                "families": families[:12],
                "feed_kinds": [{"kind": k, "n": v} for k, v in
                               sorted(kinds.items(), key=lambda x: -x[1])],
                "runs": runs, "top_hosted": top_hosted[:4], "latest": latest}

    def families(self) -> list[dict]:
        """Every malware family, most signals first. Spellings differing only
        in case are one family, shown under the most common spelling."""
        merged: dict[str, dict] = {}
        for name, n, last in self.conn.execute(
                "SELECT malware_family, COUNT(*), MAX(collected_at) FROM signals "
                "WHERE malware_family != '' AND malware_family NOT LIKE 'Unknown%' "
                "GROUP BY 1 ORDER BY 2 DESC"):
            f = merged.setdefault(name.lower(), {"family": name, "signals": 0, "last_seen": ""})
            f["signals"] += n
            f["last_seen"] = max(f["last_seen"], (last or "")[:10])
        return sorted(merged.values(), key=lambda f: -f["signals"])

    def family_profile(self, family: str) -> Optional[dict]:
        """One malware family: activity, hosting and its indicators.

        Names match case-insensitively because feeds disagree on case. The
        catch-all "Unknown ..." labels are not families, so they get no profile.
        """
        if not family or family.lower().startswith("unknown"):
            return None
        rows = self.conn.execute(
            "SELECT source_name, collected_at, ip_addresses, domains, urls, malware_hashes, "
            "ip_enrichment, cve_ids, raw_text FROM signals WHERE malware_family = ? COLLATE NOCASE",
            (family,)).fetchall()
        if not rows:
            return None
        def _list(raw):
            try:
                return json.loads(raw or "[]")
            except ValueError:
                return []
        seen: dict[str, dict[str, str]] = {"ip": {}, "domain": {}, "url": {}, "hash": {}}
        runs: dict[str, int] = {}
        kinds: dict[str, int] = {}
        hosted: dict[str, dict] = {}
        cves: set[str] = set()
        for src, at, ips, doms, urls, hashes, enrich, cve, raw_text in rows:
            day = (at or "")[:10]
            runs[day] = runs.get(day, 0) + 1
            kind = _feed_kind(src)
            kinds[kind] = kinds.get(kind, 0) + 1
            cves.update(_list(cve))
            for t, raw in (("ip", ips), ("domain", doms), ("url", urls), ("hash", hashes)):
                for v in _list(raw):
                    seen[t][v] = max(seen[t].get(v, ""), day)
            if src == "ThreatFox":  # its hash and URL indicators are stored only in the text
                for v in _TF_URL.findall(raw_text or ""):
                    seen["url"][v] = max(seen["url"].get(v, ""), day)
                # A hash-like token inside a URL is part of that URL, not a file hash.
                for v in _TF_HASH.findall(_TF_URL.sub(" ", raw_text or "")):
                    seen["hash"][v.lower()] = max(seen["hash"].get(v.lower(), ""), day)
            try:
                info = json.loads(enrich or "{}")
            except ValueError:
                info = {}
            for ip, e in info.items():
                if e.get("country") or e.get("asn"):
                    hosted[ip] = e
        def _top(key, label=None):
            n: dict[str, int] = {}
            for e in hosted.values():
                if e.get(key):
                    n[e[key]] = n.get(e[key], 0) + 1
            names = {e[key]: e.get(label, "") for e in hosted.values() if label and e.get(key)}
            return [{"key": k, "n": v, "name": names.get(k, "")}
                    for k, v in sorted(n.items(), key=lambda x: -x[1])[:8]]
        days = sorted(d for d in runs if d)
        return {"family": family, "signals": len(rows),
                "first_seen": days[0] if days else "", "last_seen": days[-1] if days else "",
                "runs": [{"day": d, "n": runs[d]} for d in days],
                "feed_kinds": [{"kind": k, "n": v} for k, v in
                            sorted(kinds.items(), key=lambda x: -x[1])],
                "hosted_ips": len(hosted), "countries": _top("country"),
                "countries_total": len({e["country"] for e in hosted.values() if e.get("country")}),
                "networks_total": len({e["asn"] for e in hosted.values() if e.get("asn")}),
                "networks": _top("asn", "as_name"), "cves": sorted(cves)[:50],
                "indicators": {t: sorted(({"value": v, "last_seen": d} for v, d in vals.items()),
                                         key=lambda x: x["last_seen"], reverse=True)
                               for t, vals in seen.items()}}

    def log_crawl_run(self, source_name: str) -> int:
        """Start a crawl run log entry. Returns run ID."""
        cur = self.conn.execute(
            "INSERT INTO crawl_runs (source_name) VALUES (?)", (source_name,)
        )
        self.conn.commit()
        return cur.lastrowid

    def finish_crawl_run(self, run_id: int, signals: int, pages: int, errors: int = 0):
        """Mark a crawl run as complete."""
        self.conn.execute("""
            UPDATE crawl_runs SET
                finished_at = ?, signals_found = ?, pages_crawled = ?,
                errors = ?, status = 'done'
            WHERE id = ?
        """, (datetime.utcnow().isoformat(), signals, pages, errors, run_id))
        self.conn.commit()

    def save_ip_enrichment(self, signal_id: str, enrichment: dict[str, dict]) -> None:
        """Persist RDAP enrichment ({ip: {org, country, asn, cidr, ...}}) for a signal."""
        self.conn.execute(
            "UPDATE signals SET ip_enrichment = ? WHERE signal_id = ?",
            (json.dumps(enrichment), signal_id),
        )
        self.conn.commit()

    def get_otx_without_indicators(self, limit: int = 200) -> list[dict]:
        """OTX signals stored before pulses were fetched in full: no IOCs at all."""
        rows = self.conn.execute("""
            SELECT signal_id, source_url FROM signals
            WHERE source = 'otx' AND ip_addresses = '[]' AND domains = '[]'
              AND malware_hashes = '[]' AND urls = '[]'
            ORDER BY collected_at DESC LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]

    _IOC_COLUMNS = ("malware_hashes", "ip_addresses", "domains", "urls", "tags",
                    "threat_actor", "malware_family", "target_country")

    def update_signal_iocs(self, signal_id: str, fields: dict) -> None:
        """Overwrite a signal's IOC fields (whitelisted columns only) and reset
        its IP enrichment so the new IPs get geolocated on the next pass."""
        cols = [c for c in self._IOC_COLUMNS if c in fields]
        values = [json.dumps(fields[c]) if isinstance(fields[c], list) else fields[c] for c in cols]
        self.conn.execute(
            f"UPDATE signals SET {', '.join(f'{c} = ?' for c in cols)}, ip_enrichment = '{{}}' "
            "WHERE signal_id = ?", (*values, signal_id))
        self.conn.commit()

    def get_unenriched_ips(self, limit: int = 200) -> list[dict]:
        """Signals that have IPs but no enrichment recorded yet."""
        rows = self.conn.execute("""
            SELECT signal_id, ip_addresses FROM signals
            WHERE ip_addresses != '[]' AND ip_enrichment = '{}'
            LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]

    def save_hash_enrichment(self, signal_id: str, enrichment: dict[str, dict]) -> None:
        """Persist VirusTotal reputation ({hash: {malicious, total_engines, ...}})."""
        self.conn.execute(
            "UPDATE signals SET hash_enrichment = ? WHERE signal_id = ?",
            (json.dumps(enrichment), signal_id),
        )
        self.conn.commit()

    def get_unenriched_hashes(self, limit: int = 200) -> list[dict]:
        """Signals that have hashes but no VT enrichment recorded yet."""
        rows = self.conn.execute("""
            SELECT signal_id, malware_hashes FROM signals
            WHERE malware_hashes != '[]' AND hash_enrichment = '{}'
            LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]

    def close(self):
        self.conn.close()
