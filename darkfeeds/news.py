"""RSS/Atom news collection for threat-intel and vulnerability reporting."""
from __future__ import annotations
from . import focus

import hashlib
import urllib.request
import xml.etree.ElementTree as ET
from typing import Iterable

from .collectors import _parse_ts
from .extractors import extract_all
from .models import Confidence, Priority, SignalSource, SignalType, ThreatSignal

DEFAULT_NEWS_FEEDS = [
    "https://www.bleepingcomputer.com/feed/",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://krebsonsecurity.com/feed/",
    "https://www.cisa.gov/uscert/ncas/alerts.xml",
    "https://msrc.microsoft.com/update-guide/rss",
]


def parse_rss_feed(xml_text: str, source_name: str = "RSS") -> list[dict[str, str]]:
    """Parse a minimal RSS/Atom payload and return story metadata."""
    items: list[dict[str, str]] = []
    root = ET.fromstring(xml_text)
    channel = root.find("channel")
    if channel is not None:
        entries = channel.findall("item")
    else:
        entries = root.findall(".//entry")

    for entry in entries:
        title = _text(entry, "title") or "Untitled"
        link = _text(entry, "link") or _text(entry, "id") or ""
        published = _text(entry, "pubDate") or _text(entry, "published") or _text(entry, "updated") or ""
        description = _text(entry, "description") or _text(entry, "summary") or title
        items.append({
            "title": title,
            "link": link,
            "published": published,
            "description": description,
            "source_name": source_name,
        })
    return items


def _text(node, tag: str) -> str:
    elem = node.find(tag)
    if elem is None and tag == "link":
        for child in list(node):
            if child.tag.endswith("link") and child.get("href"):
                return child.get("href")
        return ""
    if elem is None:
        return ""
    return (elem.text or "").strip()


def fetch_rss_feed(url: str, timeout: int = 20) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "darkfeeds-news/0.1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def collect_news_feeds(feed_urls: Iterable[str] | None = None, limit: int = 20) -> list[ThreatSignal]:
    """Collect threat-relevant stories from RSS/Atom feeds and normalize them.

    Each item becomes a ThreatSignal with extracted CVEs, product names, and actor strings.
    """
    urls = list(feed_urls or DEFAULT_NEWS_FEEDS)
    signals: list[ThreatSignal] = []

    for url in urls[:10]:
        try:
            xml_text = fetch_rss_feed(url)
        except Exception:
            continue
        try:
            parsed = parse_rss_feed(xml_text, source_name=url)
        except Exception:
            continue

        for item in parsed[:limit]:
            title = item["title"]
            body = f"{title} {item['description']} {item['link']}"
            extraction = extract_all(body)
            signal_type = SignalType.VULN_DISCUSSION if extraction.cve_ids else SignalType.GENERAL_INTEL
            if extraction.threat_actor:
                signal_type = SignalType.THREAT_ACTOR
            elif extraction.malware_family:
                signal_type = SignalType.MALWARE_SAMPLE

            signal = ThreatSignal(
                signal_id=hashlib.sha256(f"rss:{title}:{item['link']}".encode()).hexdigest()[:16],
                signal_type=signal_type,
                source=SignalSource.RSS,
                source_name=item["source_name"],
                source_url=item["link"],
                title=title,
                raw_text=item["description"],
                cve_ids=extraction.cve_ids,
                malware_family=extraction.malware_family,
                product_names=extraction.products,
                threat_actor=extraction.threat_actor,
                target_country=focus.target(extraction.focus_relevance),
                relevance_score=extraction.overall_score,
                evidence_snippet=item["description"][:300],
                tags=["news", "rss"],
                confidence=Confidence.MEDIUM,
                priority=Priority.HIGH if extraction.threat_actor or extraction.cve_ids or extraction.focus_relevance > 0.5 else Priority.MEDIUM,
                posted_at=_parse_ts(item["published"]),
            )
            signals.append(signal)

    return signals
