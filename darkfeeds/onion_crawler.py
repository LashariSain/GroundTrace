"""
Onion Crawler — automated passive monitoring of .onion forums via Tor.

Architecture:
  1. Tor runs as a SOCKS5 proxy on localhost:9050
  2. All HTTP requests route through Tor
  3. We fetch forum index pages → extract thread titles + preview text
  4. Run extractors on each thread to find CVEs, IoCs, exploit signals
  5. Store results as ThreatSignals in SQLite

Supports two modes:
  - HTTP mode (requests + BeautifulSoup) — for simple HTML forums
  - Browser mode (Playwright) — for JavaScript-heavy forums

Safety:
  - Read-only. Never POST, never log in, never interact.
  - Randomized delays between requests (3-8 seconds).
  - User-agent rotation.
  - Tor circuit rotation every N requests.
"""
from __future__ import annotations
from . import focus

import hashlib
import random
import time
import re
from datetime import datetime
from typing import Optional
from urllib.parse import urljoin

from .config import Config
from .models import ThreatSignal, SignalSource, ForumTarget
from .extractors import extract_all

# ─── User Agent Pool ──────────────────────────────────────────────────────

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7; rv:128.0) Gecko/20100101 Firefox/128.0",
]


# ─── Core Crawler ─────────────────────────────────────────────────────────

class OnionCrawler:
    """
    Passive .onion forum monitor. Read-only — never interacts.

    Usage:
        config = Config()
        crawler = OnionCrawler(config)
        if not crawler.check_tor():
            print("Tor is not running!")
            return
        signals = crawler.crawl_forum(forum_target)
    """

    def __init__(self, config: Config):
        self.config = config
        self._request_count = 0
        self._session = None

    def _get_session(self):
        """Create a requests session routed through Tor."""
        # Lazy import — requests + socks are optional dependencies
        import requests
        if self._session is None:
            self._session = requests.Session()
            self._session.proxies = self.config.tor.proxies
            self._session.headers.update({
                "User-Agent": random.choice(_USER_AGENTS),
                "Accept": "text/html,application/xhtml+xml,*/*",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
            })
        return self._session

    def check_tor(self) -> bool:
        """Verify that Tor is running and we're connected."""
        try:
            import requests  # noqa: F401 — probe the optional crawler dependency
            session = self._get_session()
            r = session.get(
                "https://check.torproject.org/api/ip",
                timeout=15,
            )
            data = r.json()
            if data.get("IsTor"):
                print(f"[+] Tor is active. Exit IP: {data.get('IP', 'unknown')}")
                return True
            else:
                print(f"[!] Connected but NOT through Tor. IP: {data.get('IP')}")
                return False
        except Exception as e:
            print(f"[!] Tor connection failed: {e}")
            print(f"    Make sure Tor is running on {self.config.tor.host}:{self.config.tor.port}")
            return False

    def rotate_circuit(self):
        """Request a new Tor circuit (new exit IP)."""
        try:
            import socket
            with socket.create_connection(
                (self.config.tor.host, self.config.tor.control_port), timeout=5
            ) as s:
                s.send(b'AUTHENTICATE "' + self.config.tor.control_password.encode() + b'"\r\n')
                resp = s.recv(256)
                if b"250" in resp:
                    s.send(b"SIGNAL NEWNYM\r\n")
                    s.recv(256)
                    print("[+] Tor circuit rotated — new exit identity")
                    time.sleep(5)  # Wait for new circuit
                else:
                    print(f"[!] Tor control auth failed: {resp}")
        except Exception as e:
            print(f"[!] Circuit rotation failed: {e} (non-critical, continuing)")

    def _wait(self):
        """Random delay between requests to avoid detection."""
        delay = random.uniform(
            self.config.crawl.delay_min,
            self.config.crawl.delay_max,
        )
        time.sleep(delay)

        # Rotate circuit periodically
        self._request_count += 1
        if self._request_count % self.config.crawl.rotate_circuit_every == 0:
            self.rotate_circuit()
            # Also rotate user agent
            self._get_session().headers["User-Agent"] = random.choice(_USER_AGENTS)

    def fetch_page(self, url: str) -> Optional[str]:
        """
        Fetch a single page through Tor. Returns HTML string or None.
        Includes retry logic and polite delays.
        """
        session = self._get_session()

        for attempt in range(self.config.crawl.max_retries + 1):
            try:
                self._wait()
                resp = session.get(url, timeout=self.config.crawl.request_timeout)
                resp.raise_for_status()
                return resp.text
            except Exception as e:
                print(f"[!] Attempt {attempt + 1} failed for {url}: {e}")
                if attempt < self.config.crawl.max_retries:
                    time.sleep(5 * (attempt + 1))  # Back off
                    self.rotate_circuit()
        return None

    def crawl_forum(self, target: ForumTarget) -> list[ThreatSignal]:
        """
        Crawl a forum's monitored sections. Returns extracted ThreatSignals.

        This method:
          1. Fetches each section's thread listing page(s)
          2. Parses thread titles and preview text
          3. Runs extractors to identify CVEs, IoCs, exploit signals
          4. Returns ThreatSignals for anything that scored above threshold
        """
        if not target.enabled:
            print(f"[*] {target.name} is disabled, skipping")
            return []

        print(f"\n{'='*60}")
        print(f"[*] Crawling: {target.name}")
        print(f"    Base URL: {target.base_url}")
        print(f"    Sections: {len(target.sections)}")
        print(f"{'='*60}")

        all_signals = []

        for section in target.sections:
            section_path = section.get("path", "")
            section_name = section.get("name", section_path)
            max_pages = min(section.get("pages", 3), target.max_pages)

            print(f"\n[>] Section: {section_name}")

            for page_num in range(1, max_pages + 1):
                # Build page URL (forum-type specific)
                page_url = self._build_page_url(
                    target.base_url, section_path, page_num, target.forum_type
                )
                print(f"    Page {page_num}: {page_url}")

                html = self.fetch_page(page_url)
                if html is None:
                    print("    [!] Failed to fetch, skipping remaining pages")
                    break

                # Parse threads from the HTML
                threads = self._parse_threads(html, target.forum_type)
                print(f"    Found {len(threads)} threads")

                for thread in threads:
                    title = thread.get("title", "")
                    preview = thread.get("preview", "")
                    thread_url = thread.get("url", "")
                    posted_at = thread.get("date")
                    text = f"{title}\n{preview}"

                    # Run all extractors
                    extraction = extract_all(text)

                    # Only keep signals that scored above threshold
                    if extraction.overall_score < 0.15:
                        continue

                    signal_id = hashlib.sha256(
                        f"{target.name}:{thread_url}:{title}".encode()
                    ).hexdigest()[:16]

                    signal = ThreatSignal(
                        signal_id=signal_id,
                        source=SignalSource.ONION_FORUM if target.requires_tor
                               else SignalSource.CLEARNET_FORUM,
                        source_name=target.name,
                        source_url=urljoin(target.base_url, thread_url) if thread_url else page_url,
                        source_section=section_name,
                        title=title[:500],
                        raw_text=preview[:2000] if self.config.crawl.store_full_html else preview[:500],
                        language=target.language,
                        posted_at=posted_at,
                        cve_ids=extraction.cve_ids,
                        malware_hashes=extraction.hashes,
                        malware_family=extraction.malware_family,
                        ip_addresses=extraction.ips,
                        domains=extraction.domains,
                        urls=extraction.urls,
                        product_names=extraction.products,
                        exploit_type=extraction.exploit_type,
                        price=extraction.price,
                        threat_actor=extraction.threat_actor,
                        relevance_score=extraction.overall_score,
                        tags=extraction.urgency_signals,
                    )

                    # Set priority based on score
                    from .models import Priority
                    if extraction.overall_score >= 0.7:
                        signal.priority = Priority.CRITICAL
                    elif extraction.overall_score >= 0.5:
                        signal.priority = Priority.HIGH
                    elif extraction.overall_score >= 0.3:
                        signal.priority = Priority.MEDIUM
                    else:
                        signal.priority = Priority.LOW

                    # Focus-country relevance
                    if extraction.focus_relevance > 0:
                        signal.target_country = focus.get().country

                    all_signals.append(signal)
                    print(f"    [!] Signal: {signal.priority.value} | "
                          f"score={extraction.overall_score:.2f} | "
                          f"{title[:60]}...")

        print(f"\n[+] {target.name}: {len(all_signals)} signals extracted")
        return all_signals

    def _build_page_url(self, base: str, section_path: str,
                        page: int, forum_type: str) -> str:
        """Build paginated URL based on forum software type."""
        section_url = urljoin(base.rstrip("/") + "/", section_path.lstrip("/"))

        if forum_type == "xenforo":
            return f"{section_url}page-{page}" if page > 1 else section_url
        elif forum_type == "mybb":
            return f"{section_url}?page={page}" if page > 1 else section_url
        elif forum_type == "smf":
            offset = (page - 1) * 20
            return f"{section_url}?start={offset}" if page > 1 else section_url
        elif forum_type == "discourse":
            return f"{section_url}?page={page}" if page > 1 else section_url
        else:
            # Generic — try query param
            return f"{section_url}?page={page}" if page > 1 else section_url

    def _parse_threads(self, html: str, forum_type: str) -> list[dict]:
        """
        Parse thread listings from HTML. Returns list of:
          {"title": str, "preview": str, "url": str, "date": datetime|None}

        Uses heuristic parsing that works across most forum software.
        """
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            print("[!] beautifulsoup4 not installed. Using regex fallback.")
            return self._parse_threads_regex(html)

        soup = BeautifulSoup(html, "html.parser")
        threads = []

        # Strategy: try forum-specific selectors first, fall back to generic
        if forum_type == "xenforo":
            thread_elements = soup.select(".structItem--thread, .discussionListItem")
        elif forum_type == "mybb":
            thread_elements = soup.select(".thread_listing tr, .tborder tr")
        else:
            # Generic: look for anything that looks like a thread listing
            thread_elements = soup.select(
                "[class*='thread'], [class*='topic'], [class*='post-item'], "
                "[class*='discussion'], tr[id*='thread'], li[class*='row']"
            )

        for el in thread_elements:
            # Try to find title link
            title_link = (
                el.select_one("a[class*='title'], a[class*='subject'], "
                              ".thread-title a, .topic-title a, "
                              "a[href*='thread'], a[href*='topic']")
                or el.select_one("a")  # fallback: first link
            )

            if not title_link:
                continue

            title = title_link.get_text(strip=True)
            if len(title) < 5:  # Skip navigation links, etc.
                continue

            url = title_link.get("href", "")

            # Try to find preview/snippet text
            preview_el = el.select_one(
                ".structItem-title, .preview, .snippet, .message-text, "
                "[class*='preview'], [class*='snippet']"
            )
            preview = preview_el.get_text(strip=True) if preview_el else ""

            # Try to find date
            date_el = el.select_one(
                "time, [class*='date'], [class*='time'], .DateTime"
            )
            posted_at = None
            if date_el:
                date_str = date_el.get("datetime") or date_el.get("title") or date_el.get_text(strip=True)
                posted_at = self._parse_date(date_str)

            threads.append({
                "title": title,
                "preview": preview,
                "url": url,
                "date": posted_at,
            })

        return threads

    def _parse_threads_regex(self, html: str) -> list[dict]:
        """Fallback parser when BeautifulSoup is not available."""
        threads = []
        # Find <a> tags that look like thread titles
        pattern = re.compile(
            r'<a[^>]*href=["\']([^"\']*(?:thread|topic|viewtopic)[^"\']*)["\'][^>]*>'
            r'([^<]{5,200})</a>',
            re.IGNORECASE,
        )
        for m in pattern.finditer(html):
            url, title = m.group(1), m.group(2).strip()
            threads.append({"title": title, "preview": "", "url": url, "date": None})
        return threads

    @staticmethod
    def _parse_date(date_str: str) -> Optional[datetime]:
        """Best-effort date parsing."""
        if not date_str:
            return None
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d",
                    "%b %d, %Y", "%d %b %Y", "%m/%d/%Y"):
            try:
                return datetime.strptime(date_str.strip()[:19], fmt)
            except ValueError:
                continue
        return None
