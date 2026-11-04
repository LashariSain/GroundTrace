"""Best-effort web search fallback via DuckDuckGo's HTML endpoint (no API key).

When a CVE isn't in NVD or the CVE.org registry — e.g. a pre-disclosure/embargoed
id — we still want to show the analyst whatever the web knows: vendor writeups,
PoCs, advisory FAQs. This scrapes `html.duckduckgo.com` (no key, no account).

Best-effort by design: any network/parse failure returns an empty list so the
caller degrades cleanly. Results are untrusted web content — the caller must
render title/snippet as text and restrict links to http(s).
"""
from __future__ import annotations

import sys
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser

# DDG's HTML endpoint serves a resultless challenge page to bare GETs; it wants
# a POST with form data and browser-like headers.
_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/120 Safari/537.36"),
    "Accept": "text/html,application/xhtml+xml",
    "Accept-Language": "en-US,en;q=0.9",
    "Content-Type": "application/x-www-form-urlencoded",
}
_TIMEOUT = 15
_ENDPOINT = "https://html.duckduckgo.com/html/"


def _decode_ddg(href: str) -> str:
    """DDG wraps result links as //duckduckgo.com/l/?uddg=<encoded-real-url>."""
    if "uddg=" in href:
        q = urllib.parse.urlparse(("https:" + href) if href.startswith("//") else href).query
        uddg = urllib.parse.parse_qs(q).get("uddg", [""])[0]
        if uddg:
            return urllib.parse.unquote(uddg)
    return href


class _ResultParser(HTMLParser):
    """Pulls (title, url, snippet) triples out of DDG's HTML results page.
    Each result has a `result__a` anchor (title + wrapped link) followed by a
    `result__snippet` element, so a snippet attaches to the most recent title."""

    def __init__(self):
        super().__init__()
        self.results: list[dict] = []
        self._in_title = False
        self._in_snippet = False
        self._cur: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        cls = a.get("class") or ""
        if tag == "a" and "result__a" in cls:
            self._cur = {"title": "", "url": _decode_ddg(a.get("href", "")), "snippet": ""}
            self._in_title = True
        elif "result__snippet" in cls:
            self._in_snippet = True

    def handle_endtag(self, tag):
        if self._in_title and tag == "a" and self._cur is not None:
            self.results.append(self._cur)
            self._cur = None
            self._in_title = False
        elif self._in_snippet and tag in ("a", "div"):
            self._in_snippet = False

    def handle_data(self, data):
        if self._in_title and self._cur is not None:
            self._cur["title"] += data
        elif self._in_snippet and self.results:
            self.results[-1]["snippet"] += data


def search_web(query: str, *, max_results: int = 6) -> list[dict]:
    """Top web results for `query`, each {title, url, snippet}. Empty on any
    failure. Only http(s) links are returned."""
    data = urllib.parse.urlencode({"q": query}).encode()
    try:
        req = urllib.request.Request(_ENDPOINT, data=data, headers=_HEADERS)  # POST
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            html = r.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        print(f"[websearch] DuckDuckGo query failed: {e}", file=sys.stderr)
        return []

    parser = _ResultParser()
    try:
        parser.feed(html)
    except Exception as e:  # malformed HTML must not crash the caller
        print(f"[websearch] parse error: {e}", file=sys.stderr)
        return []

    out: list[dict] = []
    seen: set[str] = set()
    for r in parser.results:
        link = (r.get("url") or "").strip()
        title = " ".join((r.get("title") or "").split())
        if not link.startswith(("http://", "https://")) or not title or link in seen:
            continue
        seen.add(link)
        out.append({"title": title, "url": link,
                    "snippet": " ".join((r.get("snippet") or "").split())[:300]})
        if len(out) >= max_results:
            break
    return out
