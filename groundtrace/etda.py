"""ETDA / ThaiCERT "Threat Group Cards" — dated operations for every group.

apt.etda.or.th keeps, per group, a curated table of operations with dates
("Mar 2025: APT36-style ClickFix attack spoofs Indian Ministry ...") and the
report behind each, plus counter-operations (arrests, sanctions, takedowns),
observed sectors/countries, and which vendor uses which name. That history is
what turns "whom has it ever targeted" into "when was it active, and where".

Access: only the HTML pages robots.txt allows (the group list and
showcard.cgi). The bulk export endpoints (getmisp.cgi, getcard.cgi) are
disallowed there and are never used. Pages are fetched politely (one every
couple of seconds), cached on disk, and refreshed weekly. Credit: ThaiCERT.
"""
from __future__ import annotations

import html
import json
import re
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

from .config import get_config

BASE = "https://apt.etda.or.th/cgi-bin/"
CREDIT = {"name": "Threat Group Cards by ETDA / ThaiCERT", "url": "https://apt.etda.or.th/"}
_UA = {"User-Agent": "groundtrace/0.1 (research tool; weekly, rate-limited)"}
_MAX_AGE = 7 * 24 * 3600
_PAUSE = 2.0

_MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}
_SEASON = {"early": 2, "spring": 4, "mid": 6, "summer": 7, "late": 10, "autumn": 10, "fall": 10,
           "winter": 1, "end": 11, "q1": 2, "q2": 5, "q3": 8, "q4": 11, "h1": 3, "h2": 9}


def _dir() -> Path:
    d = Path(get_config().db_path).expanduser().parent / "etda"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _text(fragment: str) -> str:
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", fragment)).split())


def parse_date(s: str) -> tuple[Optional[str], str]:
    """'Mar 2016' -> ('2016-03-01', 'month'); 'Early 2020' -> ('2020-02-01',
    'approx'); '2019' -> ('2019-01-01', 'year'). The precision travels with
    the date so the UI never shows 'Jan 2019' for a year-only entry."""
    s = (s or "").strip().lower().replace("-", " ").replace(",", " ")
    year = re.search(r"\b(19|20)\d{2}\b", s)
    if not year:
        return None, ""
    y = year.group(0)
    for word in s.split():
        if word[:3] in _MONTHS:
            return f"{y}-{_MONTHS[word[:3]]:02d}-01", "month"
        if word in _SEASON:
            return f"{y}-{_SEASON[word]:02d}-01", "approx"
    return f"{y}-01-01", "year"


def _cell(page: str, label: str) -> Optional[str]:
    """Raw HTML of the value cell next to a card's row label."""
    m = re.search(r'<td[^>]*class="tshaded"[^>]*>\s*(?:<[^>]+>\s*)*' + re.escape(label) +
                  r'\s*(?:<[^>]+>\s*)*</td>\s*<td[^>]*>(.*?)</td>\s*</tr>', page, re.S)
    return m.group(1) if m else None


def _section(page: str, label: str) -> Optional[str]:
    """Everything from a row label to the next label: holds a nested table,
    so a lazy match to the first </td></tr> would stop inside it."""
    m = re.search(r'class="tshaded"[^>]*>\s*(?:<[^>]+>\s*)*' + re.escape(label) + r"\s*(?:<[^>]+>\s*)*</td>", page)
    if not m:
        return None
    nxt = page.find('class="tshaded"', m.end())
    return page[m.end(): nxt if nxt > 0 else len(page)]


def _rows(fragment: Optional[str]) -> list[dict]:
    """Dated rows of the nested Operations / Counter operations tables."""
    out = []
    for row in re.findall(r"<tr>(.*?)</tr>", fragment or "", re.S):
        cells = re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)
        if len(cells) < 2:
            continue
        day, precision = parse_date(_text(cells[0]))
        if not day:
            continue
        links = [u for u in re.findall(r'href="(https?://[^"]+)"', cells[1])
                 if "etda.or.th" not in u]
        out.append({"date": _text(cells[0]), "day": day, "precision": precision,
                    "text": re.sub(r"\s*<[^<>]*>", "", _text(cells[1])).strip()[:1200],
                    "url": links[0] if links else ""})
    return out


def parse_card(page: str, slug: str = "") -> Optional[dict]:
    title = re.search(r"<title>(.*?)\s+-\s+Threat Group Cards", page, re.S)
    if not title:
        return None
    names_cell = _text(_cell(page, "Names") or "")
    names = [{"name": n.strip(), "vendor": v.strip()}
             for n, v in re.findall(r"([^()]+?)\s*\(([^()]*)\)", names_cell) if n.strip()]
    observed = _text(_cell(page, "Observed") or "")
    sectors = re.search(r"Sectors:\s*(.*?)(?:\.\s*Countries:|$)", observed)
    countries = re.search(r"Countries:\s*(.*?)\.?\s*$", observed)
    split = lambda m: [x.strip() for x in m.group(1).split(",") if x.strip()] if m else []
    return {
        "slug": slug,
        "title": _text(title.group(1)),
        "url": BASE + "showcard.cgi?g=" + urllib.parse.quote(slug or _text(title.group(1))),
        "names": names,
        "country": _text(_cell(page, "Country") or ""),
        "motivation": _text(_cell(page, "Motivation") or ""),
        "first_seen": _text(_cell(page, "First seen") or ""),
        "observed_sectors": split(sectors),
        "observed_countries": split(countries),
        "operations": _rows(_section(page, "Operations performed")),
        "counter_operations": _rows(_section(page, "Counter operations")),
        "mitre": re.findall(r"attack\.mitre\.org/groups/(G\d{4})", page)[:1],
    }


def _get(url: str) -> Optional[str]:
    try:
        req = urllib.request.Request(url, headers=_UA)
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.read().decode("utf-8", "replace")
    except OSError as e:
        print(f"[etda] {url}: {e}", file=sys.stderr)
        return None


def card_slugs() -> list[str]:
    page = _get(BASE + "listgroups.cgi")
    return list(dict.fromkeys(urllib.parse.unquote(s) for s in
                              re.findall(r'showcard\.cgi\?g=([^"&]+)', page or "")))


def refresh(max_cards: int = 60, pause: float = _PAUSE) -> int:
    """Fetch up to `max_cards` cards whose cached copy is missing or a week
    old, oldest first. Returns how many were fetched."""
    d = _dir()
    slugs = card_slugs()
    if not slugs:
        return 0
    path = lambda s: d / (re.sub(r"[^A-Za-z0-9]+", "_", s)[:80] + ".json")
    stale = sorted((s for s in slugs if not path(s).exists()
                    or time.time() - path(s).stat().st_mtime > _MAX_AGE),
                   key=lambda s: path(s).stat().st_mtime if path(s).exists() else 0)
    n = 0
    for slug in stale[:max_cards]:
        page = _get(BASE + "showcard.cgi?g=" + urllib.parse.quote(slug))
        card = parse_card(page, slug) if page else None
        if card:
            path(slug).write_text(json.dumps(card), encoding="utf-8")
            n += 1
        time.sleep(pause)
    return n


def cards() -> list[dict]:
    out = []
    for f in _dir().glob("*.json"):
        try:
            out.append(json.loads(f.read_text(encoding="utf-8")))
        except ValueError:
            continue
    return out
