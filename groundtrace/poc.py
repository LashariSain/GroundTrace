"""Find public proof-of-concept exploits for a CVE — links only.

Sources (no key needed):
  * nomi-sec/PoC-in-GitHub — a curated daily index of GitHub repos per CVE.
  * GitHub repository search — catches repos the index hasn't picked up yet.
    Keyless it allows 10 searches/min; set GROUNDTRACE_GITHUB_TOKEN to raise that.
  * Exploit-DB — its official CVE index, topped up live (see exploitdb.py).
  * The CVE's own NVD references — Exploit-DB, Packet Storm, Metasploit.

Safety: this module never downloads, clones or executes anything. It returns
metadata and links. Fake "PoC" repos that ship malware to researchers are a
known lure, so every result carries heuristic red flags, and the dashboard tells
the analyst to read the code in an isolated VM before running it.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Optional

_UA = {"User-Agent": "groundtrace/0.1 (research tool)", "Accept": "application/vnd.github+json"}
_TIMEOUT = 15
_INDEX = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve}.json"
_SEARCH = "https://api.github.com/search/repositories?q={q}&sort=stars&order=desc&per_page=30"
_CACHE_TTL = 3600
_cache: dict[str, tuple[float, dict]] = {}

# Exploit write-ups hosted by reputable archives, matched against NVD references.
_ARCHIVES = (
    (re.compile(r"exploit-db\.com/exploits/\d+"), "Exploit-DB"),
    (re.compile(r"packetstormsecurity\.com/files/\d+"), "Packet Storm"),
    (re.compile(r"github\.com/rapid7/metasploit-framework/"), "Metasploit"),
    (re.compile(r"github\.com/projectdiscovery/nuclei-templates/"), "Nuclei template"),
)

# Phrases typical of malware-lure repos: they want you to download a binary,
# unpack an archive with a password, or pay/contact someone, not read code.
# Kept narrow on purpose: plain words like "download", "setup" or "password"
# also describe legitimate patch packages and labs, and flagging those as bait
# would be a false accusation.
_LURE = re.compile(
    r"(\.exe\b|\.scr\b|\.rar\b|\.7z\b"
    r"|\b(zip|rar|7z|archive)\b.{0,40}\bpass(word)?\b|\bpass(word)?\b.{0,40}\b(zip|rar|7z|archive)\b"
    r"|\bt\.me/|\btelegram\b|discord\.gg|\bcontact me\b|\bdm me\b"
    r"|\b(buy|sell|selling|price|for sale)\b)",
    re.I)


class _NotFound:
    """Marker: the source answered, and has nothing for this CVE."""
    __slots__ = ()


_NOT_FOUND = _NotFound()


def _get(url: str, headers: dict) -> Optional[object]:
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return _NOT_FOUND          # the index has no entry for this CVE
        print(f"[poc] {urllib.parse.urlparse(url).netloc} HTTP {e.code}", file=sys.stderr)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
        print(f"[poc] {urllib.parse.urlparse(url).netloc} failed: {e}", file=sys.stderr)
    return None


def _age_days(ts: Optional[str], now: datetime) -> Optional[float]:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (now - dt).total_seconds() / 86400


def notes(repo: dict, now: Optional[datetime] = None) -> list[str]:
    """Weak signals: context, not accusations. Most new PoC repos for a fresh
    CVE are legitimate; these just mean nobody has vetted it yet."""
    now = now or datetime.now(timezone.utc)
    out = []
    age = _age_days(repo.get("created_at"), now)
    if age is not None and age < 7 and not repo.get("stargazers_count"):
        out.append("new and unstarred, so not yet vetted by anyone")
    if not (repo.get("description") or "").strip():
        out.append("no description")
    return out


def red_flags(repo: dict, cve_id: str, now: Optional[datetime] = None) -> list[str]:
    """Strong signals of a malware lure or an irrelevant repo, from metadata
    alone. Absence of flags is not a guarantee of safety."""
    flags = []
    desc = repo.get("description") or ""
    if _LURE.search(desc):
        flags.append("description points to an executable, a password-protected archive, "
                     "a contact or a sale; a common malware-lure pattern")
    if repo.get("fork"):
        flags.append("fork of another repo; prefer the original")
    name = (repo.get("full_name") or "").lower()
    if cve_id.lower() not in name and cve_id.lower() not in desc.lower():
        flags.append("CVE id not in the name or description; may be unrelated")
    return flags


def _repo_entry(repo: dict, cve_id: str, source: str, now: datetime) -> Optional[dict]:
    url = repo.get("html_url") or ""
    if not url.startswith("https://github.com/"):
        return None
    return {
        "kind": "github",
        "name": repo.get("full_name") or url[len("https://github.com/"):],
        "url": url,
        "description": " ".join((repo.get("description") or "").split())[:300],
        "stars": repo.get("stargazers_count") or 0,
        "forks": repo.get("forks_count") or 0,
        "created_at": (repo.get("created_at") or "")[:10],
        "pushed_at": (repo.get("pushed_at") or "")[:10],
        "source": source,
        "red_flags": red_flags(repo, cve_id, now),
        "notes": notes(repo, now),
    }


def archive_links(references: list[str]) -> list[dict]:
    out, seen = [], set()
    for ref in references or []:
        if not isinstance(ref, str) or not ref.startswith("https://") or ref in seen:
            continue
        for rx, label in _ARCHIVES:
            if rx.search(ref):
                seen.add(ref)
                out.append({"kind": "archive", "name": label, "url": ref, "source": "NVD references",
                            "red_flags": [], "notes": []})
                break
    return out


def indexed_repos(cve_id: str) -> Optional[list[dict]]:
    """Repos the PoC-in-GitHub index lists for a CVE (no key, no search quota).

    Returns [] when the index genuinely lists none, and None when the lookup
    could not be made. The caller must keep those apart: reporting a failed
    fetch as "no public PoC" is an affirmative claim we have not earned, and
    it silently zeroed this component on every radar entry ever computed.
    """
    cve_id = cve_id.upper()
    parts = cve_id.split("-")
    if len(parts) < 3:
        return None
    data = _get(_INDEX.format(year=parts[1], cve=cve_id), {"User-Agent": _UA["User-Agent"]})
    if isinstance(data, list):
        return data
    return [] if data is _NOT_FOUND else None


def find_pocs(cve_id: str, references: Optional[list[str]] = None) -> dict:
    """Public PoCs for `cve_id`: archive links first, then GitHub repos ranked
    unflagged-first, then by stars. Cached for an hour per CVE."""
    cve_id = cve_id.upper()
    hit = _cache.get(cve_id)
    if hit and time.time() - hit[0] < _CACHE_TTL:
        result = dict(hit[1])
    else:
        now = datetime.now(timezone.utc)
        repos: dict[str, dict] = {}
        errors = []
        year = cve_id.split("-")[1]
        idx = _get(_INDEX.format(year=year, cve=cve_id), {"User-Agent": _UA["User-Agent"]})
        for r in idx if isinstance(idx, list) else []:
            e = _repo_entry(r, cve_id, "PoC-in-GitHub", now)
            if e:
                repos[e["url"].lower()] = e

        headers = dict(_UA)
        token = os.getenv("GROUNDTRACE_GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        found = _get(_SEARCH.format(q=urllib.parse.quote(f'"{cve_id}"')), headers)
        if found is None:
            errors.append("GitHub search unavailable (rate limit or network); showing indexed results only")
        for r in (found or {}).get("items", []) if isinstance(found, dict) else []:
            e = _repo_entry(r, cve_id, "GitHub search", now)
            if e and e["url"].lower() not in repos:
                repos[e["url"].lower()] = e

        ranked = sorted(repos.values(), key=lambda e: (bool(e["red_flags"]), -e["stars"]))
        result = {"cve_id": cve_id, "repos": ranked, "errors": errors}
        if not errors:
            _cache[cve_id] = (time.time(), result)
        result = dict(result)

    from .exploitdb import exploits_for
    result["exploitdb"] = exploits_for(cve_id, live=True)
    # An NVD reference to an exploit already listed above is a duplicate.
    edb_ids = {e["id"] for e in result["exploitdb"]}
    result["archives"] = [a for a in archive_links(references or [])
                          if not (a["name"] == "Exploit-DB" and a["url"].rstrip("/").rsplit("/", 1)[-1] in edb_ids)]
    result["warning"] = ("Links only: nothing was downloaded or run. Public PoCs are unverified "
                         "and some are malware aimed at researchers. Read the code and run it "
                         "only in an isolated VM against systems you are authorised to test.")
    return result
