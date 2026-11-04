"""
Extractors — pull structured intelligence from raw text.

These run against every scraped post/paste/message to extract:
  - CVE IDs
  - Malware hashes (MD5, SHA1, SHA256)
  - IP addresses and domains
  - Product/vendor names
  - Exploit types (RCE, LPE, etc.)
  - Prices (exploit sale indicators)
  - Urgency signals (0day, unpatched, etc.)
  - Threat actor names

Each extractor is a pure function: text in → structured data out.
"""
from __future__ import annotations
from . import focus

import re
from dataclasses import dataclass, field


# ─── CVE Extraction ──────────────────────────────────────────────────────

_CVE_PATTERN = re.compile(r"CVE-(\d{4})-(\d{4,})", re.IGNORECASE)


def extract_cve_ids(text: str) -> list[str]:
    """Extract all CVE IDs from text. Returns normalized format."""
    return sorted(set(f"CVE-{m.group(1)}-{m.group(2)}" for m in _CVE_PATTERN.finditer(text)))


# ─── Hash Extraction ─────────────────────────────────────────────────────

_MD5 = re.compile(r"\b([a-fA-F0-9]{32})\b")
_SHA1 = re.compile(r"\b([a-fA-F0-9]{40})\b")
_SHA256 = re.compile(r"\b([a-fA-F0-9]{64})\b")


def extract_hashes(text: str) -> list[str]:
    """Extract all potential malware hashes (SHA256 > SHA1 > MD5)."""
    hashes = []
    # SHA256 first (most specific)
    for m in _SHA256.finditer(text):
        hashes.append(m.group(1).lower())
    # SHA1 (skip if already captured as part of SHA256)
    for m in _SHA1.finditer(text):
        h = m.group(1).lower()
        if not any(h in s for s in hashes):
            hashes.append(h)
    # MD5 (skip if already captured)
    for m in _MD5.finditer(text):
        h = m.group(1).lower()
        if not any(h in s for s in hashes):
            hashes.append(h)
    return hashes


# ─── Network IoC Extraction ──────────────────────────────────────────────

_IPV4 = re.compile(
    r"\b((?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3})\b"
)
# Excludes common false positives like version numbers
_IP_EXCLUDE = re.compile(r"^(0\.|10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)")

_DOMAIN = re.compile(
    r"\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:onion|com|net|org|io|ru|cc|top|xyz|tk|ml|ga|cf|gq|pw|biz|info|me|co))\b",
    re.IGNORECASE,
)
_DOMAIN_EXCLUDE = {"github.com", "google.com", "microsoft.com", "twitter.com",
                    "reddit.com", "youtube.com", "wikipedia.org", "t.me"}

_URL = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)


def extract_ips(text: str) -> list[str]:
    """Extract public IPv4 addresses."""
    ips = []
    for m in _IPV4.finditer(text):
        ip = m.group(1)
        if not _IP_EXCLUDE.match(ip):
            ips.append(ip)
    return sorted(set(ips))


def extract_domains(text: str) -> list[str]:
    """Extract domain names (including .onion)."""
    domains = []
    for m in _DOMAIN.finditer(text):
        d = m.group(1).lower()
        if d not in _DOMAIN_EXCLUDE:
            domains.append(d)
    return sorted(set(domains))


def extract_urls(text: str) -> list[str]:
    """Extract full URLs."""
    return sorted(set(m.group(0).rstrip(".,;:)") for m in _URL.finditer(text)))


# ─── Product / Vendor Name Matching ──────────────────────────────────────

_PRODUCTS = {
    # Product regex → normalized name
    r"\bapache\b": "Apache",
    r"\bnginx\b": "Nginx",
    r"\bwordpress\b": "WordPress",
    r"\bdrupal\b": "Drupal",
    r"\bjoomla\b": "Joomla",
    r"\bfortinet|fortigate|fortios\b": "Fortinet",
    r"\bcisco\b": "Cisco",
    r"\bpalo\s*alto\b": "Palo Alto",
    r"\bsonicwall\b": "SonicWall",
    r"\bf5\s*big[- ]?ip\b": "F5 BIG-IP",
    r"\bmikrotik\b": "MikroTik",
    r"\bwindows\s*(server|1[01]|7)?\b": "Windows",
    r"\bexchange\s*(server)?\b": "Exchange",
    r"\boutlook\b": "Outlook",
    r"\boffice\b": "Microsoft Office",
    r"\bvmware|vcenter|esxi\b": "VMware",
    r"\bcitrix\b": "Citrix",
    r"\bivanti\b": "Ivanti",
    r"\bconfluence\b": "Confluence",
    r"\bjira\b": "Jira",
    r"\blinux\s*kernel\b": "Linux Kernel",
    r"\bchrome|chromium\b": "Chrome",
    r"\bfirefox\b": "Firefox",
    r"\bspring\b": "Spring Framework",
    r"\blog4j|log4shell\b": "Log4j",
    r"\bmoveit\b": "MOVEit",
    r"\bwhatsapp\b": "WhatsApp",
    r"\bandroid\b": "Android",
}
_PRODUCT_PATTERNS = [(re.compile(p, re.IGNORECASE), name) for p, name in _PRODUCTS.items()]


def extract_products(text: str) -> list[str]:
    """Match product/vendor names mentioned in text."""
    found = []
    for pattern, name in _PRODUCT_PATTERNS:
        if pattern.search(text) and name not in found:
            found.append(name)
    return found


# ─── Exploit Type Detection ──────────────────────────────────────────────

_EXPLOIT_TYPES = {
    r"\bRCE\b|remote code execution": "RCE",
    r"\bLPE\b|local privilege escalation|privesc": "LPE",
    r"\bSQL\s*injection|SQLi\b": "SQLi",
    r"\bXSS\b|cross[- ]site scripting": "XSS",
    r"\bSSRF\b|server[- ]side request forgery": "SSRF",
    r"\bXXE\b|xml external entity": "XXE",
    r"\bIDOR\b|insecure direct object": "IDOR",
    r"\bauth(entication)?\s*bypass\b": "Auth Bypass",
    r"\bpath\s*traversal|directory\s*traversal|LFI\b": "Path Traversal",
    r"\bRFI\b|remote file inclu": "RFI",
    r"\bbuffer\s*overflow\b": "Buffer Overflow",
    r"\buse[- ]after[- ]free|UAF\b": "Use-After-Free",
    r"\bheap\s*(spray|overflow)\b": "Heap Exploit",
    r"\bdeserialization\b": "Deserialization",
    r"\bcommand\s*injection|cmd\s*injection\b": "Command Injection",
}
_EXPLOIT_PATTERNS = [(re.compile(p, re.IGNORECASE), name) for p, name in _EXPLOIT_TYPES.items()]


def extract_exploit_type(text: str) -> str:
    """Identify the exploit type mentioned. Returns first match."""
    for pattern, name in _EXPLOIT_PATTERNS:
        if pattern.search(text):
            return name
    return ""


# ─── Price Detection (Exploit Sale Indicator) ────────────────────────────

_PRICE_PATTERNS = [
    re.compile(r"\$\s*[\d,]+\.?\d*\s*[kK]?\b"),                # $50k, $50,000
    re.compile(r"[\d,]+\.?\d*\s*(USD|usd|USDT)\b"),             # 50000 USD
    re.compile(r"[\d.]+\s*(BTC|btc|Bitcoin)\b"),                 # 2.5 BTC
    re.compile(r"[\d.]+\s*(XMR|xmr|Monero)\b"),                 # 100 XMR
    re.compile(r"[\d,]+\s*(ETH|eth|Ethereum)\b"),                # 10 ETH
    re.compile(r"(?i)(price|DM for price|contact for price|PM for details)"),
]


def extract_price(text: str) -> str:
    """Extract price mentions — indicates exploit/access sale."""
    for pattern in _PRICE_PATTERNS:
        m = pattern.search(text)
        if m:
            return m.group(0).strip()
    return ""


# ─── Urgency / Zero-Day Signals ──────────────────────────────────────────

_URGENCY_SIGNALS = [
    (re.compile(r"(?i)\b0[- ]?day|zero[- ]?day\b"), "zero_day", 0.4),
    (re.compile(r"(?i)\bunpatched\b"), "unpatched", 0.3),
    (re.compile(r"(?i)\bin[- ]the[- ]wild\b"), "in_the_wild", 0.3),
    (re.compile(r"(?i)\bactively\s+exploit"), "active_exploitation", 0.3),
    (re.compile(r"(?i)\bmass\s*scan"), "mass_scanning", 0.2),
    (re.compile(r"(?i)\bno\s*(fix|patch)\b"), "no_fix", 0.3),
    (re.compile(r"(?i)\bbefore\s*(a\s*)?(patch|fix)\b"), "pre_patch", 0.3),
    (re.compile(r"(?i)\bworking\s+on\s+latest\b"), "latest_affected", 0.2),
    (re.compile(r"(?i)\bprivate\s+exploit\b"), "private_exploit", 0.2),
    (re.compile(r"(?i)\bpre[- ]?auth\b"), "pre_auth", 0.15),
    (re.compile(r"(?i)\bwormable\b"), "wormable", 0.3),
]


def extract_urgency_score(text: str) -> tuple[float, list[str]]:
    """Score urgency 0-1 based on language signals. Returns (score, matched_signals)."""
    score = 0.0
    signals = []
    for pattern, label, weight in _URGENCY_SIGNALS:
        if pattern.search(text):
            score += weight
            signals.append(label)
    return min(score, 1.0), signals


# ─── Threat Actor Matching ───────────────────────────────────────────────

_THREAT_ACTORS = {
    # Regional APTs
    r"(?i)\b(APT[- ]?36|transparent\s*tribe|mythic\s*leopard)\b": "APT36 (Transparent Tribe)",
    r"(?i)\b(sidewinder|rattlesnake|T-APT-04)\b": "SideWinder",
    r"(?i)\b(bitter\s*(apt)?|T-APT-17)\b": "Bitter APT",
    r"(?i)\b(donot\s*(team)?|APT-C-35)\b": "Donot Team",
    r"(?i)\b(sidecopy)\b": "SideCopy",
    r"(?i)\b(patchwork|dropping\s*elephant)\b": "Patchwork",
    r"(?i)\b(muddy\s*water)\b": "MuddyWater",
    r"(?i)\b(charming\s*kitten|APT[- ]?35)\b": "Charming Kitten",
    # Ransomware groups
    r"(?i)\b(lockbit)\b": "LockBit",
    r"(?i)\b(blackcat|alphv)\b": "BlackCat/ALPHV",
    r"(?i)\b(cl0p|clop)\b": "Cl0p",
    r"(?i)\b(black\s*basta)\b": "Black Basta",
    r"(?i)\b(play\s*ransomware)\b": "Play",
    r"(?i)\b(rhysida)\b": "Rhysida",
    r"(?i)\b(akira)\b(?!\s*stealer)": "Akira",
    # Major APTs
    r"(?i)\b(lazarus|APT[- ]?38)\b": "Lazarus (APT38)",
    r"(?i)\b(APT[- ]?28|fancy\s*bear)\b": "APT28 (Fancy Bear)",
    r"(?i)\b(APT[- ]?29|cozy\s*bear)\b": "APT29 (Cozy Bear)",
    r"(?i)\b(APT[- ]?41|winnti)\b": "APT41 (Winnti)",
}
_ACTOR_PATTERNS = [(re.compile(p), name) for p, name in _THREAT_ACTORS.items()]

# Malware families linked to APTs
_MALWARE_TO_APT = {
    "crimsonrat": "APT36 (Transparent Tribe)",
    "obliquerat": "APT36 (Transparent Tribe)",
    "caprarat": "APT36 (Transparent Tribe)",
    "warhawk": "SideWinder",
    "stealerbot": "SideWinder",
    "bitterat": "Bitter APT",
    "artradownloader": "Bitter APT",
    "badnews": "Patchwork",
    "ragnatela": "Patchwork",
    "actionrat": "SideCopy",
    "margulasrat": "SideCopy",
}


def extract_threat_actor(text: str) -> str:
    """Match known threat actor / APT group names."""
    for pattern, name in _ACTOR_PATTERNS:
        if pattern.search(text):
            return name
    # Also check malware family names → APT attribution
    text_lower = text.lower()
    for malware, apt in _MALWARE_TO_APT.items():
        if malware in text_lower:
            return apt
    return ""


def extract_malware_family(text: str) -> str:
    """Extract known malware family name."""
    text_lower = text.lower()
    for malware in _MALWARE_TO_APT:
        if malware in text_lower:
            return malware.title()
    # Additional families
    families = [
        "cobalt strike", "metasploit", "mimikatz", "quasarrat",
        "njrat", "remcos", "asyncrat", "agent tesla", "emotet",
        "trickbot", "qakbot", "icedid", "redline", "raccoon",
        "vidar", "lumma", "stealc",
    ]
    for fam in families:
        if fam in text_lower:
            return fam.title()
    return ""


# ─── Master Extraction ───────────────────────────────────────────────────

@dataclass
class ExtractionResult:
    """Everything extracted from a piece of text."""
    cve_ids: list[str] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    products: list[str] = field(default_factory=list)
    exploit_type: str = ""
    price: str = ""
    urgency_score: float = 0.0
    urgency_signals: list[str] = field(default_factory=list)
    threat_actor: str = ""
    malware_family: str = ""
    focus_relevance: float = 0.0
    overall_score: float = 0.0


def extract_all(text: str) -> ExtractionResult:
    """Run all extractors on a piece of text. Returns structured result."""
    urgency, urgency_signals = extract_urgency_score(text)

    result = ExtractionResult(
        cve_ids=extract_cve_ids(text),
        hashes=extract_hashes(text),
        ips=extract_ips(text),
        domains=extract_domains(text),
        urls=extract_urls(text),
        products=extract_products(text),
        exploit_type=extract_exploit_type(text),
        price=extract_price(text),
        urgency_score=urgency,
        urgency_signals=urgency_signals,
        threat_actor=extract_threat_actor(text),
        malware_family=extract_malware_family(text),
        focus_relevance=focus.relevance(text),
    )

    # Overall relevance score
    score = 0.0
    if result.cve_ids:
        score += 0.25
    if result.hashes:
        score += 0.15
    if result.exploit_type:
        score += 0.1
    if result.price:
        score += 0.15          # Something is being sold
    if result.threat_actor:
        score += 0.15
    score += result.urgency_score * 0.3
    score += result.focus_relevance * 0.2
    result.overall_score = min(score, 1.0)

    return result
