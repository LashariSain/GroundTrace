"""
Data models for DarkFeeds — all signals, IoCs, and extracted intelligence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class SignalSource(str, Enum):
    """Where the signal was collected from."""
    ONION_FORUM = "onion_forum"
    CLEARNET_FORUM = "clearnet_forum"
    PASTE_SITE = "paste_site"
    TELEGRAM = "telegram"
    MALWAREBAZAAR = "malwarebazaar"
    THREATFOX = "threatfox"
    URLHAUS = "urlhaus"
    OTX = "otx"
    RANSOMWARE_LIVE = "ransomware_live"   # legacy (paywalled) — kept for stored rows
    RANSOMLOOK = "ransomlook"             # free leak-site claim tracker (ransomlook.io)
    AHMIA = "ahmia"
    GITHUB = "github"
    RSS = "rss"


class SignalType(str, Enum):
    """What kind of intelligence this signal represents."""
    EXPLOIT_SALE = "exploit_sale"           # Someone selling an exploit
    EXPLOIT_SHARE = "exploit_share"         # Free PoC / exploit code shared
    MALWARE_SAMPLE = "malware_sample"       # New malware hash
    ACCESS_SALE = "access_sale"             # Selling access to compromised org
    DATA_LEAK = "data_leak"                # Database / credential leak
    VULN_DISCUSSION = "vuln_discussion"    # CVE discussion / analysis
    ZERO_DAY = "zero_day"                  # Pre-disclosure vulnerability
    RANSOMWARE_VICTIM = "ransomware_victim" # Ransomware group claims victim
    C2_INFRASTRUCTURE = "c2_infrastructure" # Command & control server
    THREAT_ACTOR = "threat_actor"          # APT / group activity
    GENERAL_INTEL = "general_intel"        # Other relevant intelligence


class Priority(str, Enum):
    CRITICAL = "P1"    # Active zero-day, PK under attack
    HIGH = "P2"        # New APT campaign, KEV-listed CVE being exploited
    MEDIUM = "P3"      # Exploit sale, new malware variant
    LOW = "P4"         # General chatter, old CVE discussion


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class ThreatSignal:
    """
    A single piece of intelligence extracted from an underground source.
    This is the core data unit — everything we collect becomes a ThreatSignal.
    """
    # Identity
    signal_id: str = ""                         # auto-generated unique ID
    signal_type: SignalType = SignalType.GENERAL_INTEL
    priority: Priority = Priority.LOW
    confidence: Confidence = Confidence.LOW

    # Source
    source: SignalSource = SignalSource.ONION_FORUM
    source_name: str = ""                       # "XSS.is", "BreachForums", etc.
    source_url: str = ""                        # URL where found (may be .onion)
    source_section: str = ""                    # Forum section / channel name

    # Content
    title: str = ""                             # Thread title / post subject
    raw_text: str = ""                          # The actual post content (or snippet)
    language: str = "en"                        # "en", "ru", etc.

    # Timestamps
    posted_at: Optional[datetime] = None        # When the post was made
    collected_at: datetime = field(default_factory=datetime.utcnow)

    # Extracted intelligence
    cve_ids: list[str] = field(default_factory=list)        # CVE-2026-XXXXX
    malware_hashes: list[str] = field(default_factory=list) # SHA256, MD5
    malware_family: str = ""                                 # CrimsonRAT, etc.
    ip_addresses: list[str] = field(default_factory=list)   # C2 IPs
    domains: list[str] = field(default_factory=list)         # C2 / malicious domains
    urls: list[str] = field(default_factory=list)            # Malicious URLs
    product_names: list[str] = field(default_factory=list)   # Fortinet, Windows, etc.
    exploit_type: str = ""                                   # RCE, LPE, SQLi, etc.
    price: str = ""                                          # "$50k", "5 BTC"

    # APT / threat actor
    threat_actor: str = ""                      # APT36, SideWinder, etc.
    target_country: str = ""                    # lowercase country name
    target_sector: str = ""                     # "military", "government", etc.

    # Scoring
    relevance_score: float = 0.0                # 0-1 how relevant to our mission

    # Evidence
    evidence_snippet: str = ""                  # The key phrase that triggered extraction
    tags: list[str] = field(default_factory=list)


@dataclass
class ForumTarget:
    """A forum to monitor — its URL, sections, and crawl settings."""
    name: str                                   # Human-readable name
    base_url: str                               # Base .onion or clearnet URL
    forum_type: str = "generic"                 # "xenforo", "mybb", "smf", "custom"
    language: str = "en"
    requires_tor: bool = True
    requires_js: bool = False                   # Need headless browser?

    # Which sections / subforums to monitor
    sections: list[dict] = field(default_factory=list)
    # Each: {"path": "/forum/exploits/", "name": "Exploits", "priority": "high"}

    # Crawl settings
    enabled: bool = True
    crawl_interval_hours: float = 12.0
    max_pages: int = 5                          # Pages of thread listing per section
