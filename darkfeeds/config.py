"""
Configuration for DarkFeeds crawler.

All settings can be overridden via environment variables prefixed with DARKFEEDS_.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TorConfig:
    """Tor SOCKS5 proxy settings."""
    host: str = "127.0.0.1"
    port: int = 9050
    control_port: int = 9051           # For circuit rotation (optional)
    control_password: str = ""         # Tor control auth password

    @property
    def proxy_url(self) -> str:
        return f"socks5h://{self.host}:{self.port}"

    @property
    def proxies(self) -> dict[str, str]:
        return {"http": self.proxy_url, "https": self.proxy_url}


@dataclass
class CrawlConfig:
    """Crawling behavior settings."""
    request_timeout: int = 45          # .onion sites are slow
    delay_min: float = 3.0             # minimum seconds between requests
    delay_max: float = 8.0             # maximum seconds (randomized)
    max_pages_per_source: int = 25     # don't deep-crawl
    max_retries: int = 2               # retry failed requests
    rotate_circuit_every: int = 10     # requests before new Tor circuit
    store_full_html: bool = False      # only store extracted data, not raw HTML
    headless_browser: bool = False     # use Playwright for JS-heavy sites


@dataclass
class Config:
    """Master configuration."""
    tor: TorConfig = field(default_factory=TorConfig)
    crawl: CrawlConfig = field(default_factory=CrawlConfig)

    # Storage
    db_path: str = ""

    # API keys (from environment) — never hardcode, never commit a real value
    otx_api_key: str = ""              # AlienVault OTX
    vt_api_key: str = ""               # VirusTotal
    shodan_api_key: str = ""           # Shodan

    def __post_init__(self):
        self.db_path = os.environ.get("DARKFEEDS_DB_PATH", self.db_path)
        if not self.db_path:
            data_dir = Path.home() / ".darkfeeds"
            data_dir.mkdir(exist_ok=True)
            self.db_path = str(data_dir / "darkfeeds.db")

        # Load from env
        self.otx_api_key = os.environ.get("DARKFEEDS_OTX_KEY", self.otx_api_key)
        self.vt_api_key = os.environ.get("DARKFEEDS_VT_KEY", self.vt_api_key)
        self.shodan_api_key = os.environ.get("DARKFEEDS_SHODAN_KEY", self.shodan_api_key)
        tor_host = os.environ.get("DARKFEEDS_TOR_HOST")
        if tor_host:
            self.tor.host = tor_host
        tor_port = os.environ.get("DARKFEEDS_TOR_PORT")
        if tor_port:
            self.tor.port = int(tor_port)
