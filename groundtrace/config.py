"""
Config dataclass. Loads from environment variables so no secrets ever live in
source or in the SQLite DB. Every field has a safe default — the tool works
fully unconfigured (unauthenticated NVD, no darkweb, no API server).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env_str(name: str, default: str | None = None) -> str | None:
    return os.environ.get(name, default)


def _env_float(name: str, default: float) -> float:
    v = os.environ.get(name)
    try:
        return float(v) if v else default
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    v = os.environ.get(name)
    try:
        return int(v) if v else default
    except ValueError:
        return default


@dataclass
class Config:
    # API keys (never hardcode — env vars only)
    nvd_api_key: str | None = field(default_factory=lambda: _env_str("GROUNDTRACE_NVD_API_KEY"))

    # NVD rate limits — public tier is 5 req/30s; an API key raises it to 50/30s.
    nvd_tokens_per_window: int = 5
    nvd_window_seconds: float = 30.0

    # How long the downloaded CISA KEV catalog is reused before a re-fetch.
    kev_sync_hours: float = field(default_factory=lambda: _env_float("GROUNDTRACE_KEV_SYNC_HOURS", 12.0))

    # Safety: hard daily request ceiling per feed (circuit breaker).
    max_daily_requests: int = field(default_factory=lambda: _env_int("GROUNDTRACE_MAX_DAILY_REQUESTS", 5000))

    # Storage
    db_path: str = field(default_factory=lambda: _env_str(
        "GROUNDTRACE_DB_PATH", str(Path.home() / ".groundtrace" / "groundtrace.db")))

    def __post_init__(self):
        if self.nvd_api_key:
            self.nvd_tokens_per_window = 50

    def ensure_db_dir(self) -> Path:
        p = Path(self.db_path).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        return p


_default: Config | None = None


def get_config() -> Config:
    """Process-wide default Config, built once from the environment."""
    global _default
    if _default is None:
        _default = Config()
    return _default
