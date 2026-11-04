"""DarkFeeds — Passive threat intelligence collector from underground sources."""

from .deepweb import build_deepweb_signal
from .news import collect_news_feeds, parse_rss_feed

__version__ = "0.1.0"
__all__ = ["build_deepweb_signal", "collect_news_feeds", "parse_rss_feed"]
