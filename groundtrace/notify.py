"""
Alert delivery: generic/Slack/Discord webhook and Telegram (stdlib only).

  GROUNDTRACE_WEBHOOK_URL         any webhook; payload shape is picked from the
                               URL (Slack: {"text"}, Discord: {"content"},
                               anything else: {"text", "alerts": [...]})
  GROUNDTRACE_TELEGRAM_BOT_TOKEN  + GROUNDTRACE_TELEGRAM_CHAT_ID  -> Telegram bot

With neither configured, alerts still go to stderr and the alerts table, so
the watcher is useful (and testable) before any channel is set up. A failed
delivery is reported, never raised — one broken channel mustn't stop the
watcher or the other channel.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field

_TIMEOUT = 15
# Discord caps message content at 2000 chars, Telegram at 4096.
_MAX_TEXT = 1900


@dataclass
class Alert:
    key: str                  # dedup key, e.g. "kev:CVE-2026-1234"
    kind: str                 # kev | exploitdb | underground | watch | critical | signal
    title: str
    detail: str = ""
    url: str = ""
    data: dict = field(default_factory=dict)

    def line(self) -> str:
        s = f"• {self.title}"
        if self.detail:
            s += f" — {self.detail}"
        if self.url:
            s += f"\n  {self.url}"
        return s


def _post(url: str, payload: dict) -> None:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json",
                 "User-Agent": "groundtrace/0.1"})
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
        r.read()


def _format(alerts: list[Alert], overflow: int) -> str:
    head = f"GroundTrace: {len(alerts) + overflow} new alert(s)"
    lines = [a.line() for a in alerts]
    if overflow:
        lines.append(f"… and {overflow} more (run `python -m groundtrace alerts` to see all)")
    text = head + "\n\n" + "\n".join(lines)
    return text if len(text) <= _MAX_TEXT else text[:_MAX_TEXT - 1] + "…"


def channels() -> list[str]:
    """Alert destinations that are actually configured, by name.

    Empty means nothing leaves this machine: alerts are written to the store
    and printed to stderr, and that is all. Callers must not present that as
    delivery.
    """
    out = []
    if os.environ.get("GROUNDTRACE_WEBHOOK_URL"):
        out.append("webhook")
    if os.environ.get("GROUNDTRACE_TELEGRAM_BOT_TOKEN") and os.environ.get("GROUNDTRACE_TELEGRAM_CHAT_ID"):
        out.append("telegram")
    return out


def send(alerts: list[Alert], *, overflow: int = 0) -> dict[str, str]:
    """Deliver one digest message per channel. Returns {channel: "ok"|error}.

    An empty result means no channel is configured and nothing was sent
    anywhere. It is not a successful delivery, and recording it as one is how
    30 alerts came to be stored as delivered when they had only ever been
    printed to a terminal nobody was watching.
    """
    if not alerts:
        return {}
    text = _format(alerts, overflow)
    print(f"\n[alert]\n{text}\n", file=sys.stderr)
    results: dict[str, str] = {}

    hook = os.environ.get("GROUNDTRACE_WEBHOOK_URL")
    if hook:
        if "hooks.slack.com" in hook:
            payload = {"text": text}
        elif "discord.com/api/webhooks" in hook or "discordapp.com/api/webhooks" in hook:
            payload = {"content": text}
        else:
            payload = {"text": text, "alerts": [
                {"key": a.key, "kind": a.kind, "title": a.title, "detail": a.detail,
                 "url": a.url, "data": a.data} for a in alerts]}
        try:
            _post(hook, payload)
            results["webhook"] = "ok"
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            results["webhook"] = f"{type(e).__name__}: {e}"

    token = os.environ.get("GROUNDTRACE_TELEGRAM_BOT_TOKEN")
    chat = os.environ.get("GROUNDTRACE_TELEGRAM_CHAT_ID")
    if token and chat:
        try:
            _post(f"https://api.telegram.org/bot{token}/sendMessage",
                  {"chat_id": chat, "text": text, "disable_web_page_preview": True})
            results["telegram"] = "ok"
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            # never echo the URL here — it contains the bot token
            results["telegram"] = f"{type(e).__name__}"

    for ch, res in results.items():
        if res != "ok":
            print(f"[!] alert delivery via {ch} failed: {res}", file=sys.stderr)
    if not results:
        print("[!] no alert channel configured (set GROUNDTRACE_WEBHOOK_URL, or "
              "GROUNDTRACE_TELEGRAM_BOT_TOKEN with GROUNDTRACE_TELEGRAM_CHAT_ID). "
              "Alerts are recorded and visible in the dashboard, but nothing "
              "was sent anywhere.", file=sys.stderr)
    return results
