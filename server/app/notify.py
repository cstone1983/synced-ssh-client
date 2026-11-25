"""Delivers a requested enrollment code to the owner (an n8n webhook).

The server never holds a Telegram token: it POSTs a small JSON document to
SSHSYNC_NOTIFY_URL with the shared key in X-Sshsync-Key, and the webhook
sends the message. Only the code, its lifetime and who asked are sent.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Callable

from .config import Settings

log = logging.getLogger("sshsync")

TIMEOUT_SECONDS = 10

# notify(payload) -> None; raises NotifyError when the code was not delivered.
Notifier = Callable[[dict], None]


class NotifyError(Exception):
    pass


def webhook_notifier(url: str, key: str) -> Notifier:
    def notify(payload: dict) -> None:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json", "X-Sshsync-Key": key},
        )
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as res:
                status = res.status
        except urllib.error.HTTPError as e:
            status = e.code
        except (urllib.error.URLError, OSError) as e:
            # The reason only; never the payload (it holds the code).
            raise NotifyError(f"webhook unreachable ({type(e).__name__})") from None
        if not 200 <= status < 300:
            raise NotifyError(f"webhook answered {status}")

    return notify


def make_notifier(settings: Settings) -> Notifier | None:
    if not settings.notify_url:
        return None
    if not settings.notify_url.lower().startswith(("http://", "https://")):
        log.error("SSHSYNC_NOTIFY_URL must be an http(s) URL; code requests are off")
        return None
    if not settings.notify_key:
        log.error("SSHSYNC_NOTIFY_URL is set but SSHSYNC_NOTIFY_KEY is not; code requests are off")
        return None
    return webhook_notifier(settings.notify_url, settings.notify_key)
