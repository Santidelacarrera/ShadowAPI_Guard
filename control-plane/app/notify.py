"""Webhook notifications (Slack-compatible `{"text": ...}` payload) with de-duplication."""
import logging
import os
import threading
import time

import httpx

log = logging.getLogger("notify")
_seen: dict[str, float] = {}
_sender = None  # test hook: callable(url, payload)
DEDUPE_SECONDS = 300


def _post(url: str, payload: dict) -> None:
    try:
        if _sender:
            _sender(url, payload)
        else:
            httpx.post(url, json=payload, timeout=5)
    except Exception as e:  # notifications must never break ingestion
        log.warning("webhook failed: %s", e)


def notify(kind: str, key: str, text: str) -> bool:
    """Send `text` unless the same (kind, key) was sent in the last 5 minutes. Returns True if sent."""
    url = os.environ.get("ALERT_WEBHOOK_URL", "")
    if not url:
        return False
    now = time.time()
    k = f"{kind}:{key}"
    if now - _seen.get(k, 0) < DEDUPE_SECONDS:
        return False
    _seen[k] = now
    payload = {"text": f"[ShadowAPI Guard] {text}"}
    if _sender:
        _post(url, payload)  # synchronous under test
    else:
        threading.Thread(target=_post, args=(url, payload), daemon=True).start()
    return True


def reset() -> None:
    _seen.clear()
