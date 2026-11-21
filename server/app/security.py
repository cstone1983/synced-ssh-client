"""Tokens, enrollment codes, client-IP resolution and the rate limiter."""

from __future__ import annotations

import hashlib
import ipaddress
import secrets
import threading
import time
from collections import deque

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .db import Device, EnrollmentCode

CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
CODE_LENGTH = 10


def now_ms() -> int:
    return int(time.time() * 1000)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)  # 256 bits, 43 chars, no padding


def normalize_code(raw: str) -> str | None:
    """Canonical 10-char code, or None if it cannot be a valid one."""
    code = raw.replace("-", "").replace(" ", "").upper()
    if len(code) != CODE_LENGTH or any(c not in CODE_ALPHABET for c in code):
        return None
    return code


def format_code(code: str) -> str:
    return f"{code[:5]}-{code[5:]}"


def create_enrollment_code(s: Session, ttl_seconds: int) -> tuple[str, int]:
    """Create a single-use code. Returns (display form, expires_at ms)."""
    now = now_ms()
    s.execute(delete(EnrollmentCode).where(EnrollmentCode.expires_at <= now))
    code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))
    expires_at = now + ttl_seconds * 1000
    s.add(EnrollmentCode(code_hash=sha256_hex(code), created_at=now, expires_at=expires_at))
    return format_code(code), expires_at


def needs_bootstrap_code(s: Session) -> bool:
    """True when nobody can get in: no active device and no usable code."""
    if s.scalar(select(Device.id).where(Device.revoked_at.is_(None)).limit(1)):
        return False
    usable = select(EnrollmentCode.code_hash).where(
        EnrollmentCode.used_at.is_(None), EnrollmentCode.expires_at > now_ms()
    )
    return s.scalar(usable.limit(1)) is None


def client_ip(peer: str | None, forwarded_for: str | None, trusted) -> str:
    """The address to key rate limits on.

    X-Forwarded-For is only believed when the direct peer is a trusted proxy;
    we then walk it right to left and take the first address that is not
    itself a trusted proxy.
    """
    peer = peer or "unknown"
    if not trusted or not forwarded_for or not _is_trusted(peer, trusted):
        return peer
    for hop in reversed([h.strip() for h in forwarded_for.split(",")]):
        try:
            ipaddress.ip_address(hop)
        except ValueError:
            return peer
        if not _is_trusted(hop, trusted):
            return hop
    return peer


def _is_trusted(addr: str, trusted) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip.version == net.version and ip in net for net in trusted)


class RateLimiter:
    """Sliding-window counter kept in memory (the server is one process)."""

    def __init__(self, enabled: bool = True, window: float = 60.0) -> None:
        self.enabled = enabled
        self.window = window
        self._hits: dict[tuple, deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: tuple, limit: int) -> bool:
        """Record one event. False means the limit was already reached."""
        if not self.enabled:
            return True
        now = time.monotonic()
        with self._lock:
            if len(self._hits) > 10_000:
                self._prune(now)
            q = self._hits.setdefault(key, deque())
            while q and q[0] <= now - self.window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True

    def _prune(self, now: float) -> None:
        for key in [k for k, q in self._hits.items() if not q or q[-1] <= now - self.window]:
            del self._hits[key]
