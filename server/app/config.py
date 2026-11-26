"""Runtime configuration, read from environment variables."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass

PROTOCOL_VERSION = 1

MAX_BODY_BYTES = 8 * 1024 * 1024
MAX_BLOB_BYTES = 256 * 1024
MAX_KEYSLOT_BYTES = 16 * 1024
MAX_PUSH_ITEMS = 500
MAX_PULL_LIMIT = 500
# Soft cap on the decoded blob bytes in one pull page; the page is cut short
# (has_more=true) once it is exceeded, so a response stays a sane size.
PULL_PAGE_BYTES = 8 * 1024 * 1024

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def _flag(value: str) -> bool:
    return value.strip().lower() not in ("off", "0", "false", "no", "")


def _secret(env, name: str) -> str:
    """NAME, or the contents of the file named by NAME_FILE (Docker secrets)."""
    path = env.get(f"{name}_FILE", "").strip()
    if path:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    return env.get(name, "").strip()


def parse_networks(value: str) -> tuple[IPNetwork, ...]:
    return tuple(
        ipaddress.ip_network(part.strip(), strict=False)
        for part in value.split(",")
        if part.strip()
    )


@dataclass(frozen=True)
class Settings:
    db_path: str = "/data/sshsync.db"
    trusted_proxies: tuple[IPNetwork, ...] = ()
    rate_limit: bool = True
    code_ttl_seconds: int = 600
    log_level: str = "INFO"
    # Where a requested enrollment code is delivered (an n8n webhook that
    # forwards it to Telegram). Empty URL = code requests are switched off.
    notify_url: str = ""
    notify_key: str = ""
    # Limits per minute. Not exposed as env vars; tests override them.
    enroll_per_minute: int = 5
    auth_fail_per_minute: int = 10
    device_per_minute: int = 600
    # Code requests: per client address per minute, and in total per hour.
    code_request_per_minute: int = 3
    code_request_per_hour: int = 10

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "Settings":
        env = os.environ if env is None else env
        return cls(
            db_path=env.get("SSHSYNC_DB_PATH", "/data/sshsync.db"),
            trusted_proxies=parse_networks(env.get("SSHSYNC_TRUSTED_PROXIES", "")),
            rate_limit=_flag(env.get("SSHSYNC_RATE_LIMIT", "on")),
            code_ttl_seconds=int(env.get("SSHSYNC_CODE_TTL_SECONDS", "600")),
            log_level=env.get("SSHSYNC_LOG_LEVEL", "INFO").upper(),
            notify_url=env.get("SSHSYNC_NOTIFY_URL", "").strip(),
            notify_key=_secret(env, "SSHSYNC_NOTIFY_KEY"),
        )
