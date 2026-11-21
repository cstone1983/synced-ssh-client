"""Application factory.

Run with:  uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8080
"""

from __future__ import annotations

import logging
import sys

from fastapi import FastAPI

from . import config
from .config import Settings
from .db import Database
from .errors import install_error_handlers
from .middleware import RequestContextMiddleware
from .routes import router
from .security import RateLimiter, create_enrollment_code, needs_bootstrap_code


class _StdoutHandler(logging.StreamHandler):
    """Writes to whatever sys.stdout is at emit time (it can be replaced)."""

    def __init__(self) -> None:
        logging.Handler.__init__(self)

    @property
    def stream(self):
        return sys.stdout


def configure_logging(level: str) -> None:
    log = logging.getLogger("sshsync")
    log.setLevel(getattr(logging, level.upper(), logging.INFO))
    if not log.handlers:
        handler = _StdoutHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        log.addHandler(handler)


def print_enrollment_code(code: str, ttl_seconds: int, reason: str) -> None:
    """The only place an enrollment code is ever written out."""
    line = "=" * 60
    print(
        f"\n{line}\n {reason}\n Enrollment code: {code}\n"
        f" Single use, valid for {ttl_seconds // 60} min {ttl_seconds % 60} s.\n{line}\n",
        flush=True,
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    configure_logging(settings.log_level)

    app = FastAPI(title="sshsync", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.db = Database(settings.db_path)
    app.state.limiter = RateLimiter(enabled=settings.rate_limit)

    install_error_handlers(app)
    app.add_middleware(RequestContextMiddleware, max_body_bytes=config.MAX_BODY_BYTES)
    app.include_router(router)

    # Bootstrap: if nobody can get in, hand out one code on the console.
    with app.state.db.tx() as s:
        code = (
            create_enrollment_code(s, settings.code_ttl_seconds)[0]
            if needs_bootstrap_code(s)
            else None
        )
    if code:
        print_enrollment_code(code, settings.code_ttl_seconds, "No device is enrolled yet.")
    return app
