"""Outermost request handling: ids, timing headers, body cap, logging, 500s."""

from __future__ import annotations

import json
import logging
import time
import traceback
import uuid
from urllib.parse import quote

from starlette.datastructures import Headers, MutableHeaders

from .errors import error_body
from .security import now_ms

log = logging.getLogger("sshsync")


class RequestContextMiddleware:
    """Pure ASGI middleware.

    - gives every request an id and stamps X-Request-Id / X-Server-Time
    - reads the body up front and refuses anything over the cap (both by
      Content-Length and by bytes actually received)
    - logs one line per request: never bodies, headers or query strings
    - turns any unhandled exception into a JSON 500
    """

    def __init__(self, app, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = uuid.uuid4().hex
        state = scope.setdefault("state", {})
        state["request_id"] = request_id
        started = time.monotonic()
        sent = {"status": 0, "bytes": 0}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                sent["status"] = message["status"]
                headers = MutableHeaders(scope=message)
                headers["X-Request-Id"] = request_id
                headers["X-Server-Time"] = str(now_ms())
            elif message["type"] == "http.response.body":
                sent["bytes"] += len(message.get("body", b""))
            await send(message)

        async def respond(status: int, body: dict):
            payload = json.dumps(body).encode()
            await send_wrapper(
                {
                    "type": "http.response.start",
                    "status": status,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(payload)).encode()),
                    ],
                }
            )
            await send_wrapper({"type": "http.response.body", "body": payload})

        received = 0
        failure = None
        try:
            declared = Headers(scope=scope).get("content-length")
            too_large = declared is not None and declared.isdigit() and int(declared) > self.max_body_bytes
            chunks = []
            while not too_large:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                chunk = message.get("body", b"")
                received += len(chunk)
                if received > self.max_body_bytes:
                    too_large = True
                    break
                chunks.append(chunk)
                if not message.get("more_body", False):
                    break
            if too_large:
                await respond(413, error_body("too_large", "request body too large"))
                return
            body = b"".join(chunks)
            replayed = False

            async def replay():
                nonlocal replayed
                if not replayed:
                    replayed = True
                    return {"type": "http.request", "body": body, "more_body": False}
                return await receive()

            await self.app(scope, replay, send_wrapper)
        except Exception as exc:  # noqa: BLE001 - last line of defence
            failure = (type(exc).__name__, "".join(traceback.format_tb(exc.__traceback__)))
        finally:
            if failure:
                # Exception type and stack frames only. The exception *message*
                # is left out: it is the one part that could quote request data.
                log.error("unhandled %s request_id=%s\n%s", failure[0], request_id, failure[1])
                if sent["status"] == 0:
                    await respond(
                        500, error_body("internal", "internal server error", request_id=request_id)
                    )
            log.info(
                "%s %s %s device=%s request_id=%s in=%d out=%d ms=%d",
                scope["method"],
                quote(scope["path"])[:200],
                sent["status"] or "-",
                state.get("device_id", "-"),
                request_id,
                received,
                sent["bytes"],
                (time.monotonic() - started) * 1000,
            )
