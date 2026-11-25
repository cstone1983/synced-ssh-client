"""HTTP endpoints. See docs/PLAN.md section 7 for the contract."""

from __future__ import annotations

import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import delete, func, select

from . import config
from .db import Device, EnrollmentCode, Keyslot, Record, get_meta, get_seq, set_seq
from .errors import ApiError
from .notify import NotifyError
from .schemas import (
    CodeRequest,
    EnrollRequest,
    KeyslotPut,
    PushRequest,
    RotateTokenRequest,
    decode_blob,
    encode_blob,
)
from .security import (
    client_ip,
    create_enrollment_code,
    new_token,
    normalize_code,
    now_ms,
    sha256_hex,
)

router = APIRouter()
log = logging.getLogger("sshsync")


def _rate_limited() -> ApiError:
    return ApiError(429, "rate_limited", "too many requests, slow down", headers={"Retry-After": "60"})


def _ip(request: Request) -> str:
    peer = request.client.host if request.client else None
    return client_ip(
        peer, request.headers.get("x-forwarded-for"), request.app.state.settings.trusted_proxies
    )


def enroll_limit(request: Request) -> None:
    st = request.app.state
    if not st.limiter.hit(("enroll", _ip(request)), st.settings.enroll_per_minute):
        raise _rate_limited()


def authenticate(request: Request) -> str:
    """Resolve the bearer token to a device id, or raise 401/429."""
    st = request.app.state
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    token = token.strip()
    failure = "unauthorized"
    if scheme.lower() == "bearer" and token:
        with st.db.tx() as s:
            device = s.scalar(select(Device).where(Device.token_hash == sha256_hex(token)))
            if device is not None:
                request.state.device_id = device.id
                if device.revoked_at is None:
                    device.last_seen_at = now_ms()
                    failure = ""
                else:
                    failure = "device_revoked"
    if failure:
        if not st.limiter.hit(("auth_fail", _ip(request)), st.settings.auth_fail_per_minute):
            raise _rate_limited()
        message = "device has been revoked" if failure == "device_revoked" else "missing or invalid token"
        raise ApiError(401, failure, message, headers={"WWW-Authenticate": "Bearer"})
    if not st.limiter.hit(("device", device.id), st.settings.device_per_minute):
        raise _rate_limited()
    return device.id


DeviceId = Annotated[str, Depends(authenticate)]


@router.get("/healthz")
def healthz():
    return {"status": "ok"}


@router.post("/v1/enroll", status_code=201, dependencies=[Depends(enroll_limit)])
def enroll(body: EnrollRequest, request: Request):
    st = request.app.state
    invalid = ApiError(401, "invalid_code", "enrollment code is wrong, expired or already used")
    code = normalize_code(body.code)
    if code is None:
        raise invalid
    now = now_ms()
    token = new_token()
    device_id = str(uuid.uuid4())
    with st.db.tx() as s:
        row = s.get(EnrollmentCode, sha256_hex(code))
        if row is None or row.used_at is not None or row.expires_at <= now:
            raise invalid
        row.used_at = now
        s.add(
            Device(
                id=device_id,
                name=body.device_name,
                platform=body.platform,
                token_hash=sha256_hex(token),
                created_at=now,
                last_seen_at=now,
            )
        )
        vault_id = get_meta(s, "vault_id")
    request.state.device_id = device_id
    return {
        "device_id": device_id,
        "token": token,
        "vault_id": vault_id,
        "protocol": config.PROTOCOL_VERSION,
    }


@router.post("/v1/enrollment-codes", status_code=201)
def create_code(request: Request, _: DeviceId):
    st = request.app.state
    with st.db.tx() as s:
        code, expires_at = create_enrollment_code(s, st.settings.code_ttl_seconds)
    return {"code": code, "expires_at": expires_at}


@router.post("/v1/enrollment-codes/request", status_code=202)
def request_code(body: CodeRequest, request: Request):
    """Send a fresh one-time code to the owner (Telegram, via n8n).

    Needs no token: this is how a new device gets in. The caller never sees
    the code, and the reply is the same whatever devices the server has.
    """
    st = request.app.state
    ip = _ip(request)
    if not st.limiter.hit(("code_request", ip), st.settings.code_request_per_minute):
        raise _rate_limited()
    if st.notify is None:
        raise ApiError(
            404,
            "not_available",
            "this server cannot send codes; run `sshsync enroll-code` on the server",
        )
    if not st.hourly_limiter.hit(("code_request",), st.settings.code_request_per_hour):
        raise ApiError(
            429, "rate_limited", "too many codes requested, try again later",
            headers={"Retry-After": "600"},
        )
    ttl = st.settings.code_ttl_seconds
    with st.db.tx() as s:
        code, expires_at = create_enrollment_code(s, ttl)
    payload = {
        "code": code,
        "expires_minutes": max(1, round(ttl / 60)),
        "device_name": body.device_name,
        "platform": body.platform,
        "ip": ip,
    }
    try:
        st.notify(payload)
    except Exception as e:
        # Nobody received this code, so it must not stay usable.
        with st.db.tx() as s:
            code_hash = sha256_hex(normalize_code(code))
            s.execute(delete(EnrollmentCode).where(EnrollmentCode.code_hash == code_hash))
        reason = str(e) if isinstance(e, NotifyError) else type(e).__name__
        log.warning("enrollment code request from %s not delivered: %s", ip, reason)
        raise ApiError(502, "notify_failed", "the code could not be sent, try again") from None
    log.info("enrollment code sent for %r (%s) requested from %s", body.device_name, body.platform, ip)
    return {"sent": True, "expires_at": expires_at}


@router.get("/v1/keyslot")
def get_keyslot(request: Request, _: DeviceId):
    with request.app.state.db.tx() as s:
        slot = s.get(Keyslot, 1)
        if slot is None:
            raise ApiError(404, "not_found", "no keyslot has been uploaded")
        return {"version": slot.version, "blob": encode_blob(slot.blob)}


@router.put("/v1/keyslot")
def put_keyslot(body: KeyslotPut, request: Request, _: DeviceId):
    blob = decode_blob(body.blob, config.MAX_KEYSLOT_BYTES, "keyslot")
    with request.app.state.db.tx() as s:
        slot = s.get(Keyslot, 1)
        current = slot.version if slot else 0
        if body.base_version != current:
            raise ApiError(
                409,
                "version_conflict",
                "keyslot was changed by another device",
                current={"version": current, "blob": encode_blob(slot.blob) if slot else ""},
            )
        if slot is None:
            s.add(Keyslot(id=1, version=1, blob=blob, updated_at=now_ms()))
        else:
            slot.version, slot.blob, slot.updated_at = current + 1, blob, now_ms()
        return {"version": current + 1}


@router.post("/v1/push")
def push(body: PushRequest, request: Request, device_id: DeviceId):
    if len(body.changes) > config.MAX_PUSH_ITEMS:
        raise ApiError(413, "too_large", f"at most {config.MAX_PUSH_ITEMS} changes per push")
    # Validate every blob before touching the database.
    blobs = [
        decode_blob(c.blob, config.MAX_BLOB_BYTES, f"changes[{i}]")
        for i, c in enumerate(body.changes)
    ]
    results = []
    with request.app.state.db.tx() as s:  # BEGIN IMMEDIATE: one writer at a time
        seq = get_seq(s)
        now = now_ms()
        for change, blob in zip(body.changes, blobs):
            record_id = str(change.id)
            record = s.get(Record, record_id)
            current = record.seq if record else 0
            if change.base_seq != current:
                results.append(
                    {
                        "id": record_id,
                        "status": "conflict",
                        "seq": current,
                        "deleted": record.deleted if record else False,
                        "blob": encode_blob(record.blob) if record else "",
                    }
                )
                continue
            seq += 1
            if record is None:
                record = Record(id=record_id)
                s.add(record)
            record.seq = seq
            record.deleted = change.deleted
            record.blob = blob
            record.device_id = device_id
            record.updated_at = now
            s.flush()
            results.append({"id": record_id, "status": "ok", "seq": seq})
        set_seq(s, seq)
    return {"results": results, "cursor": seq}


@router.get("/v1/pull")
def pull(
    request: Request,
    _: DeviceId,
    since: Annotated[int, Query(ge=0, le=2**62)] = 0,
    limit: Annotated[int, Query(ge=1, le=config.MAX_PULL_LIMIT)] = 200,
):
    changes = []
    has_more = False
    size = 0
    stmt = select(Record).where(Record.seq > since).order_by(Record.seq).limit(limit + 1)
    with request.app.state.db.tx() as s:
        for record in s.scalars(stmt):
            if len(changes) == limit or (changes and size >= config.PULL_PAGE_BYTES):
                has_more = True
                break
            size += len(record.blob)
            changes.append(
                {
                    "id": record.id,
                    "seq": record.seq,
                    "deleted": record.deleted,
                    "blob": encode_blob(record.blob),
                    "device_id": record.device_id,
                    "updated_at": record.updated_at,
                }
            )
    return {
        "changes": changes,
        "cursor": changes[-1]["seq"] if changes else since,
        "has_more": has_more,
    }


@router.get("/v1/devices")
def list_devices(request: Request, device_id: DeviceId):
    with request.app.state.db.tx() as s:
        devices = s.scalars(select(Device).order_by(Device.created_at, Device.id)).all()
    return {
        "devices": [
            {
                "id": d.id,
                "name": d.name,
                "platform": d.platform,
                "created_at": d.created_at,
                "last_seen_at": d.last_seen_at,
                "revoked": d.revoked_at is not None,
                "current": d.id == device_id,
            }
            for d in devices
        ]
    }


# Declared before /v1/devices/{target_id} so "self" is never read as an id.
@router.post("/v1/devices/self/rotate-token")
def rotate_token(request: Request, device_id: DeviceId, body: RotateTokenRequest | None = None):
    """Replace this device's token.

    Preferred: the client sends the hash of a token it generated and saved
    beforehand. If the reply is lost, the client simply tries its saved new
    token. Repeating the call with the same hash is harmless.

    Without a body the server makes the token and returns it (older clients);
    a lost reply then locks the device out.
    """
    with request.app.state.db.tx() as s:
        device = s.get(Device, device_id)
        if body is None:
            token = new_token()
            device.token_hash = sha256_hex(token)
            return {"token": token}
        if body.token_hash != device.token_hash:
            taken = s.scalar(select(Device.id).where(Device.token_hash == body.token_hash))
            if taken is not None:
                raise ApiError(409, "token_in_use", "choose a different token")
            device.token_hash = body.token_hash
    return {"rotated": True}


@router.delete("/v1/devices/{target_id}")
def revoke_device(target_id: uuid.UUID, request: Request, _: DeviceId):
    with request.app.state.db.tx() as s:
        device = s.get(Device, str(target_id))
        if device is None:
            raise ApiError(404, "not_found", "no such device")
        if device.revoked_at is None:
            device.revoked_at = now_ms()
    return {"revoked": True}


@router.get("/v1/status")
def status(request: Request, _: DeviceId):
    with request.app.state.db.tx() as s:
        records = s.scalar(select(func.count()).select_from(Record).where(Record.deleted.is_(False)))
        return {
            "server_time": now_ms(),
            "records": records,
            "cursor": get_seq(s),
            "protocol": config.PROTOCOL_VERSION,
            "vault_id": get_meta(s, "vault_id"),
        }
