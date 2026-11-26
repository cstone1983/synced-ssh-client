"""Request models. Unknown fields are rejected; ints and bools are strict."""

from __future__ import annotations

import base64
import binascii
import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr

from .errors import ApiError


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EnrollRequest(_Model):
    code: StrictStr = Field(max_length=64)
    device_name: StrictStr = Field(min_length=1, max_length=64)
    platform: Literal["android", "windows", "linux", "other"]


class CodeRequest(_Model):
    device_name: StrictStr = Field(min_length=1, max_length=64)
    platform: Literal["android", "windows", "linux", "other"]


class KeyslotPut(_Model):
    base_version: StrictInt = Field(ge=0)
    blob: StrictStr


class RotateTokenRequest(_Model):
    # SHA-256 (lowercase hex) of a token the client generated and stored
    # first, so a lost reply can never leave the device without a token.
    token_hash: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")


class Change(_Model):
    id: uuid.UUID
    base_seq: StrictInt = Field(ge=0)
    deleted: StrictBool
    blob: StrictStr


class PushRequest(_Model):
    changes: list[Change]


def decode_blob(value: str, max_bytes: int, where: str) -> bytes:
    """Strict standard base64 -> bytes. 422 if malformed/empty, 413 if too big."""
    if len(value) > (max_bytes + 2) // 3 * 4:
        raise ApiError(413, "too_large", f"{where}: blob exceeds {max_bytes} bytes")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ApiError(422, "invalid_request", f"{where}: blob is not valid base64") from None
    if not raw:
        raise ApiError(422, "invalid_request", f"{where}: blob is empty")
    if len(raw) > max_bytes:
        raise ApiError(413, "too_large", f"{where}: blob exceeds {max_bytes} bytes")
    return raw


def encode_blob(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")
