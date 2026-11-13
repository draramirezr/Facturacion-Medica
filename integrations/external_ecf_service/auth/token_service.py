"""Tokens JWT para integraciones externas (HS256)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import jwt


class ExternalECFTokenError(ValueError):
    """Token inválido o expirado."""


def issue_token(
    *,
    secret: str,
    ttl_seconds: int,
    client_id: int,
    emitter_id: int,
    tenant_id: int,
    rnc: str,
    environment: str,
) -> tuple[str, datetime]:
    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=ttl_seconds)
    payload = {
        'sub': f'ext-ecf:{client_id}:{emitter_id}',
        'client_id': client_id,
        'emitter_id': emitter_id,
        'tenant_id': tenant_id,
        'rnc': rnc,
        'environment': environment,
        'iat': int(now.timestamp()),
        'exp': int(expires.timestamp()),
        'typ': 'external_ecf',
    }
    token = jwt.encode(payload, secret, algorithm='HS256')
    return token, expires


def decode_token(token: str, *, secret: str) -> dict[str, Any]:
    try:
        return jwt.decode(
            token,
            secret,
            algorithms=['HS256'],
            options={'require': ['exp', 'iat', 'sub']},
        )
    except jwt.PyJWTError as error:
        raise ExternalECFTokenError('Token inválido') from error
