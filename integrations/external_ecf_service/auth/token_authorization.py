"""Validación JWT para endpoints protegidos (p. ej. POST /api/Enviar)."""

from __future__ import annotations

import re
from dataclasses import dataclass

from integrations.external_ecf_service.auth.token_service import (
    ExternalECFTokenError,
    decode_token,
)
from integrations.external_ecf_service.security.permissions import (
    ambiente_coincide,
    cliente_habilitado,
    emisor_habilitado,
)


@dataclass(frozen=True)
class AuthorizedIntegrationContext:
    client_id: int
    emitter_id: int
    tenant_id: int
    rnc: str
    environment: str


@dataclass(frozen=True)
class TokenAuthFailure:
    codigo: int
    mensaje: str


def _normalize_rnc(value: str) -> str:
    return re.sub(r'\D', '', str(value or ''))


def authorize_bearer_token(
    *,
    token: str,
    config,
    get_client,
    get_emitter,
) -> AuthorizedIntegrationContext | TokenAuthFailure:
    if not config.enabled:
        return TokenAuthFailure(codigo=99, mensaje='Servicio no disponible')

    token = (token or '').strip()
    if not token:
        return TokenAuthFailure(codigo=1, mensaje='Token inválido')

    try:
        payload = decode_token(token, secret=config.jwt_secret)
    except ExternalECFTokenError:
        return TokenAuthFailure(codigo=1, mensaje='Token inválido')

    if payload.get('typ') != 'external_ecf':
        return TokenAuthFailure(codigo=1, mensaje='Token inválido')

    if str(payload.get('environment', '')).upper() != config.environment.upper():
        return TokenAuthFailure(codigo=1, mensaje='Token inválido')

    try:
        client_id = int(payload['client_id'])
        emitter_id = int(payload['emitter_id'])
        tenant_id = int(payload['tenant_id'])
    except (KeyError, TypeError, ValueError):
        return TokenAuthFailure(codigo=1, mensaje='Token inválido')

    rnc = _normalize_rnc(payload.get('rnc'))
    if not rnc:
        return TokenAuthFailure(codigo=1, mensaje='Token inválido')

    client = get_client(client_id)
    if not cliente_habilitado(client):
        return TokenAuthFailure(codigo=1, mensaje='Token inválido')

    emitter = get_emitter(emitter_id, client_id)
    if not emisor_habilitado(emitter):
        return TokenAuthFailure(codigo=1, mensaje='Token inválido')

    emitter_rnc = _normalize_rnc(emitter.get('rnc'))
    if emitter_rnc != rnc:
        return TokenAuthFailure(codigo=1, mensaje='Token inválido')

    if int(emitter.get('tenant_id') or 0) != tenant_id:
        return TokenAuthFailure(codigo=1, mensaje='Token inválido')

    if not ambiente_coincide(emitter, config.environment):
        return TokenAuthFailure(codigo=1, mensaje='Token inválido')

    return AuthorizedIntegrationContext(
        client_id=client_id,
        emitter_id=emitter_id,
        tenant_id=tenant_id,
        rnc=emitter_rnc,
        environment=config.environment,
    )
