"""Autenticación compatible con POST /api/Autenticacion (contrato HKA)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

from integrations.external_ecf_service.auth.token_service import issue_token
from integrations.external_ecf_service.security.credentials import (
    verify_integration_password,
)
from integrations.external_ecf_service.security.permissions import (
    ambiente_coincide,
    cliente_habilitado,
    credencial_habilitada,
    emisor_habilitado,
)


@dataclass(frozen=True)
class AuthSuccess:
    codigo: int
    mensaje: str
    token: str
    fecha_expiracion: str
    client_id: int
    emitter_id: int
    tenant_id: int


@dataclass(frozen=True)
class AuthFailure:
    codigo: int
    mensaje: str


def _normalize_rnc(value: str) -> str:
    return re.sub(r'\D', '', str(value or ''))


def _format_expiration(dt: datetime) -> str:
    if dt.tzinfo is None:
        return dt.strftime('%Y-%m-%dT%H:%M:%S')
    return dt.astimezone().replace(tzinfo=None).strftime('%Y-%m-%dT%H:%M:%S')


def authenticate_hka_request(
    *,
    usuario: str,
    clave: str,
    rnc: str,
    config,
    resolve_emitter,
    find_credential,
    get_client,
) -> AuthSuccess | AuthFailure:
    if not config.enabled:
        return AuthFailure(
            codigo=99,
            mensaje='Servicio no disponible',
        )

    usuario = (usuario or '').strip()
    rnc_norm = _normalize_rnc(rnc)
    if not usuario or not clave or not rnc_norm:
        return AuthFailure(codigo=1, mensaje='Credenciales inválidas')

    credential = find_credential(usuario)
    if not credencial_habilitada(credential):
        return AuthFailure(codigo=1, mensaje='Credenciales inválidas')

    if not verify_integration_password(clave, credential.get('password_hash') or ''):
        return AuthFailure(codigo=1, mensaje='Credenciales inválidas')

    client = get_client(credential['client_id'])
    if not cliente_habilitado(client):
        return AuthFailure(codigo=1, mensaje='Credenciales inválidas')

    emitter = resolve_emitter(
        client_id=credential['client_id'],
        emitter_id=credential.get('emitter_id'),
        rnc=rnc_norm,
    )
    if not emisor_habilitado(emitter):
        return AuthFailure(codigo=1, mensaje='Credenciales inválidas')

    emitter_rnc = _normalize_rnc(emitter.get('rnc'))
    if emitter_rnc != rnc_norm:
        return AuthFailure(codigo=1, mensaje='Credenciales inválidas')

    if credential.get('emitter_id') and int(credential['emitter_id']) != int(
        emitter['id']
    ):
        return AuthFailure(codigo=1, mensaje='Credenciales inválidas')

    if not ambiente_coincide(emitter, config.environment):
        return AuthFailure(codigo=1, mensaje='Credenciales inválidas')

    token, expires = issue_token(
        secret=config.jwt_secret,
        ttl_seconds=config.token_ttl_seconds,
        client_id=int(client['id']),
        emitter_id=int(emitter['id']),
        tenant_id=int(emitter['tenant_id']),
        rnc=emitter_rnc,
        environment=config.environment,
    )
    return AuthSuccess(
        codigo=0,
        mensaje='Autenticación exitosa',
        token=token,
        fecha_expiracion=_format_expiration(expires),
        client_id=int(client['id']),
        emitter_id=int(emitter['id']),
        tenant_id=int(emitter['tenant_id']),
    )
