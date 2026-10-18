"""La contraseña nueva solo entra en vigor tras el enlace enviado desde soporte."""

import logging
import secrets
from datetime import datetime, timedelta
from urllib.parse import urljoin

from flask import url_for

from core.config import IS_PRODUCTION, url_publica_base
from core.database import execute_query, execute_update

logger = logging.getLogger(__name__)

HORAS_VALIDEZ = 48
_COLUMNAS = {
    'password_pendiente_hash': 'VARCHAR(255) NULL',
    'password_cambio_token': 'VARCHAR(255) NULL',
    'password_cambio_expira': 'DATETIME NULL',
    'password_pendiente_temporal': 'TINYINT(1) NULL',
}


def asegurar_columnas_cambio_password():
    for nombre, definicion in _COLUMNAS.items():
        if execute_query(f"SHOW COLUMNS FROM usuarios LIKE '{nombre}'"):
            continue
        execute_update(
            f'ALTER TABLE usuarios ADD COLUMN `{nombre}` {definicion}'
        )


def _enlace(token):
    base = url_publica_base().strip()
    ruta = url_for('confirmar_cambio_password', token=token).lstrip('/')
    if base:
        return urljoin(base.rstrip('/') + '/', ruta)
    if not IS_PRODUCTION:
        return url_for('confirmar_cambio_password', token=token, _external=True)
    raise RuntimeError('APP_BASE_URL no está configurada')


def _limpiar(usuario_id, tenant_id):
    execute_update(
        '''
        UPDATE usuarios
        SET password_pendiente_hash=NULL,
            password_cambio_token=NULL,
            password_cambio_expira=NULL,
            password_pendiente_temporal=NULL
        WHERE id=%s AND tenant_id <=> %s
        ''',
        (usuario_id, tenant_id),
    )


def solicitar_cambio_password(
    usuario_id, tenant_id, email, nombre, password_hash, temporal=True,
):
    """
    Deja la contraseña actual y envía el enlace a ``email`` desde soporte.
    Retorna (ok, detalle).
    """
    asegurar_columnas_cambio_password()
    token = secrets.token_urlsafe(32)
    expira = datetime.now() + timedelta(hours=HORAS_VALIDEZ)
    execute_update(
        '''
        UPDATE usuarios
        SET password_pendiente_hash=%s,
            password_cambio_token=%s,
            password_cambio_expira=%s,
            password_pendiente_temporal=%s
        WHERE id=%s AND tenant_id <=> %s
        ''',
        (password_hash, token, expira, 1 if temporal else 0, usuario_id, tenant_id),
    )
    try:
        enlace = _enlace(token)
    except Exception as error:
        logger.error('URL de cambio de contraseña: %s', error)
        _limpiar(usuario_id, tenant_id)
        return False, 'Falta APP_BASE_URL para el enlace de validación.'
    from services.email_content import correo_cambio_password
    from services.platform_mail import enviar_desde_soporte

    asunto, texto, html = correo_cambio_password(
        nombre, enlace, horas_validez=HORAS_VALIDEZ,
    )
    ok, detalle = enviar_desde_soporte(
        email, asunto, html, texto=texto, nombre_destinatario=nombre or email,
    )
    if not ok:
        _limpiar(usuario_id, tenant_id)
        return False, detalle or 'No se pudo enviar el correo de validación.'
    return True, email


def confirmar_cambio_password(token):
    asegurar_columnas_cambio_password()
    if not token:
        return False, 'El enlace no es válido.'
    usuario = execute_query(
        '''
        SELECT id, tenant_id, nombre, password_pendiente_hash,
               password_pendiente_temporal
        FROM usuarios
        WHERE password_cambio_token=%s
          AND password_cambio_expira > %s
          AND password_pendiente_hash IS NOT NULL
        ''',
        (token, datetime.now()),
    )
    if not usuario:
        return False, 'El enlace no es válido o ya venció. Solicite el cambio de nuevo.'
    temporal = 1 if usuario.get('password_pendiente_temporal') else 0
    execute_update(
        '''
        UPDATE usuarios
        SET password_hash=%s,
            password_temporal=%s,
            password_pendiente_hash=NULL,
            password_cambio_token=NULL,
            password_cambio_expira=NULL,
            password_pendiente_temporal=NULL
        WHERE id=%s AND password_cambio_token=%s
        ''',
        (usuario['password_pendiente_hash'], temporal, usuario['id'], token),
    )
    return True, (
        f'Contraseña de {usuario.get("nombre") or "la cuenta"} actualizada. '
        'Ya puede iniciar sesión con la nueva clave.'
    )
