"""El correo de la empresa solo cambia tras abrir el enlace enviado al nuevo buzón."""

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
    'email_pendiente': 'VARCHAR(255) NULL',
    'email_cambio_token': 'VARCHAR(255) NULL',
    'email_cambio_expira': 'DATETIME NULL',
}


def asegurar_columnas_cambio_correo():
    for nombre, definicion in _COLUMNAS.items():
        if execute_query(f"SHOW COLUMNS FROM empresas LIKE '{nombre}'"):
            continue
        execute_update(
            f'ALTER TABLE empresas ADD COLUMN `{nombre}` {definicion}'
        )


def _enlace(token):
    base = url_publica_base().strip()
    ruta = url_for('confirmar_correo_empresa', token=token).lstrip('/')
    if base:
        return urljoin(base.rstrip('/') + '/', ruta)
    if not IS_PRODUCTION:
        return url_for('confirmar_correo_empresa', token=token, _external=True)
    raise RuntimeError('APP_BASE_URL no está configurada')


def _limpiar_pendiente(empresa_id):
    execute_update(
        '''
        UPDATE empresas
        SET email_pendiente=NULL,
            email_cambio_token=NULL,
            email_cambio_expira=NULL
        WHERE id=%s
        ''',
        (empresa_id,),
    )


def solicitar_cambio_correo_empresa(empresa_id, email_actual, email_nuevo, nombre):
    """
    Guarda el correo nuevo como pendiente y envía el enlace.
    Retorna ('igual'|'enviado'|'fallo', detalle).
    """
    asegurar_columnas_cambio_correo()
    actual = (email_actual or '').strip().lower()
    nuevo = (email_nuevo or '').strip().lower()
    if actual == nuevo:
        _limpiar_pendiente(empresa_id)
        return 'igual', ''
    token = secrets.token_urlsafe(32)
    expira = datetime.now() + timedelta(hours=HORAS_VALIDEZ)
    execute_update(
        '''
        UPDATE empresas
        SET email_pendiente=%s,
            email_cambio_token=%s,
            email_cambio_expira=%s
        WHERE id=%s
        ''',
        (nuevo, token, expira, empresa_id),
    )
    try:
        enlace = _enlace(token)
    except Exception as error:
        logger.error('URL de cambio de correo: %s', error)
        _limpiar_pendiente(empresa_id)
        return 'fallo', 'Falta APP_BASE_URL para el enlace de validación.'
    from services.email_content import correo_cambio_email_empresa
    from services.platform_mail import enviar_correo_plataforma

    asunto, texto, html = correo_cambio_email_empresa(
        nombre, enlace, horas_validez=HORAS_VALIDEZ,
    )
    ok, detalle = enviar_correo_plataforma(
        nuevo, asunto, html, texto=texto, reply_to=None,
    )
    if not ok:
        _limpiar_pendiente(empresa_id)
        return 'fallo', detalle or 'No se pudo enviar el correo de validación.'
    if actual:
        from services.email_content import correo_aviso_correo_empresa

        asunto_aviso, texto_aviso, html_aviso = correo_aviso_correo_empresa(
            nombre, nuevo,
        )
        enviar_correo_plataforma(
            actual, asunto_aviso, html_aviso, texto=texto_aviso,
        )
    return 'enviado', nuevo


def confirmar_cambio_correo_empresa(token):
    """Aplica el correo pendiente si el enlace sigue vigente."""
    asegurar_columnas_cambio_correo()
    if not token:
        return False, 'El enlace no es válido.'
    empresa = execute_query(
        '''
        SELECT id, nombre, email_pendiente
        FROM empresas
        WHERE email_cambio_token=%s
          AND email_cambio_expira > %s
          AND email_pendiente IS NOT NULL
          AND email_pendiente <> ''
        ''',
        (token, datetime.now()),
    )
    if not empresa:
        return False, 'El enlace no es válido o ya venció. Solicite el cambio de nuevo.'
    execute_update(
        '''
        UPDATE empresas
        SET email=%s,
            email_pendiente=NULL,
            email_cambio_token=NULL,
            email_cambio_expira=NULL
        WHERE id=%s AND email_cambio_token=%s
        ''',
        (empresa['email_pendiente'], empresa['id'], token),
    )
    return True, (
        f'Correo de {empresa.get("nombre") or "la empresa"} actualizado a '
        f'{empresa["email_pendiente"]}.'
    )
