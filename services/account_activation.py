"""Activación de cuenta por correo (primer acceso)."""

import logging
import os
import secrets
from datetime import datetime, timedelta
from urllib.parse import urljoin

from flask import url_for

from core.config import ENVIRONMENT, url_publica_base
from core.database import execute_query, execute_update

logger = logging.getLogger(__name__)


def asegurar_columnas_activacion_usuario():
    if not execute_query("SHOW COLUMNS FROM usuarios LIKE 'email_verificado'"):
        execute_update(
            'ALTER TABLE usuarios '
            'ADD COLUMN email_verificado TINYINT(1) NOT NULL DEFAULT 1'
        )
    if not execute_query("SHOW COLUMNS FROM usuarios LIKE 'activacion_token'"):
        execute_update(
            'ALTER TABLE usuarios ADD COLUMN activacion_token VARCHAR(255) NULL'
        )
    if not execute_query(
        "SHOW COLUMNS FROM usuarios LIKE 'activacion_token_expiracion'"
    ):
        execute_update(
            'ALTER TABLE usuarios '
            'ADD COLUMN activacion_token_expiracion DATETIME NULL'
        )


def url_activacion_cuenta(token):
    base = url_publica_base().strip()
    if base:
        return urljoin(
            base.rstrip('/') + '/',
            url_for('activar_cuenta', token=token).lstrip('/'),
        )
    from core.config import IS_PRODUCTION
    if not IS_PRODUCTION:
        return url_for('activar_cuenta', token=token, _external=True)
    raise RuntimeError('APP_BASE_URL no está configurada')


def registrar_activacion_pendiente(usuario_id, tenant_id, horas_validez=72):
    asegurar_columnas_activacion_usuario()
    token = secrets.token_urlsafe(32)
    expira = datetime.now() + timedelta(hours=horas_validez)
    execute_update(
        '''
        UPDATE usuarios
        SET email_verificado=0,
            activacion_token=%s,
            activacion_token_expiracion=%s
        WHERE id=%s AND tenant_id <=> %s
        ''',
        (token, expira, usuario_id, tenant_id),
    )
    return token


def enviar_invitacion_activacion(tenant_id, nombre, email, token):
    """Envía el enlace de activación (SMTP del consultorio o Zoho plataforma)."""
    try:
        enlace = url_activacion_cuenta(token)
    except Exception as error:
        logger.error('No se pudo construir URL de activación: %s', error)
        return False, 'Falta APP_BASE_URL para generar el enlace de activación.'

    from services.email_content import correo_invitacion_usuario

    asunto, texto, html = correo_invitacion_usuario(nombre, enlace)

    if tenant_id:
        from services.tenant_mail import enviar_correo_consultorio

        ok, detalle = enviar_correo_consultorio(
            tenant_id,
            email,
            asunto,
            html,
            fallback_plataforma=True,
        )
    else:
        from services.platform_mail import enviar_correo_plataforma

        ok, detalle = enviar_correo_plataforma(
            email, asunto, html, texto=texto,
        )
    if ok:
        return True, detalle

    if (
        ENVIRONMENT == 'development'
        and os.getenv('ALLOW_INSECURE_DEV_RESET_TOKEN', '').lower() == 'true'
    ):
        return True, enlace
    return False, detalle or (
        'Configure el correo SMTP del consultorio o Zoho (ZOHO_SMTP_*) '
        'para enviar la invitación.'
    )


def enviar_correo_activacion_demo(nombre, email, token, horas_validez=72):
    """Demo público: siempre desde el buzón Zoho de ClinicRD (noreply@clinicrd.com)."""
    from services.platform_mail import enviar_correo_plataforma

    try:
        enlace = url_activacion_cuenta(token)
    except Exception as error:
        logger.error('No se pudo construir URL de activación demo: %s', error)
        return False, 'Falta APP_BASE_URL para generar el enlace de activación.'

    from services.email_content import correo_activacion_demo

    asunto, texto, html = correo_activacion_demo(
        nombre, enlace, horas_validez=horas_validez,
    )
    ok, detalle = enviar_correo_plataforma(
        email, asunto, html, texto=texto,
    )
    if ok:
        return True, detalle
    if (
        ENVIRONMENT == 'development'
        and os.getenv('ALLOW_INSECURE_DEV_RESET_TOKEN', '').lower() == 'true'
    ):
        return True, enlace
    return False, detalle or (
        'No se pudo enviar el correo de activación. '
        'Revise la configuración Zoho (ZOHO_SMTP_*).'
    )
