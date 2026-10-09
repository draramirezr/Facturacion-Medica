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

try:
    from sendgrid import SendGridAPIClient
    from sendgrid.helpers.mail import Mail
    SENDGRID_AVAILABLE = True
except ImportError:
    SENDGRID_AVAILABLE = False


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
    """Envía el enlace de activación (SMTP del consultorio o SendGrid)."""
    try:
        enlace = url_activacion_cuenta(token)
    except Exception as error:
        logger.error('No se pudo construir URL de activación: %s', error)
        return False, 'Falta APP_BASE_URL para generar el enlace de activación.'

    asunto = 'Active su cuenta de ClinicRD'
    html = (
        f'<p>Hola {nombre or ""},</p>'
        '<p>Le crearon un usuario en ClinicRD. Para validar su correo '
        'y entrar la primera vez, abra este enlace:</p>'
        f'<p><a href="{enlace}">Activar mi cuenta</a></p>'
        '<p>El enlace vence en 72 horas. Después deberá definir '
        'su contraseña personal.</p>'
        '<p>Si no solicitó esta cuenta, ignore este mensaje.</p>'
    )

    if tenant_id:
        from services.tenant_mail import enviar_correo_consultorio
        ok, detalle = enviar_correo_consultorio(
            tenant_id,
            email,
            asunto,
            html,
            fallback_plataforma=True,
        )
        if ok:
            return True, detalle

    if SENDGRID_AVAILABLE and os.getenv('SENDGRID_API_KEY'):
        try:
            mensaje = Mail(
                from_email=os.getenv(
                    'SENDGRID_FROM_EMAIL',
                    os.getenv('EMAIL_FROM', 'noreply@clinicrd.com'),
                ),
                to_emails=email,
                subject=asunto,
                html_content=html,
            )
            SendGridAPIClient(os.getenv('SENDGRID_API_KEY')).send(mensaje)
            return True, 'Correo enviado'
        except Exception as error:
            logger.error('SendGrid activación falló: %s', error, exc_info=True)
            return False, f'No se pudo enviar el correo: {error}'

    if (
        ENVIRONMENT == 'development'
        and os.getenv('ALLOW_INSECURE_DEV_RESET_TOKEN', '').lower() == 'true'
    ):
        return True, enlace
    return False, (
        'Configure el correo SMTP del consultorio o SendGrid para enviar '
        'la invitación.'
    )
