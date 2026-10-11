"""Correo saliente de ClinicRD (Zoho) cuando el consultorio no tiene SMTP propio."""

import logging
import os
import smtplib
import ssl
from email.message import EmailMessage

from services.tenant_mail import describir_error_smtp

logger = logging.getLogger(__name__)


def _config_zoho():
    """Variables de entorno del buzón Zoho de la plataforma."""
    usuario = (
        os.getenv('ZOHO_SMTP_USER', '').strip()
        or os.getenv('EMAIL_FROM', '').strip()
    )
    return {
        'host': (
            os.getenv('ZOHO_SMTP_HOST', '').strip()
            or os.getenv('PLATFORM_SMTP_HOST', 'smtp.zoho.com').strip()
        ),
        'port': int(os.getenv('ZOHO_SMTP_PORT', os.getenv('PLATFORM_SMTP_PORT', '587'))),
        'usuario': usuario,
        'password': (
            os.getenv('ZOHO_SMTP_PASSWORD', '').strip()
            or os.getenv('PLATFORM_SMTP_PASSWORD', '').strip()
        ),
        'remitente': (
            os.getenv('ZOHO_FROM_EMAIL', '').strip()
            or os.getenv('EMAIL_FROM', '').strip()
            or usuario
        ),
        'nombre_remitente': (
            os.getenv('ZOHO_FROM_NAME', '').strip()
            or os.getenv('PLATFORM_SMTP_FROM_NAME', 'ClinicRD').strip()
        ),
        'usar_tls': os.getenv('ZOHO_SMTP_USE_TLS', '1').strip().lower() not in (
            '0', 'false', 'no',
        ),
    }


def plataforma_correo_configurado():
    cfg = _config_zoho()
    return bool(cfg['host'] and cfg['password'] and cfg['remitente'])


def enviar_correo_plataforma(
    destinatario,
    asunto,
    html,
    adjuntos=None,
    reply_to=None,
):
    """Envía correo desde el buzón Zoho de ClinicRD."""
    if not destinatario:
        return False, 'No hay destinatario'
    cfg = _config_zoho()
    if not cfg['password'] or not cfg['remitente']:
        return False, (
            'Falta configurar el correo Zoho de ClinicRD '
            '(ZOHO_SMTP_PASSWORD y ZOHO_FROM_EMAIL o EMAIL_FROM).'
        )
    host = cfg['host']
    puerto = cfg['port'] or 587
    usuario = cfg['usuario'] or cfg['remitente']
    nombre = cfg['nombre_remitente']
    origen = f'{nombre} <{cfg["remitente"]}>' if nombre else cfg['remitente']
    mensaje = EmailMessage()
    mensaje['Subject'] = asunto
    mensaje['From'] = origen
    mensaje['To'] = destinatario
    if reply_to:
        mensaje['Reply-To'] = reply_to
    mensaje.set_content(
        'Este mensaje está en HTML. Ábrelo en un cliente de correo moderno.'
    )
    mensaje.add_alternative(html, subtype='html')
    for adjunto in adjuntos or []:
        nombre_archivo, contenido, mime = adjunto
        maintype, _, subtype = (mime or 'application/octet-stream').partition('/')
        mensaje.add_attachment(
            contenido,
            maintype=maintype or 'application',
            subtype=subtype or 'octet-stream',
            filename=nombre_archivo,
        )
    try:
        contexto = ssl.create_default_context()
        if puerto == 465:
            with smtplib.SMTP_SSL(
                host, puerto, context=contexto, timeout=25,
            ) as servidor:
                servidor.login(usuario, cfg['password'])
                servidor.send_message(mensaje)
        else:
            with smtplib.SMTP(host, puerto, timeout=25) as servidor:
                if cfg['usar_tls']:
                    servidor.starttls(context=contexto)
                servidor.login(usuario, cfg['password'])
                servidor.send_message(mensaje)
    except Exception as error:
        logger.error('Correo Zoho plataforma falló: %s', error, exc_info=True)
        return False, describir_error_smtp(error)
    return True, 'Correo enviado'
