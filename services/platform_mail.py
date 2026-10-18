"""Correo saliente de ClinicRD (Zoho) cuando el consultorio no tiene SMTP propio."""

import base64
import logging
import os
import smtplib
import ssl
from email.message import EmailMessage

import requests

from core.presentation import SOPORTE_EMAIL_PREDETERMINADO
from services.tenant_mail import describir_error_smtp

logger = logging.getLogger(__name__)


def _reply_to_plataforma(explicito):
    if explicito:
        return explicito
    return (
        os.getenv('SOPORTE_EMAIL', '').strip()
        or SOPORTE_EMAIL_PREDETERMINADO
    )

ZEPTOMAIL_API_DEFAULT = 'https://cpaas.zoho.com/v1.1/email'
ZEPTOMAIL_SMTP_HOST = 'smtp.zeptomail.com'
ZEPTOMAIL_SMTP_USER = 'emailapikey'


def _parse_port(default=587):
    raw = os.getenv('ZOHO_SMTP_PORT', os.getenv('PLATFORM_SMTP_PORT', str(default)))
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def _zeptomail_token():
    raw = (
        os.getenv('ZEPTOMAIL_API_KEY', '').strip()
        or os.getenv('ZOHO_ZEPTOMAIL_API_KEY', '').strip()
    )
    prefijo = 'Zoho-enczapikey '
    if raw.lower().startswith(prefijo.lower()):
        raw = raw[len(prefijo):].strip()
    return raw


def _zeptomail_api_url():
    return (
        os.getenv('ZEPTOMAIL_API_URL', '').strip()
        or ZEPTOMAIL_API_DEFAULT
    )


def _config_zoho():
    """Variables de entorno del buzón Zoho / ZeptoMail de la plataforma."""
    token = _zeptomail_token()
    host_env = (
        os.getenv('ZOHO_SMTP_HOST', '').strip()
        or os.getenv('PLATFORM_SMTP_HOST', '').strip()
    )
    if not host_env and token:
        host_env = ZEPTOMAIL_SMTP_HOST
    if not host_env:
        host_env = 'smtp.zoho.com'
    password = (
        os.getenv('ZOHO_SMTP_PASSWORD', '').strip()
        or os.getenv('PLATFORM_SMTP_PASSWORD', '').strip()
    )
    if not password and token:
        password = token
    usuario = os.getenv('ZOHO_SMTP_USER', '').strip()
    if not usuario and token and host_env == ZEPTOMAIL_SMTP_HOST:
        usuario = ZEPTOMAIL_SMTP_USER
    if not usuario:
        usuario = os.getenv('EMAIL_FROM', '').strip()
    remitente = (
        os.getenv('ZOHO_FROM_EMAIL', '').strip()
        or os.getenv('EMAIL_FROM', '').strip()
        or usuario
    )
    puerto_default = 465 if host_env == ZEPTOMAIL_SMTP_HOST else 587
    return {
        'host': host_env,
        'port': _parse_port(puerto_default),
        'usuario': usuario,
        'password': password,
        'remitente': remitente,
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
    if not cfg['remitente']:
        return False
    return bool(cfg['password'])


def _mensaje_smtp(mensaje, cfg, destinatario, reply_to):
    nombre = cfg['nombre_remitente']
    origen = f'{nombre} <{cfg["remitente"]}>' if nombre else cfg['remitente']
    mensaje['Subject'] = mensaje.get('Subject') or ''
    mensaje['From'] = origen
    mensaje['To'] = destinatario
    if reply_to:
        mensaje['Reply-To'] = reply_to


def _build_email_message(
    destinatario, asunto, html, cfg, adjuntos=None, reply_to=None, texto=None,
):
    mensaje = EmailMessage()
    mensaje['Subject'] = asunto
    reply = _reply_to_plataforma(reply_to)
    _mensaje_smtp(mensaje, cfg, destinatario, reply)
    mensaje.set_content(
        texto or 'Este mensaje está en HTML. Ábrelo en un cliente de correo moderno.',
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
    return mensaje


def _smtp_attempts(host, puerto):
    """Puertos/host alternativos (Railway suele bloquear 587)."""
    intentos = []
    vistos = set()

    def add(h, p, ssl_directo):
        clave = (h, p, ssl_directo)
        if clave in vistos:
            return
        vistos.add(clave)
        intentos.append(clave)

    add(host, puerto, puerto == 465)
    if puerto == 587:
        add(host, 465, True)
    if host == 'smtp.zoho.com':
        add('smtppro.zoho.com', 465, True)
        add('smtppro.zoho.com', 587, False)
    if host == ZEPTOMAIL_SMTP_HOST and puerto == 587:
        add(ZEPTOMAIL_SMTP_HOST, 465, True)
    return intentos


def _enviar_smtp(mensaje, cfg, host, puerto, ssl_directo):
    usuario = cfg['usuario'] or cfg['remitente']
    password = cfg['password']
    contexto = ssl.create_default_context()
    timeout = 35
    if ssl_directo or puerto == 465:
        with smtplib.SMTP_SSL(
            host, puerto, context=contexto, timeout=timeout,
        ) as servidor:
            servidor.login(usuario, password)
            servidor.send_message(mensaje)
        return
    with smtplib.SMTP(host, puerto, timeout=timeout) as servidor:
        if cfg['usar_tls']:
            servidor.starttls(context=contexto)
        servidor.login(usuario, password)
        servidor.send_message(mensaje)


def _enviar_zeptomail(
    destinatario, asunto, html, cfg, adjuntos=None, reply_to=None, texto=None,
):
    token = _zeptomail_token()
    if not token:
        return False, 'ZeptoMail no configurado'
    reply = _reply_to_plataforma(reply_to)
    payload = {
        'from': {
            'address': cfg['remitente'],
            'name': cfg['nombre_remitente'] or 'ClinicRD',
        },
        'to': [
            {'email_address': {'address': destinatario, 'name': destinatario}},
        ],
        'subject': asunto,
        'htmlbody': html,
        'track_clicks': False,
        'track_opens': False,
    }
    if texto:
        payload['textbody'] = texto
    if reply:
        payload['reply_to'] = [{'address': reply, 'name': 'Soporte ClinicRD'}]
    if adjuntos:
        payload['attachments'] = [
            {
                'name': nombre,
                'content': base64.b64encode(contenido).decode('ascii'),
                'mime_type': mime or 'application/octet-stream',
            }
            for nombre, contenido, mime in adjuntos
        ]
    try:
        respuesta = requests.post(
            _zeptomail_api_url(),
            headers={
                'Authorization': f'Zoho-enczapikey {token}',
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },
            json=payload,
            timeout=30,
        )
    except requests.RequestException as error:
        logger.error('ZeptoMail HTTP falló: %s', error, exc_info=True)
        return False, f'No se pudo contactar ZeptoMail: {error}'
    if respuesta.status_code not in (200, 201, 202):
        logger.error(
            'ZeptoMail rechazó el envío: %s %s',
            respuesta.status_code,
            respuesta.text[:500],
        )
        return False, (
            'ZeptoMail no aceptó el correo. Verifique dominio y remitente '
            f'noreply@clinicrd.com ({respuesta.status_code}).'
        )
    return True, 'Correo enviado'


def _preferir_api():
    modo = os.getenv('PLATFORM_MAIL_MODE', '').strip().lower()
    if modo == 'api':
        return True
    if modo == 'smtp':
        return False
    # En Railway / nube: API evita bloqueo SMTP saliente.
    if _zeptomail_token() and (
        os.getenv('RAILWAY_ENVIRONMENT')
        or os.getenv('RAILWAY_PROJECT_ID')
        or os.getenv('FLASK_ENV', '').lower() == 'production'
    ):
        return True
    return bool(_zeptomail_token()) and not os.getenv('ZOHO_SMTP_PASSWORD')


def enviar_correo_plataforma(
    destinatario,
    asunto,
    html,
    adjuntos=None,
    reply_to=None,
    texto=None,
):
    """Envía correo desde ClinicRD (ZeptoMail API o SMTP Zoho)."""
    if not destinatario:
        return False, 'No hay destinatario'
    cfg = _config_zoho()
    if not cfg['remitente']:
        return False, (
            'Falta ZOHO_FROM_EMAIL (p. ej. noreply@clinicrd.com).'
        )

    token = _zeptomail_token()
    if token and (_preferir_api() or not cfg['password']):
        ok, detalle = _enviar_zeptomail(
            destinatario, asunto, html, cfg,
            adjuntos=adjuntos, reply_to=reply_to, texto=texto,
        )
        if ok:
            return True, detalle
        if not cfg['password']:
            return False, detalle

    if not cfg['password']:
        return False, (
            'En Railway configure ZEPTOMAIL_API_KEY (recomendado) o '
            'ZOHO_SMTP_PASSWORD. El SMTP directo suele quedar bloqueado.'
        )

    mensaje = _build_email_message(
        destinatario, asunto, html, cfg,
        adjuntos=adjuntos, reply_to=reply_to, texto=texto,
    )
    ultimo_error = None
    for host, puerto, ssl_directo in _smtp_attempts(cfg['host'], cfg['port']):
        try:
            _enviar_smtp(mensaje, cfg, host, puerto, ssl_directo)
            return True, 'Correo enviado'
        except Exception as error:
            ultimo_error = error
            logger.warning(
                'SMTP plataforma falló %s:%s ssl=%s: %s',
                host, puerto, ssl_directo, error,
            )

    if token:
        ok, detalle = _enviar_zeptomail(
            destinatario, asunto, html, cfg,
            adjuntos=adjuntos, reply_to=reply_to, texto=texto,
        )
        if ok:
            return True, detalle

    detalle = describir_error_smtp(ultimo_error) if ultimo_error else 'Error SMTP'
    if 'espera' in detalle.lower() or 'bloqueada' in detalle.lower():
        detalle += (
            ' En Railway use ZeptoMail (Zoho): variable ZEPTOMAIL_API_KEY '
            'desde https://www.zoho.com/zeptomail/'
        )
    return False, detalle
