"""Correo saliente del consultorio (SMTP propio) con respaldo de plataforma."""

import logging
import os
import smtplib
import ssl
from email.message import EmailMessage

from flask import current_app

from core.database import execute_query, execute_update

logger = logging.getLogger(__name__)

COLUMNAS_SMTP = {
    'smtp_host': 'VARCHAR(255) NULL',
    'smtp_port': 'INT NULL',
    'smtp_usuario': 'VARCHAR(255) NULL',
    'smtp_password_cifrado': 'TEXT NULL',
    'smtp_remitente': 'VARCHAR(255) NULL',
    'smtp_nombre_remitente': 'VARCHAR(150) NULL',
    'smtp_usar_tls': 'TINYINT(1) NOT NULL DEFAULT 1',
}


def _fernet():
    from cryptography.fernet import Fernet
    import base64
    import hashlib

    secreto = str(current_app.secret_key).encode('utf-8')
    clave = base64.urlsafe_b64encode(hashlib.sha256(secreto).digest())
    return Fernet(clave)


def cifrar_smtp_password(texto):
    if not texto:
        return None
    return _fernet().encrypt(texto.encode('utf-8')).decode('ascii')


def descifrar_smtp_password(token):
    if not token:
        return None
    from cryptography.fernet import InvalidToken

    try:
        return _fernet().decrypt(token.encode('ascii')).decode('utf-8')
    except (InvalidToken, ValueError, TypeError):
        return None


def asegurar_esquema_correo():
    for nombre, definicion in COLUMNAS_SMTP.items():
        existe = execute_query(
            f"SHOW COLUMNS FROM empresas LIKE '{nombre}'"
        )
        if existe:
            continue
        execute_update(
            f'ALTER TABLE empresas ADD COLUMN `{nombre}` {definicion}'
        )


def resumen_correo_empresa(empresa):
    empresa = empresa or {}
    return {
        'configurado': bool(empresa.get('smtp_host') and empresa.get('smtp_remitente')),
        'smtp_host': empresa.get('smtp_host') or '',
        'smtp_port': empresa.get('smtp_port') or 587,
        'smtp_usuario': empresa.get('smtp_usuario') or '',
        'smtp_remitente': empresa.get('smtp_remitente') or empresa.get('email') or '',
        'smtp_nombre_remitente': empresa.get('smtp_nombre_remitente') or empresa.get('nombre') or '',
        'smtp_usar_tls': int(empresa.get('smtp_usar_tls') if empresa.get('smtp_usar_tls') is not None else 1),
        'tiene_password': bool(empresa.get('smtp_password_cifrado')),
    }


def guardar_correo_empresa(tenant_id, datos, password_nueva=None):
    asegurar_esquema_correo()
    password_sql = ''
    params = [
        datos.get('smtp_host') or None,
        datos.get('smtp_port') or 587,
        datos.get('smtp_usuario') or None,
        datos.get('smtp_remitente') or None,
        datos.get('smtp_nombre_remitente') or None,
        1 if datos.get('smtp_usar_tls') else 0,
    ]
    if password_nueva:
        password_sql = ', smtp_password_cifrado=%s'
        params.append(cifrar_smtp_password(password_nueva))
    params.append(tenant_id)
    execute_update(
        f'''
        UPDATE empresas SET
            smtp_host=%s, smtp_port=%s, smtp_usuario=%s,
            smtp_remitente=%s, smtp_nombre_remitente=%s, smtp_usar_tls=%s
            {password_sql}
        WHERE id=%s
        ''',
        tuple(params),
    )


def _enviar_smtp(empresa, destinatario, asunto, html, adjuntos=None):
    host = (empresa.get('smtp_host') or '').strip()
    remitente = (empresa.get('smtp_remitente') or '').strip()
    if not host or not remitente:
        return False, 'Falta el servidor o el correo remitente'
    password = descifrar_smtp_password(empresa.get('smtp_password_cifrado'))
    puerto = int(empresa.get('smtp_port') or 587)
    usuario = (empresa.get('smtp_usuario') or remitente).strip()
    nombre = (empresa.get('smtp_nombre_remitente') or '').strip()
    origen = f'{nombre} <{remitente}>' if nombre else remitente
    mensaje = EmailMessage()
    mensaje['Subject'] = asunto
    mensaje['From'] = origen
    mensaje['To'] = destinatario
    mensaje.set_content('Este mensaje está en HTML. Ábrelo en un cliente de correo moderno.')
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
    contexto = ssl.create_default_context()
    if puerto == 465:
        with smtplib.SMTP_SSL(host, puerto, context=contexto, timeout=20) as servidor:
            if password:
                servidor.login(usuario, password)
            servidor.send_message(mensaje)
    else:
        with smtplib.SMTP(host, puerto, timeout=20) as servidor:
            if empresa.get('smtp_usar_tls', 1):
                servidor.starttls(context=contexto)
            if password:
                servidor.login(usuario, password)
            servidor.send_message(mensaje)
    return True, 'Correo enviado'


def _enviar_sendgrid(destinatario, asunto, html, adjuntos=None, remitente=None):
    api_key = os.getenv('SENDGRID_API_KEY', '').strip()
    if not api_key:
        return False, 'No hay SMTP del consultorio ni SendGrid de la plataforma'
    try:
        from sendgrid import SendGridAPIClient
        from sendgrid.helpers.mail import (
            Attachment, Disposition, FileContent, FileName, FileType, Mail,
        )
        import base64
    except ImportError:
        return False, 'SendGrid no está instalado'
    origen = remitente or os.getenv('SENDGRID_FROM_EMAIL', 'noreply@clinicrd.com')
    mensaje = Mail(
        from_email=origen,
        to_emails=destinatario,
        subject=asunto,
        html_content=html,
    )
    for adjunto in adjuntos or []:
        nombre_archivo, contenido, mime = adjunto
        archivo = Attachment(
            FileContent(base64.b64encode(contenido).decode()),
            FileName(nombre_archivo),
            FileType(mime or 'application/octet-stream'),
            Disposition('attachment'),
        )
        mensaje.add_attachment(archivo)
    SendGridAPIClient(api_key).send(mensaje)
    return True, 'Correo enviado'


def enviar_correo_consultorio(
    tenant_id,
    destinatario,
    asunto,
    html,
    adjuntos=None,
    fallback_plataforma=True,
):
    """Enviar desde el SMTP de la empresa; si falta, usa el correo de ClinicRD."""
    if not destinatario:
        return False, 'No hay destinatario'
    empresa = None
    if tenant_id:
        asegurar_esquema_correo()
        empresa = execute_query(
            'SELECT * FROM empresas WHERE id=%s',
            (tenant_id,),
        )
    if empresa and empresa.get('smtp_host') and empresa.get('smtp_remitente'):
        try:
            return _enviar_smtp(empresa, destinatario, asunto, html, adjuntos)
        except Exception as error:
            logger.error('SMTP del consultorio falló: %s', error)
            if not fallback_plataforma:
                return False, 'No se pudo enviar con el correo del consultorio'
    if fallback_plataforma:
        remitente = None
        if empresa:
            remitente = empresa.get('smtp_remitente') or None
        try:
            return _enviar_sendgrid(
                destinatario, asunto, html, adjuntos, remitente=remitente
            )
        except Exception as error:
            logger.error('SendGrid falló: %s', error)
            return False, 'No se pudo enviar el correo'
    return False, 'Configure el correo del consultorio en Configuración'


def notificar_paciente(tenant_id, paciente_id, asunto, html):
    paciente = execute_query(
        'SELECT email, nombre FROM pacientes WHERE id=%s AND tenant_id=%s',
        (paciente_id, tenant_id),
    )
    correo = (paciente or {}).get('email') or ''
    if '@' not in correo:
        return False, 'El paciente no tiene correo'
    return enviar_correo_consultorio(tenant_id, correo.strip(), asunto, html)
