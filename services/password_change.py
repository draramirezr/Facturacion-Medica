"""La contraseña nueva solo entra en vigor tras el enlace enviado desde soporte."""

import logging
import secrets
from datetime import datetime, timedelta
from urllib.parse import urljoin

from flask import url_for
from werkzeug.security import generate_password_hash

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


def generar_clave_temporal():
    """12 caracteres con mayúscula, minúscula y número."""
    import string

    letras = string.ascii_letters + string.digits
    while True:
        clave = ''.join(secrets.choice(letras) for _ in range(12))
        if (
            any(c.isupper() for c in clave)
            and any(c.islower() for c in clave)
            and any(c.isdigit() for c in clave)
        ):
            return clave


def asignar_clave_temporal(usuario_id, tenant_id, email, nombre, password_plano):
    """
    Deja la clave generada por el administrador como temporal y la envía por correo.
    Al entrar, el sistema obliga a cambiarla. Si el correo falla, queda la anterior.
    """
    asegurar_columnas_cambio_password()
    anterior = execute_query(
        '''
        SELECT password_hash, password_temporal
        FROM usuarios
        WHERE id=%s AND tenant_id <=> %s
        ''',
        (usuario_id, tenant_id),
    )
    if not anterior:
        return False, 'Usuario no encontrado'
    execute_update(
        '''
        UPDATE usuarios
        SET password_hash=%s,
            password_temporal=1,
            password_pendiente_hash=NULL,
            password_cambio_token=NULL,
            password_cambio_expira=NULL,
            password_pendiente_temporal=NULL
        WHERE id=%s AND tenant_id <=> %s
        ''',
        (generate_password_hash(password_plano), usuario_id, tenant_id),
    )
    from services.email_content import correo_clave_temporal
    from services.platform_mail import enviar_desde_soporte

    asunto, texto, html = correo_clave_temporal(nombre, password_plano)
    ok, detalle = enviar_desde_soporte(
        email, asunto, html, texto=texto, nombre_destinatario=nombre or email,
    )
    if ok:
        return True, email
    execute_update(
        '''
        UPDATE usuarios
        SET password_hash=%s, password_temporal=%s
        WHERE id=%s AND tenant_id <=> %s
        ''',
        (
            anterior.get('password_hash'),
            1 if anterior.get('password_temporal') else 0,
            usuario_id,
            tenant_id,
        ),
    )
    return False, detalle or 'No se pudo enviar la contraseña temporal.'


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
        nombre,
        enlace,
        horas_validez=HORAS_VALIDEZ,
        bloquea_actual=temporal,
    )
    ok, detalle = enviar_desde_soporte(
        email, asunto, html, texto=texto, nombre_destinatario=nombre or email,
    )
    if not ok:
        _limpiar(usuario_id, tenant_id)
        return False, detalle or 'No se pudo enviar el correo de validación.'
    if temporal:
        execute_update(
            '''
            UPDATE usuarios
            SET password_hash=%s
            WHERE id=%s AND tenant_id <=> %s
            ''',
            (
                generate_password_hash(secrets.token_urlsafe(32)),
                usuario_id,
                tenant_id,
            ),
        )
    return True, email


def cambio_admin_vigente(usuario):
    """True si un administrador dejó una clave nueva y la anterior ya no sirve."""
    if not usuario or not usuario.get('password_pendiente_temporal'):
        return False
    if not usuario.get('password_cambio_token') or not usuario.get('password_pendiente_hash'):
        return False
    expira = usuario.get('password_cambio_expira')
    if isinstance(expira, str):
        try:
            expira = datetime.strptime(expira[:19], '%Y-%m-%d %H:%M:%S')
        except ValueError:
            return False
    return bool(expira and expira > datetime.now())


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
