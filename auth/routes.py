"""Rutas públicas de autenticación y recuperación de cuenta."""

import logging
import os
import secrets
import time
from datetime import date, datetime, timedelta
from urllib.parse import urljoin, urlparse

from flask import (
    flash, redirect, render_template, request, session, url_for,
)
from flask_login import current_user, login_required, login_user, logout_user
from auth.helpers import destino_inicio_sesion
from werkzeug.security import check_password_hash, generate_password_hash

from auth.models import User
from core.config import ENVIRONMENT, IS_PRODUCTION, url_publica_base
from core.database import database_transaction, execute_query, execute_update
from core.security import rate_limit, rate_limit_lock, request_counts
from routes.support import (
    sanitize_input, validar_password_segura, validate_digits, validate_email,
)
from services.catalogos_ars import sembrar_ars_tenant
from services.platform import asegurar_tablas_plataforma
from services.subscriptions import (
    check_license_available, verificar_suscripciones_vencidas,
)

logger = logging.getLogger(__name__)

try:
    from sendgrid import SendGridAPIClient
    from sendgrid.helpers.mail import Mail
    SENDGRID_AVAILABLE = True
except ImportError:
    SENDGRID_AVAILABLE = False


def _redirigir_login():
    siguiente = request.values.get('volver') or request.values.get('next') or ''
    if siguiente:
        return redirect(url_for('login', next=siguiente))
    return redirect(url_for('login'))


def login():
    if current_user.is_authenticated:
        return redirect(url_retorno_segura())
    if request.method == 'POST':
        verificar_suscripciones_vencidas()
        client_ip = request.remote_addr
        current_time = time.time()
        key = f'{client_ip}_login'
        with rate_limit_lock:
            request_counts[key] = [
                attempt for attempt in request_counts.get(key, [])
                if current_time - attempt < 300
            ]
            if len(request_counts[key]) >= 5:
                flash('Demasiados intentos. Espera 5 minutos.', 'error')
                return _redirigir_login()
            request_counts[key].append(current_time)

        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        if not email or not password:
            flash('Por favor ingresa email y contraseña', 'error')
            return _redirigir_login()
        user_data = execute_query(
            """
            SELECT u.*, e.nombre AS empresa_nombre,
                   e.estado AS empresa_estado, e.fecha_fin AS empresa_fecha_fin,
                   e.es_demo AS empresa_es_demo
            FROM usuarios u
            LEFT JOIN empresas e ON u.tenant_id=e.id
            WHERE u.email=%s
            """,
            (email,),
        )
        if user_data and user_data['activo']:
            es_dueno = user_data.get('tenant_id') is None
            estado = user_data.get('empresa_estado')
            if not es_dueno and estado != 'activo':
                message = (
                    'Tu demo de 7 días terminó. Si cerraron el acuerdo, '
                    'ClinicRD puede darte de alta.'
                    if user_data.get('empresa_es_demo')
                    else (
                        'Suscripción vencida o suspendida. Contacta al administrador '
                        'del sistema.'
                        if estado == 'suspendido'
                        else 'La empresa asociada a este usuario está inactiva'
                    )
                )
                flash(message, 'error')
                return _redirigir_login()
            fecha_fin = user_data.get('empresa_fecha_fin')
            if isinstance(fecha_fin, str):
                fecha_fin = datetime.strptime(fecha_fin, '%Y-%m-%d').date()
            if not es_dueno and fecha_fin and fecha_fin < date.today():
                es_demo = bool(user_data.get('empresa_es_demo'))
                execute_update(
                    "UPDATE empresas SET estado=%s "
                    "WHERE id=%s AND estado='activo'",
                    (
                        'inactivo' if es_demo else 'suspendido',
                        user_data.get('tenant_id'),
                    ),
                )
                flash(
                    'Tu demo de 7 días terminó. Si cerraron el acuerdo, '
                    'ClinicRD puede darte de alta.'
                    if es_demo else
                    'La suscripción de tu empresa ha vencido. '
                    'Contacta al administrador.',
                    'error',
                )
                return _redirigir_login()
            if check_password_hash(user_data['password_hash'], password):
                if user_data['password_temporal']:
                    session['cambio_password_usuario_id'] = user_data['id']
                    session['cambio_password_email'] = user_data['email']
                    session['cambio_password_tenant_id'] = user_data.get('tenant_id')
                    flash('Debes cambiar tu contraseña temporal', 'warning')
                    return redirect(url_for('cambiar_password_obligatorio'))
                user = _build_user(user_data)
                session.permanent = True
                session['tenant_id'] = user.tenant_id
                session['empresa_nombre'] = user.empresa_nombre
                login_user(user, remember=True)
                execute_update(
                    'UPDATE usuarios SET last_login=%s '
                    'WHERE id=%s AND tenant_id <=> %s',
                    (datetime.now(), user.id, user.tenant_id),
                )
                return redirect(url_retorno_segura(destino_inicio_sesion(user)))
            flash('Contraseña incorrecta', 'error')
        else:
            flash('Usuario no encontrado o inactivo', 'error')
        return _redirigir_login()
    allow_prefill = (
        ENVIRONMENT == 'development'
        and os.getenv('ALLOW_DEV_LOGIN_PREFILL', '').lower() == 'true'
    )
    return render_template(
        'login.html',
        dev_login_email=(
            os.getenv('DEV_LOGIN_EMAIL', '').strip() if allow_prefill else ''
        ),
        dev_login_password=(
            os.getenv('DEV_LOGIN_PASSWORD', '') if allow_prefill else ''
        ),
        development_prefill_enabled=allow_prefill,
    )


def _build_user(data):
    return User(
        id=data['id'],
        nombre=data['nombre'],
        email=data['email'],
        perfil=data['perfil'],
        tema_color=data.get('tema_color', 'cyan'),
        fuente_ui=data.get('fuente_ui', 'arsflow'),
        tenant_id=data.get('tenant_id', 1),
        empresa_nombre=data.get('empresa_nombre', ''),
        mostrar_chat=data.get('mostrar_chat', 1),
        idioma_correccion=data.get('idioma_correccion', 'es'),
    )


@rate_limit(max_requests=5, window=300)
def registro():
    if current_user.is_authenticated:
        return redirect(url_for(destino_inicio_sesion(current_user)))
    if request.method == 'GET':
        return render_template('registro.html')
    nombre_empresa = sanitize_input(request.form.get('nombre_empresa', ''), 255)
    tipo_empresa = request.form.get('tipo_empresa', '').strip()
    nombre = sanitize_input(request.form.get('nombre', ''), 255)
    email = request.form.get('email', '').strip().lower()
    telefono = sanitize_input(request.form.get('telefono', ''), 20)
    password = request.form.get('password', '')
    confirmation = request.form.get('password_confirm', '')
    if not all((nombre_empresa, nombre, email, telefono, password)):
        flash('Completa todos los campos obligatorios', 'error')
        return render_template('registro.html')
    if tipo_empresa not in ('medico', 'centro_salud'):
        flash('Selecciona un tipo de empresa válido', 'error')
        return render_template('registro.html')
    if not validate_email(email):
        flash('Ingresa un correo electrónico válido', 'error')
        return render_template('registro.html')
    if not validate_digits(telefono, 10):
        flash('El teléfono debe contener exactamente 10 números', 'error')
        return render_template('registro.html')
    if password != confirmation:
        flash('Las contraseñas no coinciden', 'error')
        return render_template('registro.html')
    password_errors = validar_password_segura(password)
    if password_errors:
        flash(f'Contraseña no válida: {", ".join(password_errors)}', 'error')
        return render_template('registro.html')
    if execute_query('SELECT id FROM usuarios WHERE email=%s', (email,)):
        flash(
            'Ya existe una cuenta con ese correo. Inicia sesión o recupera '
            'tu contraseña.',
            'error',
        )
        return render_template('registro.html')
    if execute_query('SELECT id FROM empresas WHERE nombre=%s', (nombre_empresa,)):
        flash(
            'Ya existe una empresa con ese nombre. Usa otro nombre o inicia sesión.',
            'error',
        )
        return render_template('registro.html')
    fecha_inicio = date.today()
    fecha_fin = fecha_inicio + timedelta(days=7)
    asegurar_tablas_plataforma()
    _asegurar_columnas_activacion()
    try:
        with database_transaction():
            empresa_id = execute_update(
                """
                INSERT INTO empresas (
                    nombre, razon_social, telefono, email, fecha_inicio, fecha_fin,
                    licencias_totales, licencias_usadas, plan, estado, tipo_empresa,
                    es_demo
                ) VALUES (%s,%s,%s,%s,%s,%s,5,1,'basico','activo',%s,1)
                """,
                (
                    nombre_empresa, nombre_empresa, telefono, email,
                    fecha_inicio, fecha_fin, tipo_empresa,
                ),
            )
            if not empresa_id:
                raise RuntimeError('No se pudo crear la empresa')
            user_id = execute_update(
                """
                INSERT INTO usuarios (
                    tenant_id, nombre, email, password_hash, perfil,
                    activo, password_temporal, email_verificado
                ) VALUES (%s,%s,%s,%s,'Administrador',1,0,1)
                """,
                (empresa_id, nombre, email, generate_password_hash(password)),
            )
            if not user_id:
                raise RuntimeError('No se pudo crear el usuario administrador')
            sembrar_ars_tenant(empresa_id)
        flash('Demo de 7 días activado. Ya puedes iniciar sesión.', 'success')
        return redirect(url_for('login'))
    except Exception as error:
        logger.error('Error en registro público: %s', error, exc_info=True)
        flash('Ocurrió un error al crear la cuenta. Intenta de nuevo.', 'error')
        return render_template('registro.html')


RUTAS_RETORNO_PROHIBIDAS = frozenset({
    '/',
    '/login',
    '/logout',
    '/registro',
    '/solicitar-recuperacion',
    '/cambiar-password-obligatorio',
    '/mi-cuenta/cambiar-password',
})


@login_required
def logout():
    logout_user()
    flash('Sesión cerrada correctamente', 'success')
    return redirect(url_for('index'))


def url_retorno_segura(destino_alterno=None):
    """Devolver la página previa solo si pertenece a esta aplicación."""
    if destino_alterno is None:
        destino_alterno = destino_inicio_sesion(
            current_user if current_user.is_authenticated else None
        )
    candidato = (
        request.values.get('volver')
        or request.values.get('next')
        or request.referrer
        or ''
    )
    partes = urlparse(candidato)
    if partes.scheme and partes.scheme not in ('http', 'https'):
        return url_for(destino_alterno)
    if partes.netloc and partes.netloc != request.host:
        return url_for(destino_alterno)
    ruta = partes.path or ''
    if not ruta.startswith('/') or ruta.startswith('//'):
        return url_for(destino_alterno)
    if (
        ruta in RUTAS_RETORNO_PROHIBIDAS
        or ruta.startswith('/recuperar-password')
        or ruta == request.path
    ):
        return url_for(destino_alterno)
    return f'{ruta}?{partes.query}' if partes.query else ruta


@login_required
def cambiar_mi_password():
    """Permitir que el usuario autenticado cambie únicamente su contraseña."""
    volver_url = url_retorno_segura()
    if request.method == 'GET':
        return render_template(
            'cambiar_mi_password.html',
            volver_url=volver_url,
        )

    password_actual = request.form.get('password_actual', '')
    password_nuevo = request.form.get('password_nuevo', '')
    password_confirm = request.form.get('password_confirm', '')
    usuario = execute_query(
        'SELECT id, password_hash FROM usuarios '
        'WHERE id=%s AND tenant_id <=> %s AND activo=1',
        (current_user.id, current_user.tenant_id),
    )
    if not usuario or not check_password_hash(
        usuario['password_hash'],
        password_actual,
    ):
        flash('La contraseña actual no es correcta', 'error')
        return redirect(url_for('cambiar_mi_password', volver=volver_url))
    if password_nuevo != password_confirm:
        flash('Las contraseñas nuevas no coinciden', 'error')
        return redirect(url_for('cambiar_mi_password', volver=volver_url))
    if check_password_hash(usuario['password_hash'], password_nuevo):
        flash('La contraseña nueva debe ser diferente a la actual', 'error')
        return redirect(url_for('cambiar_mi_password', volver=volver_url))
    errors = validar_password_segura(password_nuevo)
    if errors:
        flash(f'Contraseña no válida: {", ".join(errors)}', 'error')
        return redirect(url_for('cambiar_mi_password', volver=volver_url))

    execute_update(
        'UPDATE usuarios SET password_hash=%s, password_temporal=0, '
        'reset_token=NULL, reset_token_expiracion=NULL '
        'WHERE id=%s AND tenant_id <=> %s',
        (
            generate_password_hash(password_nuevo),
            current_user.id,
            current_user.tenant_id,
        ),
    )
    flash('Tu contraseña fue actualizada correctamente', 'success')
    return redirect(volver_url)


def cambiar_password_obligatorio():
    if 'cambio_password_usuario_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'GET':
        return render_template(
            'cambiar_password_obligatorio.html',
            email=session.get('cambio_password_email', ''),
        )
    password = request.form.get('password', '')
    confirmation = request.form.get('password_confirm', '')
    if not password or not confirmation:
        flash('Debes completar todos los campos', 'error')
        return redirect(url_for('cambiar_password_obligatorio'))
    if password != confirmation:
        flash('Las contraseñas no coinciden', 'error')
        return redirect(url_for('cambiar_password_obligatorio'))
    errors = validar_password_segura(password)
    if errors:
        flash(f'Contraseña no válida: {", ".join(errors)}', 'error')
        return redirect(url_for('cambiar_password_obligatorio'))
    user_id = session['cambio_password_usuario_id']
    tenant_id = session.get('cambio_password_tenant_id')
    execute_update(
        'UPDATE usuarios SET password_hash=%s, password_temporal=0 '
        'WHERE id=%s AND tenant_id <=> %s',
        (generate_password_hash(password), user_id, tenant_id),
    )
    data = execute_query(
        'SELECT * FROM usuarios WHERE id=%s AND tenant_id <=> %s',
        (user_id, tenant_id),
    )
    for key in (
        'cambio_password_usuario_id',
        'cambio_password_email',
        'cambio_password_tenant_id',
    ):
        session.pop(key, None)
    user = _build_user(data)
    login_user(user, remember=True)
    flash('Contraseña cambiada exitosamente', 'success')
    return redirect(url_for(destino_inicio_sesion(user)))


@rate_limit(max_requests=3, window=300)
def solicitar_recuperacion():
    if current_user.is_authenticated:
        return redirect(url_for(destino_inicio_sesion(current_user)))
    if request.method == 'GET':
        return render_template('solicitar_recuperacion.html')
    email = request.form.get('email', '').strip().lower()
    if not email or not validate_email(email):
        flash('Por favor ingresa un email válido', 'error')
        return redirect(url_for('solicitar_recuperacion'))
    usuario = execute_query(
        'SELECT * FROM usuarios WHERE email=%s AND activo=1',
        (email,),
    )
    if usuario:
        token = secrets.token_urlsafe(32)
        execute_update(
            'UPDATE usuarios SET reset_token=%s, reset_token_expiracion=%s '
            'WHERE id=%s AND tenant_id <=> %s',
            (
                token, datetime.now() + timedelta(hours=1),
                usuario['id'], usuario.get('tenant_id'),
            ),
        )
        _send_recovery_email(usuario, email, token)
    else:
        flash(
            'Si el email existe, recibirás instrucciones para recuperar '
            'tu contraseña',
            'info',
        )
    return redirect(url_for('login'))


def _send_recovery_email(usuario, email, token):
    if SENDGRID_AVAILABLE:
        try:
            base_url = os.getenv('APP_BASE_URL', '').strip()
            if base_url:
                reset_url = urljoin(
                    base_url.rstrip('/') + '/',
                    url_for('recuperar_password', token=token).lstrip('/'),
                )
            elif not IS_PRODUCTION:
                reset_url = url_for(
                    'recuperar_password', token=token, _external=True,
                )
            else:
                raise RuntimeError('APP_BASE_URL no está configurada')
            message = Mail(
                from_email=os.getenv(
                    'SENDGRID_FROM_EMAIL', 'noreply@facturacion.com',
                ),
                to_emails=email,
                subject='Recuperación de Contraseña - ClinicRD',
                html_content=(
                    f'<p>Hola {usuario["nombre"]},</p>'
                    f'<p><a href="{reset_url}">Recuperar Contraseña</a></p>'
                    '<p>Este enlace expirará en 1 hora.</p>'
                ),
            )
            SendGridAPIClient(os.getenv('SENDGRID_API_KEY')).send(message)
            flash(
                'Se ha enviado un email con instrucciones para recuperar '
                'tu contraseña',
                'success',
            )
        except Exception as error:
            logger.error('Error enviando email: %s', error)
            flash('Error al enviar el email. Contacta al administrador.', 'error')
    elif (
        ENVIRONMENT == 'development'
        and os.getenv('ALLOW_INSECURE_DEV_RESET_TOKEN', '').lower() == 'true'
    ):
        flash(f'Token de recuperación (solo desarrollo): {token}', 'info')
        flash('Usa este enlace para recuperar tu contraseña', 'info')
    else:
        logger.error('Recuperación solicitada sin proveedor de correo.')
        flash('No fue posible enviar el correo. Contacta al administrador.', 'error')


def recuperar_password(token):
    if current_user.is_authenticated:
        return redirect(url_for(destino_inicio_sesion(current_user)))
    usuario = execute_query(
        """
        SELECT * FROM usuarios
        WHERE reset_token=%s AND reset_token_expiracion>%s AND activo=1
        """,
        (token, datetime.now()),
    )
    if not usuario:
        flash('El enlace de recuperación es inválido o ha expirado', 'error')
        return redirect(url_for('login'))
    if request.method == 'GET':
        return render_template('recuperar_password.html', token=token)
    password = request.form.get('password', '')
    confirmation = request.form.get('password_confirm', '')
    if not password or not confirmation:
        flash('Debes completar todos los campos', 'error')
        return redirect(url_for('recuperar_password', token=token))
    if password != confirmation:
        flash('Las contraseñas no coinciden', 'error')
        return redirect(url_for('recuperar_password', token=token))
    errors = validar_password_segura(password)
    if errors:
        flash(f'Contraseña no válida: {", ".join(errors)}', 'error')
        return redirect(url_for('recuperar_password', token=token))
    execute_update(
        """
        UPDATE usuarios SET password_hash=%s, password_temporal=0,
               reset_token=NULL, reset_token_expiracion=NULL
        WHERE id=%s AND tenant_id <=> %s
        """,
        (
            generate_password_hash(password),
            usuario['id'],
            usuario.get('tenant_id'),
        ),
    )
    flash(
        'Contraseña actualizada exitosamente. Ahora puedes iniciar sesión.',
        'success',
    )
    return redirect(url_for('login'))


def _asegurar_columnas_activacion():
    if execute_query("SHOW COLUMNS FROM usuarios LIKE 'email_verificado'"):
        return
    execute_update(
        'ALTER TABLE usuarios '
        'ADD COLUMN email_verificado TINYINT(1) NOT NULL DEFAULT 1'
    )
    execute_update(
        'ALTER TABLE usuarios ADD COLUMN activacion_token VARCHAR(255) NULL'
    )
    execute_update(
        'ALTER TABLE usuarios '
        'ADD COLUMN activacion_token_expiracion DATETIME NULL'
    )


def _url_absoluta(endpoint, **valores):
    base = url_publica_base().strip()
    if base:
        return urljoin(
            base.rstrip('/') + '/',
            url_for(endpoint, **valores).lstrip('/'),
        )
    if not IS_PRODUCTION:
        return url_for(endpoint, _external=True, **valores)
    raise RuntimeError('APP_BASE_URL no está configurada')


def _enviar_correo_activacion(usuario, email):
    token = usuario.get('activacion_token')
    if not token:
        token = secrets.token_urlsafe(32)
        execute_update(
            '''
            UPDATE usuarios
            SET activacion_token=%s, activacion_token_expiracion=%s
            WHERE email=%s
            ''',
            (token, datetime.now() + timedelta(hours=48), email),
        )
    if not SENDGRID_AVAILABLE:
        if (
            ENVIRONMENT == 'development'
            and os.getenv('ALLOW_INSECURE_DEV_RESET_TOKEN', '').lower() == 'true'
        ):
            try:
                enlace = _url_absoluta('activar_cuenta', token=token)
            except Exception:
                enlace = token
            flash(f'Enlace de activación (solo desarrollo): {enlace}', 'info')
            return True
        logger.error('Registro sin proveedor de correo para activar la cuenta.')
        return False
    try:
        enlace = _url_absoluta('activar_cuenta', token=token)
        mensaje = Mail(
            from_email=os.getenv(
                'SENDGRID_FROM_EMAIL',
                os.getenv('EMAIL_FROM', 'noreply@clinicrd.com'),
            ),
            to_emails=email,
            subject='Activa tu cuenta de ClinicRD',
            html_content=(
                f'<p>Hola {usuario.get("nombre") or ""},</p>'
                '<p>Para entrar la primera vez, abre este enlace:</p>'
                f'<p><a href="{enlace}">Activar mi cuenta</a></p>'
                '<p>El enlace vence en 48 horas. Sin abrirlo no podrás iniciar sesión.</p>'
            ),
        )
        SendGridAPIClient(os.getenv('SENDGRID_API_KEY')).send(mensaje)
        return True
    except Exception as error:
        logger.error('Error enviando correo de activación: %s', error)
        return False


@rate_limit(max_requests=10, window=300)
def activar_cuenta(token):
    if current_user.is_authenticated:
        return redirect(url_for(destino_inicio_sesion(current_user)))
    usuario = execute_query(
        '''
        SELECT u.*, e.nombre AS empresa_nombre
        FROM usuarios u
        LEFT JOIN empresas e ON u.tenant_id = e.id
        WHERE u.activacion_token=%s
          AND u.activacion_token_expiracion > %s
        ''',
        (token, datetime.now()),
    )
    if not usuario:
        flash(
            'El enlace no es válido o ya venció. '
            'Revisa tu correo o solicita ayuda a soporte.',
            'error',
        )
        return redirect(url_for('login'))
    execute_update(
        '''
        UPDATE usuarios
        SET email_verificado=1,
            activacion_token=NULL,
            activacion_token_expiracion=NULL,
            last_login=%s
        WHERE id=%s
        ''',
        (datetime.now(), usuario['id']),
    )
    user = _build_user({**usuario, 'email_verificado': 1})
    session.permanent = True
    session['tenant_id'] = user.tenant_id
    session['empresa_nombre'] = user.empresa_nombre
    login_user(user, remember=True)
    flash('Cuenta activada. Bienvenido a ClinicRD.', 'success')
    return redirect(url_for(destino_inicio_sesion(user)))


def register_auth_routes(app):
    app.add_url_rule('/login', 'login', login, methods=['GET', 'POST'])
    app.add_url_rule('/registro', 'registro', registro, methods=['GET', 'POST'])
    app.add_url_rule(
        '/activar-cuenta/<token>',
        'activar_cuenta',
        activar_cuenta,
    )
    app.add_url_rule('/logout', 'logout', logout)
    app.add_url_rule(
        '/mi-cuenta/cambiar-password',
        'cambiar_mi_password',
        cambiar_mi_password,
        methods=['GET', 'POST'],
    )
    app.add_url_rule(
        '/cambiar-password-obligatorio',
        'cambiar_password_obligatorio',
        cambiar_password_obligatorio,
        methods=['GET', 'POST'],
    )
    app.add_url_rule(
        '/solicitar-recuperacion',
        'solicitar_recuperacion',
        solicitar_recuperacion,
        methods=['GET', 'POST'],
    )
    app.add_url_rule(
        '/recuperar-password/<token>',
        'recuperar_password',
        recuperar_password,
        methods=['GET', 'POST'],
    )
