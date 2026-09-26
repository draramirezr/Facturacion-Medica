"""Enlaces QR para que el paciente agende en el tenant del código."""

import base64
import hashlib
import io
import re
import secrets
from datetime import datetime, timedelta
from urllib.parse import quote, urljoin

import qrcode
from cryptography.fernet import Fernet, InvalidToken
from flask import (
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import current_user, login_required

from auth import permission_required
from core.clock import ahora_clinica, fecha_clinica
from core.config import IS_PRODUCTION, url_publica_base
from core.database import execute_query, execute_update, transactional_methods
from core.security import rate_limit
from core.tenant import get_current_tenant_id
from routes.appointments import (
    _avisar_cita_paciente,
    calcular_huecos,
    conflicto_horario_cita,
    hashear_token_cita,
    hora_como_time,
    medico_id_agenda_restringida,
    ocupaciones_medico_dia,
    puede_gestionar_qr_citas,
)
from routes.support import sanitize_input, validate_int


def _fernet_enlace():
    secreto = str(current_app.secret_key).encode('utf-8')
    clave = base64.urlsafe_b64encode(hashlib.sha256(secreto).digest())
    return Fernet(clave)


def cifrar_token_enlace(token):
    return _fernet_enlace().encrypt(token.encode('utf-8')).decode('ascii')


def descifrar_token_enlace(token_cifrado):
    if not token_cifrado:
        return None
    try:
        return _fernet_enlace().decrypt(
            token_cifrado.encode('ascii')
        ).decode('utf-8')
    except (InvalidToken, ValueError, TypeError):
        return None


def _url_agendar(token):
    base = url_publica_base().strip()
    ruta = url_for('cita_agendar_publica', token=token)
    if base:
        return urljoin(base.rstrip('/') + '/', ruta.lstrip('/'))
    if not IS_PRODUCTION:
        return url_for('cita_agendar_publica', token=token, _external=True)
    raise RuntimeError('APP_BASE_URL no está configurada')


def _dias_permitidos(texto):
    dias = set()
    for parte in str(texto or '').split(','):
        parte = parte.strip()
        if parte.isdigit() and 1 <= int(parte) <= 7:
            dias.add(int(parte))
    return dias or {1, 2, 3, 4, 5, 6}


def _solo_digitos(valor):
    return re.sub(r'\D+', '', valor or '')


def numero_whatsapp(telefono):
    """Número internacional para wa.me (RD: 1 + 10 dígitos)."""
    digits = _solo_digitos(telefono)
    if len(digits) == 10:
        digits = '1' + digits
    if len(digits) < 11:
        return ''
    return digits


def url_whatsapp(telefono, texto=''):
    numero = numero_whatsapp(telefono)
    if not numero:
        return ''
    return 'https://wa.me/%s?text=%s' % (numero, quote(texto or ''))


def tel_href(telefono):
    numero = numero_whatsapp(telefono)
    return ('tel:+' + numero) if numero else ''


def _contacto_agendar(enlace):
    centro = enlace.get('empresa_telefono') or ''
    medico = enlace.get('medico_telefono') or ''
    texto = 'Hola, quiero información para agendar en %s' % (
        enlace.get('empresa_nombre') or 'el consultorio'
    )
    return {
        'centro': centro,
        'centro_href': tel_href(centro),
        'medico': medico,
        'medico_href': tel_href(medico),
        'direccion': enlace.get('empresa_direccion') or '',
        'whatsapp': url_whatsapp(medico or centro, texto),
        'whatsapp_centro': url_whatsapp(centro, texto),
        'texto': texto,
    }


def obtener_enlace_por_token(token):
    if not token or not (20 <= len(token) <= 80):
        return None
    return execute_query(
        '''
        SELECT e.*, emp.nombre AS empresa_nombre, emp.telefono AS empresa_telefono,
               emp.direccion AS empresa_direccion,
               m.nombre AS medico_nombre, m.especialidad AS medico_especialidad,
               m.telefono AS medico_telefono
        FROM enlaces_cita_qr e
        JOIN empresas emp ON emp.id=e.tenant_id
        LEFT JOIN medicos m
          ON m.id=e.medico_id AND m.tenant_id=e.tenant_id AND m.activo=1
        WHERE e.token_hash=%s AND e.activo=1
        ''',
        (hashear_token_cita(token),),
    )


def _medicos_enlace(enlace):
    if enlace.get('medico_id'):
        if not enlace.get('medico_nombre'):
            return []
        return [{
            'id': enlace['medico_id'],
            'nombre': enlace['medico_nombre'],
            'especialidad': enlace.get('medico_especialidad'),
            'telefono': enlace.get('medico_telefono'),
        }]
    return execute_query(
        'SELECT id, nombre, especialidad, telefono FROM medicos '
        'WHERE tenant_id=%s AND activo=1 ORDER BY nombre',
        (enlace['tenant_id'],),
        fetch='all',
    ) or []


def _medico_permitido(enlace, medico_id):
    medico_id = validate_int(medico_id, min_value=1, default=None)
    if enlace.get('medico_id'):
        return medico_id if medico_id == int(enlace['medico_id']) else None
    if not medico_id:
        return None
    existe = execute_query(
        'SELECT id FROM medicos WHERE id=%s AND tenant_id=%s AND activo=1',
        (medico_id, enlace['tenant_id']),
    )
    return medico_id if existe else None


def _huecos_enlace(enlace, medico_id, fecha):
    if fecha.isoweekday() not in _dias_permitidos(enlace.get('dias_semana')):
        return []
    ocupados = ocupaciones_medico_dia(enlace['tenant_id'], medico_id, fecha)
    return calcular_huecos(
        fecha,
        enlace.get('duracion_minutos') or 30,
        enlace.get('hora_inicio'),
        enlace.get('hora_fin'),
        ocupados,
    )


def _buscar_paciente_conocido(tenant_id, cedula, telefono):
    cedula_n = _solo_digitos(cedula)
    if len(cedula_n) >= 8:
        filas = execute_query(
            '''
            SELECT id, nombre, cedula, telefono, email
            FROM pacientes
            WHERE tenant_id=%s AND REPLACE(REPLACE(IFNULL(cedula,''),'-',''),' ','')=%s
            LIMIT 2
            ''',
            (tenant_id, cedula_n),
            fetch='all',
        ) or []
        if len(filas) == 1:
            return filas[0]
        if len(filas) > 1:
            return None
    telefono_n = _solo_digitos(telefono)
    if len(telefono_n) >= 7:
        filas = execute_query(
            '''
            SELECT id, nombre, cedula, telefono, email
            FROM pacientes
            WHERE tenant_id=%s
              AND REPLACE(REPLACE(REPLACE(IFNULL(telefono,''),'-',''),' ',''),'+','')=%s
            LIMIT 2
            ''',
            (tenant_id, telefono_n),
            fetch='all',
        ) or []
        if len(filas) == 1:
            return filas[0]
    return None


def _resolver_paciente(tenant_id, nombre, cedula, telefono, email):
    conocido = _buscar_paciente_conocido(tenant_id, cedula, telefono)
    if conocido and conocido.get('id'):
        if (not conocido.get('telefono') and telefono) or (
            not conocido.get('email') and email
        ):
            execute_update(
                '''
                UPDATE pacientes
                SET telefono=COALESCE(NULLIF(telefono,''), %s),
                    email=COALESCE(NULLIF(email,''), %s)
                WHERE id=%s AND tenant_id=%s
                ''',
                (telefono or None, email or None, conocido['id'], tenant_id),
            )
        return conocido['id']
    paciente_id = execute_update(
        '''
        INSERT INTO pacientes (
            tenant_id, nombre, cedula, telefono, email, registro_incompleto
        ) VALUES (%s, %s, %s, %s, %s, %s)
        ''',
        (
            tenant_id,
            nombre,
            cedula or None,
            telefono or None,
            email or None,
            0 if cedula else 1,
        ),
    )
    return paciente_id


@login_required
@permission_required('citas.crear')
@transactional_methods('POST')
def facturacion_citas_qr():
    if not puede_gestionar_qr_citas():
        flash('El perfil médico no genera códigos QR. Pida el cartel en recepción.', 'error')
        return redirect(url_for('facturacion_citas'))
    tenant_id = get_current_tenant_id()
    medico_restringido = medico_id_agenda_restringida()
    url_creada = None
    if request.method == 'POST':
        accion = request.form.get('accion', 'crear')
        if accion == 'desactivar':
            enlace_id = validate_int(request.form.get('enlace_id'), min_value=1)
            execute_update(
                'UPDATE enlaces_cita_qr SET activo=0, updated_by=%s '
                'WHERE id=%s AND tenant_id=%s',
                (current_user.id, enlace_id, tenant_id),
            )
            flash('El código QR dejó de funcionar.', 'success')
            return redirect(url_for('facturacion_citas_qr'))
        if accion == 'regenerar':
            enlace_id = validate_int(request.form.get('enlace_id'), min_value=1)
            enlace = execute_query(
                'SELECT id FROM enlaces_cita_qr '
                'WHERE id=%s AND tenant_id=%s AND activo=1',
                (enlace_id, tenant_id),
            )
            if not enlace:
                flash('Enlace no encontrado', 'error')
                return redirect(url_for('facturacion_citas_qr'))
            token = secrets.token_urlsafe(32)
            execute_update(
                '''
                UPDATE enlaces_cita_qr
                SET token_hash=%s, token_cifrado=%s, updated_by=%s
                WHERE id=%s AND tenant_id=%s
                ''',
                (
                    hashear_token_cita(token),
                    cifrar_token_enlace(token),
                    current_user.id,
                    enlace_id,
                    tenant_id,
                ),
            )
            try:
                url_creada = _url_agendar(token)
            except RuntimeError:
                flash('Configure APP_BASE_URL para imprimir el QR público.', 'error')
            else:
                flash('Se generó un código nuevo. El anterior ya no sirve.', 'success')
        else:
            nombre = sanitize_input(request.form.get('nombre', ''), 150)
            medico_id = medico_restringido or validate_int(
                request.form.get('medico_id'), min_value=1, default=None,
            )
            hora_inicio = request.form.get('hora_inicio', '08:00').strip() or '08:00'
            hora_fin = request.form.get('hora_fin', '18:00').strip() or '18:00'
            duracion = validate_int(
                request.form.get('duracion_minutos'), min_value=15, max_value=120,
                default=30,
            )
            dias = ','.join(
                parte for parte in request.form.getlist('dias')
                if parte.isdigit() and 1 <= int(parte) <= 7
            ) or '1,2,3,4,5,6'
            if not nombre:
                flash('Indique un nombre para el cartel (por ejemplo Recepción).', 'error')
                return redirect(url_for('facturacion_citas_qr'))
            if medico_id and not execute_query(
                'SELECT id FROM medicos WHERE id=%s AND tenant_id=%s AND activo=1',
                (medico_id, tenant_id),
            ):
                flash('El médico no es válido', 'error')
                return redirect(url_for('facturacion_citas_qr'))
            token = secrets.token_urlsafe(32)
            execute_update(
                '''
                INSERT INTO enlaces_cita_qr (
                    tenant_id, token_hash, token_cifrado, nombre, medico_id,
                    hora_inicio, hora_fin, duracion_minutos, dias_semana,
                    created_by, updated_by
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ''',
                (
                    tenant_id, hashear_token_cita(token), cifrar_token_enlace(token),
                    nombre, medico_id, hora_inicio, hora_fin, duracion, dias,
                    current_user.id, current_user.id,
                ),
            )
            try:
                url_creada = _url_agendar(token)
            except RuntimeError:
                flash(
                    'El enlace se guardó, pero falta APP_BASE_URL para el QR público.',
                    'error',
                )
            else:
                flash('Código QR listo para imprimir.', 'success')
    medicos_sql = (
        'SELECT id, nombre, especialidad FROM medicos '
        'WHERE tenant_id=%s AND activo=1'
    )
    params = [tenant_id]
    if medico_restringido:
        medicos_sql += ' AND id=%s'
        params.append(medico_restringido)
    medicos_sql += ' ORDER BY nombre'
    enlaces = execute_query(
        '''
        SELECT e.*, m.nombre AS medico_nombre
        FROM enlaces_cita_qr e
        LEFT JOIN medicos m ON m.id=e.medico_id AND m.tenant_id=e.tenant_id
        WHERE e.tenant_id=%s AND e.activo=1
        ORDER BY e.created_at DESC
        ''',
        (tenant_id,),
        fetch='all',
    ) or []
    empresa = execute_query(
        'SELECT nombre FROM empresas WHERE id=%s', (tenant_id,),
    ) or {}
    return render_template(
        'facturacion/citas_qr.html',
        enlaces=enlaces,
        medicos=execute_query(medicos_sql, tuple(params), fetch='all') or [],
        url_creada=url_creada,
        empresa_nombre=empresa.get('nombre', ''),
        agenda_restringida=bool(medico_restringido),
    )


@login_required
@permission_required('citas.crear')
def facturacion_citas_qr_imagen(enlace_id):
    if not puede_gestionar_qr_citas():
        flash('El perfil médico no genera códigos QR. Pida el cartel en recepción.', 'error')
        return redirect(url_for('facturacion_citas'))
    tenant_id = get_current_tenant_id()
    enlace = execute_query(
        'SELECT * FROM enlaces_cita_qr WHERE id=%s AND tenant_id=%s AND activo=1',
        (enlace_id, tenant_id),
    )
    if not enlace:
        flash('Enlace no encontrado', 'error')
        return redirect(url_for('facturacion_citas_qr'))
    token = descifrar_token_enlace(enlace.get('token_cifrado'))
    if not token:
        flash('Regenere el código para poder imprimirlo.', 'error')
        return redirect(url_for('facturacion_citas_qr'))
    try:
        url = _url_agendar(token)
    except RuntimeError:
        flash('Configure APP_BASE_URL para generar el QR.', 'error')
        return redirect(url_for('facturacion_citas_qr'))
    imagen = qrcode.make(url)
    buffer = io.BytesIO()
    imagen.save(buffer, format='PNG')
    buffer.seek(0)
    return send_file(buffer, mimetype='image/png', download_name='cita-qr.png')


@rate_limit(max_requests=40, window=300, methods=('GET', 'POST'))
@transactional_methods('POST')
def cita_agendar_publica(token):
    enlace = obtener_enlace_por_token(token)
    if not enlace:
        return render_template(
            'agendar_cita.html', invalido=True, enlace=None, medicos=[],
        )
    medicos = _medicos_enlace(enlace)
    contacto = _contacto_agendar(enlace)
    for medico in medicos:
        medico['whatsapp_url'] = url_whatsapp(
            medico.get('telefono'), contacto['texto'],
        ) or contacto['whatsapp_centro']
    contexto = {
        'invalido': False,
        'enlace': enlace,
        'medicos': medicos,
        'contacto': contacto,
        'token': token,
        'hoy': fecha_clinica().isoformat(),
        'max_fecha': (fecha_clinica() + timedelta(days=21)).isoformat(),
        'exito': False,
        'error': None,
        'form_data': {},
        'whatsapp_url': contacto['whatsapp'],
        'whatsapp_centro': contacto['whatsapp_centro'],
    }
    if request.method != 'POST':
        return render_template('agendar_cita.html', **contexto)
    nombre = sanitize_input(request.form.get('nombre', ''), 200)
    cedula = _solo_digitos(request.form.get('cedula', ''))[:20]
    telefono = sanitize_input(request.form.get('telefono', ''), 20)
    email = sanitize_input(request.form.get('email', ''), 100)
    motivo = sanitize_input(request.form.get('motivo', ''), 2000)
    medico_id = _medico_permitido(enlace, request.form.get('medico_id'))
    fecha_txt = request.form.get('fecha', '').strip()
    hora_txt = request.form.get('hora', '').strip()
    contexto['form_data'] = request.form
    if not all([nombre, telefono, motivo, medico_id, fecha_txt, hora_txt]):
        contexto['error'] = 'Complete nombre, teléfono, médico, fecha, hora y motivo.'
        return render_template('agendar_cita.html', **contexto)
    if email and '@' not in email:
        contexto['error'] = 'El correo no es válido.'
        return render_template('agendar_cita.html', **contexto)
    try:
        fecha = datetime.strptime(fecha_txt, '%Y-%m-%d').date()
    except ValueError:
        contexto['error'] = 'La fecha no es válida.'
        return render_template('agendar_cita.html', **contexto)
    if fecha < fecha_clinica() or fecha > fecha_clinica() + timedelta(days=21):
        contexto['error'] = 'Elija una fecha dentro de los próximos 21 días.'
        return render_template('agendar_cita.html', **contexto)
    huecos = _huecos_enlace(enlace, medico_id, fecha)
    if hora_txt not in huecos:
        contexto['error'] = 'Ese horario ya no está disponible. Elija otro.'
        return render_template('agendar_cita.html', **contexto)
    hora_obj = hora_como_time(hora_txt)
    if not hora_obj:
        contexto['error'] = 'La hora no es válida.'
        return render_template('agendar_cita.html', **contexto)
    inicio = datetime.combine(fecha, hora_obj)
    if inicio < ahora_clinica():
        contexto['error'] = 'Ese horario ya pasó. Elija otro.'
        return render_template('agendar_cita.html', **contexto)
    paciente_id = _resolver_paciente(
        enlace['tenant_id'], nombre, cedula, telefono, email,
    )
    if not paciente_id:
        contexto['error'] = 'No se pudo registrar al paciente. Inténtelo de nuevo.'
        return render_template('agendar_cita.html', **contexto)
    medico = execute_query(
        'SELECT especialidad FROM medicos WHERE id=%s AND tenant_id=%s',
        (medico_id, enlace['tenant_id']),
    ) or {}
    duracion = int(enlace.get('duracion_minutos') or 30)
    choque = conflicto_horario_cita(
        enlace['tenant_id'], medico_id, paciente_id, fecha, hora_obj, duracion,
    )
    if choque:
        contexto['error'] = 'Ese horario ya no está disponible. Elija otro.'
        return render_template('agendar_cita.html', **contexto)
    cita_id = execute_update(
        '''
        INSERT INTO citas_medicas (
            tenant_id, paciente_id, medico_id, fecha, hora, duracion_minutos,
            especialidad, motivo, notas, estado, origen
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'Programada', 'QR')
        ''',
        (
            enlace['tenant_id'], paciente_id, medico_id, fecha, hora_obj,
            duracion, medico.get('especialidad'), motivo,
            'Agendada por el paciente (QR)',
        ),
    )
    if not cita_id:
        contexto['error'] = 'No se pudo guardar la cita. Inténtelo de nuevo.'
        return render_template('agendar_cita.html', **contexto)
    _avisar_cita_paciente(
        enlace['tenant_id'], cita_id, paciente_id,
        fecha, hora_obj, 'programada',
    )
    contexto['exito'] = True
    contexto['resumen'] = {
        'fecha': fecha_txt,
        'hora': hora_txt,
        'medico': next(
            (item['nombre'] for item in medicos if int(item['id']) == medico_id),
            '',
        ),
    }
    return render_template('agendar_cita.html', **contexto)


@rate_limit(max_requests=40, window=300, methods=('GET',))
def cita_agendar_horarios(token):
    enlace = obtener_enlace_por_token(token)
    if not enlace:
        return jsonify({'huecos': [], 'error': 'Enlace inválido'}), 404
    medico_id = _medico_permitido(enlace, request.args.get('medico_id'))
    try:
        fecha = datetime.strptime(request.args.get('fecha', ''), '%Y-%m-%d').date()
    except ValueError:
        return jsonify({'huecos': []})
    if not medico_id:
        return jsonify({'huecos': []})
    return jsonify({'huecos': _huecos_enlace(enlace, medico_id, fecha)})


@rate_limit(max_requests=20, window=300, methods=('GET',))
def cita_agendar_paciente(token):
    enlace = obtener_enlace_por_token(token)
    if not enlace:
        return jsonify({'encontrado': False}), 404
    fila = _buscar_paciente_conocido(
        enlace['tenant_id'],
        request.args.get('cedula', ''),
        request.args.get('telefono', ''),
    )
    if not fila:
        return jsonify({'encontrado': False})
    return jsonify({
        'encontrado': True,
        'nombre': fila.get('nombre') or '',
        'cedula': fila.get('cedula') or '',
        'telefono': fila.get('telefono') or '',
        'email': fila.get('email') or '',
    })


def register_cita_qr_routes(app):
    app.add_url_rule(
        '/facturacion/citas/qr',
        endpoint='facturacion_citas_qr',
        view_func=facturacion_citas_qr,
        methods=['GET', 'POST'],
    )
    app.add_url_rule(
        '/facturacion/citas/qr/<int:enlace_id>/imagen',
        endpoint='facturacion_citas_qr_imagen',
        view_func=facturacion_citas_qr_imagen,
    )
    app.add_url_rule(
        '/agendar/<token>',
        endpoint='cita_agendar_publica',
        view_func=cita_agendar_publica,
        methods=['GET', 'POST'],
    )
    app.add_url_rule(
        '/agendar/<token>/horarios',
        endpoint='cita_agendar_horarios',
        view_func=cita_agendar_horarios,
    )
    app.add_url_rule(
        '/agendar/<token>/paciente',
        endpoint='cita_agendar_paciente',
        view_func=cita_agendar_paciente,
    )
