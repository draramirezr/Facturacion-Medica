"""Turnos de atenci?n y pantallas p?blicas."""

import base64
import hashlib
import json
import re
import secrets
from datetime import datetime

from cryptography.fernet import Fernet, InvalidToken
from flask import (
    current_app, flash, jsonify, redirect, render_template, request, url_for,
)
from flask_login import current_user, login_required

from auth import permission_required, user_has_permission
from core.database import execute_query, execute_update, transactional_methods
from core.tenant import get_current_tenant_id
from routes.support import sanitize_input
from turnos import EstadoTurno, validar_transicion


def _token_fernet():
    secreto = str(current_app.secret_key).encode('utf-8')
    clave = base64.urlsafe_b64encode(hashlib.sha256(secreto).digest())
    return Fernet(clave)


def cifrar_token_pantalla(token):
    return _token_fernet().encrypt(token.encode('utf-8')).decode('ascii')


def descifrar_token_pantalla(token_cifrado):
    if not token_cifrado:
        return None
    try:
        return _token_fernet().decrypt(
            token_cifrado.encode('ascii')
        ).decode('utf-8')
    except (InvalidToken, ValueError, TypeError):
        return None


def obtener_turno_tenant(turno_id, tenant_id, bloquear=False):
    sufijo = ' FOR UPDATE' if bloquear else ''
    return execute_query(
        f'''
        SELECT t.*, p.nombre AS paciente_nombre, p.cedula,
               m.nombre AS medico_nombre,
               COALESCE(t.especialidad_snapshot, m.especialidad)
                   AS especialidad
        FROM turnos_atencion t
        JOIN pacientes p
          ON p.id=t.paciente_id AND p.tenant_id=t.tenant_id
        JOIN medicos m
          ON m.id=t.medico_id AND m.tenant_id=t.tenant_id
        WHERE t.id=%s AND t.tenant_id=%s{sufijo}
        ''',
        (turno_id, tenant_id)
    )

def registrar_evento_turno(
    turno_id,
    tenant_id,
    estado_anterior,
    estado_nuevo,
    motivo=None,
    datos=None,
):
    execute_update('''
        INSERT INTO turnos_eventos (
            tenant_id, turno_id, estado_anterior, estado_nuevo,
            motivo, actor_id, datos
        ) VALUES (%s,%s,%s,%s,%s,%s,%s)
    ''', (
        tenant_id,
        turno_id,
        estado_anterior,
        estado_nuevo,
        motivo,
        current_user.id if current_user.is_authenticated else None,
        json.dumps(datos, ensure_ascii=False) if datos else None,
    ))

def reservar_numero_turno(tenant_id, fecha, medico_id):
    execute_update('''
        INSERT INTO secuencias_turnos (
            tenant_id, fecha, medico_id, ultimo_numero
        ) VALUES (%s,%s,%s,1)
        ON DUPLICATE KEY UPDATE
            ultimo_numero=LAST_INSERT_ID(ultimo_numero+1)
    ''', (tenant_id, fecha, medico_id))
    secuencia = execute_query(
        'SELECT ultimo_numero FROM secuencias_turnos '
        'WHERE tenant_id=%s AND fecha=%s AND medico_id=%s FOR UPDATE',
        (tenant_id, fecha, medico_id)
    )
    return int(secuencia['ultimo_numero'])

def puede_operar_cola(turno, permiso):
    if user_has_permission(current_user, 'turnos.administrar'):
        return True
    if user_has_permission(current_user, permiso):
        if (
            user_has_permission(current_user, 'turnos.cola_propia')
            and current_user.medico_id
        ):
            return int(turno['medico_id']) == int(current_user.medico_id)
        return permiso != 'turnos.llamar'
    return False

def listar_turnos(fecha, medico_id=None):
    tenant_id = get_current_tenant_id()
    params = [tenant_id, fecha]
    filtro = ''
    if medico_id:
        filtro = ' AND t.medico_id=%s'
        params.append(medico_id)
    return execute_query(f'''
        SELECT t.*, p.nombre AS paciente_nombre, p.cedula,
               m.nombre AS medico_nombre,
               COALESCE(t.especialidad_snapshot,m.especialidad)
                   AS especialidad
        FROM turnos_atencion t
        JOIN pacientes p
          ON p.id=t.paciente_id AND p.tenant_id=t.tenant_id
        JOIN medicos m
          ON m.id=t.medico_id AND m.tenant_id=t.tenant_id
        WHERE t.tenant_id=%s AND t.fecha=%s{filtro}
        ORDER BY m.nombre, t.posicion, t.id
    ''', params, fetch='all') or []

@login_required
@permission_required('turnos.ver')
def turnos_recepcion():
    if not (
        user_has_permission(current_user, 'turnos.crear')
        or user_has_permission(current_user, 'turnos.administrar')
    ):
        if user_has_permission(current_user, 'turnos.cola_propia'):
            return redirect(url_for('turnos_mi_cola'))
        return jsonify({'error': 'Permiso denegado'}), 403
    tenant_id = get_current_tenant_id()
    fecha = request.args.get('fecha') or datetime.now().strftime('%Y-%m-%d')
    medico_id = request.args.get('medico_id', type=int)
    busqueda = sanitize_input(request.args.get('q', ''), 100)
    pacientes = []
    if busqueda:
        patron = f'%{busqueda}%'
        phone_digits = re.sub(r'\D', '', busqueda)
        phone_pattern = f'%{phone_digits}%' if phone_digits else patron
        pacientes = execute_query('''
            SELECT id, nombre, cedula, telefono, registro_incompleto
            FROM pacientes
            WHERE tenant_id=%s
              AND (
                  nombre LIKE %s OR cedula LIKE %s
                  OR REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(
                      COALESCE(telefono,''),'-',''),' ',''),'(',''),')',''),'+','')
                      LIKE %s
              )
            ORDER BY nombre LIMIT 20
        ''', (tenant_id, patron, patron, phone_pattern), fetch='all') or []
    medicos = execute_query(
        'SELECT id, nombre, especialidad FROM medicos '
        'WHERE tenant_id=%s AND activo=1 ORDER BY nombre',
        (tenant_id,),
        fetch='all'
    ) or []
    citas = execute_query('''
        SELECT c.id, c.paciente_id, c.medico_id, c.hora, c.motivo,
               p.nombre AS paciente_nombre, m.nombre AS medico_nombre
        FROM citas_medicas c
        JOIN pacientes p
          ON p.id=c.paciente_id AND p.tenant_id=c.tenant_id
        JOIN medicos m
          ON m.id=c.medico_id AND m.tenant_id=c.tenant_id
        LEFT JOIN turnos_atencion t
          ON t.cita_id=c.id AND t.tenant_id=c.tenant_id
        WHERE c.tenant_id=%s AND c.fecha=%s
          AND c.estado='Programada' AND t.id IS NULL
        ORDER BY c.hora LIMIT 100
    ''', (tenant_id, fecha), fetch='all') or []
    return render_template(
        'turnos/recepcion.html',
        fecha=fecha,
        medico_id=medico_id,
        pacientes=pacientes,
        medicos=medicos,
        citas=citas,
        turnos=listar_turnos(fecha, medico_id),
        busqueda=busqueda,
    )

@login_required
@permission_required('turnos.crear')
@transactional_methods('POST')
def turnos_nuevo():
    tenant_id = get_current_tenant_id()
    paciente_id = request.form.get('paciente_id', type=int)
    medico_id = request.form.get('medico_id', type=int)
    cita_id = request.form.get('cita_id', type=int)
    motivo = sanitize_input(request.form.get('motivo', ''), 1000)
    fecha = datetime.now().strftime('%Y-%m-%d')
    registro_incompleto = 0

    if cita_id:
        cita = execute_query('''
            SELECT * FROM citas_medicas
            WHERE id=%s AND tenant_id=%s AND fecha=%s
              AND estado='Programada'
            FOR UPDATE
        ''', (cita_id, tenant_id, fecha))
        if not cita:
            flash('La cita no está disponible para registrar llegada', 'error')
            return redirect(url_for('turnos_recepcion'))
        paciente_id = cita['paciente_id']
        medico_id = cita['medico_id']
        motivo = motivo or cita.get('motivo')

    if not paciente_id:
        nombres = sanitize_input(request.form.get('nombres', ''), 100)
        apellidos = sanitize_input(request.form.get('apellidos', ''), 100)
        cedula = sanitize_input(request.form.get('cedula', ''), 20)
        telefono = sanitize_input(request.form.get('telefono', ''), 20)
        if not nombres or not apellidos or not cedula:
            flash('Para el alta rápida indica nombres, apellidos y cédula', 'error')
            return redirect(url_for('turnos_recepcion'))
        existente = execute_query(
            'SELECT id FROM pacientes WHERE tenant_id=%s AND cedula=%s',
            (tenant_id, cedula)
        )
        if existente:
            paciente_id = existente['id']
        else:
            paciente_id = execute_update('''
                INSERT INTO pacientes (
                    tenant_id, nombre, cedula, telefono, registro_incompleto
                ) VALUES (%s,%s,%s,%s,1)
            ''', (
                tenant_id,
                f'{nombres} {apellidos}'.strip(),
                cedula,
                telefono or None,
            ))
            registro_incompleto = 1

    paciente = execute_query(
        'SELECT id, registro_incompleto FROM pacientes '
        'WHERE id=%s AND tenant_id=%s',
        (paciente_id, tenant_id)
    )
    medico = execute_query(
        'SELECT id, especialidad FROM medicos '
        'WHERE id=%s AND tenant_id=%s AND activo=1',
        (medico_id, tenant_id)
    )
    if not paciente or not medico:
        flash('Paciente o médico no válido', 'error')
        return redirect(url_for('turnos_recepcion'))
    duplicado = execute_query('''
        SELECT id FROM turnos_atencion
        WHERE tenant_id=%s AND fecha=%s AND paciente_id=%s
          AND estado IN ('EnEspera','Llamado','EnConsulta')
        FOR UPDATE
    ''', (tenant_id, fecha, paciente_id))
    if duplicado:
        flash('El paciente ya tiene un turno activo hoy', 'warning')
        return redirect(url_for('turnos_recepcion'))

    numero = reservar_numero_turno(tenant_id, fecha, medico_id)
    posicion_row = execute_query('''
        SELECT COALESCE(MAX(posicion),0)+1 AS siguiente
        FROM turnos_atencion
        WHERE tenant_id=%s AND fecha=%s AND medico_id=%s
        FOR UPDATE
    ''', (tenant_id, fecha, medico_id))
    turno_id = execute_update('''
        INSERT INTO turnos_atencion (
            tenant_id, fecha, paciente_id, medico_id,
            especialidad_snapshot, cita_id, numero, posicion,
            estado, motivo, registro_incompleto, llegada_at,
            actor_id, created_by, updated_by
        ) VALUES (
            %s,%s,%s,%s,%s,%s,%s,%s,'EnEspera',%s,%s,NOW(),%s,%s,%s
        )
    ''', (
        tenant_id,
        fecha,
        paciente_id,
        medico_id,
        medico.get('especialidad'),
        cita_id,
        numero,
        posicion_row['siguiente'],
        motivo or None,
        registro_incompleto or paciente.get('registro_incompleto', 0),
        current_user.id,
        current_user.id,
        current_user.id,
    ))
    if cita_id:
        execute_update(
            "UPDATE citas_medicas SET estado='Confirmada', updated_by=%s "
            'WHERE id=%s AND tenant_id=%s',
            (current_user.id, cita_id, tenant_id)
        )
    registrar_evento_turno(
        turno_id,
        tenant_id,
        None,
        EstadoTurno.EnEspera.value,
        datos={'origen': 'Cita' if cita_id else 'Recepción'},
    )
    flash(f'Turno {numero:03d} creado correctamente', 'success')
    if request.form.get('imprimir') == '1':
        return redirect(url_for('turnos_ticket', turno_id=turno_id))
    return redirect(url_for('turnos_recepcion'))

@login_required
@permission_required('turnos.llamar')
@transactional_methods('POST')
def turnos_accion(turno_id):
    tenant_id = get_current_tenant_id()
    turno = obtener_turno_tenant(turno_id, tenant_id, bloquear=True)
    if not turno or not puede_operar_cola(turno, 'turnos.llamar'):
        return jsonify({'error': 'Turno no encontrado o sin permiso'}), 404
    accion = request.form.get('accion', '')
    motivo = sanitize_input(request.form.get('motivo', ''), 500)
    destinos = {
        'llamar': EstadoTurno.Llamado,
        'iniciar': EstadoTurno.EnConsulta,
        'atender': EstadoTurno.Atendido,
        'no_presente': EstadoTurno.NoPresente,
        'anular': EstadoTurno.Anulado,
        'reinsertar': EstadoTurno.EnEspera,
    }
    if accion in {'subir', 'bajar'}:
        if not user_has_permission(current_user, 'turnos.administrar'):
            return jsonify({'error': 'Permiso denegado'}), 403
        operador = '<' if accion == 'subir' else '>'
        orden = 'DESC' if accion == 'subir' else 'ASC'
        otro = execute_query(f'''
            SELECT id, posicion FROM turnos_atencion
            WHERE tenant_id=%s AND fecha=%s AND medico_id=%s
              AND posicion {operador} %s
              AND estado IN ('EnEspera','Llamado')
            ORDER BY posicion {orden} LIMIT 1 FOR UPDATE
        ''', (
            tenant_id,
            turno['fecha'],
            turno['medico_id'],
            turno['posicion'],
        ))
        if otro:
            posicion_actual = turno['posicion']
            execute_update(
                'UPDATE turnos_atencion SET posicion=0 WHERE id=%s AND tenant_id=%s',
                (turno_id, tenant_id)
            )
            execute_update(
                'UPDATE turnos_atencion SET posicion=%s WHERE id=%s AND tenant_id=%s',
                (posicion_actual, otro['id'], tenant_id)
            )
            execute_update(
                'UPDATE turnos_atencion SET posicion=%s, updated_by=%s '
                'WHERE id=%s AND tenant_id=%s',
                (otro['posicion'], current_user.id, turno_id, tenant_id)
            )
        return redirect(request.referrer or url_for('turnos_recepcion'))
    destino = destinos.get(accion)
    if not destino:
        return jsonify({'error': 'Acción inválida'}), 400
    if accion == 'anular' and not user_has_permission(
        current_user,
        'turnos.administrar',
    ):
        return jsonify({'error': 'Permiso denegado'}), 403
    if accion == 'anular' and not motivo:
        flash('Indica el motivo de anulación', 'error')
        return redirect(request.referrer or url_for('turnos_recepcion'))
    try:
        validar_transicion(turno['estado'], destino)
    except ValueError as exc:
        flash(str(exc), 'error')
        return redirect(request.referrer or url_for('turnos_recepcion'))
    marcas = {
        EstadoTurno.Llamado: 'llamado_at=NOW()',
        EstadoTurno.EnConsulta: 'consulta_iniciada_at=NOW()',
        EstadoTurno.Atendido: 'finalizado_at=NOW()',
        EstadoTurno.Anulado: 'finalizado_at=NOW()',
    }
    marca = marcas.get(destino)
    extra = f', {marca}' if marca else ''
    execute_update(f'''
        UPDATE turnos_atencion
        SET estado=%s, actor_id=%s, updated_by=%s{extra}
        WHERE id=%s AND tenant_id=%s
    ''', (destino.value, current_user.id, current_user.id, turno_id, tenant_id))
    registrar_evento_turno(
        turno_id,
        tenant_id,
        turno['estado'],
        destino.value,
        motivo or None,
    )
    if destino == EstadoTurno.EnConsulta:
        return redirect(url_for(
            'facturacion_historia_clinica_nueva',
            paciente_id=turno['paciente_id'],
            turno_id=turno_id,
            medico_id=turno['medico_id'],
        ))
    return redirect(request.referrer or url_for('turnos_recepcion'))

@login_required
@permission_required('turnos.llamar')
@transactional_methods('POST')
def turnos_siguiente():
    tenant_id = get_current_tenant_id()
    medico_id = request.form.get('medico_id', type=int)
    if (
        user_has_permission(current_user, 'turnos.cola_propia')
        and not user_has_permission(current_user, 'turnos.administrar')
    ):
        medico_id = current_user.medico_id
    if not medico_id:
        flash('Selecciona una cola médica', 'error')
        return redirect(request.referrer or url_for('turnos_recepcion'))
    turno = execute_query('''
        SELECT * FROM turnos_atencion
        WHERE tenant_id=%s AND fecha=CURDATE() AND medico_id=%s
          AND estado='EnEspera'
        ORDER BY posicion, id LIMIT 1 FOR UPDATE
    ''', (tenant_id, medico_id))
    if not turno:
        flash('No hay pacientes en espera', 'warning')
        return redirect(request.referrer or url_for('turnos_recepcion'))
    if not puede_operar_cola(turno, 'turnos.llamar'):
        return jsonify({'error': 'Permiso denegado'}), 403
    execute_update('''
        UPDATE turnos_atencion
        SET estado='Llamado', llamado_at=NOW(), actor_id=%s, updated_by=%s
        WHERE id=%s AND tenant_id=%s
    ''', (current_user.id, current_user.id, turno['id'], tenant_id))
    registrar_evento_turno(
        turno['id'],
        tenant_id,
        turno['estado'],
        EstadoTurno.Llamado.value,
    )
    return redirect(request.referrer or url_for('turnos_recepcion'))

@login_required
@permission_required('turnos.cola_propia')
def turnos_mi_cola():
    if not current_user.medico_id:
        flash('Tu usuario no está vinculado a un médico', 'error')
        return redirect(url_for('facturacion_menu'))
    medico = execute_query(
        'SELECT id, nombre, especialidad FROM medicos '
        'WHERE id=%s AND tenant_id=%s',
        (current_user.medico_id, get_current_tenant_id())
    )
    if not medico:
        flash('El médico vinculado ya no está disponible', 'error')
        return redirect(url_for('facturacion_menu'))
    fecha = datetime.now().strftime('%Y-%m-%d')
    return render_template(
        'turnos/mi_cola.html',
        medico=medico,
        fecha=fecha,
        turnos=listar_turnos(fecha, current_user.medico_id),
    )

@login_required
@permission_required('turnos.imprimir')
def turnos_ticket(turno_id):
    tenant_id = get_current_tenant_id()
    turno = obtener_turno_tenant(turno_id, tenant_id)
    if not turno:
        flash('Turno no encontrado', 'error')
        return redirect(url_for('turnos_recepcion'))
    empresa = execute_query(
        'SELECT nombre, ancho_ticket_turnos FROM empresas WHERE id=%s',
        (tenant_id,)
    ) or {}
    ancho = str(empresa.get('ancho_ticket_turnos') or '80')
    if ancho not in {'58', '80'}:
        ancho = '80'
    return render_template(
        'turnos/ticket.html',
        turno=turno,
        empresa=empresa,
        ancho=ancho,
    )

def obtener_pantallas_turnos(tenant_id):
    pantallas = execute_query('''
        SELECT pt.*, m.nombre AS medico_nombre
        FROM pantallas_turnos pt
        LEFT JOIN medicos m
          ON m.id=pt.medico_id AND m.tenant_id=pt.tenant_id
        WHERE pt.tenant_id=%s
        ORDER BY pt.activo DESC, pt.nombre
    ''', (tenant_id,), fetch='all') or []
    for pantalla in pantallas:
        token = descifrar_token_pantalla(pantalla.get('token_cifrado'))
        pantalla['url_publica'] = (
            url_for('turnos_pantalla_publica', token=token, _external=True)
            if token and pantalla.get('activo') else None
        )
    return pantallas

@login_required
@permission_required('turnos.pantalla')
@transactional_methods('POST')
def turnos_pantallas():
    tenant_id = get_current_tenant_id()
    url_creada = None
    if request.method == 'POST':
        if request.form.get('accion') == 'regenerar':
            pantalla_id = request.form.get('pantalla_id', type=int)
            pantalla = execute_query(
                'SELECT id FROM pantallas_turnos '
                'WHERE id=%s AND tenant_id=%s AND activo=1 FOR UPDATE',
                (pantalla_id, tenant_id),
            )
            if not pantalla:
                flash('Pantalla no encontrada', 'error')
                return redirect(url_for('turnos_pantallas'))
            token = secrets.token_urlsafe(32)
            execute_update(
                '''
                UPDATE pantallas_turnos
                SET token_hash=%s, token_cifrado=%s, updated_by=%s
                WHERE id=%s AND tenant_id=%s
                ''',
                (
                    hashlib.sha256(token.encode('utf-8')).hexdigest(),
                    cifrar_token_pantalla(token),
                    current_user.id,
                    pantalla_id,
                    tenant_id,
                ),
            )
            url_creada = url_for(
                'turnos_pantalla_publica',
                token=token,
                _external=True,
            )
        else:
            nombre = sanitize_input(request.form.get('nombre', ''), 150)
            medico_id = request.form.get('medico_id', type=int)
            if not nombre:
                flash('Indica un nombre para la pantalla', 'error')
                return redirect(url_for('turnos_pantallas'))
            if medico_id and not execute_query(
                'SELECT id FROM medicos WHERE id=%s AND tenant_id=%s',
                (medico_id, tenant_id)
            ):
                flash('Médico no válido', 'error')
                return redirect(url_for('turnos_pantallas'))
            pantalla_existente = execute_query(
                'SELECT id, activo FROM pantallas_turnos '
                'WHERE tenant_id=%s AND nombre=%s FOR UPDATE',
                (tenant_id, nombre),
            )
            if pantalla_existente and pantalla_existente.get('activo'):
                flash(
                    'Ya existe una pantalla activa con ese nombre. '
                    'Puedes abrir su enlace desde la lista.',
                    'warning',
                )
                return redirect(url_for('turnos_pantallas'))
            token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
            token_cifrado = cifrar_token_pantalla(token)
            if pantalla_existente:
                execute_update(
                    '''
                    UPDATE pantallas_turnos
                    SET token_hash=%s, token_cifrado=%s, medico_id=%s,
                        activo=1, updated_by=%s
                    WHERE id=%s AND tenant_id=%s
                    ''',
                    (
                        token_hash,
                        token_cifrado,
                        medico_id,
                        current_user.id,
                        pantalla_existente['id'],
                        tenant_id,
                    ),
                )
            else:
                execute_update('''
                    INSERT INTO pantallas_turnos (
                        tenant_id, token_hash, token_cifrado, nombre, medico_id,
                        activo, created_by, updated_by
                    ) VALUES (%s,%s,%s,%s,%s,1,%s,%s)
                ''', (
                    tenant_id,
                    token_hash,
                    token_cifrado,
                    nombre,
                    medico_id,
                    current_user.id,
                    current_user.id,
                ))
            url_creada = url_for(
                'turnos_pantalla_publica',
                token=token,
                _external=True,
            )
    medicos = execute_query(
        'SELECT id, nombre, especialidad FROM medicos '
        'WHERE tenant_id=%s AND activo=1 ORDER BY nombre',
        (tenant_id,),
        fetch='all'
    ) or []
    empresa = execute_query(
        'SELECT ancho_ticket_turnos FROM empresas WHERE id=%s',
        (tenant_id,)
    ) or {}
    return render_template(
        'turnos/pantallas.html',
        pantallas=obtener_pantallas_turnos(tenant_id),
        medicos=medicos,
        ancho=str(empresa.get('ancho_ticket_turnos') or '80'),
        url_creada=url_creada,
    )

@login_required
@permission_required('turnos.pantalla')
@transactional_methods('POST')
def turnos_configuracion_ticket():
    ancho = request.form.get('ancho')
    if ancho not in {'58', '80'}:
        flash('Ancho de ticket no válido', 'error')
        return redirect(url_for('turnos_pantallas'))
    execute_update(
        'UPDATE empresas SET ancho_ticket_turnos=%s WHERE id=%s',
        (ancho, get_current_tenant_id())
    )
    flash('Formato de impresión actualizado', 'success')
    return redirect(url_for('turnos_pantallas'))

@login_required
@permission_required('turnos.pantalla')
@transactional_methods('POST')
def turnos_pantalla_revocar(pantalla_id):
    execute_update('''
        UPDATE pantallas_turnos
        SET activo=0, updated_by=%s
        WHERE id=%s AND tenant_id=%s
    ''', (current_user.id, pantalla_id, get_current_tenant_id()))
    flash('Acceso de pantalla revocado', 'success')
    return redirect(url_for('turnos_pantallas'))

def resolver_pantalla_por_token(token):
    if not token or len(token) > 100:
        return None
    token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
    return execute_query(
        'SELECT * FROM pantallas_turnos '
        'WHERE token_hash=%s AND activo=1',
        (token_hash,)
    )

def turnos_pantalla_publica(token):
    pantalla = resolver_pantalla_por_token(token)
    if not pantalla:
        return render_template('turnos/pantalla_revocada.html'), 404
    return render_template(
        'turnos/pantalla_publica.html',
        pantalla=pantalla,
        token=token,
    )

def turnos_pantalla_feed(token):
    pantalla = resolver_pantalla_por_token(token)
    if not pantalla:
        return jsonify({'error': 'Pantalla no disponible'}), 404
    params = [pantalla['tenant_id']]
    filtro = ''
    if pantalla.get('medico_id'):
        filtro = ' AND t.medico_id=%s'
        params.append(pantalla['medico_id'])
    filas = execute_query(f'''
        SELECT t.numero, t.estado, t.posicion,
               m.nombre AS medico,
               COALESCE(t.especialidad_snapshot,m.especialidad,'General')
                   AS especialidad
        FROM turnos_atencion t
        JOIN medicos m
          ON m.id=t.medico_id AND m.tenant_id=t.tenant_id
        WHERE t.tenant_id=%s AND t.fecha=CURDATE()
          AND t.estado IN ('Llamado','EnEspera'){filtro}
        ORDER BY m.nombre,
                 CASE WHEN t.estado='Llamado' THEN 0 ELSE 1 END,
                 t.posicion, t.id
    ''', params, fetch='all') or []
    colas = {}
    for fila in filas:
        clave = (fila['medico'], fila['especialidad'])
        cola = colas.setdefault(clave, {
            'medico': fila['medico'],
            'especialidad': fila['especialidad'],
            'actual': None,
            'siguiente': None,
        })
        numero = f"{int(fila['numero']):03d}"
        if fila['estado'] == EstadoTurno.Llamado.value and not cola['actual']:
            cola['actual'] = numero
        elif fila['estado'] == EstadoTurno.EnEspera.value and not cola['siguiente']:
            cola['siguiente'] = numero
    return jsonify({
        'colas': list(colas.values()),
        'actualizado': datetime.now().strftime('%H:%M:%S'),
    })

def register_turnos_routes(app):
    app.add_url_rule('/turnos', endpoint='turnos_recepcion', view_func=turnos_recepcion)
    app.add_url_rule('/turnos/nuevo', endpoint='turnos_nuevo', view_func=turnos_nuevo, methods=['POST'])
    app.add_url_rule('/turnos/<int:turno_id>/accion', endpoint='turnos_accion', view_func=turnos_accion, methods=['POST'])
    app.add_url_rule('/turnos/siguiente', endpoint='turnos_siguiente', view_func=turnos_siguiente, methods=['POST'])
    app.add_url_rule('/turnos/mi-cola', endpoint='turnos_mi_cola', view_func=turnos_mi_cola)
    app.add_url_rule('/turnos/<int:turno_id>/ticket', endpoint='turnos_ticket', view_func=turnos_ticket)
    app.add_url_rule('/turnos/pantallas', endpoint='turnos_pantallas', view_func=turnos_pantallas, methods=['GET', 'POST'])
    app.add_url_rule('/turnos/configuracion-ticket', endpoint='turnos_configuracion_ticket', view_func=turnos_configuracion_ticket, methods=['POST'])
    app.add_url_rule('/turnos/pantallas/<int:pantalla_id>/revocar', endpoint='turnos_pantalla_revocar', view_func=turnos_pantalla_revocar, methods=['POST'])
    app.add_url_rule('/sala/<token>', endpoint='turnos_pantalla_publica', view_func=turnos_pantalla_publica)
    app.add_url_rule('/api/sala/<token>', endpoint='turnos_pantalla_feed', view_func=turnos_pantalla_feed)
