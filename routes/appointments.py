"""Rutas y helpers de citas m?dicas."""

import calendar as calendar_module
from collections import defaultdict
from datetime import datetime, timedelta

from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from auth import permission_required, user_has_permission
from core.database import execute_query, execute_update
from core.tenant import get_current_tenant_id
from core.presentation import hora_input
from routes.support import sanitize_input, validate_int

def actualizar_citas_vencidas(tenant_id):
    execute_update('''
        UPDATE citas_medicas
        SET estado='Vencida'
        WHERE tenant_id=%s
          AND estado IN ('Programada', 'Confirmada')
          AND (
              fecha<CURDATE()
              OR (
                  fecha=CURDATE()
                  AND ADDTIME(hora, SEC_TO_TIME(duracion_minutos * 60))<CURTIME()
              )
          )
    ''', (tenant_id,))


def contexto_formulario_cita(tenant_id):
    return {
        'pacientes': execute_query(
            'SELECT id, nombre, cedula, telefono FROM pacientes '
            'WHERE tenant_id=%s ORDER BY nombre',
            (tenant_id,), fetch='all'
        ) or [],
        'medicos': execute_query(
            'SELECT id, nombre, especialidad FROM medicos '
            'WHERE tenant_id=%s AND activo=1 ORDER BY nombre',
            (tenant_id,), fetch='all'
        ) or []
    }


def validar_formulario_cita(tenant_id, cita_id=None):
    paciente_id = validate_int(request.form.get('paciente_id'), min_value=1, default=None)
    medico_id = validate_int(request.form.get('medico_id'), min_value=1, default=None)
    fecha = request.form.get('fecha', '').strip()
    hora = request.form.get('hora', '').strip()
    duracion = validate_int(
        request.form.get('duracion_minutos'), min_value=10,
        max_value=480, default=None
    )
    especialidad = sanitize_input(request.form.get('especialidad', ''), 150)
    motivo = sanitize_input(request.form.get('motivo', ''), 2000)
    notas = sanitize_input(request.form.get('notas', ''), 3000)
    estado = request.form.get('estado', 'Programada').strip()
    estados_validos = [
        'Programada', 'Confirmada', 'Completada',
        'Cancelada', 'No asistió', 'Vencida'
    ]
    if not all([paciente_id, medico_id, fecha, hora, duracion, motivo]):
        return None, 'Complete todos los campos obligatorios'
    if estado not in estados_validos:
        return None, 'El estado de la cita no es válido'
    try:
        fecha_obj = datetime.strptime(fecha, '%Y-%m-%d').date()
        hora_obj = datetime.strptime(hora, '%H:%M').time()
    except ValueError:
        return None, 'La fecha u hora no es válida'
    paciente = execute_query(
        'SELECT id FROM pacientes WHERE id=%s AND tenant_id=%s',
        (paciente_id, tenant_id)
    )
    medico = execute_query(
        'SELECT id, especialidad FROM medicos '
        'WHERE id=%s AND tenant_id=%s AND activo=1',
        (medico_id, tenant_id)
    )
    if not paciente or not medico:
        return None, 'El paciente o médico seleccionado no es válido'
    if estado in ['Programada', 'Confirmada']:
        inicio = datetime.combine(fecha_obj, hora_obj)
        if inicio < datetime.now():
            return None, 'No puede programar una cita en una fecha u hora pasada'
    parametros = [
        tenant_id, medico_id, paciente_id, fecha_obj, hora_obj, duracion,
        hora_obj
    ]
    conflicto_sql = '''
        SELECT c.id, c.hora, c.medico_id, c.paciente_id,
               c.duracion_minutos, p.nombre AS paciente_nombre
        FROM citas_medicas c
        JOIN pacientes p
          ON p.id=c.paciente_id AND p.tenant_id=c.tenant_id
        WHERE c.tenant_id=%s AND (c.medico_id=%s OR c.paciente_id=%s)
          AND c.fecha=%s
          AND c.estado NOT IN ('Cancelada', 'Vencida', 'No asistió')
          AND c.hora<ADDTIME(%s, SEC_TO_TIME(%s * 60))
          AND ADDTIME(c.hora, SEC_TO_TIME(c.duracion_minutos * 60))>%s
    '''
    if cita_id:
        conflicto_sql += ' AND c.id<>%s'
        parametros.append(cita_id)
    conflicto_sql += ' LIMIT 1'
    conflicto = None
    if estado in ['Programada', 'Confirmada']:
        conflicto = execute_query(conflicto_sql, tuple(parametros))
    if conflicto:
        recurso = 'El médico' if conflicto['medico_id'] == medico_id else 'El paciente'
        return None, (
            f"{recurso} ya tiene una cita a las {hora_input(conflicto['hora'])} "
            f"con {conflicto['paciente_nombre']}"
        )
    return {
        'paciente_id': paciente_id,
        'medico_id': medico_id,
        'fecha': fecha_obj,
        'hora': hora_obj,
        'duracion': duracion,
        'especialidad': especialidad or medico.get('especialidad'),
        'motivo': motivo,
        'notas': notas or None,
        'estado': estado
    }, None


@login_required
@permission_required('citas.ver')
def facturacion_citas():
    tenant_id = get_current_tenant_id()
    actualizar_citas_vencidas(tenant_id)
    vista = request.args.get('vista', 'mes')
    if vista not in ['mes', 'hoy', 'proximas', 'todas']:
        vista = 'mes'
    mes_texto = request.args.get('mes', datetime.now().strftime('%Y-%m'))
    try:
        primer_dia = datetime.strptime(mes_texto, '%Y-%m').date().replace(day=1)
    except ValueError:
        primer_dia = datetime.now().date().replace(day=1)
        mes_texto = primer_dia.strftime('%Y-%m')
    ultimo_dia_numero = calendar_module.monthrange(
        primer_dia.year, primer_dia.month
    )[1]
    ultimo_dia = primer_dia.replace(day=ultimo_dia_numero)
    mes_anterior = (primer_dia - timedelta(days=1)).replace(day=1)
    mes_siguiente = (ultimo_dia + timedelta(days=1)).replace(day=1)
    paciente_id = validate_int(
        request.args.get('paciente_id'), min_value=1, default=None
    )
    medico_id = validate_int(
        request.args.get('medico_id'), min_value=1, default=None
    )
    estado = request.args.get('estado', '').strip()
    buscar = request.args.get('buscar', '').strip()
    query = '''
        SELECT c.*, p.nombre AS paciente_nombre, p.telefono,
               m.nombre AS medico_nombre, m.especialidad AS medico_especialidad
        FROM citas_medicas c
        JOIN pacientes p ON p.id=c.paciente_id AND p.tenant_id=c.tenant_id
        JOIN medicos m ON m.id=c.medico_id AND m.tenant_id=c.tenant_id
        WHERE c.tenant_id=%s
    '''
    params = [tenant_id]
    hoy = datetime.now().date()
    if vista == 'mes':
        query += ' AND c.fecha BETWEEN %s AND %s'
        params.extend([primer_dia, ultimo_dia])
    elif vista == 'hoy':
        query += ' AND c.fecha=%s'
        params.append(hoy)
    elif vista == 'proximas':
        query += " AND c.fecha>=%s AND c.estado NOT IN ('Cancelada','Completada','Vencida','No asistió')"
        params.append(hoy)
    if paciente_id:
        query += ' AND c.paciente_id=%s'
        params.append(paciente_id)
    if medico_id:
        query += ' AND c.medico_id=%s'
        params.append(medico_id)
    if estado in [
        'Programada', 'Confirmada', 'Completada',
        'Cancelada', 'No asistió', 'Vencida'
    ]:
        query += ' AND c.estado=%s'
        params.append(estado)
    if buscar:
        patron = f'%{buscar}%'
        query += ' AND (p.nombre LIKE %s OR m.nombre LIKE %s OR c.motivo LIKE %s)'
        params.extend([patron, patron, patron])
    query += ' ORDER BY c.fecha ASC, c.hora ASC'
    citas = execute_query(query, tuple(params), fetch='all') or []
    citas_por_fecha = defaultdict(list)
    for cita in citas:
        citas_por_fecha[cita['fecha'].isoformat()].append(cita)
    calendario = calendar_module.Calendar(firstweekday=0)
    semanas = calendario.monthdatescalendar(primer_dia.year, primer_dia.month)
    contexto = contexto_formulario_cita(tenant_id)
    return render_template(
        'facturacion/citas.html',
        citas=citas, citas_por_fecha=dict(citas_por_fecha),
        semanas=semanas, vista=vista, mes=mes_texto,
        mes_numero=primer_dia.month, anio=primer_dia.year,
        mes_anterior=mes_anterior.strftime('%Y-%m'),
        mes_siguiente=mes_siguiente.strftime('%Y-%m'),
        hoy=hoy, filtros=request.args, **contexto
    )


@login_required
@permission_required('citas.crear')
def facturacion_citas_nueva():
    tenant_id = get_current_tenant_id()
    contexto = contexto_formulario_cita(tenant_id)
    consulta_id = validate_int(
        request.args.get('consulta_id') or request.form.get('consulta_origen_id'),
        min_value=1, default=None
    )
    consulta_origen = None
    if consulta_id:
        consulta_origen = execute_query('''
            SELECT c.id, c.paciente_id, c.medico_id, c.proxima_cita,
                   c.proxima_hora, c.proxima_especialidad, c.proxima_motivo,
                   c.indicaciones_seguimiento
            FROM consultas_clinicas c
            WHERE c.id=%s AND c.tenant_id=%s
        ''', (consulta_id, tenant_id))
    if request.method == 'POST':
        datos, error = validar_formulario_cita(tenant_id)
        if error:
            flash(error, 'error')
            return render_template(
                'facturacion/cita_form.html', cita=None,
                consulta_origen=consulta_origen, form_data=request.form,
                **contexto
            )
        if consulta_id:
            existente = execute_query(
                'SELECT id FROM citas_medicas '
                'WHERE tenant_id=%s AND consulta_origen_id=%s',
                (tenant_id, consulta_id)
            )
            if existente:
                flash('Esta consulta ya tiene una próxima cita en la agenda', 'warning')
                return redirect(url_for(
                    'facturacion_cita_editar', cita_id=existente['id']
                ))
        cita_id = execute_update('''
            INSERT INTO citas_medicas (
                tenant_id, paciente_id, medico_id, consulta_origen_id,
                fecha, hora, duracion_minutos, especialidad, motivo,
                notas, estado, origen, created_by, updated_by
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
        ''', (
            tenant_id, datos['paciente_id'], datos['medico_id'], consulta_id,
            datos['fecha'], datos['hora'], datos['duracion'],
            datos['especialidad'], datos['motivo'], datos['notas'],
            datos['estado'], 'Historia clinica' if consulta_id else 'Manual',
            current_user.id, current_user.id
        ))
        flash('Cita programada exitosamente', 'success')
        return redirect(url_for(
            'facturacion_citas', vista='mes',
            mes=datos['fecha'].strftime('%Y-%m')
        ))
    return render_template(
        'facturacion/cita_form.html', cita=None,
        consulta_origen=consulta_origen, form_data={},
        fecha_actual=request.args.get('fecha', ''),
        paciente_preseleccionado=request.args.get('paciente_id', ''),
        medico_preseleccionado=request.args.get('medico_id', ''),
        **contexto
    )


@login_required
@permission_required('citas.editar')
def facturacion_cita_editar(cita_id):
    tenant_id = get_current_tenant_id()
    cita = execute_query(
        'SELECT * FROM citas_medicas WHERE id=%s AND tenant_id=%s',
        (cita_id, tenant_id)
    )
    if not cita:
        flash('Cita no encontrada', 'error')
        return redirect(url_for('facturacion_citas'))
    contexto = contexto_formulario_cita(tenant_id)
    if request.method == 'POST':
        datos, error = validar_formulario_cita(tenant_id, cita_id)
        if error:
            flash(error, 'error')
            return render_template(
                'facturacion/cita_form.html', cita=cita,
                consulta_origen=None, form_data=request.form, **contexto
            )
        execute_update('''
            UPDATE citas_medicas SET
                paciente_id=%s, medico_id=%s, fecha=%s, hora=%s,
                duracion_minutos=%s, especialidad=%s, motivo=%s,
                notas=%s, estado=%s, updated_by=%s
            WHERE id=%s AND tenant_id=%s
        ''', (
            datos['paciente_id'], datos['medico_id'], datos['fecha'],
            datos['hora'], datos['duracion'], datos['especialidad'],
            datos['motivo'], datos['notas'], datos['estado'],
            current_user.id, cita_id, tenant_id
        ))
        flash('Cita actualizada correctamente', 'success')
        return redirect(url_for(
            'facturacion_citas', vista='mes',
            mes=datos['fecha'].strftime('%Y-%m')
        ))
    return render_template(
        'facturacion/cita_form.html', cita=cita,
        consulta_origen=None, form_data=cita, **contexto
    )


@login_required
@permission_required('citas.editar')
def facturacion_cita_estado(cita_id):
    tenant_id = get_current_tenant_id()
    estado = request.form.get('estado', '').strip()
    if estado not in [
        'Programada', 'Confirmada', 'Completada',
        'Cancelada', 'No asistió'
    ]:
        flash('Estado de cita no válido', 'error')
        return redirect(url_for('facturacion_citas'))
    if (
        estado == 'Cancelada'
        and not user_has_permission(current_user, 'citas.cancelar')
    ):
        flash('No tienes permisos para cancelar citas', 'error')
        return redirect(request.referrer or url_for('facturacion_citas'))
    cita = execute_query(
        'SELECT id FROM citas_medicas WHERE id=%s AND tenant_id=%s',
        (cita_id, tenant_id)
    )
    if not cita:
        flash('Cita no encontrada', 'error')
        return redirect(url_for('facturacion_citas'))
    motivo_cancelacion = sanitize_input(
        request.form.get('motivo_cancelacion', ''), 1000
    )
    if estado == 'Cancelada' and not motivo_cancelacion:
        flash('Indique el motivo de cancelación', 'error')
        return redirect(request.referrer or url_for('facturacion_citas'))
    execute_update('''
        UPDATE citas_medicas SET estado=%s, updated_by=%s,
            cancelada_por=%s, fecha_cancelacion=%s, motivo_cancelacion=%s
        WHERE id=%s AND tenant_id=%s
    ''', (
        estado, current_user.id,
        current_user.id if estado == 'Cancelada' else None,
        datetime.now() if estado == 'Cancelada' else None,
        motivo_cancelacion if estado == 'Cancelada' else None,
        cita_id, tenant_id
    ))
    flash('Estado de la cita actualizado', 'success')
    return redirect(request.referrer or url_for('facturacion_citas'))


def register_appointment_routes(app):
    app.add_url_rule('/facturacion/citas', endpoint='facturacion_citas', view_func=facturacion_citas)
    app.add_url_rule('/facturacion/citas/nueva', endpoint='facturacion_citas_nueva', view_func=facturacion_citas_nueva, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/citas/<int:cita_id>/editar', endpoint='facturacion_cita_editar', view_func=facturacion_cita_editar, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/citas/<int:cita_id>/estado', endpoint='facturacion_cita_estado', view_func=facturacion_cita_estado, methods=['POST'])
