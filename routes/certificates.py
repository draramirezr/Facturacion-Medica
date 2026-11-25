"""Rutas y helpers de constancias médicas (asistencia a consulta)."""

import re
from datetime import datetime

from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from auth import permission_required, user_has_permission
from core.database import execute_query, execute_update, transactional_methods
from core.tenant import get_current_tenant_id
from routes.licenses import medico_id_licencias_restringido
from routes.support import (
    calcular_edad_clinica, execute_paginated_query, id_consulta_retorno,
    sanitize_input, url_historia_clinica, validate_int,
)
from services.subscriptions import get_empresa_info

DIRIGIDA_A_PREDETERMINADA = 'A quien pueda interesar'
ESTADOS_CONSTANCIA = ('Activa', 'Anulada')


def medico_id_constancias_restringido():
    """Un médico operativo solo ve y gestiona sus propias constancias."""
    return medico_id_licencias_restringido()


def obtener_constancia_medica(constancia_id, tenant_id, medico_id_restringido=None):
    return execute_query(
        """
        SELECT cm.*, p.nombre AS paciente_nombre, p.cedula,
               p.fecha_nacimiento, m.nombre AS medico_nombre,
               m.especialidad, m.exequatur,
               c.fecha AS consulta_fecha,
               uc.nombre AS creado_por_nombre,
               ua.nombre AS anulado_por_nombre
        FROM constancias_medicas cm
        JOIN pacientes p ON p.id=cm.paciente_id AND p.tenant_id=cm.tenant_id
        JOIN medicos m ON m.id=cm.medico_id AND m.tenant_id=cm.tenant_id
        LEFT JOIN consultas_clinicas c
          ON c.id=cm.consulta_id AND c.tenant_id=cm.tenant_id
        LEFT JOIN usuarios uc
          ON uc.id=cm.created_by AND uc.tenant_id=cm.tenant_id
        LEFT JOIN usuarios ua
          ON ua.id=cm.anulado_por AND ua.tenant_id=cm.tenant_id
        WHERE cm.id=%s AND cm.tenant_id=%s
          AND (%s IS NULL OR cm.medico_id=%s)
        """,
        (
            constancia_id, tenant_id,
            medico_id_restringido, medico_id_restringido,
        ),
    )


def contexto_formulario_constancia(
    tenant_id, paciente_preseleccionado=None, medico_id_restringido=None,
):
    pacientes = execute_query(
        "SELECT id, nombre, cedula, fecha_nacimiento FROM pacientes "
        "WHERE tenant_id=%s ORDER BY nombre",
        (tenant_id,), fetch='all'
    ) or []
    medicos_sql = (
        "SELECT id, nombre, especialidad FROM medicos "
        "WHERE tenant_id=%s AND activo=1"
    )
    medicos_params = [tenant_id]
    if medico_id_restringido:
        medicos_sql += " AND id=%s"
        medicos_params.append(medico_id_restringido)
    medicos_sql += " ORDER BY nombre"
    medicos = execute_query(
        medicos_sql, tuple(medicos_params), fetch='all'
    ) or []
    consultas_sql = """
        SELECT c.id, c.paciente_id, c.fecha, c.hora,
               m.nombre AS medico_nombre
        FROM consultas_clinicas c
        JOIN medicos m
          ON m.id=c.medico_id AND m.tenant_id=c.tenant_id
        WHERE c.tenant_id=%s
    """
    consultas_params = [tenant_id]
    if medico_id_restringido:
        consultas_sql += " AND c.medico_id=%s"
        consultas_params.append(medico_id_restringido)
    consultas_sql += " ORDER BY c.fecha DESC, c.id DESC"
    consultas = execute_query(
        consultas_sql, tuple(consultas_params), fetch='all'
    ) or []
    return {
        'pacientes': pacientes,
        'medicos': medicos,
        'consultas': consultas,
        'paciente_preseleccionado': paciente_preseleccionado,
        'constancias_restringidas': bool(medico_id_restringido),
        'dirigida_a_predeterminada': DIRIGIDA_A_PREDETERMINADA,
    }


def _parsear_hora(valor):
    valor = (valor or '').strip()
    if not valor:
        return None, None
    if not re.fullmatch(r'\d{1,2}:\d{2}(:\d{2})?', valor):
        return None, 'La hora indicada no es válida'
    formato = '%H:%M:%S' if valor.count(':') == 2 else '%H:%M'
    try:
        return datetime.strptime(valor, formato).time(), None
    except ValueError:
        return None, 'La hora indicada no es válida'


def validar_datos_constancia(tenant_id, fuente=None):
    form = fuente if fuente is not None else request.form
    paciente_id = validate_int(form.get('paciente_id'), min_value=1, default=None)
    medico_id = (
        medico_id_constancias_restringido()
        or validate_int(form.get('medico_id'), min_value=1, default=None)
    )
    consulta_id = validate_int(form.get('consulta_id'), min_value=1, default=None)
    fecha_atencion = (form.get('fecha_atencion') or '').strip()
    dirigida_a = (
        sanitize_input(form.get('dirigida_a', ''), 200)
        or DIRIGIDA_A_PREDETERMINADA
    )
    motivo = sanitize_input(form.get('motivo', ''), 500)

    if not all([paciente_id, medico_id, fecha_atencion]):
        return None, 'Complete todos los campos obligatorios'
    try:
        fecha = datetime.strptime(fecha_atencion, '%Y-%m-%d').date()
    except ValueError:
        return None, 'La fecha de atención no es válida'
    hora_entrada, error = _parsear_hora(form.get('hora_entrada'))
    if error:
        return None, error
    hora_salida, error = _parsear_hora(form.get('hora_salida'))
    if error:
        return None, error
    if hora_entrada and hora_salida and hora_salida < hora_entrada:
        return None, 'La hora de salida no puede ser menor que la hora de entrada'

    paciente = execute_query(
        "SELECT id FROM pacientes WHERE id=%s AND tenant_id=%s",
        (paciente_id, tenant_id)
    )
    medico = execute_query(
        "SELECT id FROM medicos WHERE id=%s AND tenant_id=%s AND activo=1",
        (medico_id, tenant_id)
    )
    if not paciente or not medico:
        return None, 'El paciente o el médico no es válido'

    if consulta_id:
        restringido = medico_id_constancias_restringido()
        consulta = execute_query(
            "SELECT id, paciente_id FROM consultas_clinicas "
            "WHERE id=%s AND tenant_id=%s "
            "AND (%s IS NULL OR medico_id=%s)",
            (consulta_id, tenant_id, restringido, restringido)
        )
        if not consulta or consulta['paciente_id'] != paciente_id:
            return None, 'La consulta seleccionada no pertenece al paciente'

    return {
        'paciente_id': paciente_id, 'medico_id': medico_id,
        'consulta_id': consulta_id, 'fecha_atencion': fecha,
        'hora_entrada': hora_entrada, 'hora_salida': hora_salida,
        'dirigida_a': dirigida_a, 'motivo': motivo or None,
    }, None


def siguiente_numero_constancia(tenant_id):
    """Correlativo por empresa; FOR UPDATE serializa emisiones simultáneas.

    Se llama dentro de la transacción del POST (transactional_methods), y la
    clave única (tenant_id, numero) impide duplicados aunque algo falle.
    """
    fila = execute_query(
        "SELECT COALESCE(MAX(numero), 0) + 1 AS siguiente "
        "FROM constancias_medicas WHERE tenant_id=%s FOR UPDATE",
        (tenant_id,)
    ) or {}
    return int(fila.get('siguiente') or 1)


def insertar_constancia_medica(tenant_id, datos):
    numero = siguiente_numero_constancia(tenant_id)
    codigo = f'CM-{numero:06d}'
    return execute_update(
        """
        INSERT INTO constancias_medicas (
            tenant_id, numero, codigo, paciente_id, medico_id, consulta_id,
            fecha_atencion, hora_entrada, hora_salida, dirigida_a, motivo,
            estado, created_by, updated_by
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'Activa', %s, %s
        )
        """,
        (
            tenant_id, numero, codigo, datos['paciente_id'],
            datos['medico_id'], datos['consulta_id'],
            datos['fecha_atencion'], datos['hora_entrada'],
            datos['hora_salida'], datos['dirigida_a'], datos['motivo'],
            current_user.id, current_user.id,
        )
    )


def emitir_constancia_desde_consulta(
    tenant_id, paciente_id, medico_id, consulta_id, fecha, hora,
):
    """Si marcó emitir constancia en la consulta, registrarla."""
    if not user_has_permission(current_user, 'constancias.crear'):
        return None
    if request.form.get('emitir_constancia') != '1':
        return None
    fuente = {
        'paciente_id': paciente_id,
        'medico_id': medico_id,
        'consulta_id': consulta_id,
        'fecha_atencion': str(fecha or ''),
        'hora_entrada': (
            request.form.get('constancia_hora_entrada') or hora or ''
        ),
        'hora_salida': request.form.get('constancia_hora_salida', ''),
        'dirigida_a': request.form.get('constancia_dirigida_a', ''),
        'motivo': request.form.get('constancia_motivo', ''),
    }
    datos, error = validar_datos_constancia(tenant_id, fuente)
    if error:
        flash(f'Constancia no emitida: {error}', 'error')
        return None
    constancia_id = insertar_constancia_medica(tenant_id, datos)
    flash('Constancia médica registrada. Imprímala para entregársela al paciente.', 'success')
    return constancia_id


@login_required
@permission_required('constancias.ver')
def facturacion_constancias_medicas():
    tenant_id = get_current_tenant_id()
    medico_id_restringido = medico_id_constancias_restringido()
    buscar = request.args.get('buscar', '').strip()
    fecha = request.args.get('fecha', '').strip()
    medico_id = medico_id_restringido or validate_int(
        request.args.get('medico_id'), min_value=1, default=None
    )
    estado = request.args.get('estado', '').strip()
    orden = request.args.get('orden', 'recientes').strip()
    query = """
        SELECT cm.*, p.nombre AS paciente_nombre, m.nombre AS medico_nombre
        FROM constancias_medicas cm
        JOIN pacientes p
          ON p.id=cm.paciente_id AND p.tenant_id=cm.tenant_id
        JOIN medicos m
          ON m.id=cm.medico_id AND m.tenant_id=cm.tenant_id
        WHERE cm.tenant_id=%s
    """
    params = [tenant_id]
    if buscar:
        patron = f'%{buscar}%'
        phone_digits = re.sub(r'\D', '', buscar)
        phone_pattern = f'%{phone_digits}%' if phone_digits else patron
        query += """
            AND (
                cm.codigo LIKE %s OR p.nombre LIKE %s OR p.cedula LIKE %s
                OR REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(
                    COALESCE(p.telefono,''),'-',''),' ',''),'(',''),')',''),'+','')
                    LIKE %s
                OR cm.dirigida_a LIKE %s
            )
        """
        params.extend([patron, patron, patron, phone_pattern, patron])
    if fecha:
        query += " AND cm.fecha_atencion=%s"
        params.append(fecha)
    if medico_id:
        query += " AND cm.medico_id=%s"
        params.append(medico_id)
    if estado in ESTADOS_CONSTANCIA:
        query += " AND cm.estado=%s"
        params.append(estado)
    ordenes = {
        'recientes': 'cm.fecha_atencion DESC, cm.id DESC',
        'antiguas': 'cm.fecha_atencion ASC, cm.id ASC',
        'paciente': 'p.nombre ASC, cm.fecha_atencion DESC',
        'medico': 'm.nombre ASC, cm.fecha_atencion DESC',
        'estado': 'cm.estado ASC, cm.fecha_atencion DESC',
    }
    constancias, pagination = execute_paginated_query(
        query, params, ordenes.get(orden, ordenes['recientes']),
    )
    medicos = execute_query(
        "SELECT id, nombre FROM medicos "
        "WHERE tenant_id=%s AND activo=1 "
        "AND (%s IS NULL OR id=%s) ORDER BY nombre",
        (tenant_id, medico_id_restringido, medico_id_restringido),
        fetch='all',
    ) or []
    return render_template(
        'facturacion/constancias_medicas.html', constancias=constancias,
        medicos=medicos, filtros=request.args, pagination=pagination,
        constancias_restringidas=bool(medico_id_restringido),
    )


@login_required
@transactional_methods('POST')
@permission_required('constancias.crear')
def facturacion_constancias_medicas_nueva():
    tenant_id = get_current_tenant_id()
    medico_id_restringido = medico_id_constancias_restringido()
    paciente_preseleccionado = validate_int(
        request.args.get('paciente_id') or request.form.get('paciente_id'),
        min_value=1, default=None
    )
    contexto = contexto_formulario_constancia(
        tenant_id, paciente_preseleccionado, medico_id_restringido,
    )
    if request.method == 'POST':
        datos, error = validar_datos_constancia(tenant_id)
        if error:
            flash(error, 'error')
            volver = id_consulta_retorno()
            if volver:
                return redirect(url_historia_clinica(volver, 'constancias'))
            return render_template(
                'facturacion/constancia_medica_form.html',
                constancia=None, form_data=request.form, **contexto
            )
        constancia_id = insertar_constancia_medica(tenant_id, datos)
        flash('Constancia médica registrada exitosamente', 'success')
        volver = id_consulta_retorno()
        if volver:
            return redirect(url_historia_clinica(volver, 'constancias'))
        return redirect(url_for(
            'facturacion_constancia_medica_ver', constancia_id=constancia_id
        ))

    form_data = {}
    consulta_preseleccionada = validate_int(
        request.args.get('consulta_id'), min_value=1, default=None
    )
    if consulta_preseleccionada:
        form_data['consulta_id'] = consulta_preseleccionada
    return render_template(
        'facturacion/constancia_medica_form.html', constancia=None,
        form_data=form_data, fecha_actual=datetime.now().strftime('%Y-%m-%d'),
        **contexto
    )


@login_required
@permission_required('constancias.ver')
def facturacion_constancia_medica_ver(constancia_id):
    tenant_id = get_current_tenant_id()
    # Igual que licencias: ver e imprimir no se limitan al médico propio
    # (la consulta y el expediente muestran documentos de otros médicos).
    constancia = obtener_constancia_medica(constancia_id, tenant_id)
    if not constancia:
        flash('Constancia médica no encontrada', 'error')
        return redirect(url_for('facturacion_constancias_medicas'))
    constancia['edad'] = calcular_edad_clinica(
        constancia.get('fecha_nacimiento'), constancia['fecha_atencion']
    )
    return render_template(
        'facturacion/constancia_medica_ver.html',
        constancia=constancia, imprimir=False,
        centro=get_empresa_info(tenant_id) or {},
    )


@login_required
@transactional_methods('POST')
@permission_required('constancias.editar')
def facturacion_constancia_medica_editar(constancia_id):
    tenant_id = get_current_tenant_id()
    medico_id_restringido = medico_id_constancias_restringido()
    constancia = obtener_constancia_medica(
        constancia_id, tenant_id, medico_id_restringido,
    )
    if not constancia:
        flash('Constancia médica no encontrada', 'error')
        return redirect(url_for('facturacion_constancias_medicas'))
    if constancia['estado'] != 'Activa':
        flash('Solo las constancias activas pueden editarse', 'warning')
        return redirect(url_for(
            'facturacion_constancia_medica_ver', constancia_id=constancia_id
        ))
    contexto = contexto_formulario_constancia(
        tenant_id, constancia['paciente_id'], medico_id_restringido,
    )
    if request.method == 'POST':
        datos, error = validar_datos_constancia(tenant_id)
        if error:
            flash(error, 'error')
            return render_template(
                'facturacion/constancia_medica_form.html',
                constancia=constancia, form_data=request.form, **contexto
            )
        execute_update(
            """
            UPDATE constancias_medicas SET
                paciente_id=%s, medico_id=%s, consulta_id=%s,
                fecha_atencion=%s, hora_entrada=%s, hora_salida=%s,
                dirigida_a=%s, motivo=%s, updated_by=%s
            WHERE id=%s AND tenant_id=%s AND estado='Activa'
            """,
            (
                datos['paciente_id'], datos['medico_id'], datos['consulta_id'],
                datos['fecha_atencion'], datos['hora_entrada'],
                datos['hora_salida'], datos['dirigida_a'], datos['motivo'],
                current_user.id, constancia_id, tenant_id,
            )
        )
        flash('Constancia médica actualizada', 'success')
        return redirect(url_for(
            'facturacion_constancia_medica_ver', constancia_id=constancia_id
        ))
    return render_template(
        'facturacion/constancia_medica_form.html', constancia=constancia,
        form_data=constancia, **contexto
    )


@login_required
@transactional_methods('POST')
@permission_required('constancias.anular')
def facturacion_constancia_medica_anular(constancia_id):
    tenant_id = get_current_tenant_id()
    constancia = obtener_constancia_medica(
        constancia_id, tenant_id, medico_id_constancias_restringido(),
    )
    motivo = sanitize_input(request.form.get('motivo_anulacion', ''), 2000)
    if not constancia:
        flash('Constancia médica no encontrada', 'error')
        return redirect(url_for('facturacion_constancias_medicas'))
    if constancia['estado'] == 'Anulada':
        flash('La constancia ya está anulada', 'warning')
        return redirect(url_for(
            'facturacion_constancia_medica_ver', constancia_id=constancia_id
        ))
    if not motivo:
        flash('Debe indicar el motivo de la anulación', 'error')
        return redirect(url_for(
            'facturacion_constancia_medica_ver', constancia_id=constancia_id
        ))
    execute_update(
        """
        UPDATE constancias_medicas
        SET estado='Anulada', anulado_por=%s, fecha_anulacion=NOW(),
            motivo_anulacion=%s, updated_by=%s
        WHERE id=%s AND tenant_id=%s
        """,
        (current_user.id, motivo, current_user.id, constancia_id, tenant_id)
    )
    flash('Constancia anulada; el documento permanece en el historial', 'success')
    return redirect(url_for(
        'facturacion_constancia_medica_ver', constancia_id=constancia_id
    ))


@login_required
@permission_required('constancias.imprimir')
def facturacion_constancia_medica_imprimir(constancia_id):
    tenant_id = get_current_tenant_id()
    # Igual que licencias: ver e imprimir no se limitan al médico propio
    # (la consulta y el expediente muestran documentos de otros médicos).
    constancia = obtener_constancia_medica(constancia_id, tenant_id)
    if not constancia:
        flash('Constancia médica no encontrada', 'error')
        return redirect(url_for('facturacion_constancias_medicas'))
    constancia['edad'] = calcular_edad_clinica(
        constancia.get('fecha_nacimiento'), constancia['fecha_atencion']
    )
    return render_template(
        'facturacion/constancia_medica_ver.html',
        constancia=constancia, imprimir=True,
        centro=get_empresa_info(tenant_id) or {},
    )


def register_certificate_routes(app):
    app.add_url_rule('/facturacion/constancias-medicas', endpoint='facturacion_constancias_medicas', view_func=facturacion_constancias_medicas)
    app.add_url_rule('/facturacion/constancias-medicas/nueva', endpoint='facturacion_constancias_medicas_nueva', view_func=facturacion_constancias_medicas_nueva, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/constancias-medicas/<int:constancia_id>', endpoint='facturacion_constancia_medica_ver', view_func=facturacion_constancia_medica_ver)
    app.add_url_rule('/facturacion/constancias-medicas/<int:constancia_id>/editar', endpoint='facturacion_constancia_medica_editar', view_func=facturacion_constancia_medica_editar, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/constancias-medicas/<int:constancia_id>/anular', endpoint='facturacion_constancia_medica_anular', view_func=facturacion_constancia_medica_anular, methods=['POST'])
    app.add_url_rule('/facturacion/constancias-medicas/<int:constancia_id>/imprimir', endpoint='facturacion_constancia_medica_imprimir', view_func=facturacion_constancia_medica_imprimir)
