"""Rutas y helpers de licencias m?dicas y sus tipos."""

import json
import re
import secrets
from datetime import datetime

from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from auth import permission_required
from core.database import execute_query, execute_update, transactional_methods
from core.tenant import get_current_tenant_id
from routes.patients import paciente_adulto_sin_cedula
from routes.support import (
    calcular_edad_clinica, execute_paginated_query, sanitize_input, validate_int,
)


def medico_id_licencias_restringido():
    """Restringir al médico vinculado cuando el usuario tiene rol Médico."""
    roles_rbac = set(getattr(current_user, 'rbac_roles', ()))
    es_medico = (
        'Médico' in roles_rbac
        or getattr(current_user, 'perfil', None) == 'Médico'
    )
    es_administrador = (
        'Administrador' in roles_rbac
        or getattr(current_user, 'perfil', None) == 'Administrador'
    )
    medico_id = getattr(current_user, 'medico_id', None)
    return medico_id if medico_id and es_medico and not es_administrador else None


def actualizar_licencias_vencidas(tenant_id):
    execute_update(
        """
        UPDATE licencias_medicas
        SET estado='Vencida'
        WHERE tenant_id=%s AND estado='Emitida' AND fecha_termino < CURDATE()
        """,
        (tenant_id,)
    )


def obtener_licencia_medica(
    licencia_id,
    tenant_id,
    medico_id_restringido=None,
):
    return execute_query(
        """
        SELECT l.*, p.nombre AS paciente_nombre, p.cedula, p.fecha_nacimiento,
               p.telefono, p.direccion, m.nombre AS medico_nombre,
               m.especialidad, m.exequatur, t.nombre AS tipo_licencia,
               c.fecha AS consulta_fecha, c.motivo_consulta AS consulta_motivo,
               uc.nombre AS creado_por_nombre, um.nombre AS modificado_por_nombre,
               ua.nombre AS anulado_por_nombre
        FROM licencias_medicas l
        JOIN pacientes p ON p.id=l.paciente_id AND p.tenant_id=l.tenant_id
        JOIN medicos m ON m.id=l.medico_id AND m.tenant_id=l.tenant_id
        JOIN tipos_licencia_medica t ON t.id=l.tipo_licencia_id AND t.tenant_id=l.tenant_id
        LEFT JOIN consultas_clinicas c ON c.id=l.consulta_id AND c.tenant_id=l.tenant_id
        LEFT JOIN usuarios uc
          ON uc.id=l.created_by AND uc.tenant_id=l.tenant_id
        LEFT JOIN usuarios um
          ON um.id=l.updated_by AND um.tenant_id=l.tenant_id
        LEFT JOIN usuarios ua
          ON ua.id=l.anulado_por AND ua.tenant_id=l.tenant_id
        WHERE l.id=%s AND l.tenant_id=%s
          AND (%s IS NULL OR l.medico_id=%s)
        """,
        (
            licencia_id, tenant_id,
            medico_id_restringido, medico_id_restringido,
        )
    )


def contexto_formulario_licencia(
    tenant_id,
    paciente_preseleccionado=None,
    medico_id_restringido=None,
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
        SELECT c.id, c.paciente_id, c.fecha, c.diagnostico_principal,
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
    tipos = execute_query(
        "SELECT id, nombre FROM tipos_licencia_medica "
        "WHERE tenant_id=%s AND activo=1 ORDER BY nombre",
        (tenant_id,), fetch='all'
    ) or []
    return {
        'pacientes': pacientes,
        'medicos': medicos,
        'consultas': consultas,
        'tipos_licencia': tipos,
        'paciente_preseleccionado': paciente_preseleccionado,
        'licencias_restringidas': bool(medico_id_restringido),
    }


def validar_datos_licencia(tenant_id):
    paciente_id = validate_int(request.form.get('paciente_id'), min_value=1, default=None)
    medico_id = (
        medico_id_licencias_restringido()
        or validate_int(request.form.get('medico_id'), min_value=1, default=None)
    )
    consulta_id = validate_int(request.form.get('consulta_id'), min_value=1, default=None)
    tipo_id = validate_int(request.form.get('tipo_licencia_id'), min_value=1, default=None)
    diagnostico = sanitize_input(request.form.get('diagnostico', ''), 5000)
    motivo = sanitize_input(request.form.get('motivo_condicion', ''), 5000)
    observaciones = sanitize_input(request.form.get('observaciones', ''), 5000)
    fecha_emision = request.form.get('fecha_emision', '').strip()
    fecha_inicio = request.form.get('fecha_inicio', '').strip()
    fecha_termino = request.form.get('fecha_termino', '').strip()
    estado = request.form.get('estado', 'Borrador').strip()

    if not all([paciente_id, medico_id, tipo_id, diagnostico, motivo,
                fecha_emision, fecha_inicio, fecha_termino]):
        return None, 'Complete todos los campos obligatorios'
    if estado not in ['Borrador', 'Emitida']:
        return None, 'El estado seleccionado no es válido'
    try:
        emision = datetime.strptime(fecha_emision, '%Y-%m-%d').date()
        inicio = datetime.strptime(fecha_inicio, '%Y-%m-%d').date()
        termino = datetime.strptime(fecha_termino, '%Y-%m-%d').date()
    except ValueError:
        return None, 'Las fechas de la licencia no son válidas'
    if termino < inicio:
        return None, 'La fecha de término no puede ser menor que la fecha de inicio'
    cantidad_dias = (termino - inicio).days + 1

    paciente = execute_query(
        "SELECT id, cedula, fecha_nacimiento FROM pacientes "
        "WHERE id=%s AND tenant_id=%s",
        (paciente_id, tenant_id)
    )
    medico = execute_query(
        "SELECT id FROM medicos WHERE id=%s AND tenant_id=%s AND activo=1",
        (medico_id, tenant_id)
    )
    tipo = execute_query(
        "SELECT id FROM tipos_licencia_medica "
        "WHERE id=%s AND tenant_id=%s AND activo=1",
        (tipo_id, tenant_id)
    )
    if not paciente or not medico or not tipo:
        return None, 'El paciente, médico o tipo de licencia no es válido'
    if paciente_adulto_sin_cedula(paciente):
        return None, 'Debe actualizar la cédula propia del paciente antes de emitir la licencia'

    if consulta_id:
        consulta = execute_query(
            "SELECT id, paciente_id FROM consultas_clinicas "
            "WHERE id=%s AND tenant_id=%s "
            "AND (%s IS NULL OR medico_id=%s)",
            (
                consulta_id, tenant_id,
                medico_id_licencias_restringido(),
                medico_id_licencias_restringido(),
            )
        )
        if not consulta or consulta['paciente_id'] != paciente_id:
            return None, 'La consulta seleccionada no pertenece al paciente'

    return {
        'paciente_id': paciente_id, 'medico_id': medico_id,
        'consulta_id': consulta_id, 'tipo_id': tipo_id,
        'diagnostico': diagnostico,
        'motivo': motivo, 'observaciones': observaciones or None,
        'fecha_emision': emision, 'fecha_inicio': inicio,
        'fecha_termino': termino, 'cantidad_dias': cantidad_dias,
        'estado': estado
    }, None


@login_required
@permission_required('licencias.ver')
def facturacion_licencias_medicas():
    tenant_id = get_current_tenant_id()
    medico_id_restringido = medico_id_licencias_restringido()
    actualizar_licencias_vencidas(tenant_id)
    buscar = request.args.get('buscar', '').strip()
    fecha = request.args.get('fecha', '').strip()
    medico_id = medico_id_restringido or validate_int(
        request.args.get('medico_id'), min_value=1, default=None
    )
    estado = request.args.get('estado', '').strip()
    orden = request.args.get('orden', 'recientes').strip()
    query = """
        SELECT l.*, p.nombre AS paciente_nombre, m.nombre AS medico_nombre,
               t.nombre AS tipo_licencia
        FROM licencias_medicas l
        JOIN pacientes p
          ON p.id=l.paciente_id AND p.tenant_id=l.tenant_id
        JOIN medicos m
          ON m.id=l.medico_id AND m.tenant_id=l.tenant_id
        JOIN tipos_licencia_medica t
          ON t.id=l.tipo_licencia_id AND t.tenant_id=l.tenant_id
        WHERE l.tenant_id=%s
    """
    params = [tenant_id]
    if buscar:
        patron = f'%{buscar}%'
        phone_digits = re.sub(r'\D', '', buscar)
        phone_pattern = f'%{phone_digits}%' if phone_digits else patron
        query += """
            AND (
                l.codigo LIKE %s OR p.nombre LIKE %s OR p.cedula LIKE %s
                OR REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(
                    COALESCE(p.telefono,''),'-',''),' ',''),'(',''),')',''),'+','')
                    LIKE %s
                OR l.diagnostico LIKE %s
            )
        """
        params.extend([patron, patron, patron, phone_pattern, patron])
    if fecha:
        query += " AND (l.fecha_emision=%s OR l.fecha_inicio=%s OR l.fecha_termino=%s)"
        params.extend([fecha, fecha, fecha])
    if medico_id:
        query += " AND l.medico_id=%s"
        params.append(medico_id)
    if estado in ['Borrador', 'Emitida', 'Anulada', 'Vencida']:
        query += " AND l.estado=%s"
        params.append(estado)
    ordenes = {
        'recientes': 'l.fecha_emision DESC, l.id DESC',
        'antiguas': 'l.fecha_emision ASC, l.id ASC',
        'paciente': 'p.nombre ASC, l.fecha_emision DESC',
        'medico': 'm.nombre ASC, l.fecha_emision DESC',
        'estado': 'l.estado ASC, l.fecha_emision DESC'
    }
    licencias, pagination = execute_paginated_query(
        query,
        params,
        ordenes.get(orden, ordenes['recientes']),
    )
    medicos = execute_query(
        "SELECT id, nombre FROM medicos "
        "WHERE tenant_id=%s AND activo=1 "
        "AND (%s IS NULL OR id=%s) ORDER BY nombre",
        (
            tenant_id,
            medico_id_restringido,
            medico_id_restringido,
        ),
        fetch='all',
    ) or []
    return render_template(
        'facturacion/licencias_medicas.html', licencias=licencias,
        medicos=medicos, filtros=request.args, pagination=pagination,
        licencias_restringidas=bool(medico_id_restringido),
    )


@login_required
@transactional_methods('POST')
@permission_required('licencias.crear')
def facturacion_licencias_medicas_nueva():
    tenant_id = get_current_tenant_id()
    medico_id_restringido = medico_id_licencias_restringido()
    paciente_preseleccionado = validate_int(
        request.args.get('paciente_id') or request.form.get('paciente_id'),
        min_value=1, default=None
    )
    contexto = contexto_formulario_licencia(
        tenant_id,
        paciente_preseleccionado,
        medico_id_restringido,
    )
    if request.method == 'POST':
        datos, error = validar_datos_licencia(tenant_id)
        if error:
            flash(error, 'error')
            return render_template(
                'facturacion/licencia_medica_form.html',
                licencia=None, form_data=request.form, **contexto
            )
        duplicada = execute_query(
            """
            SELECT id FROM licencias_medicas
            WHERE tenant_id=%s AND paciente_id=%s AND medico_id=%s
              AND fecha_inicio=%s AND fecha_termino=%s
              AND diagnostico=%s AND estado<>'Anulada'
            """,
            (tenant_id, datos['paciente_id'], datos['medico_id'],
             datos['fecha_inicio'], datos['fecha_termino'], datos['diagnostico'])
        )
        if duplicada:
            flash('Ya existe una licencia igual; se evitó crear un duplicado', 'error')
            return render_template(
                'facturacion/licencia_medica_form.html',
                licencia=None, form_data=request.form, **contexto
            )
        solapada = execute_query(
            """
            SELECT codigo, fecha_inicio, fecha_termino
            FROM licencias_medicas
            WHERE tenant_id=%s AND paciente_id=%s AND estado<>'Anulada'
              AND fecha_inicio<=%s AND fecha_termino>=%s
            LIMIT 1
            """,
            (tenant_id, datos['paciente_id'],
             datos['fecha_termino'], datos['fecha_inicio'])
        )
        if solapada and request.form.get('confirmar_solapamiento') != '1':
            flash(
                f"El período se solapa con {solapada['codigo']} "
                f"({solapada['fecha_inicio']} a {solapada['fecha_termino']}). "
                "Marque la confirmación para continuar.",
                'warning'
            )
            return render_template(
                'facturacion/licencia_medica_form.html',
                licencia=None, form_data=request.form,
                advertencia_solapamiento=True, **contexto
            )

        codigo = None
        while not codigo:
            candidato = f"LM-{datetime.now().strftime('%Y%m%d')}-{secrets.token_hex(3).upper()}"
            if not execute_query(
                "SELECT id FROM licencias_medicas WHERE tenant_id=%s AND codigo=%s",
                (tenant_id, candidato)
            ):
                codigo = candidato
        licencia_id = execute_update(
            """
            INSERT INTO licencias_medicas (
                tenant_id, codigo, paciente_id, medico_id, consulta_id,
                tipo_licencia_id, diagnostico, motivo_condicion,
                observaciones, fecha_emision, fecha_inicio, fecha_termino,
                cantidad_dias, estado, created_by, updated_by
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s
            )
            """,
            (
                tenant_id, codigo, datos['paciente_id'], datos['medico_id'],
                datos['consulta_id'], datos['tipo_id'], datos['diagnostico'],
                datos['motivo'], datos['observaciones'],
                datos['fecha_emision'], datos['fecha_inicio'],
                datos['fecha_termino'], datos['cantidad_dias'],
                datos['estado'], current_user.id, current_user.id
            )
        )
        execute_update(
            """
            INSERT INTO auditoria_licencias_medicas (
                tenant_id, licencia_id, usuario_id, accion, datos_nuevos,
                ip, user_agent
            ) VALUES (%s, %s, %s, 'Creación', %s, %s, %s)
            """,
            (
                tenant_id, licencia_id, current_user.id,
                json.dumps(datos, default=str, ensure_ascii=False),
                request.remote_addr, (request.user_agent.string or '')[:500]
            )
        )
        flash('Licencia médica registrada exitosamente', 'success')
        return redirect(url_for(
            'facturacion_licencia_medica_ver', licencia_id=licencia_id
        ))

    return render_template(
        'facturacion/licencia_medica_form.html', licencia=None,
        form_data={}, fecha_actual=datetime.now().strftime('%Y-%m-%d'),
        **contexto
    )


@login_required
@permission_required('licencias.ver')
def facturacion_licencia_medica_ver(licencia_id):
    tenant_id = get_current_tenant_id()
    actualizar_licencias_vencidas(tenant_id)
    licencia = obtener_licencia_medica(licencia_id, tenant_id)
    if not licencia:
        flash('Licencia médica no encontrada', 'error')
        return redirect(url_for('facturacion_licencias_medicas'))
    licencia['edad'] = calcular_edad_clinica(
        licencia.get('fecha_nacimiento'), licencia['fecha_emision']
    )
    auditoria = execute_query(
        """
        SELECT a.*, u.nombre AS usuario_nombre
        FROM auditoria_licencias_medicas a
        LEFT JOIN usuarios u
          ON u.id=a.usuario_id AND u.tenant_id=a.tenant_id
        WHERE a.licencia_id=%s AND a.tenant_id=%s
        ORDER BY a.created_at DESC
        """,
        (licencia_id, tenant_id), fetch='all'
    ) or []
    return render_template(
        'facturacion/licencia_medica_ver.html',
        licencia=licencia, auditoria=auditoria, imprimir=False
    )


@login_required
@transactional_methods('POST')
@permission_required('licencias.editar')
def facturacion_licencia_medica_editar(licencia_id):
    tenant_id = get_current_tenant_id()
    medico_id_restringido = medico_id_licencias_restringido()
    licencia = obtener_licencia_medica(
        licencia_id,
        tenant_id,
        medico_id_restringido,
    )
    if not licencia:
        flash('Licencia médica no encontrada', 'error')
        return redirect(url_for('facturacion_licencias_medicas'))
    if licencia['estado'] != 'Borrador':
        flash('Solo las licencias en borrador pueden editarse', 'warning')
        return redirect(url_for('facturacion_licencia_medica_ver', licencia_id=licencia_id))
    contexto = contexto_formulario_licencia(
        tenant_id,
        licencia['paciente_id'],
        medico_id_restringido,
    )
    if request.method == 'POST':
        datos, error = validar_datos_licencia(tenant_id)
        if error:
            flash(error, 'error')
            return render_template(
                'facturacion/licencia_medica_form.html',
                licencia=licencia, form_data=request.form, **contexto
            )
        solapada = execute_query(
            """
            SELECT codigo, fecha_inicio, fecha_termino
            FROM licencias_medicas
            WHERE tenant_id=%s AND paciente_id=%s AND id<>%s
              AND estado<>'Anulada' AND fecha_inicio<=%s AND fecha_termino>=%s
            LIMIT 1
            """,
            (tenant_id, datos['paciente_id'], licencia_id,
             datos['fecha_termino'], datos['fecha_inicio'])
        )
        if solapada and request.form.get('confirmar_solapamiento') != '1':
            flash('Existe otra licencia que se solapa con este período', 'warning')
            return render_template(
                'facturacion/licencia_medica_form.html',
                licencia=licencia, form_data=request.form,
                advertencia_solapamiento=True, **contexto
            )
        anterior = json.dumps(licencia, default=str, ensure_ascii=False)
        version = licencia['version']
        execute_update(
            """
            UPDATE licencias_medicas SET
                paciente_id=%s, medico_id=%s, consulta_id=%s,
                tipo_licencia_id=%s, diagnostico=%s, motivo_condicion=%s,
                observaciones=%s, fecha_emision=%s,
                fecha_inicio=%s, fecha_termino=%s, cantidad_dias=%s,
                estado=%s, version=version+1, updated_by=%s
            WHERE id=%s AND tenant_id=%s AND estado='Borrador'
            """,
            (
                datos['paciente_id'], datos['medico_id'], datos['consulta_id'],
                datos['tipo_id'], datos['diagnostico'], datos['motivo'],
                datos['observaciones'], datos['fecha_emision'],
                datos['fecha_inicio'], datos['fecha_termino'],
                datos['cantidad_dias'], datos['estado'], current_user.id,
                licencia_id, tenant_id
            )
        )
        nueva = execute_query(
            "SELECT * FROM licencias_medicas WHERE id=%s AND tenant_id=%s",
            (licencia_id, tenant_id)
        )
        execute_update(
            """
            INSERT INTO auditoria_licencias_medicas (
                tenant_id, licencia_id, usuario_id, accion, version_anterior,
                datos_anteriores, datos_nuevos, ip, user_agent
            ) VALUES (%s, %s, %s, 'Modificación', %s, %s, %s, %s, %s)
            """,
            (
                tenant_id, licencia_id, current_user.id, version, anterior,
                json.dumps(nueva, default=str, ensure_ascii=False),
                request.remote_addr, (request.user_agent.string or '')[:500]
            )
        )
        flash('Licencia médica actualizada con trazabilidad', 'success')
        return redirect(url_for(
            'facturacion_licencia_medica_ver', licencia_id=licencia_id
        ))
    return render_template(
        'facturacion/licencia_medica_form.html', licencia=licencia,
        form_data=licencia, **contexto
    )


@login_required
@transactional_methods('POST')
@permission_required('licencias.anular')
def facturacion_licencia_medica_anular(licencia_id):
    tenant_id = get_current_tenant_id()
    licencia = obtener_licencia_medica(
        licencia_id,
        tenant_id,
        medico_id_licencias_restringido(),
    )
    motivo = sanitize_input(request.form.get('motivo_anulacion', ''), 2000)
    if not licencia:
        flash('Licencia médica no encontrada', 'error')
        return redirect(url_for('facturacion_licencias_medicas'))
    if licencia['estado'] == 'Anulada':
        flash('La licencia ya está anulada', 'warning')
        return redirect(url_for('facturacion_licencia_medica_ver', licencia_id=licencia_id))
    if not motivo:
        flash('Debe indicar el motivo de la anulación', 'error')
        return redirect(url_for('facturacion_licencia_medica_ver', licencia_id=licencia_id))
    execute_update(
        """
        UPDATE licencias_medicas
        SET estado='Anulada', anulado_por=%s, fecha_anulacion=NOW(),
            motivo_anulacion=%s, updated_by=%s, version=version+1
        WHERE id=%s AND tenant_id=%s
        """,
        (current_user.id, motivo, current_user.id, licencia_id, tenant_id)
    )
    execute_update(
        """
        INSERT INTO auditoria_licencias_medicas (
            tenant_id, licencia_id, usuario_id, accion, version_anterior,
            datos_anteriores, motivo, ip, user_agent
        ) VALUES (%s, %s, %s, 'Anulación', %s, %s, %s, %s, %s)
        """,
        (
            tenant_id, licencia_id, current_user.id, licencia['version'],
            json.dumps(licencia, default=str, ensure_ascii=False), motivo,
            request.remote_addr, (request.user_agent.string or '')[:500]
        )
    )
    flash('Licencia anulada; el documento permanece en el historial', 'success')
    return redirect(url_for('facturacion_licencia_medica_ver', licencia_id=licencia_id))


@login_required
@permission_required('licencias.imprimir')
def facturacion_licencia_medica_imprimir(licencia_id):
    licencia = obtener_licencia_medica(
        licencia_id,
        get_current_tenant_id(),
    )
    if not licencia:
        flash('Licencia médica no encontrada', 'error')
        return redirect(url_for('facturacion_licencias_medicas'))
    licencia['edad'] = calcular_edad_clinica(
        licencia.get('fecha_nacimiento'), licencia['fecha_emision']
    )
    return render_template(
        'facturacion/licencia_medica_ver.html',
        licencia=licencia, auditoria=[], imprimir=True
    )


@login_required
@permission_required('licencias.configurar')
def facturacion_tipos_licencia_medica():
    tenant_id = get_current_tenant_id()
    if request.method == 'POST':
        nombre = sanitize_input(request.form.get('nombre', ''), 120)
        if not nombre:
            flash('El nombre del tipo es obligatorio', 'error')
        elif execute_query(
            "SELECT id FROM tipos_licencia_medica WHERE tenant_id=%s AND nombre=%s",
            (tenant_id, nombre)
        ):
            flash('Ya existe un tipo de licencia con ese nombre', 'error')
        else:
            execute_update(
                "INSERT INTO tipos_licencia_medica "
                "(tenant_id, nombre, created_by, updated_by) VALUES (%s,%s,%s,%s)",
                (tenant_id, nombre, current_user.id, current_user.id)
            )
            flash('Tipo de licencia agregado', 'success')
        return redirect(url_for('facturacion_tipos_licencia_medica'))
    tipos = execute_query(
        "SELECT * FROM tipos_licencia_medica WHERE tenant_id=%s ORDER BY nombre",
        (tenant_id,), fetch='all'
    ) or []
    return render_template('facturacion/tipos_licencia_medica.html', tipos=tipos)


@login_required
@permission_required('licencias.configurar')
def facturacion_tipo_licencia_medica_actualizar(tipo_id):
    tenant_id = get_current_tenant_id()
    tipo = execute_query(
        "SELECT id FROM tipos_licencia_medica WHERE id=%s AND tenant_id=%s",
        (tipo_id, tenant_id)
    )
    if not tipo:
        flash('Tipo de licencia no encontrado', 'error')
        return redirect(url_for('facturacion_tipos_licencia_medica'))
    nombre = sanitize_input(request.form.get('nombre', ''), 120)
    activo = 1 if request.form.get('activo') == '1' else 0
    if not nombre:
        flash('El nombre es obligatorio', 'error')
    else:
        duplicado = execute_query(
            "SELECT id FROM tipos_licencia_medica "
            "WHERE tenant_id=%s AND nombre=%s AND id<>%s",
            (tenant_id, nombre, tipo_id)
        )
        if duplicado:
            flash('Ya existe otro tipo con ese nombre', 'error')
        else:
            execute_update(
                "UPDATE tipos_licencia_medica SET nombre=%s, activo=%s, "
                "updated_by=%s WHERE id=%s AND tenant_id=%s",
                (nombre, activo, current_user.id, tipo_id, tenant_id)
            )
            flash('Tipo de licencia actualizado', 'success')
    return redirect(url_for('facturacion_tipos_licencia_medica'))


def register_license_routes(app):
    app.add_url_rule('/facturacion/licencias-medicas', endpoint='facturacion_licencias_medicas', view_func=facturacion_licencias_medicas)
    app.add_url_rule('/facturacion/licencias-medicas/nueva', endpoint='facturacion_licencias_medicas_nueva', view_func=facturacion_licencias_medicas_nueva, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/licencias-medicas/<int:licencia_id>', endpoint='facturacion_licencia_medica_ver', view_func=facturacion_licencia_medica_ver)
    app.add_url_rule('/facturacion/licencias-medicas/<int:licencia_id>/editar', endpoint='facturacion_licencia_medica_editar', view_func=facturacion_licencia_medica_editar, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/licencias-medicas/<int:licencia_id>/anular', endpoint='facturacion_licencia_medica_anular', view_func=facturacion_licencia_medica_anular, methods=['POST'])
    app.add_url_rule('/facturacion/licencias-medicas/<int:licencia_id>/imprimir', endpoint='facturacion_licencia_medica_imprimir', view_func=facturacion_licencia_medica_imprimir)
    app.add_url_rule('/facturacion/tipos-licencia-medica', endpoint='facturacion_tipos_licencia_medica', view_func=facturacion_tipos_licencia_medica, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/tipos-licencia-medica/<int:tipo_id>/actualizar', endpoint='facturacion_tipo_licencia_medica_actualizar', view_func=facturacion_tipo_licencia_medica_actualizar, methods=['POST'])
