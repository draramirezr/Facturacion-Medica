"""Rutas y helpers de recetas m?dicas."""

import re
import secrets
from datetime import datetime

from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from auth import permission_required
from core.database import execute_query, execute_update, transactional_methods
from core.tenant import get_current_tenant_id
from routes.support import (
    execute_paginated_query, id_consulta_retorno, sanitize_input, validate_int,
)
from services.tenant_mail import notificar_paciente


def clave_nombre_medicamento(nombre):
    """Normalizar el nombre para comparar duplicados sin mayúsculas ni espacios extra."""
    return ' '.join(str(nombre or '').split()).casefold()


def medico_id_recetas_restringido():
    """Restringir recetas al médico vinculado para usuarios con rol Médico."""
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


def obtener_receta_medica(receta_id, tenant_id, medico_id_restringido=None):
    receta = execute_query('''
        SELECT r.*, p.nombre AS paciente_nombre, p.cedula,
               p.fecha_nacimiento, p.telefono, p.direccion,
               m.nombre AS medico_nombre, m.especialidad, m.exequatur,
               c.fecha AS consulta_fecha
        FROM recetas_medicas r
        JOIN pacientes p ON p.id=r.paciente_id AND p.tenant_id=r.tenant_id
        JOIN medicos m ON m.id=r.medico_id AND m.tenant_id=r.tenant_id
        LEFT JOIN consultas_clinicas c
          ON c.id=r.consulta_id AND c.tenant_id=r.tenant_id
        WHERE r.id=%s AND r.tenant_id=%s
          AND (%s IS NULL OR r.medico_id=%s)
    ''', (
        receta_id, tenant_id,
        medico_id_restringido, medico_id_restringido,
    ))
    if receta:
        receta['medicamentos'] = execute_query('''
            SELECT * FROM receta_medicamentos
            WHERE receta_id=%s AND tenant_id=%s
            ORDER BY orden, id
        ''', (receta_id, tenant_id), fetch='all') or []
    return receta


@login_required
@permission_required('recetas.ver')
def facturacion_recetas_medicas():
    tenant_id = get_current_tenant_id()
    medico_id_restringido = medico_id_recetas_restringido()
    buscar = request.args.get('buscar', '').strip()
    paciente_id = validate_int(
        request.args.get('paciente_id'), min_value=1, default=None
    )
    medico_id = medico_id_restringido or validate_int(
        request.args.get('medico_id'), min_value=1, default=None
    )
    estado = request.args.get('estado', '').strip()
    query = '''
        SELECT r.id, r.codigo, r.fecha, r.diagnostico, r.estado,
               p.nombre AS paciente_nombre, m.nombre AS medico_nombre,
               COUNT(rm.id) AS total_medicamentos
        FROM recetas_medicas r
        JOIN pacientes p ON p.id=r.paciente_id AND p.tenant_id=r.tenant_id
        JOIN medicos m ON m.id=r.medico_id AND m.tenant_id=r.tenant_id
        LEFT JOIN receta_medicamentos rm
          ON rm.receta_id=r.id AND rm.tenant_id=r.tenant_id
        WHERE r.tenant_id=%s
    '''
    params = [tenant_id]
    if buscar:
        patron = f'%{buscar}%'
        phone_digits = re.sub(r'\D', '', buscar)
        phone_pattern = f'%{phone_digits}%' if phone_digits else patron
        query += (
            ' AND (r.codigo LIKE %s OR p.nombre LIKE %s OR p.cedula LIKE %s '
            "OR REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(COALESCE(p.telefono,''),"
            "'-',''),' ',''),'(',''),')',''),'+','') LIKE %s "
            'OR m.nombre LIKE %s OR r.diagnostico LIKE %s '
            'OR EXISTS (SELECT 1 FROM receta_medicamentos busqueda '
            'WHERE busqueda.receta_id=r.id AND busqueda.tenant_id=r.tenant_id '
            'AND busqueda.medicamento LIKE %s))'
        )
        params.extend([
            patron, patron, patron, phone_pattern,
            patron, patron, patron,
        ])
    if paciente_id:
        query += ' AND r.paciente_id=%s'
        params.append(paciente_id)
    if medico_id:
        query += ' AND r.medico_id=%s'
        params.append(medico_id)
    if estado in ['Emitida', 'Anulada']:
        query += ' AND r.estado=%s'
        params.append(estado)
    query += ' GROUP BY r.id'
    recetas, pagination = execute_paginated_query(
        query,
        params,
        'r.fecha DESC, r.id DESC',
    )
    pacientes = execute_query(
        'SELECT id, nombre FROM pacientes WHERE tenant_id=%s ORDER BY nombre',
        (tenant_id,), fetch='all'
    ) or []
    medicos = execute_query(
        'SELECT id, nombre FROM medicos WHERE tenant_id=%s AND activo=1 '
        'AND (%s IS NULL OR id=%s) ORDER BY nombre',
        (
            tenant_id,
            medico_id_restringido,
            medico_id_restringido,
        ),
        fetch='all',
    ) or []
    return render_template(
        'facturacion/recetas_medicas.html',
        recetas=recetas, pacientes=pacientes, medicos=medicos,
        filtros=request.args, pagination=pagination,
        recetas_restringidas=bool(medico_id_restringido),
    )


@login_required
@transactional_methods('POST')
@permission_required('recetas.crear')
def facturacion_recetas_medicas_nueva():
    tenant_id = get_current_tenant_id()
    medico_id_restringido = medico_id_recetas_restringido()
    consulta_id = validate_int(
        request.args.get('consulta_id') or request.form.get('consulta_id'),
        min_value=1, default=None
    )
    consulta = None
    if consulta_id:
        consulta = execute_query('''
            SELECT c.id, c.paciente_id, c.medico_id, c.fecha,
                   c.diagnostico_principal, c.codigo_cie10,
                   p.nombre AS paciente_nombre
            FROM consultas_clinicas c
            JOIN pacientes p ON p.id=c.paciente_id AND p.tenant_id=c.tenant_id
            WHERE c.id=%s AND c.tenant_id=%s
              AND (%s IS NULL OR c.medico_id=%s)
        ''', (
            consulta_id, tenant_id,
            medico_id_restringido, medico_id_restringido,
        ))
        if not consulta:
            flash('La consulta seleccionada no existe', 'error')
            return redirect(url_for('facturacion_recetas_medicas'))
    paciente_preseleccionado = validate_int(
        request.args.get('paciente_id') or request.form.get('paciente_id'),
        min_value=1, default=None
    )
    if consulta:
        paciente_preseleccionado = consulta['paciente_id']
    pacientes = execute_query(
        'SELECT id, nombre, cedula, fecha_nacimiento FROM pacientes '
        'WHERE tenant_id=%s ORDER BY nombre',
        (tenant_id,), fetch='all'
    ) or []
    medicos = execute_query(
        'SELECT id, nombre, especialidad FROM medicos '
        'WHERE tenant_id=%s AND activo=1 '
        'AND (%s IS NULL OR id=%s) ORDER BY nombre',
        (
            tenant_id,
            medico_id_restringido,
            medico_id_restringido,
        ),
        fetch='all',
    ) or []
    consultas = execute_query('''
        SELECT c.id, c.paciente_id, c.medico_id, c.fecha,
               c.diagnostico_principal, c.codigo_cie10, m.nombre AS medico_nombre
        FROM consultas_clinicas c
        JOIN medicos m ON m.id=c.medico_id AND m.tenant_id=c.tenant_id
        WHERE c.tenant_id=%s
          AND (%s IS NULL OR c.medico_id=%s)
        ORDER BY c.fecha DESC, c.id DESC LIMIT 300
    ''', (
        tenant_id,
        medico_id_restringido,
        medico_id_restringido,
    ), fetch='all') or []
    if request.method == 'POST':
        paciente_id = validate_int(
            request.form.get('paciente_id'), min_value=1, default=None
        )
        medico_id = medico_id_restringido or validate_int(
            request.form.get('medico_id'), min_value=1, default=None
        )
        fecha = request.form.get('fecha', '').strip()
        diagnostico = sanitize_input(request.form.get('diagnostico', ''), 5000)
        codigo_cie10 = sanitize_input(
            request.form.get('codigo_cie10', ''), 30
        ).upper()
        indicaciones_generales = sanitize_input(
            request.form.get('indicaciones_generales', ''), 5000
        )
        try:
            fecha_obj = datetime.strptime(fecha, '%Y-%m-%d').date()
        except ValueError:
            fecha_obj = None
        paciente = execute_query(
            'SELECT id FROM pacientes WHERE id=%s AND tenant_id=%s',
            (paciente_id, tenant_id)
        ) if paciente_id else None
        medico = execute_query(
            'SELECT id FROM medicos WHERE id=%s AND tenant_id=%s AND activo=1',
            (medico_id, tenant_id)
        ) if medico_id else None
        if not paciente or not medico or not fecha_obj:
            flash('Paciente, médico y fecha son obligatorios', 'error')
        elif fecha_obj > datetime.now().date():
            flash('La fecha de emisión no puede ser futura', 'error')
        elif consulta and (
            consulta['paciente_id'] != paciente_id
            or consulta['medico_id'] != medico_id
        ):
            flash('El paciente y médico deben coincidir con la Historia Clínica', 'error')
        else:
            nombres = request.form.getlist('medicamento[]')
            presentaciones = request.form.getlist('presentacion[]')
            dosis = request.form.getlist('dosis[]')
            vias = request.form.getlist('via[]')
            frecuencias = request.form.getlist('frecuencia[]')
            duraciones = request.form.getlist('duracion[]')
            cantidades = request.form.getlist('cantidad[]')
            indicaciones = request.form.getlist('indicaciones[]')
            medicamentos = []
            nombres_usados = set()
            for indice, nombre in enumerate(nombres):
                nombre = sanitize_input(nombre, 250)
                if not nombre:
                    continue
                clave = clave_nombre_medicamento(nombre)
                if clave in nombres_usados:
                    medicamentos = []
                    flash(
                        'Este medicamento ya está en la receta. '
                        'No se puede agregar dos veces.',
                        'error'
                    )
                    break
                nombres_usados.add(clave)
                dosis_item = sanitize_input(
                    dosis[indice] if indice < len(dosis) else '', 150
                )
                frecuencia = sanitize_input(
                    frecuencias[indice] if indice < len(frecuencias) else '', 150
                )
                duracion = sanitize_input(
                    duraciones[indice] if indice < len(duraciones) else '', 150
                )
                if not all([dosis_item, frecuencia, duracion]):
                    medicamentos = []
                    flash(
                        'Cada medicamento requiere dosis, frecuencia y duración',
                        'error'
                    )
                    break
                medicamentos.append({
                    'medicamento': nombre,
                    'presentacion': sanitize_input(
                        presentaciones[indice] if indice < len(presentaciones) else '', 150
                    ),
                    'dosis': dosis_item,
                    'via': sanitize_input(
                        vias[indice] if indice < len(vias) else '', 100
                    ),
                    'frecuencia': frecuencia,
                    'duracion': duracion,
                    'cantidad': sanitize_input(
                        cantidades[indice] if indice < len(cantidades) else '', 100
                    ),
                    'indicaciones': sanitize_input(
                        indicaciones[indice] if indice < len(indicaciones) else '', 2000
                    )
                })
            if medicamentos:
                codigo_temporal = f"TMP-{secrets.token_hex(8)}"
                receta_id = execute_update('''
                    INSERT INTO recetas_medicas (
                        tenant_id, codigo, paciente_id, medico_id, consulta_id,
                        fecha, diagnostico, codigo_cie10,
                        indicaciones_generales, estado, created_by
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,'Emitida',%s)
                ''', (
                    tenant_id, codigo_temporal, paciente_id, medico_id,
                    consulta_id, fecha_obj, diagnostico or None,
                    codigo_cie10 or None, indicaciones_generales or None,
                    current_user.id
                ))
                codigo = f"REC-{fecha_obj.year}-{receta_id:06d}"
                execute_update(
                    'UPDATE recetas_medicas SET codigo=%s '
                    'WHERE id=%s AND tenant_id=%s',
                    (codigo, receta_id, tenant_id)
                )
                for orden, item in enumerate(medicamentos, 1):
                    execute_update('''
                        INSERT INTO receta_medicamentos (
                            tenant_id, receta_id, medicamento, presentacion,
                            dosis, via, frecuencia, duracion, cantidad,
                            indicaciones, orden
                        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ''', (
                        tenant_id, receta_id, item['medicamento'],
                        item['presentacion'] or None, item['dosis'],
                        item['via'] or None, item['frecuencia'],
                        item['duracion'], item['cantidad'] or None,
                        item['indicaciones'] or None, orden
                    ))
                flash('Receta médica emitida correctamente', 'success')
                ok, _detalle = notificar_paciente(
                    tenant_id,
                    paciente_id,
                    'Su receta médica',
                    '<p>Se emitió una receta médica a su nombre. Consulte al consultorio si necesita el detalle.</p>',
                )
                if ok:
                    flash('Se envió un aviso al correo del paciente.', 'info')
                volver = id_consulta_retorno()
                if volver:
                    return redirect(url_historia_clinica(volver, 'recetas'))
                return redirect(url_for(
                    'facturacion_receta_medica_ver', receta_id=receta_id
                ))
        form_data = request.form
        volver = id_consulta_retorno()
        if volver:
            return redirect(url_historia_clinica(volver, 'recetas'))
    else:
        form_data = {}
    return render_template(
        'facturacion/receta_medica_form.html',
        pacientes=pacientes, medicos=medicos, consultas=consultas,
        consulta=consulta, paciente_preseleccionado=paciente_preseleccionado,
        form_data=form_data, fecha_actual=datetime.now().strftime('%Y-%m-%d'),
        recetas_restringidas=bool(medico_id_restringido),
    )


@login_required
@permission_required('recetas.ver')
def facturacion_receta_medica_ver(receta_id):
    receta = obtener_receta_medica(receta_id, get_current_tenant_id())
    if not receta:
        flash('Receta médica no encontrada', 'error')
        return redirect(url_for('facturacion_recetas_medicas'))
    receta['edad'] = calcular_edad_clinica(
        receta.get('fecha_nacimiento'), receta['fecha']
    )
    return render_template(
        'facturacion/receta_medica_ver.html', receta=receta, imprimir=False
    )


@login_required
@permission_required('recetas.imprimir')
def facturacion_receta_medica_imprimir(receta_id):
    receta = obtener_receta_medica(receta_id, get_current_tenant_id())
    if not receta:
        flash('Receta médica no encontrada', 'error')
        return redirect(url_for('facturacion_recetas_medicas'))
    receta['edad'] = calcular_edad_clinica(
        receta.get('fecha_nacimiento'), receta['fecha']
    )
    return render_template(
        'facturacion/receta_medica_ver.html', receta=receta, imprimir=True
    )


@login_required
@permission_required('recetas.anular')
def facturacion_receta_medica_anular(receta_id):
    tenant_id = get_current_tenant_id()
    medico_id_restringido = medico_id_recetas_restringido()
    receta = execute_query(
        'SELECT id, estado FROM recetas_medicas '
        'WHERE id=%s AND tenant_id=%s '
        'AND (%s IS NULL OR medico_id=%s)',
        (
            receta_id, tenant_id,
            medico_id_restringido, medico_id_restringido,
        )
    )
    motivo = sanitize_input(request.form.get('motivo_anulacion', ''), 2000)
    if not receta:
        flash('Receta médica no encontrada', 'error')
        return redirect(url_for('facturacion_recetas_medicas'))
    if receta['estado'] == 'Anulada':
        flash('La receta ya está anulada', 'warning')
    elif not motivo:
        flash('Indique el motivo de anulación', 'error')
    else:
        execute_update('''
            UPDATE recetas_medicas SET estado='Anulada', anulada_por=%s,
                fecha_anulacion=NOW(), motivo_anulacion=%s
            WHERE id=%s AND tenant_id=%s
        ''', (current_user.id, motivo, receta_id, tenant_id))
        flash('Receta anulada; permanece en el historial', 'success')
    return redirect(url_for(
        'facturacion_receta_medica_ver', receta_id=receta_id
    ))


def register_prescription_routes(app):
    app.add_url_rule('/facturacion/recetas-medicas', endpoint='facturacion_recetas_medicas', view_func=facturacion_recetas_medicas)
    app.add_url_rule('/facturacion/recetas-medicas/nueva', endpoint='facturacion_recetas_medicas_nueva', view_func=facturacion_recetas_medicas_nueva, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/recetas-medicas/<int:receta_id>', endpoint='facturacion_receta_medica_ver', view_func=facturacion_receta_medica_ver)
    app.add_url_rule('/facturacion/recetas-medicas/<int:receta_id>/imprimir', endpoint='facturacion_receta_medica_imprimir', view_func=facturacion_receta_medica_imprimir)
    app.add_url_rule('/facturacion/recetas-medicas/<int:receta_id>/anular', endpoint='facturacion_receta_medica_anular', view_func=facturacion_receta_medica_anular, methods=['POST'])
