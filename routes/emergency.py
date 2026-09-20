"""Rutas y helpers de historias cl?nicas de emergencia."""

import json
from datetime import datetime

from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from auth import permission_required
from core.database import execute_query, execute_update
from core.tenant import get_current_tenant_id
from routes.patients import paciente_adulto_sin_cedula
from routes.support import sanitize_input, validate_int


def medico_id_emergencias_restringido():
    """Restringir emergencias al médico vinculado para el rol Médico."""
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


@login_required
@permission_required('emergencia.ver')
def facturacion_historias_emergencia():
    """Listado de historias clínicas de emergencia del tenant."""
    tenant_id = get_current_tenant_id()
    medico_id_restringido = medico_id_emergencias_restringido()
    historias = execute_query('''
        SELECT id, fecha, hora_servicio, nombre_paciente, edad, sexo,
               motivo_emergencia, estatus_paciente, medico_nombre
        FROM historias_emergencia
        WHERE tenant_id = %s
          AND (%s IS NULL OR medico_id=%s)
        ORDER BY fecha DESC, hora_servicio DESC, id DESC
    ''', (
        tenant_id,
        medico_id_restringido,
        medico_id_restringido,
    ), fetch='all') or []
    return render_template(
        'facturacion/historias_emergencia.html',
        historias=historias,
        emergencias_restringidas=bool(medico_id_restringido),
    )


@login_required
@permission_required('emergencia.crear')
def facturacion_historias_emergencia_nueva():
    """Registrar una historia clínica de emergencia."""
    tenant_id = get_current_tenant_id()
    medico_id_restringido = medico_id_emergencias_restringido()

    if request.method == 'POST':
        paciente_id = request.form.get('paciente_id', '').strip()
        medico_id = (
            str(medico_id_restringido)
            if medico_id_restringido
            else request.form.get('medico_id', '').strip()
        )
        fecha = request.form.get('fecha', '').strip()
        hora_servicio = request.form.get('hora_servicio', '').strip()
        autorizacion = sanitize_input(request.form.get('autorizacion', ''), 100)
        numero_afiliado = sanitize_input(request.form.get('numero_afiliado', ''), 100)
        edad = validate_int(request.form.get('edad'), min_value=0, max_value=130, default=None)
        sexo_historia = request.form.get('sexo_historia', '').strip()
        motivo = sanitize_input(request.form.get('motivo_emergencia', ''), 4000)
        historia_actual = sanitize_input(request.form.get('historia_enfermedad', ''), 8000)
        diagnostico = sanitize_input(request.form.get('diagnostico_impresion', ''), 4000)
        estatus = request.form.get('estatus_paciente', '').strip()
        origen = request.form.get('origen_enfermedad', '').strip()
        observaciones = sanitize_input(request.form.get('observaciones', ''), 4000)

        if (not all([paciente_id, medico_id, fecha, hora_servicio, sexo_historia,
                     motivo, historia_actual, diagnostico, estatus, origen])
                or edad is None):
            flash('Complete todos los campos obligatorios de la historia', 'error')
            return redirect(url_for('facturacion_historias_emergencia_nueva'))

        paciente = execute_query('''
            SELECT p.*, a.nombre AS ars_nombre
            FROM pacientes p
            LEFT JOIN ars a
              ON p.ars_id = a.id AND a.tenant_id = p.tenant_id
            WHERE p.id = %s AND p.tenant_id = %s
        ''', (paciente_id, tenant_id))
        medico = execute_query(
            'SELECT id, nombre FROM medicos WHERE id = %s AND tenant_id = %s AND activo = 1',
            (medico_id, tenant_id)
        )
        if not paciente or not medico:
            flash('El paciente o médico seleccionado no es válido', 'error')
            return redirect(url_for('facturacion_historias_emergencia_nueva'))
        if paciente_adulto_sin_cedula(paciente):
            flash('Debe actualizar la cédula propia del paciente antes de registrar la emergencia', 'warning')
            return redirect(url_for('facturacion_paciente_acciones', paciente_id=paciente['id']))

        try:
            datetime.strptime(fecha, '%Y-%m-%d')
            datetime.strptime(hora_servicio, '%H:%M')
        except ValueError:
            flash('La fecha o la hora del servicio no es válida', 'error')
            return redirect(url_for('facturacion_historias_emergencia_nueva'))

        estatus_validos = ['Dado de alta', 'Referido', 'Alta a petición', 'Admitido', 'Fallecido']
        origenes_validos = ['Enfermedad común', 'Accidente de tránsito', 'Maternidad', 'Accidente laboral']
        if (estatus not in estatus_validos or origen not in origenes_validos
                or sexo_historia not in ['M', 'F', 'Otro']):
            flash('Seleccione un estatus y origen válidos', 'error')
            return redirect(url_for('facturacion_historias_emergencia_nueva'))

        pruebas_validas = {'Hemograma', 'Examen de orina', 'HCG suero', 'Glucosa',
                           'Radiografía', 'Sonografía', 'EKG'}
        manejos_validos = {'Hidratación', 'Nebulizaciones', 'RCP', 'Cura',
                           'Inmovilización', 'Oxígeno', 'Sutura'}
        pruebas = [valor for valor in request.form.getlist('pruebas')
                   if valor in pruebas_validas]
        manejos = [valor for valor in request.form.getlist('manejos')
                   if valor in manejos_validos]

        datos_clinicos = {
            'atenciones_previas': request.form.get('atenciones_previas') == 'si',
            'atenciones_previas_donde': sanitize_input(request.form.get('atenciones_previas_donde', ''), 500),
            'alergias': request.form.get('alergias') == 'si',
            'alergias_detalle': sanitize_input(request.form.get('alergias_detalle', ''), 500),
            'antecedentes': sanitize_input(request.form.get('antecedentes', ''), 2000),
            'hallazgos_examen': sanitize_input(request.form.get('hallazgos_examen', ''), 4000),
            'ta': sanitize_input(request.form.get('ta', ''), 30),
            'fc': sanitize_input(request.form.get('fc', ''), 30),
            'fr': sanitize_input(request.form.get('fr', ''), 30),
            'temperatura': sanitize_input(request.form.get('temperatura', ''), 30),
            'pruebas': pruebas,
            'otras_pruebas': sanitize_input(request.form.get('otras_pruebas', ''), 500),
            'manejos': manejos,
            'oxigeno_inicio': sanitize_input(request.form.get('oxigeno_inicio', ''), 20),
            'oxigeno_final': sanitize_input(request.form.get('oxigeno_final', ''), 20),
            'oxigeno_total_hora': sanitize_input(request.form.get('oxigeno_total_hora', ''), 50),
            'medicamentos': sanitize_input(request.form.get('medicamentos', ''), 4000)
        }

        historia_id = execute_update('''
            INSERT INTO historias_emergencia (
                tenant_id, paciente_id, medico_id, fecha, hora_servicio, autorizacion,
                nombre_paciente, edad, sexo, ars_nombre, numero_afiliado, nss,
                motivo_emergencia, historia_enfermedad, datos_clinicos,
                diagnostico_impresion, estatus_paciente, origen_enfermedad,
                observaciones, medico_nombre, created_by
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
        ''', (
            tenant_id, paciente['id'], medico['id'], fecha, hora_servicio,
            autorizacion or None, paciente['nombre'], edad, sexo_historia,
            paciente.get('ars_nombre'), numero_afiliado or None, paciente.get('nss'),
            motivo, historia_actual, json.dumps(datos_clinicos, ensure_ascii=False),
            diagnostico, estatus, origen, observaciones or None, medico['nombre'],
            current_user.id
        ))
        flash('Historia de emergencia registrada exitosamente', 'success')
        return redirect(url_for('facturacion_historia_emergencia_ver', historia_id=historia_id))

    pacientes = execute_query('''
        SELECT p.id, p.nombre, p.fecha_nacimiento, p.sexo, p.cedula, p.nss,
               p.ars_id, a.nombre AS ars_nombre
        FROM pacientes p
        LEFT JOIN ars a
          ON p.ars_id = a.id AND a.tenant_id = p.tenant_id
        WHERE p.tenant_id = %s
        ORDER BY p.nombre
    ''', (tenant_id,), fetch='all') or []
    medicos = execute_query(
        'SELECT id, nombre FROM medicos '
        'WHERE tenant_id = %s AND activo = 1 '
        'AND (%s IS NULL OR id=%s) ORDER BY nombre',
        (
            tenant_id,
            medico_id_restringido,
            medico_id_restringido,
        ),
        fetch='all',
    ) or []
    paciente_preseleccionado = validate_int(
        request.args.get('paciente_id'), min_value=1, default=None
    )
    if not any(paciente['id'] == paciente_preseleccionado for paciente in pacientes):
        paciente_preseleccionado = None
    if paciente_preseleccionado:
        paciente_seleccionado = next(
            paciente for paciente in pacientes
            if paciente['id'] == paciente_preseleccionado
        )
        if paciente_adulto_sin_cedula(paciente_seleccionado):
            flash('Debe actualizar la cédula propia del paciente antes de registrar la emergencia', 'warning')
            return redirect(url_for(
                'facturacion_paciente_acciones',
                paciente_id=paciente_preseleccionado
            ))
    return render_template(
        'facturacion/historia_emergencia_form.html',
        pacientes=pacientes,
        medicos=medicos,
        paciente_preseleccionado=paciente_preseleccionado,
        fecha_actual=datetime.now().strftime('%Y-%m-%d'),
        hora_actual=datetime.now().strftime('%H:%M'),
        emergencias_restringidas=bool(medico_id_restringido),
    )


def obtener_historia_emergencia(
    historia_id,
    tenant_id,
    medico_id_restringido=None,
):
    historia = execute_query(
        'SELECT * FROM historias_emergencia '
        'WHERE id = %s AND tenant_id = %s '
        'AND (%s IS NULL OR medico_id=%s)',
        (
            historia_id, tenant_id,
            medico_id_restringido, medico_id_restringido,
        )
    )
    if historia:
        try:
            historia['datos'] = json.loads(historia.get('datos_clinicos') or '{}')
        except (TypeError, ValueError):
            historia['datos'] = {}
    return historia


@login_required
@permission_required('emergencia.ver')
def facturacion_historia_emergencia_ver(historia_id):
    historia = obtener_historia_emergencia(
        historia_id,
        get_current_tenant_id(),
    )
    if not historia:
        flash('Historia de emergencia no encontrada', 'error')
        return redirect(url_for('facturacion_historias_emergencia'))
    return render_template('facturacion/historia_emergencia_ver.html', historia=historia, imprimir=False)


@login_required
@permission_required('emergencia.imprimir')
def facturacion_historia_emergencia_imprimir(historia_id):
    historia = obtener_historia_emergencia(
        historia_id,
        get_current_tenant_id(),
    )
    if not historia:
        flash('Historia de emergencia no encontrada', 'error')
        return redirect(url_for('facturacion_historias_emergencia'))
    return render_template('facturacion/historia_emergencia_ver.html', historia=historia, imprimir=True)


def register_emergency_routes(app):
    app.add_url_rule('/facturacion/historias-emergencia', endpoint='facturacion_historias_emergencia', view_func=facturacion_historias_emergencia)
    app.add_url_rule('/facturacion/historias-emergencia/nueva', endpoint='facturacion_historias_emergencia_nueva', view_func=facturacion_historias_emergencia_nueva, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/historias-emergencia/<int:historia_id>', endpoint='facturacion_historia_emergencia_ver', view_func=facturacion_historia_emergencia_ver)
    app.add_url_rule('/facturacion/historias-emergencia/<int:historia_id>/imprimir', endpoint='facturacion_historia_emergencia_imprimir', view_func=facturacion_historia_emergencia_imprimir)
