"""Rutas y helpers de hojas de enfermer?a."""

import json
import re
from datetime import datetime

from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from auth import permission_required
from core.database import execute_query, execute_update
from core.tenant import get_current_tenant_id
from routes.support import (
    calcular_edad_clinica, sanitize_input, validate_digits, validate_int,
)
from services.subscriptions import get_empresa_info

@login_required
@permission_required('enfermeria.ver')
def facturacion_hojas_enfermeria():
    """Listado de medicamentos y materiales suministrados en emergencia."""
    tenant_id = get_current_tenant_id()
    buscar = request.args.get('buscar', '').strip()
    query = '''
        SELECT h.id, h.fecha_servicio, h.hora_servicio, h.nombre_paciente,
               h.responsable, h.firma_responsable
        FROM hojas_enfermeria h
        LEFT JOIN pacientes p
          ON p.id=h.paciente_id AND p.tenant_id=h.tenant_id
        WHERE h.tenant_id=%s
    '''
    params = [tenant_id]
    if buscar:
        patron = f'%{buscar}%'
        phone_digits = re.sub(r'\D', '', buscar)
        phone_pattern = f'%{phone_digits}%' if phone_digits else patron
        query += """
            AND (
                h.nombre_paciente LIKE %s OR p.cedula LIKE %s OR p.nss LIKE %s
                OR REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(
                    COALESCE(p.telefono,''),'-',''),' ',''),'(',''),')',''),'+','')
                    LIKE %s
            )
        """
        params.extend([patron, patron, patron, phone_pattern])
    query += ' ORDER BY h.fecha_servicio DESC, h.hora_servicio DESC, h.id DESC'
    hojas = execute_query(query, tuple(params), fetch='all') or []
    return render_template(
        'facturacion/hojas_enfermeria.html',
        hojas=hojas,
        buscar=buscar
    )


@login_required
@permission_required('enfermeria.crear')
def facturacion_hojas_enfermeria_nueva():
    """Registrar una hoja de enfermería asociada a un paciente."""
    tenant_id = get_current_tenant_id()
    pacientes = execute_query('''
        SELECT p.id, p.nombre, p.fecha_nacimiento, p.sexo, p.direccion,
               p.nombre_pariente, p.telefono_pariente, a.nombre AS ars_nombre
        FROM pacientes p
        LEFT JOIN ars a ON a.id=p.ars_id AND a.tenant_id=p.tenant_id
        WHERE p.tenant_id=%s
        ORDER BY p.nombre
    ''', (tenant_id,), fetch='all') or []
    emergencias = execute_query('''
        SELECT id, paciente_id, fecha, motivo_emergencia
        FROM historias_emergencia
        WHERE tenant_id=%s
        ORDER BY fecha DESC, id DESC
    ''', (tenant_id,), fetch='all') or []
    paciente_preseleccionado = validate_int(
        request.args.get('paciente_id') or request.form.get('paciente_id'),
        min_value=1, default=None
    )

    if request.method == 'POST':
        paciente_id = validate_int(request.form.get('paciente_id'), min_value=1, default=None)
        emergencia_id = validate_int(
            request.form.get('historia_emergencia_id'), min_value=1, default=None
        )
        fecha_servicio = request.form.get('fecha_servicio', '').strip()
        hora_servicio = request.form.get('hora_servicio', '').strip()
        responsable = sanitize_input(request.form.get('responsable', ''), 200)
        telefono = re.sub(r'\D', '', request.form.get('telefono_responsable', ''))
        observaciones = sanitize_input(request.form.get('observaciones', ''), 3000)
        firma = sanitize_input(request.form.get('firma_responsable', ''), 200)

        paciente = execute_query('''
            SELECT p.*, a.nombre AS ars_nombre
            FROM pacientes p
            LEFT JOIN ars a ON a.id=p.ars_id AND a.tenant_id=p.tenant_id
            WHERE p.id=%s AND p.tenant_id=%s
        ''', (paciente_id, tenant_id)) if paciente_id else None
        if not paciente or not all([
            fecha_servicio, hora_servicio, responsable, telefono, firma
        ]):
            flash('Complete todos los datos obligatorios de la hoja', 'error')
            return render_template(
                'facturacion/hoja_enfermeria_form.html',
                pacientes=pacientes, emergencias=emergencias,
                paciente_preseleccionado=paciente_preseleccionado,
                fecha_actual=fecha_servicio, hora_actual=hora_servicio
            )
        if not validate_digits(telefono, 10):
            flash('El teléfono del responsable debe contener exactamente 10 números', 'error')
            return render_template(
                'facturacion/hoja_enfermeria_form.html',
                pacientes=pacientes, emergencias=emergencias,
                paciente_preseleccionado=paciente_id,
                fecha_actual=fecha_servicio, hora_actual=hora_servicio
            )
        try:
            fecha_obj = datetime.strptime(fecha_servicio, '%Y-%m-%d').date()
            datetime.strptime(hora_servicio, '%H:%M')
        except ValueError:
            flash('La fecha u hora del servicio no es válida', 'error')
            return render_template(
                'facturacion/hoja_enfermeria_form.html',
                pacientes=pacientes, emergencias=emergencias,
                paciente_preseleccionado=paciente_id,
                fecha_actual=fecha_servicio, hora_actual=hora_servicio
            )
        if emergencia_id:
            emergencia = execute_query(
                'SELECT id FROM historias_emergencia '
                'WHERE id=%s AND paciente_id=%s AND tenant_id=%s',
                (emergencia_id, paciente_id, tenant_id)
            )
            if not emergencia:
                flash('La historia de emergencia no pertenece al paciente', 'error')
                return redirect(url_for(
                    'facturacion_hojas_enfermeria_nueva',
                    paciente_id=paciente_id
                ))

        detalles = request.form.getlist('detalle[]')
        fechas = request.form.getlist('fecha_linea[]')
        horas = request.form.getlist('hora_linea[]')
        cantidades = request.form.getlist('cantidad[]')
        dosis_vias = request.form.getlist('dosis_via[]')
        suministros = []
        for indice, detalle_raw in enumerate(detalles):
            detalle = sanitize_input(detalle_raw, 500)
            if not detalle:
                continue
            fecha_linea = fechas[indice] if indice < len(fechas) else fecha_servicio
            hora_linea = horas[indice] if indice < len(horas) else hora_servicio
            try:
                datetime.strptime(fecha_linea, '%Y-%m-%d')
                datetime.strptime(hora_linea, '%H:%M')
            except ValueError:
                flash('Revise las fechas y horas de los suministros', 'error')
                return redirect(url_for(
                    'facturacion_hojas_enfermeria_nueva',
                    paciente_id=paciente_id
                ))
            suministros.append({
                'fecha': fecha_linea,
                'hora': hora_linea,
                'detalle': detalle,
                'cantidad': sanitize_input(
                    cantidades[indice] if indice < len(cantidades) else '', 100
                ),
                'dosis_via': sanitize_input(
                    dosis_vias[indice] if indice < len(dosis_vias) else '', 200
                ),
            })
        if not suministros:
            flash('Agregue al menos un detalle del suministro', 'error')
            return redirect(url_for(
                'facturacion_hojas_enfermeria_nueva',
                paciente_id=paciente_id
            ))

        hoja_id = execute_update('''
            INSERT INTO hojas_enfermeria (
                tenant_id, paciente_id, historia_emergencia_id,
                fecha_servicio, hora_servicio, nombre_paciente, edad, sexo,
                direccion, responsable, telefono_responsable, ars_nombre,
                medicamentos_materiales, observaciones, firma_responsable,
                created_by
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s
            )
        ''', (
            tenant_id, paciente_id, emergencia_id, fecha_servicio, hora_servicio,
            paciente['nombre'], calcular_edad_clinica(
                paciente.get('fecha_nacimiento'), fecha_obj
            ), paciente.get('sexo'), paciente.get('direccion'), responsable,
            telefono, paciente.get('ars_nombre'),
            json.dumps(suministros, ensure_ascii=False),
            observaciones or None, firma, current_user.id
        ))
        flash('Hoja de enfermería registrada exitosamente', 'success')
        return redirect(url_for(
            'facturacion_hoja_enfermeria_ver', hoja_id=hoja_id
        ))

    return render_template(
        'facturacion/hoja_enfermeria_form.html',
        pacientes=pacientes,
        emergencias=emergencias,
        paciente_preseleccionado=paciente_preseleccionado,
        fecha_actual=datetime.now().strftime('%Y-%m-%d'),
        hora_actual=datetime.now().strftime('%H:%M')
    )


def obtener_hoja_enfermeria(hoja_id, tenant_id):
    hoja = execute_query(
        'SELECT * FROM hojas_enfermeria WHERE id=%s AND tenant_id=%s',
        (hoja_id, tenant_id)
    )
    if hoja:
        try:
            hoja['suministros'] = json.loads(
                hoja.get('medicamentos_materiales') or '[]'
            )
        except (TypeError, ValueError):
            hoja['suministros'] = []
    return hoja


@login_required
@permission_required('enfermeria.ver')
def facturacion_hoja_enfermeria_ver(hoja_id):
    hoja = obtener_hoja_enfermeria(hoja_id, get_current_tenant_id())
    if not hoja:
        flash('Hoja de enfermería no encontrada', 'error')
        return redirect(url_for('facturacion_hojas_enfermeria'))
    return render_template(
        'facturacion/hoja_enfermeria_ver.html',
        hoja=hoja, imprimir=False,
        centro=get_empresa_info(get_current_tenant_id())
    )


@login_required
@permission_required('enfermeria.imprimir')
def facturacion_hoja_enfermeria_imprimir(hoja_id):
    hoja = obtener_hoja_enfermeria(hoja_id, get_current_tenant_id())
    if not hoja:
        flash('Hoja de enfermería no encontrada', 'error')
        return redirect(url_for('facturacion_hojas_enfermeria'))
    return render_template(
        'facturacion/hoja_enfermeria_ver.html',
        hoja=hoja, imprimir=True,
        centro=get_empresa_info(get_current_tenant_id())
    )


def register_nursing_routes(app):
    app.add_url_rule('/facturacion/hojas-enfermeria', endpoint='facturacion_hojas_enfermeria', view_func=facturacion_hojas_enfermeria)
    app.add_url_rule('/facturacion/hojas-enfermeria/nueva', endpoint='facturacion_hojas_enfermeria_nueva', view_func=facturacion_hojas_enfermeria_nueva, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/hojas-enfermeria/<int:hoja_id>', endpoint='facturacion_hoja_enfermeria_ver', view_func=facturacion_hoja_enfermeria_ver)
    app.add_url_rule('/facturacion/hojas-enfermeria/<int:hoja_id>/imprimir', endpoint='facturacion_hoja_enfermeria_imprimir', view_func=facturacion_hoja_enfermeria_imprimir)
