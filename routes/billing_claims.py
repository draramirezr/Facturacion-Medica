"""Reclamaciones a ARS sobre facturas."""
from datetime import datetime
from decimal import ROUND_HALF_UP, Decimal
from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from auth import permission_required
from core.database import execute_query, execute_update
from core.tenant import get_current_tenant_id
from routes.support import execute_paginated_query, sanitize_input, validate_int
from routes.billing_common import CENTAVO


def _fecha_input_reclamacion(valor):
    if hasattr(valor, 'strftime'):
        return valor.strftime('%Y-%m-%d')
    texto = str(valor or '').strip()
    return texto[:10] if texto else ''


def _validar_datos_reclamacion(tenant_id):
    factura_id = validate_int(request.form.get('factura_id'), min_value=1, default=None)
    fecha_reclamacion = sanitize_input(request.form.get('fecha_reclamacion', ''), max_length=10)
    observaciones = sanitize_input(request.form.get('observaciones', ''), max_length=2000)
    if not factura_id or not fecha_reclamacion:
        return None, 'Factura, monto y fecha son obligatorios'
    try:
        datetime.strptime(fecha_reclamacion, '%Y-%m-%d')
    except ValueError:
        return None, 'Fecha de reclamación inválida'
    factura = execute_query(
        'SELECT id, total FROM facturas WHERE id = %s AND tenant_id = %s AND estado != %s'
        " AND destinatario = 'ARS'",
        (factura_id, tenant_id, 'Anulada'),
    )
    if not factura:
        return None, 'Factura no encontrada'
    try:
        monto_dec = Decimal(str(request.form.get('monto_reclamado') or '0').replace(',', ''))
    except (TypeError, ValueError, ArithmeticError):
        return None, 'Monto inválido'
    if not monto_dec.is_finite() or monto_dec <= 0:
        return None, 'El monto debe ser mayor a cero'
    if monto_dec > Decimal(str(factura.get('total') or 0)):
        return None, 'El monto reclamado no puede superar el total de la factura'
    monto_reclamado = monto_dec.quantize(CENTAVO, rounding=ROUND_HALF_UP)
    return {
        'factura_id': factura_id,
        'monto_reclamado': monto_reclamado,
        'fecha_reclamacion': fecha_reclamacion,
        'observaciones': observaciones or None,
    }, None


def _contexto_formulario_reclamacion(tenant_id, factura_id=None, fecha_reclamacion=None):
    ars_id = validate_int(request.args.get('ars_id'), min_value=1, default=None)
    ncf = sanitize_input(request.args.get('ncf', ''), max_length=20)
    ars_list = execute_query(
        'SELECT id, nombre FROM ars WHERE activo = 1 AND tenant_id = %s ORDER BY nombre',
        (tenant_id,),
        fetch='all',
    ) or []
    facturas_sql = '''
        SELECT f.id, f.numero_factura, f.ncf, f.nombre_ars, f.total,
               f.fecha_emision, f.estado
        FROM facturas f
        WHERE f.tenant_id = %s AND f.estado != 'Anulada'
          AND f.destinatario = 'ARS'
    '''
    facturas_params = [tenant_id]
    if ars_id:
        facturas_sql += ' AND f.ars_id = %s'
        facturas_params.append(ars_id)
    if ncf:
        facturas_sql += ' AND f.ncf LIKE %s'
        facturas_params.append(f'%{ncf}%')
    facturas_sql += ' ORDER BY f.fecha_emision DESC, f.numero_factura DESC LIMIT 100'
    facturas_list = execute_query(
        facturas_sql, tuple(facturas_params), fetch='all'
    ) or []
    if factura_id and not any(str(item['id']) == str(factura_id) for item in facturas_list):
        actual = execute_query(
            '''
            SELECT f.id, f.numero_factura, f.ncf, f.nombre_ars, f.total,
                   f.fecha_emision, f.estado
            FROM facturas f
            WHERE f.id = %s AND f.tenant_id = %s
            ''',
            (factura_id, tenant_id),
        )
        if actual:
            facturas_list.insert(0, actual)
    return {
        'facturas_list': facturas_list,
        'ars_list': ars_list,
        'ars_id': ars_id,
        'ncf': ncf,
        'fecha_actual': (
            _fecha_input_reclamacion(fecha_reclamacion)
            or datetime.now().strftime('%Y-%m-%d')
        ),
        'form_data': request.form if request.method == 'POST' else {},
    }


@login_required
@permission_required('facturacion.ver')
def facturacion_reclamaciones():
    """Lista de reclamaciones - Filtrado por tenant"""
    tenant_id = get_current_tenant_id()
    query = '''
        SELECT r.id, r.factura_id, r.monto_reclamado, r.fecha_reclamacion,
               r.observaciones, r.estado,
               f.numero_factura, f.ncf, f.nombre_ars, f.total AS total_factura
        FROM reclamaciones r
        JOIN facturas f
          ON r.factura_id = f.id AND f.tenant_id = r.tenant_id
        WHERE r.tenant_id = %s
    '''
    reclamaciones_list, pagination = execute_paginated_query(
        query,
        (tenant_id,),
        'r.fecha_reclamacion DESC, r.id DESC',
    )
    return render_template(
        'facturacion/reclamaciones.html',
        reclamaciones_list=reclamaciones_list,
        pagination=pagination,
    )


@login_required
@permission_required('facturacion.editar')
def facturacion_reclamaciones_nueva():
    """Crear nueva reclamación"""
    tenant_id = get_current_tenant_id()
    
    if request.method == 'POST':
        datos, error = _validar_datos_reclamacion(tenant_id)
        if error:
            flash(error, 'error')
            return render_template(
                'facturacion/reclamacion_form.html',
                reclamacion=None,
                **_contexto_formulario_reclamacion(tenant_id),
            )
        execute_update('''
            INSERT INTO reclamaciones (factura_id, monto_reclamado, fecha_reclamacion, observaciones, tenant_id, created_by, estado)
            VALUES (%s, %s, %s, %s, %s, %s, 'Pendiente')
        ''', (
            datos['factura_id'], datos['monto_reclamado'],
            datos['fecha_reclamacion'], datos['observaciones'],
            tenant_id, current_user.id,
        ))
        flash('Reclamación creada exitosamente', 'success')
        return redirect(url_for('facturacion_reclamaciones'))
    return render_template(
        'facturacion/reclamacion_form.html',
        reclamacion=None,
        **_contexto_formulario_reclamacion(tenant_id),
    )


@login_required
@permission_required('facturacion.ver')
def facturacion_reclamacion_detalle(reclamacion_id):
    """Mostrar una reclamación perteneciente a la empresa activa."""
    tenant_id = get_current_tenant_id()
    reclamacion = execute_query('''
        SELECT r.*, f.numero_factura, f.ncf, f.nombre_ars,
               f.total AS total_factura, f.estado AS estado_factura
        FROM reclamaciones r
        JOIN facturas f
          ON f.id = r.factura_id AND f.tenant_id = r.tenant_id
        WHERE r.id = %s AND r.tenant_id = %s
    ''', (reclamacion_id, tenant_id))
    if not reclamacion:
        flash('Reclamación no encontrada', 'error')
        return redirect(url_for('facturacion_reclamaciones'))
    return render_template(
        'facturacion/reclamacion_detalle.html',
        reclamacion=reclamacion,
    )


@login_required
@permission_required('facturacion.editar')
def facturacion_reclamacion_editar(reclamacion_id):
    """Editar una reclamación de la empresa activa."""
    tenant_id = get_current_tenant_id()
    reclamacion = execute_query(
        'SELECT * FROM reclamaciones WHERE id = %s AND tenant_id = %s',
        (reclamacion_id, tenant_id),
    )
    if not reclamacion:
        flash('Reclamación no encontrada', 'error')
        return redirect(url_for('facturacion_reclamaciones'))
    if request.method == 'POST':
        datos, error = _validar_datos_reclamacion(tenant_id)
        if error:
            flash(error, 'error')
            return render_template(
                'facturacion/reclamacion_form.html',
                reclamacion=reclamacion,
                **_contexto_formulario_reclamacion(
                    tenant_id,
                    reclamacion.get('factura_id'),
                    reclamacion.get('fecha_reclamacion'),
                ),
            )
        execute_update('''
            UPDATE reclamaciones
            SET factura_id = %s,
                monto_reclamado = %s,
                fecha_reclamacion = %s,
                observaciones = %s
            WHERE id = %s AND tenant_id = %s
        ''', (
            datos['factura_id'], datos['monto_reclamado'],
            datos['fecha_reclamacion'], datos['observaciones'],
            reclamacion_id, tenant_id,
        ))
        flash('Reclamación actualizada', 'success')
        return redirect(url_for(
            'facturacion_reclamacion_detalle',
            reclamacion_id=reclamacion_id,
        ))
    return render_template(
        'facturacion/reclamacion_form.html',
        reclamacion=reclamacion,
        **_contexto_formulario_reclamacion(
            tenant_id,
            reclamacion.get('factura_id'),
            reclamacion.get('fecha_reclamacion'),
        ),
    )


@login_required
@permission_required('facturacion.editar')
def facturacion_reclamacion_cambiar_estado(reclamacion_id):
    """Actualizar el estado sin permitir acceso entre empresas."""
    tenant_id = get_current_tenant_id()
    estado = request.form.get('estado', '').strip()
    observaciones = request.form.get('observaciones_estado', '').strip()
    estados_permitidos = {'Pendiente', 'Procesada', 'Rechazada'}

    if estado not in estados_permitidos:
        flash('Estado de reclamación inválido', 'error')
        return redirect(url_for(
            'facturacion_reclamacion_detalle',
            reclamacion_id=reclamacion_id,
        ))
    if estado == 'Rechazada' and not observaciones:
        flash('Indique el motivo del rechazo', 'error')
        return redirect(url_for(
            'facturacion_reclamacion_detalle',
            reclamacion_id=reclamacion_id,
        ))

    reclamacion = execute_query(
        'SELECT id FROM reclamaciones WHERE id = %s AND tenant_id = %s',
        (reclamacion_id, tenant_id),
    )
    if not reclamacion:
        flash('Reclamación no encontrada', 'error')
        return redirect(url_for('facturacion_reclamaciones'))

    execute_update('''
        UPDATE reclamaciones
        SET estado = %s,
            observaciones = CASE
                WHEN %s <> '' THEN %s
                ELSE observaciones
            END
        WHERE id = %s AND tenant_id = %s
    ''', (
        estado,
        observaciones,
        observaciones,
        reclamacion_id,
        tenant_id,
    ))
    flash('Estado de reclamación actualizado', 'success')
    return redirect(url_for(
        'facturacion_reclamacion_detalle',
        reclamacion_id=reclamacion_id,
    ))
