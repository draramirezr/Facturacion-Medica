"""Rutas de la factura al paciente (Facturación → Paciente)."""

from datetime import date, timedelta

from flask import flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from auth import permission_required
from core.database import execute_query
from core.tenant import get_current_tenant_id
from routes.support import execute_paginated_query, sanitize_input, validate_int
from services.factura_paciente import (
    CONCEPTOS,
    DESTINATARIO,
    METODOS_PAGO,
    TIPO_POR_DEFECTO,
    TIPOS_COMPROBANTE,
    FacturaPacienteError,
    anular_factura_paciente,
    cargar_factura_paciente,
    registrar_atencion,
    validar_factura_paciente,
)


def _lineas_del_formulario():
    descripciones = request.form.getlist('linea_descripcion')
    cantidades = request.form.getlist('linea_cantidad')
    precios = request.form.getlist('linea_precio')
    servicios = request.form.getlist('linea_servicio_id')
    seguros = request.form.getlist('linea_seguro')
    autorizaciones = request.form.getlist('linea_autorizacion')
    cubiertos = request.form.getlist('linea_cubre')
    lineas = []
    for i, descripcion in enumerate(descripciones):
        if not (descripcion or '').strip() and not (precios[i] if i < len(precios) else ''):
            continue  # Fila vacía.
        lineas.append({
            'descripcion': sanitize_input(descripcion, 500),
            'cantidad': cantidades[i] if i < len(cantidades) else 1,
            'precio': precios[i] if i < len(precios) else '',
            'servicio_id': servicios[i] if i < len(servicios) else None,
            'seguro': seguros[i] if i < len(seguros) else '',
            'autorizacion': sanitize_input(autorizaciones[i] if i < len(autorizaciones) else '', 50),
            'cubre': cubiertos[i] if i < len(cubiertos) else '',
        })
    return lineas


def _contexto_formulario(tenant_id, form=None, lineas=None):
    servicios = execute_query(
        '''
        SELECT id, nombre, precio_base
        FROM servicios
        WHERE tenant_id=%s AND activo=1
        ORDER BY nombre
        ''',
        (tenant_id,),
        fetch='all',
    ) or []
    medicos = execute_query(
        'SELECT id, nombre FROM medicos WHERE tenant_id=%s AND activo=1 ORDER BY nombre',
        (tenant_id,),
        fetch='all',
    ) or []
    ars_list = execute_query(
        'SELECT id, nombre FROM ars WHERE tenant_id=%s AND activo=1 ORDER BY nombre',
        (tenant_id,),
        fetch='all',
    ) or []
    secuencias = {
        fila['tipo']: fila
        for fila in (execute_query(
            '''
            SELECT tipo, fecha_fin FROM ncf
            WHERE tenant_id=%s AND activo=1 AND tipo IN ('B01', 'B02')
            ''',
            (tenant_id,),
            fetch='all',
        ) or [])
    }
    paciente_id = (form or {}).get('paciente_id') or request.args.get('paciente_id') or ''
    pacientes = []
    if paciente_id:
        pacientes = execute_query(
            'SELECT id, nombre, cedula, nss, telefono, ars_id FROM pacientes WHERE id=%s AND tenant_id=%s',
            (validate_int(paciente_id, min_value=1, default=0), tenant_id),
            fetch='all',
        ) or []
    return {
        'form': form or {},
        'lineas': lineas or [{}],
        'servicios': servicios,
        'medicos': medicos,
        'ars_list': ars_list,
        'secuencias': secuencias,
        'pacientes': pacientes,
        'paciente_id': paciente_id,
        'tipos': TIPOS_COMPROBANTE,
        'tipo_defecto': TIPO_POR_DEFECTO,
        'metodos': METODOS_PAGO,
        'conceptos': CONCEPTOS,
    }


@login_required
@permission_required('facturacion.crear')
def factura_paciente_nueva():
    tenant_id = get_current_tenant_id()
    if request.method == 'POST':
        form = request.form.to_dict(flat=True)
        lineas = _lineas_del_formulario()
        try:
            datos = validar_factura_paciente(tenant_id, form, lineas)
            factura_id, enviadas_ars = registrar_atencion(tenant_id, datos, current_user.id)
        except FacturaPacienteError as error:
            flash(str(error), 'error')
            return render_template(
                'facturacion/factura_paciente_form.html',
                **_contexto_formulario(tenant_id, form, lineas or [{}]),
            )
        aviso_ars = (
            f' {enviadas_ars} servicio(s) enviado(s) a Estado de Facturación para la ARS.'
            if enviadas_ars else ''
        )
        if factura_id:
            flash(f'Factura emitida y cobrada.{aviso_ars}', 'success')
            return redirect(url_for('factura_paciente_ver', factura_id=factura_id, imprimir=1))
        # Todo lo cubrió el seguro: no hay nada que cobrarle al paciente.
        flash(f'El paciente no tiene diferencia que pagar.{aviso_ars}', 'success')
        return redirect(url_for('facturacion_pacientes_pendientes'))
    return render_template(
        'facturacion/factura_paciente_form.html',
        **_contexto_formulario(tenant_id),
    )


@login_required
@permission_required('facturacion.ver')
def facturas_pacientes():
    tenant_id = get_current_tenant_id()
    buscar = sanitize_input(request.args.get('buscar', ''), 120)
    query = '''
        SELECT id, ncf, fecha_emision, nombre_paciente, cedula_paciente,
               total, estado, metodo_pago, nombre_medico
        FROM facturas
        WHERE tenant_id=%s AND destinatario=%s
    '''
    params = [tenant_id, DESTINATARIO]
    if buscar:
        patron = f'%{buscar}%'
        query += ' AND (nombre_paciente LIKE %s OR ncf LIKE %s OR cedula_paciente LIKE %s)'
        params += [patron, patron, patron]
    facturas, pagination = execute_paginated_query(query, params, 'fecha_emision DESC, id DESC')
    hoy = execute_query(
        '''
        SELECT COUNT(*) AS n, COALESCE(SUM(total), 0) AS total
        FROM facturas
        WHERE tenant_id=%s AND destinatario=%s AND estado <> 'Anulada'
          AND fecha_emision = %s
        ''',
        (tenant_id, DESTINATARIO, date.today()),
    ) or {}
    return render_template(
        'facturacion/facturas_pacientes.html',
        facturas=facturas,
        pagination=pagination,
        buscar=buscar,
        hoy_cantidad=int(hoy.get('n') or 0),
        hoy_total=hoy.get('total') or 0,
    )


@login_required
@permission_required('facturacion.ver')
def factura_paciente_ver(factura_id):
    tenant_id = get_current_tenant_id()
    factura = cargar_factura_paciente(tenant_id, factura_id)
    if not factura:
        flash('Factura no encontrada', 'error')
        return redirect(url_for('facturas_pacientes'))
    from services.subscriptions import get_empresa_info

    empresa_db = get_empresa_info(tenant_id) or {}
    # Emisor: datos fiscales obligatorios en el comprobante (RNC, dirección).
    centro = {
        'razon_social': empresa_db.get('razon_social') or empresa_db.get('nombre'),
        'nombre': empresa_db.get('nombre'),
        'rnc': empresa_db.get('rnc'),
        'direccion': empresa_db.get('direccion'),
        'telefono': empresa_db.get('telefono'),
        'email': empresa_db.get('email'),
    }
    return render_template(
        'facturacion/factura_paciente_ver.html',
        factura=factura,
        centro=centro,
        tipos=TIPOS_COMPROBANTE,
        imprimir=request.args.get('imprimir') == '1',
    )


@login_required
@permission_required('facturacion.anular')
def factura_paciente_anular(factura_id):
    tenant_id = get_current_tenant_id()
    try:
        anular_factura_paciente(
            tenant_id, factura_id, request.form.get('motivo_anulacion'), current_user.id,
        )
        flash('Factura anulada.', 'success')
    except FacturaPacienteError as error:
        flash(str(error), 'error')
    return redirect(url_for('factura_paciente_ver', factura_id=factura_id))


@login_required
@permission_required('facturacion.crear')
def api_consultas_recientes_paciente(paciente_id):
    """Servicios registrados del paciente (últimos 45 días) para sugerir el cobro
    de la diferencia o copago que la ARS no cubre."""
    tenant_id = get_current_tenant_id()
    filas = execute_query(
        '''
        SELECT pp.fecha_servicio, pp.servicios_realizados, a.nombre AS ars
        FROM pacientes_pendientes pp
        LEFT JOIN ars a ON a.id = pp.ars_id AND a.tenant_id = pp.tenant_id
        WHERE pp.tenant_id=%s AND pp.paciente_id=%s AND pp.fecha_servicio >= %s
        ORDER BY pp.fecha_servicio DESC
        LIMIT 10
        ''',
        (tenant_id, paciente_id, date.today() - timedelta(days=45)),
        fetch='all',
    ) or []
    return jsonify([
        {
            'fecha': fila['fecha_servicio'].strftime('%d/%m/%Y')
            if hasattr(fila['fecha_servicio'], 'strftime') else str(fila['fecha_servicio']),
            'servicio': (fila.get('servicios_realizados') or 'Consulta').split(' - Autorización:')[0][:200],
            'ars': fila.get('ars') or '',
        }
        for fila in filas
    ])


def register_patient_invoice_routes(app):
    app.add_url_rule(
        '/facturacion/pacientes/facturas',
        endpoint='facturas_pacientes', view_func=facturas_pacientes,
    )
    app.add_url_rule(
        '/facturacion/pacientes/facturas/nueva',
        endpoint='factura_paciente_nueva', view_func=factura_paciente_nueva,
        methods=['GET', 'POST'],
    )
    app.add_url_rule(
        '/facturacion/pacientes/facturas/<int:factura_id>',
        endpoint='factura_paciente_ver', view_func=factura_paciente_ver,
    )
    app.add_url_rule(
        '/facturacion/pacientes/facturas/<int:factura_id>/anular',
        endpoint='factura_paciente_anular', view_func=factura_paciente_anular,
        methods=['POST'],
    )
    app.add_url_rule(
        '/api/facturacion/pacientes/<int:paciente_id>/consultas-recientes',
        endpoint='api_consultas_recientes_paciente',
        view_func=api_consultas_recientes_paciente,
    )
