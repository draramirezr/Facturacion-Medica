"""Rutas del dominio de facturación."""
import base64
import json
import logging
import os
import re
import secrets
import zipfile
from datetime import date, datetime, timedelta
from decimal import Decimal, InvalidOperation
from io import BytesIO
from flask import current_app, flash, jsonify, make_response, redirect, render_template, request, send_file, url_for
from flask_login import current_user, login_required
from markupsafe import escape
from auth import permission_required, user_has_permission
from auth.helpers import usuario_es_dueno_software
from core.database import database_transaction, execute_query, execute_update, get_db_connection
from core.tenant import get_current_tenant_id, validate_tenant_access
from ecf import ECFBuildError, ECFBuilder, ECFCertificateResolutionError, ECFPrintableError, ECFSchemaError, ECFSigningError, ECFValidationError, ECFValidator, TenantCertificateProvider, build_encf, build_stamp, generate_e31_pdf, generate_qr, reserve_encf
from routes.patients import paciente_adulto_sin_cedula
from routes.support import execute_paginated_query, sanitize_input, validate_int
from services.subscriptions import get_empresa_info
from services.ecf_operations import consultar_resultado_ecf_dgii, ecf_habilitado_para_tenant, obtener_configuracion_ecf_tenant, procesar_envio_ecf_dgii
logger = logging.getLogger(__name__)
try:
    from sendgrid import SendGridAPIClient
    from sendgrid.helpers.mail import Mail
    SENDGRID_AVAILABLE = True
except ImportError:
    SENDGRID_AVAILABLE = False
try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_RIGHT
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
try:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill, Protection
    from openpyxl.utils import get_column_letter
    from openpyxl.worksheet.datavalidation import DataValidation
    OPENPYXL_AVAILABLE = True
except ImportError:
    OPENPYXL_AVAILABLE = False


@login_required
def facturacion_menu():
    """Menú principal de facturación"""
    if usuario_es_dueno_software(current_user):
        return redirect(url_for('admin_empresas'))
    roles_rbac = set(getattr(current_user, 'rbac_roles', ()))
    es_administrador = (
        'Administrador' in roles_rbac
        or getattr(current_user, 'perfil', None) == 'Administrador'
    )
    if (
        getattr(current_user, 'medico_id', None)
        and user_has_permission(current_user, 'turnos.cola_propia')
        and not es_administrador
    ):
        return redirect(url_for('turnos_mi_cola'))
    return render_template('facturacion/menu.html')

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
        'SELECT id, total FROM facturas WHERE id = %s AND tenant_id = %s AND estado != %s',
        (factura_id, tenant_id, 'Anulada'),
    )
    if not factura:
        return None, 'Factura no encontrada'
    try:
        monto_reclamado = float(request.form.get('monto_reclamado') or 0)
    except (TypeError, ValueError):
        return None, 'Monto inválido'
    if monto_reclamado <= 0:
        return None, 'El monto debe ser mayor a cero'
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

def _fecha_input_pago(valor):
    if hasattr(valor, 'strftime'):
        return valor.strftime('%Y-%m-%d')
    texto = str(valor or '').strip()
    return texto[:10] if texto else ''


def _lineas_de_pago(tenant_id, pago):
    lineas = execute_query('''
        SELECT pf.factura_id, pf.monto_aplicado,
               f.numero_factura, f.total, f.nombre_ars
        FROM pago_facturas pf
        JOIN facturas f
          ON f.id = pf.factura_id AND f.tenant_id = pf.tenant_id
        WHERE pf.pago_id = %s AND pf.tenant_id = %s
        ORDER BY f.numero_factura
    ''', (pago['id'], tenant_id), fetch='all') or []
    if lineas:
        return lineas
    factura_id = pago.get('factura_id')
    if not factura_id:
        return []
    factura = execute_query(
        '''
        SELECT id, numero_factura, total, nombre_ars
        FROM facturas
        WHERE id = %s AND tenant_id = %s
        ''',
        (factura_id, tenant_id),
    )
    if not factura:
        return []
    return [{
        'factura_id': factura['id'],
        'monto_aplicado': pago.get('monto_total') or pago.get('monto') or 0,
        'numero_factura': factura['numero_factura'],
        'total': factura['total'],
        'nombre_ars': factura.get('nombre_ars'),
    }]


FACTURAS_ANTIGUAS_PAGO = 5


def _ars_del_pago(tenant_id, pago_id):
    if not pago_id:
        return None
    fila = execute_query(
        '''
        SELECT f.ars_id
        FROM pago_facturas pf
        JOIN facturas f
          ON f.id = pf.factura_id AND f.tenant_id = pf.tenant_id
        WHERE pf.pago_id = %s AND pf.tenant_id = %s AND f.ars_id IS NOT NULL
        LIMIT 1
        ''',
        (pago_id, tenant_id),
    )
    return fila.get('ars_id') if fila else None


def _consultar_facturas_pago(tenant_id, pago_id, extra_where='', extra_params=(), orden='', limite=20):
    pago_id = pago_id or 0
    saldo = '''
        COALESCE(
            SUM(CASE WHEN pf.pago_id <> %s THEN pf.monto_aplicado ELSE 0 END),
            0
        )
    '''
    return execute_query(
        f'''
        SELECT f.id, f.numero_factura, f.nombre_ars, f.ars_id, f.total,
               f.fecha_emision, f.estado, {saldo} AS monto_pagado
        FROM facturas f
        LEFT JOIN pago_facturas pf
          ON f.id = pf.factura_id AND pf.tenant_id = f.tenant_id
        WHERE f.tenant_id = %s AND f.estado != 'Anulada'
          {extra_where}
        GROUP BY f.id
        HAVING (f.total - {saldo}) > 0
            OR EXISTS (
                SELECT 1 FROM pago_facturas actual
                WHERE actual.factura_id = f.id
                  AND actual.pago_id = %s
                  AND actual.tenant_id = f.tenant_id
            )
        ORDER BY {orden}
        LIMIT %s
        ''',
        (pago_id, tenant_id, *extra_params, pago_id, pago_id, limite),
        fetch='all',
    ) or []


def _agregar_facturas_unicas(destino, filas):
    vistos = {int(item['id']) for item in destino}
    for fila in filas or []:
        factura_id = int(fila['id'])
        if factura_id not in vistos:
            destino.append(fila)
            vistos.add(factura_id)
    return destino


def _facturas_disponibles_pago(tenant_id, pago_id=None, ars_id=None, numero_factura=''):
    pago_id = pago_id or 0
    numero = sanitize_input(numero_factura or '', max_length=40).strip()
    facturas = []
    if pago_id:
        _agregar_facturas_unicas(
            facturas,
            _consultar_facturas_pago(
                tenant_id,
                pago_id,
                extra_where='''
                  AND EXISTS (
                      SELECT 1 FROM pago_facturas actual
                      WHERE actual.factura_id = f.id
                        AND actual.pago_id = %s
                        AND actual.tenant_id = f.tenant_id
                  )
                ''',
                extra_params=(pago_id,),
                orden='f.fecha_emision ASC, f.id ASC',
                limite=50,
            ),
        )
    if numero:
        extra = 'AND (f.numero_factura LIKE %s OR IFNULL(f.ncf, \'\') LIKE %s)'
        params = [f'%{numero}%', f'%{numero}%']
        if ars_id:
            extra += ' AND f.ars_id = %s'
            params.append(ars_id)
        _agregar_facturas_unicas(
            facturas,
            _consultar_facturas_pago(
                tenant_id,
                pago_id,
                extra_where=extra,
                extra_params=tuple(params),
                orden='f.fecha_emision ASC, f.id ASC',
                limite=10,
            ),
        )
    if ars_id:
        _agregar_facturas_unicas(
            facturas,
            _consultar_facturas_pago(
                tenant_id,
                pago_id,
                extra_where='AND f.ars_id = %s',
                extra_params=(ars_id,),
                orden='f.fecha_emision ASC, f.id ASC',
                limite=FACTURAS_ANTIGUAS_PAGO,
            ),
        )
    return facturas


def _contexto_formulario_pago(tenant_id, pago=None):
    pago_id = pago['id'] if pago else None
    ars_id = validate_int(request.args.get('ars_id'), min_value=1, default=None)
    numero = sanitize_input(request.args.get('numero', ''), max_length=40)
    if not ars_id and pago_id:
        ars_id = _ars_del_pago(tenant_id, pago_id)
    ars_list = execute_query(
        '''
        SELECT id, nombre FROM ars
        WHERE activo = 1 AND tenant_id = %s
        ORDER BY nombre
        ''',
        (tenant_id,),
        fetch='all',
    ) or []
    facturas_list = _facturas_disponibles_pago(
        tenant_id,
        pago_id=pago_id,
        ars_id=ars_id,
        numero_factura=numero,
    )
    lineas = {}
    if pago:
        for linea in _lineas_de_pago(tenant_id, pago):
            lineas[str(linea['factura_id'])] = linea['monto_aplicado']
    return {
        'pago': pago,
        'ars_list': ars_list,
        'ars_id': ars_id,
        'numero_factura': numero,
        'facturas_list': facturas_list,
        'lineas_por_factura': lineas,
        'fecha_actual': (
            _fecha_input_pago(pago.get('fecha_pago')) if pago
            else datetime.now().strftime('%Y-%m-%d')
        ),
    }


def _validar_lineas_pago(facturas_ids, montos):
    facturas_data = []
    facturas_vistas = set()
    for indice, factura_id in enumerate(facturas_ids):
        if indice >= len(montos) or not montos[indice]:
            continue
        try:
            factura_id_int = int(factura_id)
            monto = Decimal(str(montos[indice])).quantize(Decimal('0.01'))
        except (InvalidOperation, TypeError, ValueError):
            return None, 'Uno de los montos no es válido'
        if factura_id_int > 0 and monto > 0 and factura_id_int not in facturas_vistas:
            facturas_vistas.add(factura_id_int)
            facturas_data.append((factura_id_int, monto))
    if not facturas_data:
        return None, 'Debe seleccionar al menos una factura con monto mayor a cero'
    return facturas_data, None


def _recalcular_estado_facturas(tenant_id, factura_ids):
    for factura_id in set(factura_ids):
        factura = execute_query(
            '''
            SELECT total, estado FROM facturas
            WHERE id = %s AND tenant_id = %s
            ''',
            (factura_id, tenant_id),
        )
        if not factura or factura.get('estado') == 'Anulada':
            continue
        pagado = execute_query(
            '''
            SELECT COALESCE(SUM(monto_aplicado), 0) AS pagado
            FROM pago_facturas
            WHERE factura_id = %s AND tenant_id = %s
            ''',
            (factura_id, tenant_id),
        ) or {}
        total = Decimal(str(factura['total'] or 0))
        aplicado = Decimal(str(pagado.get('pagado') or 0))
        estado = 'Pagada' if aplicado >= total and total > 0 else 'Pendiente'
        execute_update(
            '''
            UPDATE facturas
            SET estado = %s
            WHERE id = %s AND tenant_id = %s AND estado != 'Anulada'
            ''',
            (estado, factura_id, tenant_id),
        )


@login_required
@permission_required('facturacion.ver')
def facturacion_pagos():
    """Lista de pagos - Filtrado por tenant"""
    tenant_id = get_current_tenant_id()
    query = '''
        SELECT p.*,
               CONCAT('PAGO-', LPAD(p.id, 6, '0')) AS numero_pago,
               COALESCE(SUM(pf.monto_aplicado), MAX(p.monto), 0) AS monto_total,
               CASE WHEN COUNT(pf.id) > 0 THEN COUNT(pf.id) ELSE 1 END AS cantidad_facturas,
               COALESCE(
                   NULLIF(GROUP_CONCAT(f.numero_factura SEPARATOR ', '), ''),
                   MAX(factura_directa.numero_factura)
               ) AS facturas_numeros
        FROM pagos p
        LEFT JOIN pago_facturas pf
          ON p.id = pf.pago_id AND pf.tenant_id = p.tenant_id
        LEFT JOIN facturas f
          ON pf.factura_id = f.id AND f.tenant_id = p.tenant_id
        LEFT JOIN facturas factura_directa
          ON p.factura_id = factura_directa.id
         AND factura_directa.tenant_id = p.tenant_id
        WHERE p.tenant_id = %s
        GROUP BY p.id
    '''
    pagos_list, pagination = execute_paginated_query(
        query,
        (tenant_id,),
        'p.fecha_pago DESC, p.id DESC',
    )
    return render_template(
        'facturacion/pagos.html',
        pagos_list=pagos_list,
        pagination=pagination,
    )

@login_required
@permission_required('facturacion.editar')
def facturacion_pagos_nuevo():
    """Crear nuevo pago"""
    tenant_id = get_current_tenant_id()
    
    if request.method == 'POST':
        fecha_pago = request.form.get('fecha_pago')
        metodo_pago = request.form.get('metodo_pago')
        referencia = request.form.get('referencia', '').strip()
        observaciones = request.form.get('observaciones', '').strip()
        facturas_ids = request.form.getlist('facturas_ids[]')
        montos = request.form.getlist('montos[]')
        
        if not all([fecha_pago, metodo_pago]):
            flash('Fecha y método de pago son obligatorios', 'error')
            return redirect(url_for('facturacion_pagos_nuevo'))

        facturas_data, error_lineas = _validar_lineas_pago(facturas_ids, montos)
        if error_lineas:
            flash(error_lineas, 'error')
            return redirect(url_for('facturacion_pagos_nuevo'))

        # Generar número de pago
        numero_pago = f"PAGO-{datetime.now().strftime('%Y%m%d')}-{secrets.token_hex(4).upper()}"

        try:
            with database_transaction():
                ids = [factura_id for factura_id, _monto in facturas_data]
                placeholders = ','.join(['%s'] * len(ids))
                facturas_bloqueadas = execute_query(f'''
                    SELECT id, total
                    FROM facturas
                    WHERE tenant_id = %s AND id IN ({placeholders})
                      AND estado != 'Anulada'
                    FOR UPDATE
                ''', (tenant_id, *ids), fetch='all') or []
                facturas_por_id = {
                    int(factura['id']): factura for factura in facturas_bloqueadas
                }
                if len(facturas_por_id) != len(ids):
                    raise ValueError(
                        'Una factura no existe, fue anulada o pertenece a otra empresa'
                    )

                pagos_previos = execute_query(f'''
                    SELECT pf.factura_id,
                           COALESCE(SUM(pf.monto_aplicado), 0) AS pagado
                    FROM pago_facturas pf
                    JOIN facturas f
                      ON f.id = pf.factura_id
                     AND f.tenant_id = pf.tenant_id
                    WHERE pf.tenant_id = %s
                      AND pf.factura_id IN ({placeholders})
                    GROUP BY pf.factura_id
                ''', (tenant_id, *ids), fetch='all') or []
                pagado_por_factura = {
                    int(item['factura_id']): Decimal(str(item['pagado'] or 0))
                    for item in pagos_previos
                }

                monto_total = Decimal('0.00')
                for factura_id, monto in facturas_data:
                    total_factura = Decimal(
                        str(facturas_por_id[factura_id]['total'])
                    )
                    pagado = pagado_por_factura.get(
                        factura_id, Decimal('0.00')
                    )
                    if monto > total_factura - pagado:
                        raise ValueError(
                            f'El pago supera el saldo de la factura {factura_id}'
                        )
                    monto_total += monto

                pago_id = execute_update('''
                    INSERT INTO pagos
                    (numero_pago, monto_total, fecha_pago, metodo_pago,
                     referencia, observaciones, tenant_id, created_by)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ''', (
                    numero_pago, monto_total, fecha_pago, metodo_pago,
                    referencia or None, observaciones or None,
                    tenant_id, current_user.id
                ))
                if not pago_id:
                    raise RuntimeError('No se pudo crear el pago')

                for factura_id, monto in facturas_data:
                    execute_update('''
                        INSERT INTO pago_facturas
                        (pago_id, factura_id, monto_aplicado, tenant_id)
                        VALUES (%s, %s, %s, %s)
                    ''', (pago_id, factura_id, monto, tenant_id))
                    acumulado = (
                        pagado_por_factura.get(factura_id, Decimal('0.00'))
                        + monto
                    )
                    if acumulado >= Decimal(
                        str(facturas_por_id[factura_id]['total'])
                    ):
                        execute_update('''
                            UPDATE facturas
                            SET estado = 'Pagada'
                            WHERE id = %s AND tenant_id = %s
                        ''', (factura_id, tenant_id))
        except ValueError as error:
            flash(str(error), 'error')
            return redirect(url_for('facturacion_pagos_nuevo'))
        except Exception:
            logger.error('Error al registrar pago', exc_info=True)
            flash('No se pudo registrar el pago. No se aplicó ningún cambio.', 'error')
            return redirect(url_for('facturacion_pagos_nuevo'))
        
        flash('Pago registrado exitosamente', 'success')
        return redirect(url_for('facturacion_pagos'))
    
    return render_template(
        'facturacion/pago_form.html',
        **_contexto_formulario_pago(tenant_id),
    )


@login_required
@permission_required('facturacion.ver')
def facturacion_pago_detalle(pago_id):
    """Mostrar un pago de la empresa activa."""
    tenant_id = get_current_tenant_id()
    pago = execute_query(
        '''
        SELECT p.*,
               CONCAT('PAGO-', LPAD(p.id, 6, '0')) AS numero_pago_visible
        FROM pagos p
        WHERE p.id = %s AND p.tenant_id = %s
        ''',
        (pago_id, tenant_id),
    )
    if not pago:
        flash('Pago no encontrado', 'error')
        return redirect(url_for('facturacion_pagos'))
    lineas = _lineas_de_pago(tenant_id, pago)
    monto_total = sum(
        Decimal(str(linea.get('monto_aplicado') or 0)) for linea in lineas
    ) or Decimal(str(pago.get('monto_total') or pago.get('monto') or 0))
    return render_template(
        'facturacion/pago_detalle.html',
        pago=pago,
        lineas=lineas,
        monto_total=monto_total,
    )


@login_required
@permission_required('facturacion.editar')
def facturacion_pago_editar(pago_id):
    """Editar un pago de la empresa activa."""
    tenant_id = get_current_tenant_id()
    pago = execute_query(
        'SELECT * FROM pagos WHERE id = %s AND tenant_id = %s',
        (pago_id, tenant_id),
    )
    if not pago:
        flash('Pago no encontrado', 'error')
        return redirect(url_for('facturacion_pagos'))

    if request.method == 'POST':
        fecha_pago = request.form.get('fecha_pago')
        metodo_pago = request.form.get('metodo_pago')
        referencia = sanitize_input(request.form.get('referencia', ''), max_length=100)
        observaciones = sanitize_input(request.form.get('observaciones', ''), max_length=2000)
        facturas_ids = request.form.getlist('facturas_ids[]')
        montos = request.form.getlist('montos[]')
        if not all([fecha_pago, metodo_pago]):
            flash('Fecha y método de pago son obligatorios', 'error')
            return redirect(url_for('facturacion_pago_editar', pago_id=pago_id))
        facturas_data, error_lineas = _validar_lineas_pago(facturas_ids, montos)
        if error_lineas:
            flash(error_lineas, 'error')
            return redirect(url_for('facturacion_pago_editar', pago_id=pago_id))
        try:
            with database_transaction():
                lineas_anteriores = _lineas_de_pago(tenant_id, pago)
                ids_anteriores = [
                    int(linea['factura_id']) for linea in lineas_anteriores
                ]
                execute_update(
                    '''
                    DELETE FROM pago_facturas
                    WHERE pago_id = %s AND tenant_id = %s
                    ''',
                    (pago_id, tenant_id),
                )
                ids = [factura_id for factura_id, _monto in facturas_data]
                placeholders = ','.join(['%s'] * len(ids))
                facturas_bloqueadas = execute_query(f'''
                    SELECT id, total
                    FROM facturas
                    WHERE tenant_id = %s AND id IN ({placeholders})
                      AND estado != 'Anulada'
                    FOR UPDATE
                ''', (tenant_id, *ids), fetch='all') or []
                facturas_por_id = {
                    int(factura['id']): factura for factura in facturas_bloqueadas
                }
                if len(facturas_por_id) != len(ids):
                    raise ValueError(
                        'Una factura no existe, fue anulada o pertenece a otra empresa'
                    )
                pagos_previos = execute_query(f'''
                    SELECT pf.factura_id,
                           COALESCE(SUM(pf.monto_aplicado), 0) AS pagado
                    FROM pago_facturas pf
                    JOIN facturas f
                      ON f.id = pf.factura_id
                     AND f.tenant_id = pf.tenant_id
                    WHERE pf.tenant_id = %s
                      AND pf.factura_id IN ({placeholders})
                      AND pf.pago_id <> %s
                    GROUP BY pf.factura_id
                ''', (tenant_id, *ids, pago_id), fetch='all') or []
                pagado_por_factura = {
                    int(item['factura_id']): Decimal(str(item['pagado'] or 0))
                    for item in pagos_previos
                }
                monto_total = Decimal('0.00')
                for factura_id, monto in facturas_data:
                    total_factura = Decimal(str(facturas_por_id[factura_id]['total']))
                    pagado = pagado_por_factura.get(factura_id, Decimal('0.00'))
                    if monto > total_factura - pagado:
                        raise ValueError(
                            f'El pago supera el saldo de la factura {factura_id}'
                        )
                    monto_total += monto
                execute_update('''
                    UPDATE pagos
                    SET monto_total = %s,
                        fecha_pago = %s,
                        metodo_pago = %s,
                        referencia = %s,
                        observaciones = %s
                    WHERE id = %s AND tenant_id = %s
                ''', (
                    monto_total, fecha_pago, metodo_pago,
                    referencia or None, observaciones or None,
                    pago_id, tenant_id,
                ))
                for factura_id, monto in facturas_data:
                    execute_update('''
                        INSERT INTO pago_facturas
                        (pago_id, factura_id, monto_aplicado, tenant_id)
                        VALUES (%s, %s, %s, %s)
                    ''', (pago_id, factura_id, monto, tenant_id))
                _recalcular_estado_facturas(tenant_id, ids_anteriores + ids)
        except ValueError as error:
            flash(str(error), 'error')
            return redirect(url_for('facturacion_pago_editar', pago_id=pago_id))
        except Exception:
            logger.error('Error al actualizar pago', exc_info=True)
            flash('No se pudo actualizar el pago. No se aplicó ningún cambio.', 'error')
            return redirect(url_for('facturacion_pago_editar', pago_id=pago_id))
        flash('Pago actualizado', 'success')
        return redirect(url_for('facturacion_pago_detalle', pago_id=pago_id))

    return render_template(
        'facturacion/pago_form.html',
        **_contexto_formulario_pago(tenant_id, pago),
    )

@login_required
@permission_required('facturacion.ver')
def facturacion_historico():
    """Histórico de facturación y actividad clínica."""
    from routes.reports import renderizar_historico
    return renderizar_historico()

@login_required
@permission_required('facturacion.ver')
def facturacion_ver_factura(factura_id):
    """Ver factura generada"""
    # Validar que el ID sea válido
    if not validate_int(factura_id, min_value=1):
        flash('ID de factura inválido', 'error')
        return redirect(url_for('facturacion_historico'))
    
    # Validar acceso al tenant
    if not validate_tenant_access('facturas', factura_id):
        flash('No tienes acceso a esta factura', 'error')
        return redirect(url_for('facturacion_historico'))
    
    tenant_id = get_current_tenant_id()
    
    factura = execute_query('''
        SELECT f.*, a.nombre as nombre_ars, a.rnc as ars_rnc,
               m.nombre as medico_nombre, m.especialidad as medico_especialidad,
               m.cedula as medico_cedula, m.exequatur as medico_exequatur
        FROM facturas f
        LEFT JOIN ars a
          ON f.ars_id = a.id AND a.tenant_id = f.tenant_id
        LEFT JOIN medicos m
          ON f.medico_id = m.id AND m.tenant_id = f.tenant_id
        WHERE f.id = %s AND f.tenant_id = %s
    ''', (factura_id, tenant_id))
    
    if not factura:
        flash('Factura no encontrada', 'error')
        return redirect(url_for('facturacion_historico'))
    
    # Obtener detalles de la factura (pacientes/servicios)
    detalles = execute_query('''
        SELECT * FROM factura_detalles
        WHERE factura_id = %s AND tenant_id = %s
        ORDER BY id
    ''', (factura_id, tenant_id), fetch='all') or []
    
    # Procesar detalles para mostrar como pacientes
    pacientes = []
    for detalle in detalles:
        # Extraer información del detalle
        descripcion = detalle.get('descripcion', '')
        # Intentar extraer autorización de la descripción si está presente
        autorizacion = ''
        descripcion_servicio = descripcion
        if ' - Autorización:' in descripcion:
            partes = descripcion.split(' - Autorización:')
            descripcion_servicio = partes[0].strip()
            autorizacion = partes[1].strip() if len(partes) > 1 else ''
        
        paciente = {
            'nombre_paciente': factura.get('nombre_paciente', 'N/A'),
            'nss': factura.get('nss_paciente', ''),
            'fecha_servicio': factura.get('fecha_emision', ''),
            'autorizacion': autorizacion,
            'descripcion_servicio': descripcion_servicio if descripcion_servicio else '',
            'monto_estimado': float(detalle.get('precio_unitario', 0) or 0),
            'monto': float(detalle.get('precio_unitario', 0) or 0)
        }
        pacientes.append(paciente)
    
    # Obtener centro médico
    centro_medico = None
    if factura.get('centro_medico_id'):
        centro_medico = execute_query('SELECT * FROM centros_medicos WHERE id = %s AND tenant_id = %s', 
                                     (factura['centro_medico_id'], tenant_id))
    
    if not centro_medico:
        centro_medico = execute_query('SELECT * FROM centros_medicos WHERE tenant_id = %s LIMIT 1', (tenant_id,))
    
    if not centro_medico:
        centro_medico = {
            'nombre': 'Centro Médico',
            'direccion': ''
        }
    
    # Calcular totales
    subtotal = float(factura.get('subtotal', 0) or 0)
    total = float(factura.get('total', 0) or 0)
    
    # Obtener información de la empresa para determinar tipo
    empresa_info = get_empresa_info(tenant_id)
    tipo_empresa = empresa_info.get('tipo_empresa') if empresa_info else None
    
    # Obtener médico o empresa según tipo (igual que en vista_previa)
    medico_factura = None
    if tipo_empresa == 'centro_salud':
        medico_factura = {
            'id': empresa_info.get('id'),
            'nombre': empresa_info.get('razon_social', empresa_info.get('nombre', 'N/A')),
            'especialidad': 'Centro de Salud',
            'cedula': empresa_info.get('rnc', ''),
            'telefono': empresa_info.get('telefono', ''),
            'email': empresa_info.get('email', '')
        }
    else:
        # Obtener datos completos del médico
        medico_completo = execute_query(
            'SELECT * FROM medicos WHERE id = %s AND tenant_id = %s',
            (factura.get('medico_id'), tenant_id),
        )
        if medico_completo:
            medico_factura = {
                'id': medico_completo.get('id'),
                'nombre': medico_completo.get('nombre', factura.get('medico_nombre', 'N/A')),
                'especialidad': medico_completo.get('especialidad', factura.get('medico_especialidad', '')),
                'cedula': medico_completo.get('cedula', factura.get('medico_cedula', '')),
                'exequatur': medico_completo.get('exequatur', factura.get('medico_exequatur', '')),
                'telefono': medico_completo.get('telefono', ''),
                'email': medico_completo.get('email', '')
            }
        else:
            medico_factura = {
                'id': factura.get('medico_id'),
                'nombre': factura.get('medico_nombre', 'N/A'),
                'especialidad': factura.get('medico_especialidad', ''),
                'cedula': factura.get('medico_cedula', ''),
                'exequatur': factura.get('medico_exequatur', ''),
                'telefono': '',
                'email': ''
            }
    
    # Obtener NCF completo y descripción
    ncf_numero = factura.get('ncf', '')
    ncf_prefijo = ncf_numero[:3] if len(ncf_numero) >= 3 else ''
    factura_ecf = None
    if factura.get('tipo_factura') == 'ELECTRONICA':
        factura_ecf = execute_query(
            'SELECT * FROM facturas_ecf WHERE factura_id=%s AND tenant_id=%s',
            (factura_id, tenant_id)
        )
        ncf_obj = {'id': None, 'tipo': 'E31', 'prefijo': 'E31'}
        ncf_tipo_descripcion = 'Factura de Crédito Fiscal Electrónica'
        ncf_fecha_fin = ''
    else:
        ncf_obj = execute_query(
            'SELECT * FROM ncf WHERE prefijo = %s AND tenant_id = %s LIMIT 1',
            (ncf_prefijo, tenant_id)
        )
        if not ncf_obj:
            logger.warning(
                'NCF no encontrado en tenant=%s para prefijo=%s',
                tenant_id,
                ncf_prefijo,
            )
        ncf_tipos_descripciones = {
            'B01': 'Factura de Crédito Fiscal',
            'B02': 'Factura de Consumo',
            'B14': 'Registro Único de Ingresos',
            'B15': 'GUBERNAMENTAL'
        }
        ncf_tipo_descripcion = (
            ncf_tipos_descripciones.get(ncf_obj.get('tipo', ''), '')
            if ncf_obj else ''
        )
        ncf_fecha_fin = ncf_obj.get('fecha_fin', '') if ncf_obj else ''
    ncf_completo = ncf_numero
    
    # Intentar obtener pacientes desde pacientes_pendientes que fueron facturados
    fecha_factura = factura.get('fecha_emision', '')
    pacientes_pendientes_facturados = []
    try:
        pacientes_pendientes_facturados = execute_query('''
            SELECT pp.*, a.nombre as ars_nombre
            FROM pacientes_pendientes pp
            LEFT JOIN ars a
              ON pp.ars_id = a.id AND a.tenant_id = pp.tenant_id
            WHERE pp.estado = 'Facturado'
              AND pp.ars_id = %s
              AND DATE(pp.updated_at) = DATE(%s)
              AND pp.tenant_id = %s
            ORDER BY pp.id
        ''', (
            factura.get('ars_id'),
            fecha_factura,
            tenant_id,
        ), fetch='all') or []
    except Exception as e:
        logger.error(f"Error al obtener pacientes_pendientes_facturados: {str(e)}")
        pacientes_pendientes_facturados = []
    
    # Procesar pacientes desde detalles y pacientes_pendientes (igual que en vista_previa)
    pacientes_procesados = []
    if pacientes_pendientes_facturados and len(pacientes_pendientes_facturados) == len(detalles):
        # Si encontramos pacientes_pendientes que coinciden, usarlos
        for idx, (detalle, pp) in enumerate(zip(detalles, pacientes_pendientes_facturados), 1):
            servicio_completo = pp.get('servicios_realizados', '') or ''
            if ' - Autorización:' in servicio_completo:
                partes = servicio_completo.split(' - Autorización:')
                descripcion_servicio = partes[0].strip()
                autorizacion = partes[1].strip() if len(partes) > 1 else ''
            else:
                descripcion_servicio = servicio_completo.strip()
                autorizacion = ''
            
            paciente = {
                'nombre_paciente': pp.get('nombre_paciente', factura.get('nombre_paciente', 'N/A')),
                'nss': pp.get('nss', factura.get('nss_paciente', '')),
                'fecha_servicio': pp.get('fecha_servicio', fecha_factura),
                'autorizacion': autorizacion,
                'descripcion_servicio': descripcion_servicio if descripcion_servicio else detalle.get('descripcion', ''),
                'monto_estimado': float(detalle.get('precio_unitario', 0) or 0),
                'monto': float(detalle.get('precio_unitario', 0) or 0)
            }
            pacientes_procesados.append(paciente)
    else:
        # Si no encontramos pacientes_pendientes, usar datos de la factura
        for idx, detalle in enumerate(detalles, 1):
            descripcion = detalle.get('descripcion', '')
            # Intentar extraer autorización de la descripción si está presente
            autorizacion = ''
            descripcion_servicio = descripcion
            if ' - Autorización:' in descripcion:
                partes = descripcion.split(' - Autorización:')
                descripcion_servicio = partes[0].strip()
                autorizacion = partes[1].strip() if len(partes) > 1 else ''
            
            paciente = {
                'nombre_paciente': factura.get('nombre_paciente', 'N/A'),
                'nss': factura.get('nss_paciente', ''),
                'fecha_servicio': fecha_factura,
                'autorizacion': autorizacion,
                'descripcion_servicio': descripcion_servicio if descripcion_servicio else '',
                'monto_estimado': float(detalle.get('precio_unitario', 0) or 0),
                'monto': float(detalle.get('precio_unitario', 0) or 0)
            }
            pacientes_procesados.append(paciente)
    
    # Preparar datos de ARS
    ars = {
        'id': factura.get('ars_id'),
        'nombre': factura.get('nombre_ars', 'N/A'),
        'rnc': factura.get('ars_rnc', '')
    }
    
    # Preparar datos de NCF
    ncf = {
        'id': ncf_obj.get('id') if ncf_obj else None,
        'prefijo': ncf_prefijo,
        'tipo': ncf_obj.get('tipo', '') if ncf_obj else '',
        'fecha_fin': ncf_fecha_fin
    }
    
    return render_template('facturacion/ver_factura.html',
                          factura=factura,
                          pacientes=pacientes_procesados,
                          centro_medico=centro_medico,
                          subtotal=subtotal,
                          total=total,
                          ars=ars,
                          ncf=ncf,
                          ncf_completo=ncf_completo,
                          ncf_tipo_descripcion=ncf_tipo_descripcion,
                          medico=medico_factura,
                          tipo_empresa=tipo_empresa,
                          empresa_info=empresa_info,
                          fecha_factura=fecha_factura,
                          factura_ecf=factura_ecf)

@login_required
@permission_required('facturacion.ver')
def facturacion_ver_xml_ecf(factura_id):
    """Mostrar el XML E31 generado, limitado al tenant de la factura."""
    if not validate_tenant_access('facturas', factura_id):
        flash('No tienes acceso a esta factura', 'error')
        return redirect(url_for('facturacion_historico'))

    tenant_id = get_current_tenant_id()
    document = execute_query('''
        SELECT e_ncf, xml_generado, xml_firmado
        FROM facturas_ecf
        WHERE factura_id=%s AND tenant_id=%s
        LIMIT 1
    ''', (factura_id, tenant_id))
    xml_document = (
        (document or {}).get('xml_firmado')
        or (document or {}).get('xml_generado')
    )
    if not xml_document:
        flash('Esta factura todavía no tiene un XML generado', 'warning')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))

    response = make_response(xml_document)
    response.headers['Content-Type'] = 'application/xml; charset=utf-8'
    response.headers['Content-Disposition'] = (
        f"inline; filename={document['e_ncf']}.xml"
    )
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

def _obtener_ecf_aceptado_para_ri(factura_id, tenant_id):
    document = execute_query('''
        SELECT e_ncf, estado, xml_firmado, track_id
        FROM facturas_ecf
        WHERE factura_id=%s AND tenant_id=%s
        LIMIT 1
    ''', (factura_id, tenant_id))
    if not document or document.get('estado') != 'ACEPTADO':
        raise ECFPrintableError(
            'La representación impresa se habilita cuando DGII acepta el e-CF'
        )
    if not document.get('xml_firmado'):
        raise ECFPrintableError('El e-CF aceptado no tiene XML firmado')
    return document

@login_required
@permission_required('facturacion.imprimir')
def facturacion_qr_ecf(factura_id):
    """Mostrar el QR fiscal de un e-CF aceptado por DGII."""
    if not validate_tenant_access('facturas', factura_id):
        flash('No tienes acceso a esta factura', 'error')
        return redirect(url_for('facturacion_historico'))

    try:
        document = _obtener_ecf_aceptado_para_ri(
            factura_id, get_current_tenant_id()
        )
        config = current_app.config['ECF_CONFIG']
        stamp = build_stamp(document['xml_firmado'], config.stamp_url)
        qr = generate_qr(stamp)
    except ECFPrintableError as error:
        flash(str(error), 'warning')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))
    except ValueError as error:
        logger.error('No se pudo generar QR e-CF %s: %s', factura_id, error)
        flash('No fue posible generar el QR fiscal del e-CF', 'error')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))

    response = make_response(qr.png)
    response.headers['Content-Type'] = 'image/png'
    response.headers['Content-Disposition'] = (
        f"inline; filename={document['e_ncf']}_qr.png"
    )
    response.headers['Cache-Control'] = 'private, no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

@login_required
@permission_required('facturacion.imprimir')
def facturacion_representacion_impresa_ecf(factura_id):
    """Abrir la representación impresa fiscal del e-CF 31 aceptado."""
    if not validate_tenant_access('facturas', factura_id):
        flash('No tienes acceso a esta factura', 'error')
        return redirect(url_for('facturacion_historico'))

    try:
        document = _obtener_ecf_aceptado_para_ri(
            factura_id, get_current_tenant_id()
        )
        result = generate_e31_pdf(
            document['xml_firmado'],
            current_app.config['ECF_CONFIG'].stamp_url,
            dgii_status=document['estado'],
            track_id=document.get('track_id') or '',
        )
    except ECFPrintableError as error:
        logger.error(
            'No se pudo generar representación impresa e-CF %s: %s',
            factura_id,
            error,
        )
        flash(str(error), 'error')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))

    return send_file(
        result.pdf,
        mimetype='application/pdf',
        as_attachment=False,
        download_name=f"{document['e_ncf']}_representacion_impresa.pdf",
        max_age=0,
    )

@login_required
@permission_required('facturacion.ver')
def facturacion_consultar_estado_ecf(factura_id):
    """Consultar una vez el resultado fiscal vigente en DGII."""
    if not validate_tenant_access('facturas', factura_id):
        flash('No tienes acceso a esta factura', 'error')
        return redirect(url_for('facturacion_historico'))
    tenant_id = get_current_tenant_id()
    if not ecf_habilitado_para_tenant(tenant_id, solo_consulta=True):
        flash('La cuenta no está habilitada para consultar e-CF', 'warning')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))

    document = execute_query('''
        SELECT id
        FROM facturas_ecf
        WHERE factura_id=%s AND tenant_id=%s
        LIMIT 1
    ''', (factura_id, tenant_id))
    if not document:
        flash('La factura seleccionada no es electrónica', 'error')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))

    try:
        success, status, message = consultar_resultado_ecf_dgii(
            document['id'],
            tenant_id,
            current_user.id
        )
    except Exception as error:
        logger.error(
            'Error consultando resultado DGII para factura %s: %s',
            factura_id,
            error,
            exc_info=True
        )
        flash('No fue posible completar la consulta a DGII', 'error')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))

    if success and status == 'ACEPTADO':
        flash('Comprobante aceptado por DGII', 'success')
    elif success and status == 'RECHAZADO':
        flash(f'Comprobante rechazado por DGII: {message}', 'error')
    elif success:
        flash(f'DGII todavía está procesando el comprobante: {message}', 'info')
    else:
        flash(message, 'warning')
    return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))

@login_required
@permission_required('facturacion.editar')
def facturacion_editar_factura(factura_id):
    """Editar factura generada"""
    tenant_id = get_current_tenant_id()
    if not validate_tenant_access('facturas', factura_id):
        flash('No tienes acceso a esta factura', 'error')
        return redirect(url_for('facturacion_historico'))

    factura = execute_query('''
        SELECT f.*, a.nombre as nombre_ars, a.rnc as ars_rnc,
               m.nombre as medico_nombre, m.especialidad as medico_especialidad,
               m.cedula as medico_cedula, m.exequatur as medico_exequatur
        FROM facturas f
        LEFT JOIN ars a
          ON f.ars_id = a.id AND a.tenant_id = f.tenant_id
        LEFT JOIN medicos m
          ON f.medico_id = m.id AND m.tenant_id = f.tenant_id
        WHERE f.id = %s AND f.tenant_id = %s
    ''', (factura_id, tenant_id))
    
    if not factura:
        flash('Factura no encontrada', 'error')
        return redirect(url_for('facturacion_historico'))
    
    # Calcular días transcurridos desde la creación
    from datetime import datetime, date
    fecha_creacion = factura.get('created_at')
    if isinstance(fecha_creacion, str):
        try:
            fecha_creacion = datetime.strptime(fecha_creacion, '%Y-%m-%d %H:%M:%S').date()
        except:
            fecha_creacion = date.today()
    elif isinstance(fecha_creacion, datetime):
        fecha_creacion = fecha_creacion.date()
    elif isinstance(fecha_creacion, date):
        pass
    else:
        fecha_creacion = date.today()
    
    fecha_actual = date.today()
    dias_transcurridos = (fecha_actual - fecha_creacion).days
    dias_restantes = 30 - dias_transcurridos
    
    # Verificar si se puede editar (menos de 30 días)
    if dias_transcurridos >= 30:
        flash('Esta factura no se puede editar. Han pasado más de 30 días desde su creación.', 'error')
        return redirect(url_for('facturacion_historico'))
    
    # Si es POST, procesar la actualización
    if request.method == 'POST':
        # Aquí se procesaría la actualización de la factura
        # Por ahora, solo redirigir
        flash('Funcionalidad de edición en desarrollo', 'info')
        return redirect(url_for('facturacion_historico'))
    
    # Obtener detalles de la factura (pacientes/servicios)
    detalles = execute_query('''
        SELECT * FROM factura_detalles
        WHERE factura_id = %s AND tenant_id = %s
        ORDER BY id
    ''', (factura_id, tenant_id), fetch='all') or []
    
    # Procesar detalles para mostrar como pacientes
    pacientes = []
    for detalle in detalles:
        # Extraer información del servicio desde la descripción
        descripcion_servicio = detalle.get('descripcion', '')
        servicio_nombre = descripcion_servicio
        if ' - Autorización:' in descripcion_servicio:
            servicio_nombre = descripcion_servicio.split(' - Autorización:')[0].strip()
        
        paciente = {
            'id': detalle.get('id'),
            'nombre_paciente': factura.get('nombre_paciente', 'N/A'),
            'nss': factura.get('nss_paciente', ''),
            'fecha_servicio': factura.get('fecha_emision', ''),
            'autorizacion': '',
            'descripcion_servicio': descripcion_servicio,
            'servicio_nombre': servicio_nombre,
            'medico_nombre': factura.get('medico_nombre', 'N/A'),
            'monto_estimado': float(detalle.get('precio_unitario', 0) or 0),
            'monto': float(detalle.get('precio_unitario', 0) or 0)
        }
        pacientes.append(paciente)
    
    # Agregar campos adicionales a factura para el template
    factura['fecha_factura'] = factura.get('fecha_emision', '')
    factura['ncf_numero'] = factura.get('ncf', '')
    
    return render_template('facturacion/editar_factura.html',
                          factura=factura,
                          pacientes_factura=pacientes,  # Cambiado de pacientes a pacientes_factura
                          pacientes_disponibles=[],  # Lista vacía por ahora, se puede poblar después
                          dias_transcurridos=dias_transcurridos,
                          dias_restantes=dias_restantes)

def generar_pdf_factura_vista_previa(factura_id, tenant_id=None):
    """Generar PDF de factura con el mismo formato que la vista previa"""
    if not REPORTLAB_AVAILABLE:
        return None
    
    if tenant_id is None:
        tenant_id = get_current_tenant_id()
    
    factura = execute_query('''
        SELECT f.*, a.nombre as nombre_ars, a.rnc as ars_rnc,
               m.nombre as medico_nombre, m.especialidad as medico_especialidad,
               m.cedula as medico_cedula, m.exequatur as medico_exequatur,
               m.id as medico_id
        FROM facturas f
        LEFT JOIN ars a
          ON f.ars_id = a.id AND a.tenant_id = f.tenant_id
        LEFT JOIN medicos m
          ON f.medico_id = m.id AND m.tenant_id = f.tenant_id
        WHERE f.id = %s AND f.tenant_id = %s
    ''', (factura_id, tenant_id))
    
    if not factura:
        logger.error(f"Factura {factura_id} no encontrada para tenant {tenant_id}")
        print(f"ERROR: Factura {factura_id} no encontrada para tenant {tenant_id}")
        return None
    
    logger.info(f"Iniciando generación de PDF para factura {factura_id}")
    print(f"INFO: Factura {factura_id} encontrada. Datos básicos: ncf={factura.get('ncf')}, fecha_emision={factura.get('fecha_emision')}, ars_id={factura.get('ars_id')}")
    
    # Obtener información de la empresa para determinar tipo
    empresa_info = get_empresa_info(tenant_id)
    tipo_empresa = empresa_info.get('tipo_empresa') if empresa_info else None
    
    # Obtener médico o empresa según tipo
    medico_factura = None
    if tipo_empresa == 'centro_salud':
        medico_factura = {
            'id': empresa_info.get('id'),
            'nombre': empresa_info.get('razon_social', empresa_info.get('nombre', 'N/A')),
            'especialidad': 'Centro de Salud',
            'cedula': empresa_info.get('rnc', '')
        }
    else:
        medico_factura = {
            'id': factura.get('medico_id'),
            'nombre': factura.get('medico_nombre', 'N/A'),
            'especialidad': factura.get('medico_especialidad', ''),
            'cedula': factura.get('medico_cedula', '')
        }
    
    # Obtener ARS
    ars = {
        'id': factura.get('ars_id'),
        'nombre': factura.get('nombre_ars', 'N/A'),
        'rnc': factura.get('ars_rnc', '')
    }
    
    # Obtener NCF
    ncf_numero = factura.get('ncf', '')
    ncf_prefijo = ncf_numero[:3] if len(ncf_numero) >= 3 else ''
    ncf_obj = execute_query('SELECT * FROM ncf WHERE prefijo = %s AND tenant_id = %s LIMIT 1', (ncf_prefijo, tenant_id))
    
    ncf_tipos_descripciones = {
        'B01': 'Factura de Crédito Fiscal',
        'B02': 'Factura de Consumo',
        'B14': 'Registro Único de Ingresos',
        'B15': 'GUBERNAMENTAL'
    }
    ncf_tipo_descripcion = ncf_tipos_descripciones.get(ncf_obj.get('tipo', '') if ncf_obj else '', '') if ncf_obj else ''
    ncf_fecha_fin = ncf_obj.get('fecha_fin', '') if ncf_obj else ''
    
    # Obtener fecha de factura para usar en consultas
    fecha_factura = factura.get('fecha_emision', '')
    
    # Obtener detalles de la factura (pacientes/servicios)
    detalles = execute_query('''
        SELECT * FROM factura_detalles
        WHERE factura_id = %s AND tenant_id = %s
        ORDER BY id
    ''', (factura_id, tenant_id), fetch='all') or []
    
    # Intentar obtener pacientes desde pacientes_pendientes que fueron facturados
    # Buscar pacientes_pendientes con estado 'Facturado' que coincidan con esta factura
    # Por fecha y ARS como aproximación
    pacientes_pendientes_facturados = []
    try:
        pacientes_pendientes_facturados = execute_query('''
            SELECT pp.*, a.nombre as ars_nombre
            FROM pacientes_pendientes pp
            LEFT JOIN ars a
              ON pp.ars_id = a.id AND a.tenant_id = pp.tenant_id
            WHERE pp.estado = 'Facturado'
              AND pp.ars_id = %s
              AND DATE(pp.updated_at) = DATE(%s)
              AND pp.tenant_id = %s
            ORDER BY pp.id
        ''', (
            factura.get('ars_id'),
            fecha_factura,
            tenant_id,
        ), fetch='all') or []
    except Exception as e:
        logger.error(f"Error al obtener pacientes_pendientes_facturados: {str(e)}")
        pacientes_pendientes_facturados = []
    
    # Validar que hay detalles antes de procesar
    if not detalles:
        logger.error(f"Factura {factura_id} no tiene detalles asociados. Query ejecutada: SELECT * FROM factura_detalles WHERE factura_id = {factura_id}")
        return None
    
    logger.info(f"Factura {factura_id} tiene {len(detalles)} detalles. Primer detalle: {detalles[0] if detalles else 'N/A'}")
    
    # Procesar pacientes desde detalles y pacientes_pendientes
    pacientes = []
    if pacientes_pendientes_facturados and len(pacientes_pendientes_facturados) == len(detalles):
        # Si encontramos pacientes_pendientes que coinciden, usarlos
        for idx, (detalle, pp) in enumerate(zip(detalles, pacientes_pendientes_facturados), 1):
            servicio_completo = pp.get('servicios_realizados', '') or ''
            if ' - Autorización:' in servicio_completo:
                partes = servicio_completo.split(' - Autorización:')
                descripcion_servicio = partes[0].strip()
                autorizacion = partes[1].strip() if len(partes) > 1 else ''
            else:
                descripcion_servicio = servicio_completo.strip()
                autorizacion = ''
            
            paciente = {
                'nombre_paciente': pp.get('nombre_paciente', factura.get('nombre_paciente', 'N/A')),
                'nss': pp.get('nss', factura.get('nss_paciente', '')),
                'fecha_servicio': pp.get('fecha_servicio', factura.get('fecha_emision', '')),
                'autorizacion': autorizacion,
                'descripcion_servicio': descripcion_servicio if descripcion_servicio else detalle.get('descripcion', ''),
                'monto_estimado': float(detalle.get('precio_unitario', 0) or 0),
                'monto': float(detalle.get('precio_unitario', 0) or 0)
            }
            pacientes.append(paciente)
    else:
        # Si no encontramos pacientes_pendientes, usar datos de la factura (como en ver_factura)
        for idx, detalle in enumerate(detalles, 1):
            descripcion = detalle.get('descripcion', '')
            # Intentar extraer autorización de la descripción si está presente
            autorizacion = ''
            descripcion_servicio = descripcion
            if ' - Autorización:' in descripcion:
                partes = descripcion.split(' - Autorización:')
                descripcion_servicio = partes[0].strip()
                autorizacion = partes[1].strip() if len(partes) > 1 else ''
            
            paciente = {
                'nombre_paciente': factura.get('nombre_paciente', 'N/A'),
                'nss': factura.get('nss_paciente', ''),
                'fecha_servicio': fecha_factura,
                'autorizacion': autorizacion,
                'descripcion_servicio': descripcion_servicio if descripcion_servicio else '',
                'monto_estimado': float(detalle.get('precio_unitario', 0) or 0),
                'monto': float(detalle.get('precio_unitario', 0) or 0)
            }
            pacientes.append(paciente)
    
    # Obtener centro médico
    centro_medico = None
    if factura.get('centro_medico_id'):
        centro_medico = execute_query('SELECT * FROM centros_medicos WHERE id = %s AND tenant_id = %s', 
                                     (factura['centro_medico_id'], tenant_id))
    
    if not centro_medico:
        centro_medico = execute_query('SELECT * FROM centros_medicos WHERE tenant_id = %s LIMIT 1', (tenant_id,))
    
    if not centro_medico:
        centro_medico = {
            'nombre': 'Centro Médico',
            'direccion': ''
        }
    
    # Calcular totales
    subtotal = float(factura.get('subtotal', 0) or 0)
    total = float(factura.get('total', 0) or 0)
    
    # Obtener datos completos del médico para el footer y remitente (antes de generar PDF)
    medico_completo = None
    if tipo_empresa != 'centro_salud' and medico_factura.get('id'):
        medico_completo = execute_query(
            'SELECT * FROM medicos WHERE id = %s AND tenant_id = %s',
            (medico_factura.get('id'), tenant_id),
        )
        # Actualizar medico_factura con datos completos si están disponibles
        if medico_completo:
            medico_factura['nombre'] = medico_completo.get('nombre', medico_factura.get('nombre', 'N/A'))
            medico_factura['especialidad'] = medico_completo.get('especialidad', medico_factura.get('especialidad', ''))
            medico_factura['cedula'] = medico_completo.get('cedula', medico_factura.get('cedula', ''))
            medico_factura['exequatur'] = medico_completo.get('exequatur', '')
    
    # Validar datos mínimos necesarios antes de generar PDF
    if not pacientes:
        logger.error(f"Factura {factura_id} no tiene pacientes procesados después de procesar {len(detalles)} detalles")
        logger.error(f"Detalles procesados: {detalles}")
        logger.error(f"Pacientes pendientes encontrados: {len(pacientes_pendientes_facturados)}")
        return None
    
    # Validar que tenemos datos esenciales
    if not fecha_factura:
        logger.error(f"Factura {factura_id} no tiene fecha_emision. factura['fecha_emision'] = {factura.get('fecha_emision')}")
        return None
    
    if not ars.get('nombre'):
        logger.error(f"Factura {factura_id} no tiene nombre de ARS. ars = {ars}, factura['nombre_ars'] = {factura.get('nombre_ars')}")
        return None
    
    if not ncf_numero:
        logger.error(f"Factura {factura_id} no tiene número de NCF. factura['ncf'] = {factura.get('ncf')}")
        return None
    
    logger.info(f"Iniciando generación de PDF para factura {factura_id}: {len(pacientes)} pacientes, subtotal: {subtotal}, total: {total}")
    logger.info(f"Datos validados: fecha_factura={fecha_factura}, ars={ars.get('nombre')}, ncf={ncf_numero}, tipo_empresa={tipo_empresa}")
    
    # Generar PDF
    try:
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, 
                                leftMargin=0.5*inch, rightMargin=0.5*inch,
                                topMargin=0.5*inch, bottomMargin=0.5*inch)
        story = []
        
        styles = getSampleStyleSheet()
        
        # Color primario (puede obtenerse del tema, por defecto usamos un color)
        primary_color_hex = '#CEB0B7'
        primary_color = colors.HexColor(primary_color_hex)
        primary_dark = colors.HexColor('#B89CA3')
        
        # Estilo para título
        title_style = ParagraphStyle(
            'FacturaTitle',
            parent=styles['Heading1'],
            fontSize=28,
            textColor=primary_color,
            spaceAfter=15,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        # Header: FACTURA centrado
        story.append(Paragraph("FACTURA", title_style))
        story.append(Spacer(1, 0.25*inch))
        
        # Información en 3 columnas (simuladas con tabla) - Formato como imagen
        info_box_style = ParagraphStyle(
            'InfoBox',
            parent=styles['Normal'],
            fontSize=8,
            leading=11,
            textColor=colors.black
        )
        
        info_header_style = ParagraphStyle(
            'InfoHeader',
            parent=styles['Normal'],
            fontSize=7,
            textColor=colors.white,
            fontName='Helvetica-Bold',
            spaceAfter=4
        )
        
        # Columna 1: Información de Factura
        info_factura_data = [
            [Paragraph('<b>Información de Factura</b>', info_header_style)],
            [Paragraph(f"<b>Fecha:</b> {escape(str(fecha_factura))}", info_box_style)],
            [Paragraph(f"<b>Cliente:</b> {escape(str(ars.get('nombre', 'N/A')))}", info_box_style)],
        ]
        if ars.get('rnc'):
            info_factura_data.append([Paragraph(f"<b>RNC:</b> {escape(str(ars.get('rnc')))}", info_box_style)])
        
        info_factura_table = Table(info_factura_data, colWidths=[2.4*inch])
        info_factura_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), primary_color),
            ('TEXTCOLOR', (0, 0), (0, 0), colors.white),
            ('BACKGROUND', (0, 1), (0, -1), colors.white),
            ('LEFTPADDING', (0, 0), (0, -1), 8),
            ('RIGHTPADDING', (0, 0), (0, -1), 8),
            ('TOPPADDING', (0, 0), (0, -1), 8),
            ('BOTTOMPADDING', (0, 0), (0, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, primary_color),  # Borde delgado
            ('BOX', (0, 0), (-1, -1), 1, primary_color),  # Borde alrededor de toda la tabla
        ]))
        
        # Columna 2: NCF
        ncf_data = [
            [Paragraph('<b>NCF</b>', info_header_style)],
            [Paragraph(f"<font color='{primary_color_hex}'>{escape(str(ncf_numero))}</font>", ParagraphStyle('NCFNumber', parent=info_box_style, fontSize=10, textColor=primary_color))],
        ]
        if ncf_tipo_descripcion:
            ncf_data.append([Paragraph(f"<b>Tipo:</b> {escape(str(ncf_tipo_descripcion))}", info_box_style)])
        if ncf_fecha_fin:
            ncf_data.append([Paragraph(f"<b>Válido hasta:</b> {escape(str(ncf_fecha_fin))}", info_box_style)])
        
        ncf_table = Table(ncf_data, colWidths=[2.4*inch])
        ncf_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), primary_color),
            ('TEXTCOLOR', (0, 0), (0, 0), colors.white),
            ('BACKGROUND', (0, 1), (0, -1), colors.white),
            ('LEFTPADDING', (0, 0), (0, -1), 8),
            ('RIGHTPADDING', (0, 0), (0, -1), 8),
            ('TOPPADDING', (0, 0), (0, -1), 8),
            ('BOTTOMPADDING', (0, 0), (0, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, primary_color),  # Borde delgado
            ('BOX', (0, 0), (-1, -1), 1, primary_color),  # Borde alrededor de toda la tabla
        ]))
        
        # Columna 3: Remitente
        remitente_data = [
            [Paragraph('<b>Remitente</b>', info_header_style)],
        ]
        if tipo_empresa == 'centro_salud':
            remitente_data.append([Paragraph(f"<b>{empresa_info.get('razon_social', empresa_info.get('nombre', 'N/A'))}</b>", info_box_style)])
            if empresa_info.get('rnc'):
                remitente_data.append([Paragraph(f"<b>RNC:</b> {empresa_info.get('rnc')}", info_box_style)])
        else:
            # Nombre del médico sin label "Médico:" - en negrita
            remitente_data.append([Paragraph(f"<b>{medico_factura.get('nombre', 'N/A')}</b>", info_box_style)])
            if medico_factura.get('especialidad'):
                especialidad_style = ParagraphStyle('Especialidad', parent=info_box_style, fontSize=7, textColor=colors.HexColor('#666'))
                remitente_data.append([Paragraph(medico_factura.get('especialidad', ''), especialidad_style)])
            if medico_factura.get('cedula'):
                remitente_data.append([Paragraph(f"<b>Código:</b> {medico_factura.get('cedula', '')}", info_box_style)])
            if medico_completo and medico_completo.get('exequatur'):
                remitente_data.append([Paragraph(f"<b>Exequátur:</b> {medico_completo.get('exequatur', '')}", info_box_style)])
        
        remitente_table = Table(remitente_data, colWidths=[2.4*inch])
        remitente_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), primary_color),
            ('TEXTCOLOR', (0, 0), (0, 0), colors.white),
            ('BACKGROUND', (0, 1), (0, -1), colors.white),
            ('LEFTPADDING', (0, 0), (0, -1), 8),
            ('RIGHTPADDING', (0, 0), (0, -1), 8),
            ('TOPPADDING', (0, 0), (0, -1), 8),
            ('BOTTOMPADDING', (0, 0), (0, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, primary_color),  # Borde delgado
            ('BOX', (0, 0), (-1, -1), 1, primary_color),  # Borde alrededor de toda la tabla
        ]))
        
        # Combinar las 3 columnas en una tabla con espaciado entre columnas
        info_combined = Table([[info_factura_table, ncf_table, remitente_table]], colWidths=[2.4*inch, 2.4*inch, 2.4*inch])
        info_combined.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 0),
            ('RIGHTPADDING', (0, 0), (-1, -1), 0),
            ('TOPPADDING', (0, 0), (-1, -1), 0),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ]))
        story.append(info_combined)
        story.append(Spacer(1, 0.25*inch))
        
        # Tabla de pacientes/servicios
        if pacientes:
            tabla_headers = ['No.', 'NOMBRES PACIENTE', 'NSS/CONTRATO', 'FECHA', 'AUTORIZACIÓN', 'SERVICIO', 'V/UNITARIO']
            tabla_data = [tabla_headers]
            
            for idx, paciente in enumerate(pacientes, 1):
                monto = float(paciente.get('monto') or paciente.get('monto_estimado', 0) or 0)
                tabla_data.append([
                    str(idx),
                    Paragraph(f"<b>{escape(str(paciente.get('nombre_paciente', 'N/A')))}</b>", info_box_style),
                    escape(str(paciente.get('nss', ''))),
                    escape(str(paciente.get('fecha_servicio', ''))),
                    escape(str(paciente.get('autorizacion', ''))),
                    escape(str(paciente.get('descripcion_servicio', ''))),
                    Paragraph(f"<b>{monto:,.2f}</b>", ParagraphStyle('Monto', parent=info_box_style, alignment=TA_RIGHT, fontName='Helvetica-Bold'))
                ])
            
            # Ajustar anchos de columnas según la imagen: No. (4%), NOMBRES (30%), NSS (10%), FECHA (12%), AUTORIZACIÓN (12%), SERVICIO (20%), V/UNITARIO (12%)
            # Ancho total disponible: ~7.5 inch (letter size - márgenes)
            tabla = Table(tabla_data, colWidths=[0.3*inch, 2.25*inch, 0.75*inch, 0.9*inch, 0.9*inch, 1.5*inch, 0.9*inch])
            tabla.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), primary_color),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 7),
                ('ALIGN', (0, 0), (0, -1), 'CENTER'),  # No.
                ('ALIGN', (3, 1), (3, -1), 'CENTER'),  # FECHA
                ('ALIGN', (6, 1), (6, -1), 'RIGHT'),  # V/UNITARIO
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#DDD')),
                ('LEFTPADDING', (0, 0), (-1, -1), 4),
                ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('FONTSIZE', (0, 1), (-1, -1), 7),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            story.append(tabla)
        
        story.append(Spacer(1, 0.25*inch))
        
        # Totales - alineados a la derecha
        total_style = ParagraphStyle('Total', parent=styles['Normal'], fontSize=9, alignment=TA_RIGHT, fontName='Helvetica-Bold')
        total_label_style = ParagraphStyle('TotalLabel', parent=styles['Normal'], fontSize=9, alignment=TA_RIGHT, fontName='Helvetica-Bold')
        total_final_style = ParagraphStyle('TotalFinal', parent=styles['Normal'], fontSize=12, alignment=TA_RIGHT, fontName='Helvetica-Bold', textColor=primary_color)
        
        # Crear tabla de totales alineada a la derecha
        totales_data = [
            [Paragraph('SUB-TOTAL:', total_label_style), Paragraph(f"{subtotal:,.2f}", total_style)],
            [Paragraph('ITBIS:', total_label_style), Paragraph('*E', total_style)],
            [Paragraph('TOTAL:', total_label_style), Paragraph(f"{total:,.2f}", total_final_style)],
        ]
        
        # Tabla de totales más ancha y alineada a la derecha
        totales_table = Table(totales_data, colWidths=[1.2*inch, 1.2*inch])
        totales_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LINEABOVE', (0, -1), (-1, -1), 1, primary_color),
            ('TOPPADDING', (0, -1), (-1, -1), 8),
        ]))
        
        # Contenedor para alinear totales a la derecha
        from reportlab.platypus import KeepTogether
        totales_container = Table([[totales_table]], colWidths=[7.5*inch])
        totales_container.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, 0), 'RIGHT'),
            ('VALIGN', (0, 0), (0, 0), 'TOP'),
        ]))
        story.append(totales_container)
        
        story.append(Spacer(1, 0.4*inch))
        
        # Footer
        footer_style = ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, alignment=TA_CENTER, textColor=colors.HexColor('#666'))
        footer_bold_style = ParagraphStyle('FooterBold', parent=styles['Normal'], fontSize=9, alignment=TA_CENTER, textColor=primary_color, fontName='Helvetica-Bold')
        
        if tipo_empresa == 'centro_salud':
            footer_data = [
                [Paragraph(f"<b>{empresa_info.get('razon_social', empresa_info.get('nombre', 'N/A'))}</b>", footer_bold_style)],
            ]
            if empresa_info.get('direccion'):
                footer_data.append([Paragraph(empresa_info.get('direccion', ''), footer_style)])
            footer_text = []
            if empresa_info.get('rnc'):
                footer_text.append(f"RNC: {empresa_info.get('rnc')}")
            if empresa_info.get('telefono'):
                footer_text.append(f"Tel: {empresa_info.get('telefono')}")
            if empresa_info.get('email'):
                footer_text.append(f"Email: {empresa_info.get('email')}")
            if footer_text:
                footer_data.append([Paragraph(' | '.join(footer_text), footer_style)])
        else:
            # Footer para médico - formato como ejemplo del PDF
            footer_data = [
                [Paragraph(f"<b>{medico_factura.get('nombre', 'N/A')}</b>", footer_bold_style)],
            ]
            
            # Segunda línea: Especialidad | Cédula | EXEQUATUR (en mayúsculas)
            footer_text_line1 = []
            if medico_factura.get('especialidad'):
                footer_text_line1.append(medico_factura.get('especialidad', ''))
            if medico_factura.get('cedula'):
                footer_text_line1.append(f"Cédula: {medico_factura.get('cedula', '')}")
            if medico_completo and medico_completo.get('exequatur'):
                footer_text_line1.append(f"EXEQUATUR: {medico_completo.get('exequatur', '')}")
            if footer_text_line1:
                footer_data.append([Paragraph(' | '.join(footer_text_line1), footer_style)])
            
            # Tercera línea: Dirección del centro médico (si está disponible)
            if centro_medico and centro_medico.get('nombre'):
                centro_text = centro_medico.get('nombre', '')
                if centro_medico.get('direccion'):
                    centro_text += f", {centro_medico.get('direccion', '')}"
                footer_data.append([Paragraph(centro_text, footer_style)])
        
        footer_table = Table(footer_data, colWidths=[7*inch])
        footer_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, -1), 'CENTER'),
            ('TOPPADDING', (0, 0), (0, -1), 4),
            ('BOTTOMPADDING', (0, 0), (0, -1), 4),
        ]))
        story.append(footer_table)
        
        # Construir PDF
        try:
            logger.info(f"Construyendo PDF para factura {factura_id} con {len(story)} elementos en story")
            doc.build(story)
            logger.info(f"PDF construido exitosamente para factura {factura_id}")
            
            # Obtener el contenido del buffer y crear un nuevo BytesIO para retornar
            buffer.seek(0)
            buffer_content = buffer.read()
            
            # Verificar que el buffer tiene contenido
            buffer_size = len(buffer_content) if buffer_content else 0
            if buffer_size == 0:
                logger.error(f"PDF generado para factura {factura_id} está vacío (buffer_size=0)")
                return None
            
            # Crear un nuevo BytesIO con el contenido del PDF para evitar problemas de lectura
            pdf_buffer = BytesIO(buffer_content)
            pdf_buffer.seek(0)
            
            logger.info(f"PDF generado exitosamente para factura {factura_id}, tamaño: {buffer_size} bytes")
            return pdf_buffer
        except Exception as build_error:
            import traceback
            error_trace = traceback.format_exc()
            logger.error(f"Error al construir PDF para factura {factura_id}: {error_trace}")
            print(f"Error al construir PDF para factura {factura_id}: {str(build_error)}")
            print(f"Traceback: {error_trace}")
            return None
        
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        logger.error(f"Error al generar PDF para factura {factura_id}: {error_trace}")
        logger.error(f"Tipo de error: {type(e).__name__}, Mensaje: {str(e)}")
        print(f"ERROR CRÍTICO al generar PDF para factura {factura_id}: {str(e)}")
        print(f"Traceback completo: {error_trace}")
        # También imprimir información de debug
        print(f"DEBUG - factura encontrada: {factura is not None}")
        print(f"DEBUG - detalles encontrados: {len(detalles) if detalles else 0}")
        print(f"DEBUG - pacientes procesados: {len(pacientes) if 'pacientes' in locals() else 'N/A'}")
        return None

@login_required
@permission_required('facturacion.imprimir')
def facturacion_descargar_pdf(factura_id):
    """Descargar PDF de factura"""
    if not REPORTLAB_AVAILABLE:
        flash('ReportLab no está disponible. Por favor, instale la librería reportlab.', 'error')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))
    
    tenant_id = get_current_tenant_id()
    if not validate_tenant_access('facturas', factura_id):
        flash('No tienes acceso a esta factura', 'error')
        return redirect(url_for('facturacion_historico'))
    
    try:
        factura_check = execute_query(
            'SELECT id FROM facturas WHERE id = %s AND tenant_id = %s',
            (factura_id, tenant_id),
        )
        
        if not factura_check:
            flash('La factura no existe o no tiene permisos para acceder a ella.', 'error')
            return redirect(url_for('facturacion_historico'))
        
        logger.info(f"Iniciando descarga de PDF para factura {factura_id}, tenant_id={tenant_id}")
        print(f"=== INICIANDO DESCARGA PDF FACTURA {factura_id} ===")
        
        factura_data = execute_query(
            '''
            SELECT id, ncf, fecha_emision, ars_id, subtotal, total
            FROM facturas
            WHERE id = %s AND tenant_id = %s
            ''',
            (factura_id, tenant_id),
        )
        
        if factura_data:
            logger.info(f"Datos de factura {factura_id}: ncf={factura_data.get('ncf')}, fecha={factura_data.get('fecha_emision')}, ars_id={factura_data.get('ars_id')}")
            print(f"Factura encontrada: ncf={factura_data.get('ncf')}, fecha={factura_data.get('fecha_emision')}, ars_id={factura_data.get('ars_id')}")
        else:
            logger.error(f"No se encontraron datos básicos de factura {factura_id}")
            print(f"ERROR: No se encontraron datos básicos de factura {factura_id}")
        
        detalles_check = execute_query(
            '''
            SELECT COUNT(*) as count
            FROM factura_detalles
            WHERE factura_id = %s AND tenant_id = %s
            ''',
            (factura_id, tenant_id),
        )
        detalles_count = detalles_check.get('count', 0) if detalles_check else 0
        logger.info(f"Factura {factura_id} tiene {detalles_count} detalles")
        print(f"Detalles encontrados: {detalles_count}")
        
        if detalles_count == 0:
            logger.error(f"Factura {factura_id} no tiene detalles. No se puede generar PDF.")
            print(f"ERROR: Factura {factura_id} no tiene detalles")
            flash('Error: La factura no tiene detalles asociados. No se puede generar el PDF.', 'error')
            return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))
        
        print(f"Llamando a generar_pdf_factura_vista_previa para factura {factura_id}...")
        buffer = generar_pdf_factura_vista_previa(factura_id, tenant_id)
        
        if buffer is None:
            logger.error(f"No se pudo generar PDF para factura {factura_id}")
            print(f"ERROR: generar_pdf_factura_vista_previa retornó None para factura {factura_id}")
            flash('Error al generar PDF. Verifique que la factura tiene datos válidos y detalles asociados.', 'error')
            return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))
        
        print(f"PDF generado exitosamente. Buffer tipo: {type(buffer)}")
        
        # Verificar que el buffer tiene contenido y prepararlo para envío
        try:
            # Asegurarse de que el buffer esté al inicio
            buffer.seek(0)
            
            # Verificar que el buffer tiene contenido sin leerlo (para no consumirlo)
            buffer_size = len(buffer.getvalue()) if hasattr(buffer, 'getvalue') else 0
            
            if buffer_size == 0:
                logger.error(f"PDF generado para factura {factura_id} está vacío en facturacion_descargar_pdf")
                flash('Error: El PDF generado está vacío.', 'error')
                return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))
            
            logger.info(f"PDF listo para descarga: factura {factura_id}, tamaño: {buffer_size} bytes")
            
            # Asegurarse de que el buffer esté al inicio antes de enviarlo
            buffer.seek(0)
            
            factura = execute_query(
                '''
                SELECT numero_factura
                FROM facturas
                WHERE id = %s AND tenant_id = %s
                ''',
                (factura_id, tenant_id),
            )
            filename = f"factura_{factura_id}_{factura.get('numero_factura', '') if factura else ''}.pdf"
            
            logger.info(f"Enviando PDF: factura {factura_id}, filename={filename}")
            return send_file(buffer, mimetype='application/pdf', as_attachment=True, download_name=filename)
        except Exception as buffer_error:
            import traceback
            error_trace = traceback.format_exc()
            logger.error(f"Error al preparar/enviar buffer para factura {factura_id}: {str(buffer_error)}")
            logger.error(f"Traceback: {error_trace}")
            flash(f'Error al generar/enviar PDF: {str(buffer_error)}', 'error')
            return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        logger.error(f"Error en facturacion_descargar_pdf para factura {factura_id}: {error_trace}")
        flash(f'Error al generar PDF: {str(e)}', 'error')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))

@login_required
@permission_required('facturacion.imprimir')
def facturacion_enviar_email(factura_id):
    """Enviar factura por email"""
    tenant_id = get_current_tenant_id()
    if not validate_tenant_access('facturas', factura_id):
        flash('No tienes acceso a esta factura', 'error')
        return redirect(url_for('facturacion_historico'))
    
    # Obtener email del destinatario
    destinatario = request.form.get('destinatario', '').strip()
    if not destinatario:
        flash('Debe especificar un email destinatario', 'error')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))
    
    # Validar email
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, destinatario):
        flash('Email inválido', 'error')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))
    
    factura = execute_query('''
        SELECT f.*, a.nombre as nombre_ars, a.rnc as ars_rnc,
               m.nombre as medico_nombre, m.especialidad as medico_especialidad,
               m.cedula as medico_cedula, m.exequatur as medico_exequatur,
               m.email as medico_email
        FROM facturas f
        LEFT JOIN ars a
          ON f.ars_id = a.id AND a.tenant_id = f.tenant_id
        LEFT JOIN medicos m
          ON f.medico_id = m.id AND m.tenant_id = f.tenant_id
        WHERE f.id = %s AND f.tenant_id = %s
    ''', (factura_id, tenant_id))
    
    if not factura:
        flash('Factura no encontrada', 'error')
        return redirect(url_for('facturacion_historico'))
    
    # Si SendGrid está disponible, enviar email
    if SENDGRID_AVAILABLE and REPORTLAB_AVAILABLE:
        try:
            # Generar PDF usando la función auxiliar
            buffer = generar_pdf_factura_vista_previa(factura_id, tenant_id)
            
            if not buffer:
                flash('Error al generar PDF', 'error')
                return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))
            
            pdf_data = buffer.getvalue()
            
            # Enviar email con SendGrid
            sendgrid_api_key = os.getenv('SENDGRID_API_KEY')
            sendgrid_from_email = os.getenv('SENDGRID_FROM_EMAIL', 'noreply@facturacion.com')
            
            if not sendgrid_api_key:
                flash('Configuración de email no disponible. Contacte al administrador.', 'error')
                return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))
            
            message = Mail(
                from_email=sendgrid_from_email,
                to_emails=destinatario,
                subject=f"Factura #{factura.get('numero_factura', factura_id)} - {factura.get('nombre_ars', 'N/A')}",
                html_content=f"""
                <html>
                <body>
                    <h2>Factura #{factura.get('numero_factura', factura_id)}</h2>
                    <p><strong>Fecha:</strong> {factura.get('fecha_emision', '')}</p>
                    <p><strong>NCF:</strong> {factura.get('ncf', '')}</p>
                    <p><strong>Cliente:</strong> {factura.get('nombre_ars', 'N/A')}</p>
                    <p><strong>Total:</strong> RD$ {factura.get('total', 0):,.2f}</p>
                    <p>Se adjunta el PDF de la factura.</p>
                </body>
                </html>
                """
            )
            
            # Adjuntar PDF
            encoded_pdf = base64.b64encode(pdf_data).decode()
            attachment = {
                'content': encoded_pdf,
                'filename': f"factura_{factura_id}_{factura.get('numero_factura', '')}.pdf",
                'type': 'application/pdf',
                'disposition': 'attachment'
            }
            message.attachment = attachment
            
            sg = SendGridAPIClient(sendgrid_api_key)
            response = sg.send(message)
            
            if response.status_code in [200, 202]:
                flash(f'Factura enviada exitosamente a {destinatario}', 'success')
            else:
                flash(f'Error al enviar email. Código: {response.status_code}', 'error')
            
        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            print(f"Error al enviar email: {error_trace}")
            flash(f'Error al enviar email: {str(e)}', 'error')
    else:
        flash('El servicio de envío de emails no está disponible. Contacte al administrador.', 'error')
    
    return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))

def _render_dashboard_medico(tenant_id, medico_id, fecha_desde, fecha_hasta):
    """Mostrar exclusivamente la actividad asociada al médico autenticado."""
    alcance = (tenant_id, medico_id, fecha_desde, fecha_hasta)
    consultas = execute_query('''
        SELECT COUNT(*) AS total,
               COUNT(DISTINCT paciente_id) AS pacientes,
               COALESCE(SUM(fecha = CURDATE()), 0) AS hoy
        FROM consultas_clinicas
        WHERE tenant_id=%s AND medico_id=%s
          AND fecha BETWEEN %s AND %s
    ''', alcance) or {}
    citas = execute_query('''
        SELECT COUNT(*) AS total,
               COALESCE(SUM(
                   estado = 'Programada'
                   AND TIMESTAMP(fecha, hora) >= NOW()
               ), 0) AS proximas
        FROM citas_medicas
        WHERE tenant_id=%s AND medico_id=%s
          AND fecha BETWEEN %s AND %s
    ''', alcance) or {}
    recetas = execute_query('''
        SELECT COUNT(*) AS total
        FROM recetas_medicas
        WHERE tenant_id=%s AND medico_id=%s
          AND fecha BETWEEN %s AND %s
    ''', alcance) or {}
    turnos = execute_query('''
        SELECT COUNT(*) AS total
        FROM turnos_atencion
        WHERE tenant_id=%s AND medico_id=%s
          AND fecha BETWEEN %s AND %s
          AND estado='Finalizado'
    ''', alcance) or {}
    actividad_reciente = execute_query('''
        SELECT c.id, c.paciente_id, c.fecha, c.hora,
               c.motivo_consulta, c.diagnostico_principal,
               p.nombre AS paciente_nombre
        FROM consultas_clinicas c
        JOIN pacientes p
          ON p.id=c.paciente_id AND p.tenant_id=c.tenant_id
        WHERE c.tenant_id=%s AND c.medico_id=%s
          AND c.fecha BETWEEN %s AND %s
        ORDER BY c.fecha DESC, c.hora DESC, c.id DESC
        LIMIT 10
    ''', alcance, fetch='all') or []
    medico = execute_query(
        'SELECT nombre, especialidad FROM medicos '
        'WHERE id=%s AND tenant_id=%s',
        (medico_id, tenant_id),
    ) or {}
    return render_template(
        'facturacion/dashboard_medico.html',
        medico=medico,
        consultas=consultas,
        citas=citas,
        recetas=recetas,
        turnos=turnos,
        actividad_reciente=actividad_reciente,
        fecha_desde=fecha_desde,
        fecha_hasta=fecha_hasta,
    )


@login_required
@permission_required('dashboard.ver')
def facturacion_dashboard():
    """Dashboard de facturación"""
    from datetime import datetime, timedelta
    
    # Fechas por defecto (último mes)
    fecha_hasta = request.args.get('fecha_hasta', datetime.now().strftime('%Y-%m-%d'))
    fecha_desde = request.args.get('fecha_desde', (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d'))
    
    # Estadísticas básicas
    total_facturas = 0
    total_facturado = 0.0
    monto_pendiente = 0.0
    ars_pendientes_nombres = []
    
    tenant_id = get_current_tenant_id()
    medico_id = getattr(current_user, 'medico_id', None)
    roles_rbac = set(getattr(current_user, 'rbac_roles', ()))
    es_medico = (
        'Médico' in roles_rbac
        or getattr(current_user, 'perfil', None) == 'Médico'
    )
    es_administrador = (
        'Administrador' in roles_rbac
        or getattr(current_user, 'perfil', None) == 'Administrador'
    )
    if medico_id and es_medico and not es_administrador:
        return _render_dashboard_medico(
            tenant_id,
            medico_id,
            fecha_desde,
            fecha_hasta,
        )
        
    try:
        # Total de facturas
        result = execute_query('''
            SELECT COUNT(*) as total FROM facturas 
            WHERE tenant_id = %s
        ''', (tenant_id,))
        total_facturas = result['total'] if result else 0
        
        # Total facturado
        result = execute_query('''
            SELECT COALESCE(SUM(total), 0) as total FROM facturas 
            WHERE tenant_id = %s
        ''', (tenant_id,))
        total_facturado = float(result['total']) if result and result['total'] else 0.0
        
        # Monto pendiente (si existe tabla pacientes con monto)
        try:
            result = execute_query('''
                SELECT COALESCE(SUM(monto), 0) as total FROM pacientes 
                WHERE tenant_id = %s
            ''', (tenant_id,))
            monto_pendiente = float(result['total']) if result and result['total'] else 0.0
        except:
            monto_pendiente = 0.0
        
        # ARS pendientes
        result = execute_query('''
            SELECT DISTINCT a.nombre 
            FROM pacientes_pendientes pp 
            JOIN ars a
              ON pp.ars_id = a.id
             AND a.tenant_id = pp.tenant_id
            WHERE pp.estado = 'Pendiente'
              AND pp.tenant_id = %s
        ''', (tenant_id,), fetch='all')
        ars_pendientes_nombres = [r['nombre'] for r in result] if result else []
        
    except Exception as e:
        print(f"Error en dashboard: {e}")
    
    # Facturación por mes
    facturacion_por_mes = []
    try:
        result = execute_query('''
            SELECT DATE_FORMAT(fecha_emision, '%%Y-%%m') as mes, 
                   SUM(total) as total_monto
            FROM facturas
            WHERE fecha_emision BETWEEN %s AND %s
              AND tenant_id = %s
            GROUP BY DATE_FORMAT(fecha_emision, '%%Y-%%m')
            ORDER BY mes
        ''', (fecha_desde, fecha_hasta, tenant_id), fetch='all')
        facturacion_por_mes = [{'mes': r['mes'], 'total_monto': float(r['total_monto'])} for r in result] if result else []
    except:
        facturacion_por_mes = []
    
    # Facturación por ARS y mes
    facturacion_ars_mes = []
    try:
        result = execute_query('''
            SELECT DATE_FORMAT(f.fecha_emision, '%%Y-%%m') as mes,
                   a.nombre as nombre_ars,
                   SUM(f.total) as total_monto
            FROM facturas f
            JOIN ars a
              ON f.ars_id = a.id
             AND a.tenant_id = f.tenant_id
            WHERE f.fecha_emision BETWEEN %s AND %s
              AND f.tenant_id = %s
            GROUP BY DATE_FORMAT(f.fecha_emision, '%%Y-%%m'), a.nombre
            ORDER BY mes, a.nombre
        ''', (fecha_desde, fecha_hasta, tenant_id), fetch='all')
        facturacion_ars_mes = [{'mes': r['mes'], 'nombre_ars': r['nombre_ars'], 'total_monto': float(r['total_monto'])} for r in result] if result else []
    except:
        facturacion_ars_mes = []
    
    # Listas para filtros
    tenant_id = get_current_tenant_id()
    ars_list = execute_query('SELECT * FROM ars WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    medicos_factura_list = execute_query('SELECT * FROM medicos WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    medicos_consulta_list = medicos_factura_list  # Usar la misma lista
    
    return render_template('facturacion/dashboard.html',
                          total_facturas=total_facturas,
                          total_facturado=total_facturado,
                          monto_pendiente=monto_pendiente,
                          ars_pendientes_nombres=ars_pendientes_nombres,
                          facturacion_por_mes=facturacion_por_mes,
                          facturacion_ars_mes=facturacion_ars_mes,
                          ars_list=ars_list,
                          medicos_factura_list=medicos_factura_list,
                          medicos_consulta_list=medicos_consulta_list,
                          fecha_desde=fecha_desde,
                          fecha_hasta=fecha_hasta,
                          es_administrador=user_has_permission(current_user, 'facturacion.editar'),
                          ars_ids_seleccionados=[],
                          medico_factura_ids_seleccionados=[],
                          medico_consulta_ids_seleccionados=[])

def registrar_consultas_pendientes_atomico(
    lineas,
    tenant_id,
    ars_id,
    medico_id,
    centro_medico_id,
    usuario_id,
):
    """Crear pacientes/pendientes como una unidad, sin consultas N+1."""
    normalizadas = []
    nss_vistos = set()
    for linea in lineas:
        nss = sanitize_input(linea.get('nss', ''), 50)
        nombre = sanitize_input(linea.get('nombre', ''), 200)
        if not nss or not nombre:
            continue
        if nss in nss_vistos:
            raise ValueError(f'El NSS {nss} está repetido en la carga')
        nss_vistos.add(nss)
        try:
            monto = Decimal(str(linea.get('monto', 0))).quantize(
                Decimal('0.01')
            )
        except (InvalidOperation, TypeError, ValueError):
            raise ValueError(f'El monto del paciente {nombre} no es válido')
        if monto < 0:
            raise ValueError(f'El monto del paciente {nombre} no puede ser negativo')
        normalizadas.append({
            'nss': nss,
            'nombre': nombre,
            'fecha': linea.get('fecha'),
            'autorizacion': sanitize_input(linea.get('autorizacion', ''), 50),
            'servicio': sanitize_input(linea.get('servicio', ''), 200),
            'monto': monto,
        })

    if not normalizadas:
        raise ValueError('No hay pacientes válidos para registrar')

    with database_transaction():
        placeholders = ','.join(['%s'] * len(normalizadas))
        existentes = execute_query(f'''
            SELECT id, nss, cedula, fecha_nacimiento
            FROM pacientes
            WHERE tenant_id = %s AND ars_id = %s
              AND nss IN ({placeholders})
            FOR UPDATE
        ''', (
            tenant_id,
            ars_id,
            *[linea['nss'] for linea in normalizadas],
        ), fetch='all') or []
        pacientes_por_nss = {paciente['nss']: paciente for paciente in existentes}

        for linea in normalizadas:
            paciente = pacientes_por_nss.get(linea['nss'])
            if paciente:
                if paciente_adulto_sin_cedula(paciente):
                    raise ValueError(
                        f"{linea['nombre']} ya cumplió 18 años y requiere "
                        'registrar su cédula antes de continuar'
                    )
                paciente_id = paciente['id']
                execute_update('''
                    UPDATE pacientes
                    SET nombre = %s, updated_at = NOW()
                    WHERE id = %s AND tenant_id = %s
                ''', (linea['nombre'], paciente_id, tenant_id))
            else:
                paciente_id = execute_update('''
                    INSERT INTO pacientes
                    (tenant_id, nombre, nss, ars_id, created_by)
                    VALUES (%s, %s, %s, %s, %s)
                ''', (
                    tenant_id, linea['nombre'], linea['nss'],
                    ars_id, usuario_id
                ))
                if not paciente_id:
                    raise RuntimeError('No se pudo crear el paciente')
                pacientes_por_nss[linea['nss']] = {
                    'id': paciente_id,
                    'nss': linea['nss'],
                }

            servicios = linea['servicio']
            if linea['autorizacion']:
                servicios += f" - Autorización: {linea['autorizacion']}"
            pendiente_id = execute_update('''
                INSERT INTO pacientes_pendientes
                (tenant_id, paciente_id, nombre_paciente, nss, ars_id,
                 fecha_servicio, servicios_realizados, monto_estimado,
                 estado, medico_id, centro_medico_id, created_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s,
                        'Pendiente', %s, %s, %s)
            ''', (
                tenant_id, paciente_id, linea['nombre'], linea['nss'], ars_id,
                linea['fecha'], servicios, linea['monto'], medico_id,
                centro_medico_id, usuario_id
            ))
            if not pendiente_id:
                raise RuntimeError('No se pudo crear la consulta pendiente')

    return len(normalizadas)

@login_required
@permission_required('facturacion.crear')
def facturacion_facturas_nueva():
    """Agregar pacientes para facturar"""
    tenant_id = get_current_tenant_id()
    
    if request.method == 'POST':
        # Obtener datos del formulario
        # Validar y sanitizar entrada
        medico_id = validate_int(request.form.get('medico_id'), min_value=1)
        ars_id = validate_int(request.form.get('ars_id'), min_value=1)
        centro_medico_id = validate_int(request.form.get('centro_medico_id'), min_value=1) if request.form.get('centro_medico_id') else None
        lineas_json = request.form.get('lineas_json', '').strip()
        
        if not medico_id or not ars_id or not lineas_json:
            flash('Faltan datos obligatorios (Médico, ARS o pacientes)', 'error')
            return redirect(url_for('facturacion_facturas_nueva'))
        
        # Validar que los IDs pertenezcan al tenant
        tenant_id = get_current_tenant_id()
        if not validate_tenant_access('medicos', medico_id) or \
           not validate_tenant_access('ars', ars_id):
            flash('No tienes acceso a uno o más de los recursos seleccionados', 'error')
            return redirect(url_for('facturacion_facturas_nueva'))
        
        if centro_medico_id and not validate_tenant_access('centros_medicos', centro_medico_id):
            flash('Centro médico no válido', 'error')
            return redirect(url_for('facturacion_facturas_nueva'))
        
        # Validar JSON
        try:
            import json
            lineas = json.loads(lineas_json)
            # Limitar número de pacientes por request (prevenir DoS)
            if len(lineas) > 1000:
                flash('Demasiados pacientes en una sola operación (máximo 1000)', 'error')
                return redirect(url_for('facturacion_facturas_nueva'))
        except json.JSONDecodeError as e:
            logger.error(f"Error al parsear JSON: {e}")
            flash('Error al procesar los datos de los pacientes', 'error')
            return redirect(url_for('facturacion_facturas_nueva'))
        
        if not lineas or len(lineas) == 0:
            flash('Debe agregar al menos un paciente', 'error')
            return redirect(url_for('facturacion_facturas_nueva'))
        
        try:
            pacientes_agregados = registrar_consultas_pendientes_atomico(
                lineas,
                tenant_id,
                ars_id,
                medico_id,
                centro_medico_id,
                current_user.id,
            )
        except ValueError as error:
            flash(str(error), 'error')
            return redirect(url_for('facturacion_facturas_nueva'))
        except Exception:
            logger.error(
                'Error al registrar consultas pendientes',
                exc_info=True,
            )
            flash(
                'No se pudo completar el registro. No se aplicó ningún cambio.',
                'error',
            )
            return redirect(url_for('facturacion_facturas_nueva'))
        
        flash(f'{pacientes_agregados} paciente(s) agregado(s) como pendientes de facturación', 'success')
        return redirect(url_for('facturacion_pacientes_pendientes'))
    
    # GET: Mostrar formulario
    ars_list = execute_query('SELECT * FROM ars WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    medicos = execute_query('SELECT * FROM medicos WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    
    # Obtener relaciones médico-centro para poblar el dropdown de centros médicos
    centros_medicos = execute_query('''
        SELECT 
            mc.medico_id,
            mc.centro_medico_id as centro_id,
            cm.nombre as centro_nombre,
            mc.es_defecto
        FROM medico_centro mc
        INNER JOIN centros_medicos cm
          ON mc.centro_medico_id = cm.id AND cm.tenant_id = mc.tenant_id
        WHERE mc.tenant_id = %s AND cm.activo = 1
        ORDER BY mc.medico_id, mc.es_defecto DESC, cm.nombre
    ''', (tenant_id,), fetch='all') or []
    
    # Obtener servicios para el datalist
    servicios_list = execute_query('''
        SELECT descripcion, precio_base 
        FROM servicios 
        WHERE tenant_id = %s AND activo = 1 
        ORDER BY descripcion
    ''', (tenant_id,), fetch='all') or []

    paciente_preseleccionado = None
    paciente_id = validate_int(request.args.get('paciente_id'), min_value=1, default=None)
    if paciente_id:
        paciente_preseleccionado = execute_query(
            'SELECT id, nombre, cedula, fecha_nacimiento, nss, ars_id '
            'FROM pacientes WHERE id=%s AND tenant_id=%s',
            (paciente_id, tenant_id)
        )
        if paciente_adulto_sin_cedula(paciente_preseleccionado):
            flash('Debe actualizar la cédula propia del paciente antes de registrar la consulta', 'warning')
            return redirect(url_for('facturacion_paciente_acciones', paciente_id=paciente_id))
    
    return render_template('facturacion/facturas_form.html', 
                         ars_list=ars_list, 
                         medicos=medicos, 
                         centros_medicos=centros_medicos,
                         servicios_list=servicios_list,
                         paciente_preseleccionado=paciente_preseleccionado)

@login_required
@permission_required('facturacion.crear')
def descargar_plantilla_excel():
    """Descargar plantilla Excel para importar pacientes"""
    try:
        if not OPENPYXL_AVAILABLE:
            flash('La funcionalidad de Excel no está disponible', 'error')
            return redirect(url_for('facturacion_facturas_nueva'))
        
        tenant_id = get_current_tenant_id()
        if tenant_id is None:
            flash('Error al obtener el tenant', 'error')
            return redirect(url_for('facturacion_facturas_nueva'))
        
        # Obtener tema del usuario
        TEMAS = {
            'cyan': {'primary': '#06B6D4', 'primary_dark': '#0891B2'},
            'ocean': {'primary': '#0EA5E9', 'primary_dark': '#0284C7'},
            'emerald': {'primary': '#10B981', 'primary_dark': '#059669'},
            'teal': {'primary': '#14B8A6', 'primary_dark': '#0D9488'},
            'coral': {'primary': '#FF6B6B', 'primary_dark': '#EE5A52'},
            'sunset': {'primary': '#F59E0B', 'primary_dark': '#D97706'},
            'rose': {'primary': '#F43F5E', 'primary_dark': '#E11D48'},
            'amber': {'primary': '#F59E0B', 'primary_dark': '#D97706'},
            'indigo': {'primary': '#6366F1', 'primary_dark': '#4F46E5'},
            'purple': {'primary': '#A855F7', 'primary_dark': '#9333EA'},
            'violet': {'primary': '#8B5CF6', 'primary_dark': '#7C3AED'},
            'slate': {'primary': '#64748B', 'primary_dark': '#475569'},
            'navy': {'primary': '#1E3A8A', 'primary_dark': '#1E40AF'},
            'forest': {'primary': '#166534', 'primary_dark': '#14532D'},
            'wine': {'primary': '#7F1D1D', 'primary_dark': '#991B1B'},
            'bronze': {'primary': '#92400E', 'primary_dark': '#78350F'}
        }
        
        tema_actual = 'cyan'  # Default
        if current_user.is_authenticated and hasattr(current_user, 'tema_color') and current_user.tema_color:
            tema_actual = current_user.tema_color
        
        # Asegurar que tema_actual sea válido
        if tema_actual not in TEMAS:
            tema_actual = 'cyan'
        
        tema = TEMAS.get(tema_actual, TEMAS['cyan'])
        if not tema or 'primary' not in tema:
            tema = TEMAS['cyan']
        
        color_primary = tema.get('primary', '#06B6D4')
        if not color_primary:
            color_primary = '#06B6D4'
        
        # Convertir color hexadecimal a formato de openpyxl (sin #)
        color_hex_clean = color_primary.lstrip('#')
        if not color_hex_clean:
            color_hex_clean = '06B6D4'
        
        # Convertir color hexadecimal a RGB
        def hex_to_rgb(hex_color):
            if not hex_color:
                hex_color = '#06B6D4'
            hex_color = hex_color.lstrip('#')
            if not hex_color or len(hex_color) < 6:
                hex_color = '06B6D4'
            try:
                return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
            except Exception:
                return (6, 182, 212)  # Color cyan por defecto
        
        rgb_color = hex_to_rgb(color_primary)
        
        # Obtener servicios activos del tenant
        try:
            servicios_result = execute_query(
                'SELECT descripcion FROM servicios WHERE tenant_id = %s AND activo = 1 ORDER BY descripcion', 
                (tenant_id,), fetch='all'
            )
            if servicios_result is None:
                servicios_list = []
            elif isinstance(servicios_result, list):
                servicios_list = [s for s in servicios_result if s and isinstance(s, dict)]
            else:
                servicios_list = []
        except Exception as e:
            servicios_list = []
        
        # Crear workbook
        wb = Workbook()
        
        # Eliminar hoja por defecto (si existe)
        if wb.active is not None:
            try:
                wb.remove(wb.active)
            except Exception:
                pass  # Si hay error al eliminar, continuar
    
        # ========== HOJA 1: INSTRUCCIONES ==========
        ws_instrucciones = wb.create_sheet("Instrucciones", 0)
        if ws_instrucciones is None:
            raise ValueError("No se pudo crear la hoja de Instrucciones")
        
        # Título
        title_cell = ws_instrucciones.cell(row=1, column=1, value="INSTRUCCIONES PARA CARGAR PACIENTES")
        title_cell.font = Font(bold=True, size=16, color="8B5A9F")
        ws_instrucciones.merge_cells('A1:D1')
        
        # Instrucciones numeradas
        instrucciones = [
            "Complete la hoja \"Pacientes\" con los datos de los pacientes",
            "NSS: Solo números y guiones (ej: 001-234-5678)",
            "NOMBRE: Nombre completo del paciente",
            "FECHA: Formato AAAA-MM-DD (ej: 2025-10-16)",
            "AUTORIZACIÓN: Solo números, debe ser única para cada paciente",
            "SERVICIO: Seleccione de la lista desplegable (se alimenta de la hoja \"Servicios\")",
            "MONTO: Cantidad en pesos (solo números)"
        ]
        
        row = 3
        if instrucciones and isinstance(instrucciones, list):
            for i, instruccion in enumerate(instrucciones, 1):
                if instruccion is not None:
                    num_cell = ws_instrucciones.cell(row=row, column=1, value=f"{i}.")
                    num_cell.font = Font(bold=True)
                    text_cell = ws_instrucciones.cell(row=row, column=2, value=instruccion)
                    ws_instrucciones.merge_cells(f'B{row}:D{row}')
                    row += 1
        
        # Sección IMPORTANTE
        row += 1
        importante_cell = ws_instrucciones.cell(row=row, column=1, value="IMPORTANTE:")
        importante_cell.font = Font(bold=True, size=12, color="8B5A9F")
        row += 1
        
        importantes = [
            "Los encabezados están protegidos y NO se pueden modificar",
            "La columna SERVICIO tiene lista desplegable - haga clic en la flecha para seleccionar",
            "Cada autorización debe ser única",
            "Complete directamente desde la fila 2"
        ]
        
        if importantes and isinstance(importantes, list):
            for importante in importantes:
                if importante is not None:
                    bullet_cell = ws_instrucciones.cell(row=row, column=1, value="•")
                    bullet_cell.font = Font(bold=True)
                    text_cell = ws_instrucciones.cell(row=row, column=2, value=importante)
                    ws_instrucciones.merge_cells(f'B{row}:D{row}')
                    row += 1
        
        # Sección NOTA
        row += 1
        nota_title = ws_instrucciones.cell(row=row, column=1, value="NOTA:")
        nota_title.font = Font(bold=True, size=12, color="8B5A9F")
        row += 1
        nota_text = ws_instrucciones.cell(row=row, column=1, value="Antes de cargar, debe seleccionar el Médico y ARS en la página web")
        ws_instrucciones.merge_cells(f'A{row}:D{row}')
        
        # Ajustar ancho de columnas
        ws_instrucciones.column_dimensions['A'].width = 5
        ws_instrucciones.column_dimensions['B'].width = 80
        ws_instrucciones.column_dimensions['C'].width = 10
        ws_instrucciones.column_dimensions['D'].width = 10
        
        # Proteger hoja de instrucciones
        try:
            if ws_instrucciones is not None:
                # Iterar sobre las filas que tienen datos
                rows_iter = ws_instrucciones.iter_rows(min_row=1, max_row=100)
                if rows_iter is not None:
                    for row in rows_iter:
                        if row is not None:
                            for cell in row:
                                if cell is not None:
                                    cell.protection = Protection(locked=True)
            if ws_instrucciones is not None:
                ws_instrucciones.protection.sheet = True
        except Exception as e:
            # Si hay error, solo activar la protección sin bloquear celdas
            try:
                if ws_instrucciones is not None:
                    ws_instrucciones.protection.sheet = True
            except:
                pass
        
        # ========== HOJA 2: SERVICIOS ==========
        ws_servicios = wb.create_sheet("Servicios", 1)
        if ws_servicios is None:
            raise ValueError("No se pudo crear la hoja de Servicios")
        
        # Encabezado (usar color del tema del usuario)
        header_cell = ws_servicios.cell(row=1, column=1, value="SERVICIOS DISPONIBLES")
        header_cell.font = Font(bold=True, size=14, color="FFFFFF")
        header_cell.fill = PatternFill(start_color=color_hex_clean, end_color=color_hex_clean, fill_type="solid")
        header_cell.alignment = Alignment(horizontal="center", vertical="center")
        ws_servicios.merge_cells('A1:B1')
        
        # Encabezados de tabla
        ws_servicios.cell(row=2, column=1, value="Servicio").font = Font(bold=True)
        ws_servicios.cell(row=2, column=1).fill = PatternFill(start_color="E0E0E0", end_color="E0E0E0", fill_type="solid")
        
        # Agregar servicios
        if servicios_list and isinstance(servicios_list, list) and len(servicios_list) > 0:
            try:
                for idx, servicio in enumerate(servicios_list, 3):
                    if servicio and isinstance(servicio, dict):
                        descripcion = servicio.get('descripcion', '')
                        if descripcion:
                            ws_servicios.cell(row=idx, column=1, value=descripcion)
            except Exception as e:
                ws_servicios.cell(row=3, column=1, value="Error al cargar servicios")
        else:
            ws_servicios.cell(row=3, column=1, value="No hay servicios disponibles")
        
        # Ajustar ancho
        ws_servicios.column_dimensions['A'].width = 50
        ws_servicios.column_dimensions['B'].width = 10
        
        # Proteger hoja de servicios
        try:
            if ws_servicios is not None:
                # Iterar sobre las filas que tienen datos
                rows_iter = ws_servicios.iter_rows(min_row=1, max_row=100)
                if rows_iter is not None:
                    for row in rows_iter:
                        if row is not None:
                            for cell in row:
                                if cell is not None:
                                    cell.protection = Protection(locked=True)
            if ws_servicios is not None:
                ws_servicios.protection.sheet = True
        except Exception as e:
            # Si hay error, solo activar la protección sin bloquear celdas
            try:
                if ws_servicios is not None:
                    ws_servicios.protection.sheet = True
            except:
                pass
        
        # ========== HOJA 3: PACIENTES ==========
        ws = wb.create_sheet("Pacientes", 2)
        if ws is None:
            raise ValueError("No se pudo crear la hoja de Pacientes")
        
        # Estilos para encabezados (usar color del tema del usuario)
        header_fill = PatternFill(start_color=color_hex_clean, end_color=color_hex_clean, fill_type="solid")
        header_font = Font(bold=True, color="FFFFFF", size=12)
        header_alignment = Alignment(horizontal="center", vertical="center")
        
        # Primero, desbloquear TODAS las celdas por defecto
        # Luego bloquearemos solo la fila 1 (encabezado)
        if ws is not None:
            try:
                # Desbloquear todas las celdas primero (fila 2 en adelante, hasta fila 1000)
                for row_num in range(2, 1001):
                    for col_num in range(1, 7):  # 6 columnas (A-F)
                        try:
                            cell = ws.cell(row=row_num, column=col_num)
                            if cell is not None:
                                cell.protection = Protection(locked=False)
                        except Exception:
                            pass
            except Exception:
                pass
        
        # Encabezados (bloqueados) - Solo la fila 1 estará protegida
        headers = ['NSS', 'Nombre Completo', 'Fecha', 'Autorización', 'Servicio', 'Monto']
        if headers and isinstance(headers, list):
            for col_num, header in enumerate(headers, 1):
                if header is not None:
                    cell = ws.cell(row=1, column=col_num, value=header)
                    cell.fill = header_fill
                    cell.font = header_font
                    cell.alignment = header_alignment
                    cell.protection = Protection(locked=True)  # Bloquear solo el encabezado
        
        # No agregar fila de ejemplo - el usuario llenará desde la fila 2
        
        # Validación de datos: Lista desplegable para SERVICIO (columna E)
        servicios_nombres = []
        if servicios_list and isinstance(servicios_list, list) and len(servicios_list) > 0:
            try:
                # Validar cada elemento antes de procesarlo
                for s in servicios_list:
                    if s is not None and isinstance(s, dict):
                        descripcion = s.get('descripcion', '')
                        if descripcion:
                            servicios_nombres.append(descripcion)
            except Exception as e:
                servicios_nombres = []
            
            if servicios_nombres and len(servicios_nombres) > 0:
                # Crear referencia a la hoja Servicios
                servicios_range = f"Servicios!$A$3:$A${2 + len(servicios_nombres)}"
                dv_servicio = DataValidation(type="list", formula1=servicios_range, allow_blank=False)
                dv_servicio.error = "Seleccione un servicio de la lista"
                dv_servicio.errorTitle = "Servicio inválido"
                dv_servicio.prompt = "Seleccione un servicio de la lista desplegable"
                dv_servicio.promptTitle = "Seleccionar Servicio"
                # Aplicar a toda la columna E (Servicio) desde la fila 2
                ws.add_data_validation(dv_servicio)
                dv_servicio.add(f"E2:E1048576")  # Aplicar a toda la columna E desde fila 2
        
        # Validación de datos: Autorización única (columna D)
        # Usar fórmula personalizada para verificar que no haya duplicados
        # COUNTIF($D:$D, D2) debe ser igual a 1 (solo una ocurrencia)
        dv_autorizacion = DataValidation(
            type="custom",
            formula1="COUNTIF($D:$D,D2)=1",
            allow_blank=False
        )
        dv_autorizacion.error = "Esta autorización ya existe. Cada autorización debe ser única."
        dv_autorizacion.errorTitle = "Autorización duplicada"
        dv_autorizacion.prompt = "Ingrese una autorización única (solo números)"
        dv_autorizacion.promptTitle = "Autorización"
        ws.add_data_validation(dv_autorizacion)
        dv_autorizacion.add(f"D2:D1048576")  # Aplicar a toda la columna D desde fila 2
        
        # Validación de datos: Solo números para MONTO (columna F)
        dv_monto = DataValidation(type="decimal", operator="greaterThan", formula1=0, allow_blank=False)
        dv_monto.error = "El monto debe ser un número mayor a cero"
        dv_monto.errorTitle = "Monto inválido"
        dv_monto.prompt = "Ingrese solo números (ej: 500.00)"
        dv_monto.promptTitle = "Monto"
        ws.add_data_validation(dv_monto)
        dv_monto.add(f"F2:F1048576")  # Aplicar a toda la columna F desde fila 2
        
        # Ajustar ancho de columnas
        column_widths = [15, 35, 12, 15, 30, 12]
        if column_widths and isinstance(column_widths, list):
            for col_num, width in enumerate(column_widths, 1):
                if width is not None:
                    try:
                        ws.column_dimensions[get_column_letter(col_num)].width = width
                    except Exception:
                        pass
        
        # Proteger la hoja - Solo el encabezado (fila 1) estará protegido
        # Las celdas de datos (fila 2 en adelante) permanecerán desbloqueadas
        try:
            if ws is not None and hasattr(ws, 'protection') and ws.protection is not None:
                ws.protection.sheet = True
                ws.protection.password = None
                ws.protection.formatCells = False
                ws.protection.formatColumns = False
                ws.protection.formatRows = False
                ws.protection.insertColumns = True
                ws.protection.insertRows = True
                ws.protection.insertHyperlinks = True
                ws.protection.deleteColumns = True
                ws.protection.deleteRows = True
                ws.protection.selectLockedCells = True
                ws.protection.sort = True
                ws.protection.autoFilter = True
                ws.protection.pivotTables = True
                ws.protection.selectUnlockedCells = True
            elif ws is not None:
                # Si protection no existe, solo activar la protección básica
                ws.protection.sheet = True
        except Exception as e:
            # Si hay error con la protección, continuar sin ella (no es crítico)
            try:
                if ws is not None:
                    ws.protection.sheet = True
            except:
                pass
    
        # Guardar en BytesIO
        output = BytesIO()
        wb.save(output)
        output.seek(0)
        
        # Nombre del archivo
        filename = 'plantilla_pacientes.xlsx'
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )
    except TypeError as e:
        import traceback
        error_details = traceback.format_exc()
        flash(f'Error al generar la plantilla: {str(e)}. Detalles: {error_details[:200]}', 'error')
        return redirect(url_for('facturacion_facturas_nueva'))
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        flash(f'Error inesperado al generar la plantilla: {str(e)}. Detalles: {error_details[:200]}', 'error')
        return redirect(url_for('facturacion_facturas_nueva'))

@login_required
@permission_required('facturacion.crear')
def facturacion_procesar_excel():
    """Procesar archivo Excel y devolver pacientes en formato JSON"""
    try:
        if not OPENPYXL_AVAILABLE:
            return jsonify({
                'error': True,
                'mensaje': 'La funcionalidad de Excel no está disponible',
                'errores': ['OpenPyXL no está instalado'],
                'total_errores': 1
            }), 400
        
        # Verificar que se haya enviado un archivo
        if 'archivo_excel' not in request.files:
            return jsonify({
                'error': True,
                'mensaje': 'No se recibió ningún archivo',
                'errores': ['Debe seleccionar un archivo Excel'],
                'total_errores': 1
            }), 400
        
        file = request.files['archivo_excel']
        if file.filename == '':
            return jsonify({
                'error': True,
                'mensaje': 'No se seleccionó ningún archivo',
                'errores': ['Debe seleccionar un archivo Excel'],
                'total_errores': 1
            }), 400
        
        # OpenPyXL solo procesa el formato OOXML (.xlsx).
        if not file.filename.lower().endswith('.xlsx'):
            return jsonify({
                'error': True,
                'mensaje': 'Formato de archivo inválido',
                'errores': ['El archivo debe ser .xlsx'],
                'total_errores': 1
            }), 400

        if not zipfile.is_zipfile(file.stream):
            return jsonify({
                'error': True,
                'mensaje': 'Archivo Excel inválido',
                'errores': ['El contenido no corresponde a un archivo .xlsx válido'],
                'total_errores': 1
            }), 400
        file.stream.seek(0)

        # Leer el archivo Excel
        from openpyxl import load_workbook
        wb = load_workbook(file, data_only=True, read_only=True)
        
        # Buscar la hoja "Pacientes"
        if 'Pacientes' not in wb.sheetnames:
            return jsonify({
                'error': True,
                'mensaje': 'Hoja "Pacientes" no encontrada',
                'errores': ['El archivo Excel debe contener una hoja llamada "Pacientes"'],
                'total_errores': 1
            }), 400
        
        ws = wb['Pacientes']
        max_excel_rows = int(os.getenv('MAX_EXCEL_ROWS', '5000'))
        if ws.max_row and ws.max_row - 1 > max_excel_rows:
            wb.close()
            return jsonify({
                'error': True,
                'mensaje': 'El archivo supera el límite permitido',
                'errores': [f'Máximo permitido: {max_excel_rows} pacientes'],
                'total_errores': 1
            }), 400
        
        # Obtener tenant_id
        tenant_id = get_current_tenant_id()
        if not tenant_id:
            return jsonify({
                'error': True,
                'mensaje': 'Error al obtener el tenant',
                'errores': ['No se pudo identificar la empresa'],
                'total_errores': 1
            }), 400
        
        # Obtener servicios válidos del tenant
        servicios_result = execute_query(
            'SELECT descripcion FROM servicios WHERE tenant_id = %s AND activo = 1',
            (tenant_id,), fetch='all'
        ) or []
        servicios_validos = [s['descripcion'].upper() for s in servicios_result if s and s.get('descripcion')]
        
        # Leer datos desde la fila 2 (la fila 1 es el encabezado)
        pacientes = []
        errores = []
        autorizaciones_vistas = set()
        numero_fila = 1
        
        for row in ws.iter_rows(min_row=2, values_only=False):
            numero_fila += 1
            
            # Obtener valores de las celdas
            nss = str(row[0].value).strip() if row[0].value else ''  # Columna A
            nombre = str(row[1].value).strip() if row[1].value else ''  # Columna B
            # Fecha puede venir como datetime de Excel o como string
            fecha_raw = row[2].value if row[2].value else ''
            if fecha_raw:
                # Si es datetime de Excel, convertir a string primero
                from datetime import datetime, date
                if isinstance(fecha_raw, (datetime, date)):
                    fecha = fecha_raw.strftime('%Y-%m-%d')
                else:
                    fecha = str(fecha_raw).strip()
            else:
                fecha = ''
            autorizacion = str(row[3].value).strip() if row[3].value else ''  # Columna D
            servicio = str(row[4].value).strip() if row[4].value else ''  # Columna E
            monto = row[5].value if row[5].value else ''  # Columna F
            
            # Si la fila está vacía, saltarla
            if not nss and not nombre and not fecha and not autorizacion and not servicio and not monto:
                continue
            
            # Validaciones
            errores_fila = []
            
            # Validar NSS
            if not nss:
                errores_fila.append(f'Fila {numero_fila}: NSS es obligatorio')
            elif len(nss) > 50:
                errores_fila.append(f'Fila {numero_fila}: NSS muy largo (máximo 50 caracteres)')
            
            # Validar Nombre
            if not nombre:
                errores_fila.append(f'Fila {numero_fila}: Nombre es obligatorio')
            elif len(nombre) > 200:
                errores_fila.append(f'Fila {numero_fila}: Nombre muy largo (máximo 200 caracteres)')
            
            # Validar y normalizar Fecha
            if not fecha:
                errores_fila.append(f'Fila {numero_fila}: Fecha es obligatoria')
            else:
                try:
                    from datetime import datetime, date
                    fecha_normalizada = None
                    
                    # Si ya está en formato AAAA-MM-DD, validar y usar directamente
                    try:
                        datetime.strptime(fecha, '%Y-%m-%d')
                        fecha_normalizada = fecha  # Ya está en el formato correcto
                    except ValueError:
                        # Si no está en formato AAAA-MM-DD, intentar normalizar
                        # Normalizar separadores: convertir "/" a "-"
                        fecha_str = fecha.replace('/', '-').strip()
                        
                        # Intentar parsear diferentes formatos
                        formatos_fecha = [
                            '%Y-%m-%d',      # AAAA-MM-DD (formato estándar)
                            '%d-%m-%Y',      # DD-MM-AAAA
                            '%m-%d-%Y',      # MM-DD-AAAA
                            '%Y/%m/%d',      # AAAA/MM/DD (por si acaso quedó algún /)
                            '%d/%m/%Y',      # DD/MM/AAAA
                            '%m/%d/%Y',      # MM/DD/AAAA
                        ]
                        
                        fecha_obj = None
                        for formato in formatos_fecha:
                            try:
                                fecha_obj = datetime.strptime(fecha_str, formato)
                                break
                            except ValueError:
                                continue
                        
                        if fecha_obj:
                            # Convertir a formato estándar AAAA-MM-DD
                            fecha_normalizada = fecha_obj.strftime('%Y-%m-%d')
                        else:
                            # Si no se pudo parsear, intentar con el valor original
                            raise ValueError(f'No se pudo parsear la fecha: {fecha}')
                    
                    if fecha_normalizada:
                        # Validar que el formato sea correcto (AAAA-MM-DD)
                        datetime.strptime(fecha_normalizada, '%Y-%m-%d')
                        fecha = fecha_normalizada
                    else:
                        raise ValueError(f'Fecha no válida: {fecha}')
                        
                except Exception as e:
                    errores_fila.append(f'Fila {numero_fila}: Fecha inválida "{fecha}" (formato esperado: AAAA-MM-DD o DD/MM/AAAA)')
            
            # Validar Autorización
            if not autorizacion:
                errores_fila.append(f'Fila {numero_fila}: Autorización es obligatoria')
            elif len(autorizacion) > 50:
                errores_fila.append(f'Fila {numero_fila}: Autorización muy larga (máximo 50 caracteres)')
            elif autorizacion.upper() in autorizaciones_vistas:
                errores_fila.append(f'Fila {numero_fila}: Autorización duplicada ({autorizacion})')
            else:
                autorizaciones_vistas.add(autorizacion.upper())
            
            # Validar Servicio
            if not servicio:
                errores_fila.append(f'Fila {numero_fila}: Servicio es obligatorio')
            elif servicios_validos and servicio.upper() not in servicios_validos:
                errores_fila.append(f'Fila {numero_fila}: Servicio "{servicio}" no existe. Servicios válidos: {", ".join(servicios_validos[:5])}...')
            
            # Validar Monto
            try:
                if monto == '' or monto is None:
                    errores_fila.append(f'Fila {numero_fila}: Monto es obligatorio')
                else:
                    monto_float = float(monto)
                    if monto_float <= 0:
                        errores_fila.append(f'Fila {numero_fila}: Monto debe ser mayor a cero')
            except (ValueError, TypeError):
                errores_fila.append(f'Fila {numero_fila}: Monto inválido (debe ser un número)')
            
            # Si hay errores en esta fila, agregarlos y continuar
            if errores_fila:
                errores.extend(errores_fila)
                continue
            
            # Si no hay errores, agregar el paciente
            pacientes.append({
                'nss': nss,
                'nombre': nombre.upper(),
                'fecha': fecha,
                'autorizacion': autorizacion.upper(),
                'servicio': servicio.upper(),
                'monto': float(monto)
            })
        
        # Si hay errores, devolverlos
        if errores:
            wb.close()
            return jsonify({
                'error': True,
                'mensaje': f'Se encontraron {len(errores)} error(es) en el archivo',
                'errores': errores,
                'total_errores': len(errores),
                'pacientes': []
            }), 400
        
        # Si no hay pacientes, devolver error
        if not pacientes:
            wb.close()
            return jsonify({
                'error': True,
                'mensaje': 'No se encontraron pacientes válidos en el archivo',
                'errores': ['El archivo Excel no contiene datos válidos en la hoja "Pacientes"'],
                'total_errores': 1,
                'pacientes': []
            }), 400
        
        # Si todo está bien, devolver los pacientes
        wb.close()
        return jsonify({
            'error': False,
            'mensaje': f'Se procesaron {len(pacientes)} paciente(s) correctamente',
            'pacientes': pacientes,
            'total': len(pacientes)
        }), 200
        
    except Exception as e:
        logger.error('Error al procesar archivo Excel', exc_info=True)
        return jsonify({
            'error': True,
            'mensaje': 'No fue posible procesar el archivo',
            'errores': ['Verifica el formato y vuelve a intentarlo'],
            'total_errores': 1,
        }), 500

@login_required
@permission_required('facturacion.crear')
def facturacion_generar():
    """Generar factura"""
    
    # Si es POST, redirigir al step 2
    if request.method == 'POST':
        # Validar y sanitizar entrada
        tipo_factura = request.form.get('tipo_factura', 'TRADICIONAL').strip().upper()
        ars_id = validate_int(request.form.get('ars_id'), min_value=1)
        ncf_id = (
            validate_int(request.form.get('ncf_id'), min_value=1)
            if tipo_factura == 'TRADICIONAL' else None
        )
        medico_factura_id = validate_int(request.form.get('medico_factura_id'), min_value=1)
        fecha_factura = request.form.get('fecha_factura', '').strip()

        if tipo_factura not in ['TRADICIONAL', 'ELECTRONICA']:
            flash('Tipo de factura inválido', 'error')
            return redirect(url_for('facturacion_generar'))
        if (
            tipo_factura == 'ELECTRONICA'
            and not ecf_habilitado_para_tenant(get_current_tenant_id())
        ):
            flash('La cuenta no está habilitada para facturación electrónica', 'error')
            return redirect(url_for('facturacion_generar'))
        
        # Validar fecha
        if fecha_factura:
            try:
                datetime.strptime(fecha_factura, '%Y-%m-%d')
            except ValueError:
                flash('Fecha inválida', 'error')
                return redirect(url_for('facturacion_generar'))
        
        if not all([ars_id, medico_factura_id, fecha_factura]) or (
            tipo_factura == 'TRADICIONAL' and not ncf_id
        ):
            flash('Todos los campos son obligatorios', 'error')
            return redirect(url_for('facturacion_generar'))
        
        # Validar que los IDs pertenezcan al tenant
        tenant_id = get_current_tenant_id()
        empresa_actual = get_empresa_info(tenant_id)
        es_centro_salud = (
            empresa_actual
            and empresa_actual.get('tipo_empresa') == 'centro_salud'
        )
        emisor_valido = (
            medico_factura_id == tenant_id
            if es_centro_salud
            else validate_tenant_access('medicos', medico_factura_id)
        )
        ncf_valido = (
            validate_tenant_access('ncf', ncf_id)
            if tipo_factura == 'TRADICIONAL' else True
        )
        if not validate_tenant_access('ars', ars_id) or \
           not ncf_valido or not emisor_valido:
            flash('No tienes acceso a uno o más de los recursos seleccionados', 'error')
            return redirect(url_for('facturacion_generar'))
        
        # Redirigir al step 2 con los parámetros
        return redirect(url_for('facturacion_generar_step2', 
                              tipo_factura=tipo_factura,
                              ars_id=ars_id, 
                              ncf_id=ncf_id, 
                              medico_factura_id=medico_factura_id,
                              fecha_factura=fecha_factura))
    
    tenant_id = get_current_tenant_id()
    
    # Obtener ARS activas
    ars_list = execute_query('''
        SELECT * FROM ars 
        WHERE activo = 1 AND tenant_id = %s 
        ORDER BY nombre
    ''', (tenant_id,), fetch='all') or []
    
    # Obtener NCF activos
    ncf_list = execute_query('''
        SELECT * FROM ncf 
        WHERE activo = 1 AND tenant_id = %s 
        ORDER BY tipo, prefijo
    ''', (tenant_id,), fetch='all') or []
    
    # Obtener información de la empresa para determinar tipo
    empresa_info = get_empresa_info(tenant_id)
    tipo_empresa = empresa_info.get('tipo_empresa') if empresa_info else None
    
    # Obtener médicos activos o razón social según tipo de empresa
    medicos_habilitados = []
    if tipo_empresa == 'centro_salud':
        # Si es centro de salud, usar la razón social de la empresa
        if empresa_info and empresa_info.get('razon_social'):
            medicos_habilitados = [{
                'id': empresa_info.get('id'),
                'nombre': empresa_info.get('razon_social'),
                'especialidad': 'Centro de Salud'
            }]
    else:
        # Si es médico o no tiene tipo definido, usar médicos
        medicos_habilitados = execute_query('''
            SELECT * FROM medicos 
            WHERE activo = 1 AND tenant_id = %s 
            ORDER BY nombre
        ''', (tenant_id,), fetch='all') or []
    
    pendientes = execute_query('''
        SELECT pp.*, a.nombre as ars_nombre
        FROM pacientes_pendientes pp
        LEFT JOIN ars a
          ON pp.ars_id = a.id AND a.tenant_id = pp.tenant_id
        WHERE pp.estado = 'Pendiente' AND pp.tenant_id = %s
        ORDER BY pp.created_at
    ''', (tenant_id,), fetch='all') or []
    
    # Obtener fecha actual en formato YYYY-MM-DD
    from datetime import date
    fecha_actual = date.today().strftime('%Y-%m-%d')
    
    return render_template('facturacion/generar_factura.html', 
                          pendientes=pendientes,
                          ars_list=ars_list,
                          ncf_list=ncf_list,
                          medicos_habilitados=medicos_habilitados,
                          fecha_actual=fecha_actual,
                          tipo_empresa=tipo_empresa,
                          ecf_habilitado=ecf_habilitado_para_tenant(tenant_id))

@login_required
@permission_required('facturacion.crear')
def facturacion_generar_step2():
    """Generar factura - Paso 2: Selección de pacientes"""
    
    # Si es POST, redirigir a vista previa
    if request.method == 'POST':
        tipo_factura = request.form.get('tipo_factura', 'TRADICIONAL').strip().upper()
        pacientes_ids_json = request.form.get('pacientes_ids')
        ars_id = request.form.get('ars_id')
        ncf_id = request.form.get('ncf_id')
        medico_factura_id = request.form.get('medico_factura_id')
        fecha_factura = request.form.get('fecha_factura')
        
        if tipo_factura not in ['TRADICIONAL', 'ELECTRONICA']:
            flash('Tipo de factura inválido', 'error')
            return redirect(url_for('facturacion_generar'))
        if (
            tipo_factura == 'ELECTRONICA'
            and not ecf_habilitado_para_tenant(get_current_tenant_id())
        ):
            flash('La cuenta no está habilitada para facturación electrónica', 'error')
            return redirect(url_for('facturacion_generar'))

        if not all([pacientes_ids_json, ars_id, medico_factura_id, fecha_factura]) or (
            tipo_factura == 'TRADICIONAL' and not ncf_id
        ):
            flash('Faltan datos obligatorios', 'error')
            return redirect(url_for('facturacion_generar'))
        
        try:
            import json
            pacientes_ids = json.loads(pacientes_ids_json)
        except json.JSONDecodeError:
            flash('Error al procesar los IDs de pacientes', 'error')
            return redirect(url_for('facturacion_generar'))
        
        if not pacientes_ids or len(pacientes_ids) == 0:
            flash('Debe seleccionar al menos un paciente', 'error')
            return redirect(url_for('facturacion_generar_step2',
                                  tipo_factura=tipo_factura,
                                  ars_id=ars_id,
                                  ncf_id=ncf_id,
                                  medico_factura_id=medico_factura_id,
                                  fecha_factura=fecha_factura))
        
        # Redirigir a vista previa
        return redirect(url_for('facturacion_vista_previa',
                              tipo_factura=tipo_factura,
                              pacientes_ids=','.join(map(str, pacientes_ids)),
                              ars_id=ars_id,
                              ncf_id=ncf_id,
                              medico_factura_id=medico_factura_id,
                              fecha_factura=fecha_factura))
    
    # Obtener parámetros de la URL (GET)
    tipo_factura = request.args.get('tipo_factura', 'TRADICIONAL').strip().upper()
    ars_id = request.args.get('ars_id')
    ncf_id = request.args.get('ncf_id')
    medico_factura_id = request.args.get('medico_factura_id')
    fecha_factura = request.args.get('fecha_factura')
    
    if tipo_factura not in ['TRADICIONAL', 'ELECTRONICA']:
        flash('Tipo de factura inválido', 'error')
        return redirect(url_for('facturacion_generar'))
    if (
        tipo_factura == 'ELECTRONICA'
        and not ecf_habilitado_para_tenant(get_current_tenant_id())
    ):
        flash('La cuenta no está habilitada para facturación electrónica', 'error')
        return redirect(url_for('facturacion_generar'))

    if not all([ars_id, medico_factura_id, fecha_factura]) or (
        tipo_factura == 'TRADICIONAL' and not ncf_id
    ):
        flash('Faltan parámetros obligatorios', 'error')
        return redirect(url_for('facturacion_generar'))
    
    tenant_id = get_current_tenant_id()
    
    # Obtener ARS
    ars = execute_query('SELECT * FROM ars WHERE id = %s AND tenant_id = %s', (ars_id, tenant_id))
    if not ars:
        flash('ARS no encontrada', 'error')
        return redirect(url_for('facturacion_generar'))
    
    # Obtener NCF tradicional o representar el e-CF inicial habilitado.
    if tipo_factura == 'TRADICIONAL':
        ncf = execute_query(
            'SELECT * FROM ncf WHERE id = %s AND tenant_id = %s',
            (ncf_id, tenant_id)
        )
        if not ncf:
            flash('NCF no encontrado', 'error')
            return redirect(url_for('facturacion_generar'))
    else:
        ncf = {'id': '', 'tipo': 'E31', 'prefijo': 'E31'}
    
    # Obtener información de la empresa para determinar tipo
    empresa_info = get_empresa_info(tenant_id)
    tipo_empresa = empresa_info.get('tipo_empresa') if empresa_info else None
    
    # Obtener médico o empresa según tipo
    medico_factura = None
    medico_factura_nombre = 'N/A'
    
    if tipo_empresa == 'centro_salud':
        # Si es centro de salud, buscar en empresas
        empresa_factura = execute_query('SELECT * FROM empresas WHERE id = %s', (medico_factura_id,))
        if empresa_factura and empresa_factura.get('id') == tenant_id:
            medico_factura = {
                'id': empresa_factura.get('id'),
                'nombre': empresa_factura.get('razon_social', empresa_factura.get('nombre', 'N/A')),
                'especialidad': 'Centro de Salud'
            }
            medico_factura_nombre = empresa_factura.get('razon_social', empresa_factura.get('nombre', 'N/A'))
        else:
            flash('Empresa no encontrada', 'error')
            return redirect(url_for('facturacion_generar'))
    else:
        # Si es médico, buscar en medicos
        medico_factura = execute_query('SELECT * FROM medicos WHERE id = %s AND tenant_id = %s', (medico_factura_id, tenant_id))
        if not medico_factura:
            flash('Médico no encontrado', 'error')
            return redirect(url_for('facturacion_generar'))
        medico_factura_nombre = medico_factura.get('nombre', 'N/A')
    
    pendientes_raw = execute_query('''
        SELECT pp.*, a.nombre as ars_nombre, m.nombre as medico_nombre
        FROM pacientes_pendientes pp
        LEFT JOIN ars a
          ON pp.ars_id = a.id AND a.tenant_id = pp.tenant_id
        LEFT JOIN medicos m
          ON pp.medico_id = m.id AND m.tenant_id = pp.tenant_id
        WHERE pp.estado = 'Pendiente'
          AND pp.ars_id = %s
          AND pp.tenant_id = %s
        ORDER BY pp.created_at
    ''', (ars_id, tenant_id), fetch='all') or []
    
    # Procesar los datos para extraer autorización y servicio
    pendientes = []
    for p in pendientes_raw:
        servicio_completo = p.get('servicios_realizados', '') or ''
        # Extraer servicio y autorización
        if ' - Autorización:' in servicio_completo:
            partes = servicio_completo.split(' - Autorización:')
            descripcion_servicio = partes[0].strip()
            autorizacion = partes[1].strip() if len(partes) > 1 else ''
        else:
            descripcion_servicio = servicio_completo.strip()
            autorizacion = ''
        
        p['descripcion_servicio'] = descripcion_servicio
        p['autorizacion'] = autorizacion
        p['paciente_nombre_completo'] = p.get('nombre_paciente', '')
        pendientes.append(p)
    
    # Obtener todos los médicos para el filtro
    medicos = execute_query('SELECT id, nombre FROM medicos WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    
    return render_template('facturacion/generar_factura_step2.html',
                          ars=ars,
                          ncf=ncf,
                          medico_factura_id=medico_factura_id,
                          medico_factura_nombre=medico_factura_nombre,
                          fecha_factura=fecha_factura,
                          tipo_factura=tipo_factura,
                          pendientes=pendientes,
                          medicos=medicos)

@login_required
@permission_required('facturacion.crear')
def facturacion_vista_previa():
    """Vista previa de factura antes de generar"""
    
    # Obtener parámetros
    tipo_factura = request.args.get('tipo_factura', 'TRADICIONAL').strip().upper()
    pacientes_ids_str = request.args.get('pacientes_ids', '')
    ars_id = request.args.get('ars_id')
    ncf_id = request.args.get('ncf_id')
    medico_factura_id = request.args.get('medico_factura_id')
    fecha_factura = request.args.get('fecha_factura')
    
    if tipo_factura not in ['TRADICIONAL', 'ELECTRONICA']:
        flash('Tipo de factura inválido', 'error')
        return redirect(url_for('facturacion_generar'))
    if (
        tipo_factura == 'ELECTRONICA'
        and not ecf_habilitado_para_tenant(get_current_tenant_id())
    ):
        flash('La cuenta no está habilitada para facturación electrónica', 'error')
        return redirect(url_for('facturacion_generar'))

    if not all([pacientes_ids_str, ars_id, medico_factura_id, fecha_factura]) or (
        tipo_factura == 'TRADICIONAL' and not ncf_id
    ):
        flash('Faltan parámetros obligatorios', 'error')
        return redirect(url_for('facturacion_generar'))
    
    # Convertir IDs de pacientes
    try:
        pacientes_ids = [int(id) for id in pacientes_ids_str.split(',') if id.strip()]
    except ValueError:
        flash('Error en los IDs de pacientes', 'error')
        return redirect(url_for('facturacion_generar'))
    
    if not pacientes_ids:
        flash('Debe seleccionar al menos un paciente', 'error')
        return redirect(url_for('facturacion_generar'))
    
    tenant_id = get_current_tenant_id()
    
    # Obtener datos de ARS, NCF y Médico
    ars = execute_query('SELECT * FROM ars WHERE id = %s AND tenant_id = %s', (ars_id, tenant_id))
    if not ars:
        flash('ARS no encontrada', 'error')
        return redirect(url_for('facturacion_generar'))
    
    if tipo_factura == 'TRADICIONAL':
        ncf = execute_query(
            'SELECT * FROM ncf WHERE id = %s AND tenant_id = %s',
            (ncf_id, tenant_id)
        )
        if not ncf:
            flash('NCF no encontrado', 'error')
            return redirect(url_for('facturacion_generar'))
    else:
        fecha_documento = datetime.strptime(fecha_factura, '%Y-%m-%d').date()
        secuencia_ecf = execute_query('''
            SELECT *,
                   GREATEST(ultimo_numero, secuencia_inicial - 1) + 1
                       AS proximo_numero
            FROM ecf_secuencias
            WHERE tenant_id=%s AND tipo_ecf='31' AND activo=1
              AND (fecha_autorizacion IS NULL OR fecha_autorizacion <= %s)
              AND fecha_vencimiento >= %s
              AND GREATEST(ultimo_numero, secuencia_inicial - 1)
                  < secuencia_final
            ORDER BY fecha_vencimiento, id
            LIMIT 1
        ''', (tenant_id, fecha_documento, fecha_documento))
        if not secuencia_ecf:
            flash(
                'Configure una secuencia E31 activa y vigente antes de continuar',
                'warning'
            )
            return redirect(url_for('facturacion_ncf'))
        ncf = {
            'id': '',
            'tipo': 'E31',
            'prefijo': 'E31',
            'fecha_fin': secuencia_ecf['fecha_vencimiento']
        }
    
    # Obtener información de la empresa para determinar tipo
    empresa_info = get_empresa_info(tenant_id)
    tipo_empresa = empresa_info.get('tipo_empresa') if empresa_info else None
    
    # Obtener médico o empresa según tipo
    medico_factura = None
    empresa_factura = None
    if tipo_empresa == 'centro_salud':
        # Si es centro de salud, buscar en empresas
        empresa_factura = execute_query('SELECT * FROM empresas WHERE id = %s', (medico_factura_id,))
        if empresa_factura and empresa_factura.get('id') == tenant_id:
            medico_factura = {
                'id': empresa_factura.get('id'),
                'nombre': empresa_factura.get('razon_social', empresa_factura.get('nombre', 'N/A')),
                'especialidad': 'Centro de Salud',
                'cedula': empresa_factura.get('rnc', '')
            }
        else:
            flash('Empresa no encontrada', 'error')
            return redirect(url_for('facturacion_generar'))
    else:
        # Si es médico, buscar en medicos
        medico_factura = execute_query('SELECT * FROM medicos WHERE id = %s AND tenant_id = %s', (medico_factura_id, tenant_id))
        if not medico_factura:
            flash('Médico no encontrado', 'error')
            return redirect(url_for('facturacion_generar'))
    
    # Obtener pacientes seleccionados exclusivamente dentro del tenant.
    placeholders = ','.join(['%s'] * len(pacientes_ids))
    pacientes_query = f'''
        SELECT pp.*, a.nombre as ars_nombre, m.nombre as medico_nombre
        FROM pacientes_pendientes pp
        LEFT JOIN ars a
          ON pp.ars_id = a.id AND a.tenant_id = pp.tenant_id
        LEFT JOIN medicos m
          ON pp.medico_id = m.id AND m.tenant_id = pp.tenant_id
        WHERE pp.id IN ({placeholders}) AND pp.tenant_id = %s
        ORDER BY pp.fecha_servicio
    '''
    pacientes_raw = execute_query(
        pacientes_query,
        tuple(pacientes_ids) + (tenant_id,),
        fetch='all',
    ) or []
    
    # Procesar pacientes
    pacientes = []
    for p in pacientes_raw:
        servicio_completo = p.get('servicios_realizados', '') or ''
        if ' - Autorización:' in servicio_completo:
            partes = servicio_completo.split(' - Autorización:')
            descripcion_servicio = partes[0].strip()
            autorizacion = partes[1].strip() if len(partes) > 1 else ''
        else:
            descripcion_servicio = servicio_completo.strip()
            autorizacion = ''
        
        p['descripcion_servicio'] = descripcion_servicio
        p['autorizacion'] = autorizacion
        p['paciente_nombre_completo'] = p.get('nombre_paciente', '')
        pacientes.append(p)
    
    # Obtener centro médico del médico (si tiene uno asociado)
    centro_medico = None
    if medico_factura.get('centro_medico_id'):
        centro_medico = execute_query('SELECT * FROM centros_medicos WHERE id = %s AND tenant_id = %s', 
                                     (medico_factura['centro_medico_id'], tenant_id))
    
    # Si no tiene centro médico asociado, obtener el primero del tenant
    if not centro_medico:
        centro_medico = execute_query('SELECT * FROM centros_medicos WHERE tenant_id = %s LIMIT 1', (tenant_id,))
    
    # Si aún no hay centro médico, crear uno por defecto
    if not centro_medico:
        centro_medico = {
            'nombre': 'Centro Médico',
            'direccion': ''
        }
    
    # Calcular subtotal y total
    subtotal = sum(float(p.get('monto_estimado', 0) or 0) for p in pacientes)
    total = subtotal  # Por ahora el total es igual al subtotal (ITBIS es exento)
    
    # La vista previa no reserva el consecutivo; la reserva ocurre al confirmar.
    if tipo_factura == 'ELECTRONICA':
        ncf_completo = build_encf('31', secuencia_ecf['proximo_numero'])
        ncf_tipo_descripcion = 'Factura de Crédito Fiscal Electrónica'
    else:
        proximo_numero = ncf.get('ultimo_numero', 0) + 1
        tamano_secuencia = ncf.get('tamano_secuencia', 8)
        ncf_completo = (
            f"{ncf.get('prefijo', '')}"
            f"{proximo_numero:0{tamano_secuencia}d}"
        )
        ncf_tipos_descripciones = {
            'B01': 'Factura de Crédito Fiscal',
            'B02': 'Factura de Consumo',
            'B14': 'Registro Único de Ingresos',
            'B15': 'GUBERNAMENTAL'
        }
        ncf_tipo_descripcion = ncf_tipos_descripciones.get(
            ncf.get('tipo', ''),
            ncf.get('tipo', '')
        )
    
    return render_template('facturacion/vista_previa_factura.html',
                          pacientes=pacientes,
                          pacientes_ids=','.join(map(str, pacientes_ids)),
                          tipo_factura=tipo_factura,
                          ars=ars,
                          ncf=ncf,
                          ncf_completo=ncf_completo,  # Número completo del NCF
                          ncf_tipo_descripcion=ncf_tipo_descripcion,  # Descripción del tipo de NCF
                          medico=medico_factura,  # Cambiado de medico_factura a medico
                          medico_factura=medico_factura,  # Mantener también por si acaso
                          medico_factura_id=medico_factura_id,
                          fecha_factura=fecha_factura,
                          ars_id=ars_id,
                          ncf_id=ncf_id,
                          centro_medico=centro_medico,
                          subtotal=subtotal,
                          total=total,
                          tipo_empresa=tipo_empresa,
                          empresa_info=empresa_info,
                          idempotency_key=secrets.token_hex(16))

@login_required
@permission_required('facturacion.crear')
def facturacion_generar_final():
    """Generar factura final en la base de datos"""
    
    tenant_id = get_current_tenant_id()
    
    # Obtener datos del formulario
    tipo_factura = request.form.get('tipo_factura', 'TRADICIONAL').strip().upper()
    pacientes_ids_str = request.form.get('pacientes_ids', '')
    ars_id = request.form.get('ars_id')
    ncf_id = request.form.get('ncf_id')
    medico_factura_id = request.form.get('medico_factura_id')
    fecha_factura = request.form.get('fecha_factura')
    idempotency_key = request.form.get('idempotency_key', '').strip().lower()
    
    if tipo_factura not in ['TRADICIONAL', 'ELECTRONICA']:
        flash('Tipo de factura inválido', 'error')
        return redirect(url_for('facturacion_generar'))
    if (
        tipo_factura == 'ELECTRONICA'
        and not ecf_habilitado_para_tenant(get_current_tenant_id())
    ):
        flash('La cuenta no está habilitada para facturación electrónica', 'error')
        return redirect(url_for('facturacion_generar'))

    if not all([pacientes_ids_str, ars_id, medico_factura_id, fecha_factura]) or (
        tipo_factura == 'TRADICIONAL' and not ncf_id
    ):
        flash('Faltan datos obligatorios', 'error')
        return redirect(url_for('facturacion_generar'))

    if tipo_factura == 'ELECTRONICA':
        if not re.fullmatch(r'[a-f0-9]{32}', idempotency_key):
            flash('La confirmación electrónica expiró. Genere otra vista previa.', 'error')
            return redirect(url_for('facturacion_generar'))
        factura_existente = execute_query('''
            SELECT factura_id
            FROM facturas_ecf
            WHERE tenant_id=%s AND idempotency_key=%s
            LIMIT 1
        ''', (tenant_id, idempotency_key))
        if factura_existente:
            return redirect(url_for(
                'facturacion_ver_factura',
                factura_id=factura_existente['factura_id']
            ))
    
    # Convertir IDs de pacientes
    try:
        pacientes_ids = [int(id) for id in pacientes_ids_str.split(',') if id.strip()]
    except ValueError:
        flash('Error en los IDs de pacientes', 'error')
        return redirect(url_for('facturacion_generar'))
    
    if not pacientes_ids:
        flash('Debe seleccionar al menos un paciente', 'error')
        return redirect(url_for('facturacion_generar'))
    
    # Obtener datos de ARS, NCF y Médico
    ars = execute_query('SELECT * FROM ars WHERE id = %s AND tenant_id = %s', (ars_id, tenant_id))
    if not ars:
        flash('ARS no encontrada', 'error')
        return redirect(url_for('facturacion_generar'))
    
    ncf = None
    if tipo_factura == 'TRADICIONAL':
        ncf = execute_query(
            'SELECT * FROM ncf WHERE id = %s AND tenant_id = %s',
            (ncf_id, tenant_id)
        )
        if not ncf:
            flash('NCF no encontrado', 'error')
            return redirect(url_for('facturacion_generar'))
    
    # Obtener información de la empresa para determinar tipo
    empresa_info = get_empresa_info(tenant_id)
    tipo_empresa = empresa_info.get('tipo_empresa') if empresa_info else None

    if tipo_factura == 'ELECTRONICA':
        rnc_emisor = re.sub(r'\D', '', (empresa_info or {}).get('rnc') or '')
        rnc_comprador = re.sub(r'\D', '', ars.get('rnc') or '')
        if len(rnc_emisor) not in [9, 11]:
            flash('Configure un RNC o cédula válido para el emisor', 'error')
            return redirect(url_for('facturacion_generar'))
        if len(rnc_comprador) not in [9, 11]:
            flash('La ARS debe tener un RNC válido para emitir un E31', 'error')
            return redirect(url_for('facturacion_generar'))
    
    # Obtener médico o empresa según tipo
    medico_factura = None
    empresa_factura = None
    if tipo_empresa == 'centro_salud':
        # Si es centro de salud, buscar en empresas
        empresa_factura = execute_query('SELECT * FROM empresas WHERE id = %s', (medico_factura_id,))
        if empresa_factura and empresa_factura.get('id') == tenant_id:
            medico_factura = {
                'id': empresa_factura.get('id'),
                'nombre': empresa_factura.get('razon_social', empresa_factura.get('nombre', 'N/A')),
                'especialidad': 'Centro de Salud',
                'cedula': empresa_factura.get('rnc', '')
            }
        else:
            flash('Empresa no encontrada', 'error')
            return redirect(url_for('facturacion_generar'))
    else:
        # Si es médico, buscar en medicos
        medico_factura = execute_query('SELECT * FROM medicos WHERE id = %s AND tenant_id = %s', (medico_factura_id, tenant_id))
        if not medico_factura:
            flash('Médico no encontrado', 'error')
            return redirect(url_for('facturacion_generar'))
    
    # Obtener únicamente pacientes pendientes de la empresa actual.
    placeholders = ','.join(['%s'] * len(pacientes_ids))
    pacientes_raw = execute_query(f'''
        SELECT pp.*, a.nombre as ars_nombre, m.nombre as medico_nombre
        FROM pacientes_pendientes pp
        LEFT JOIN ars a
          ON pp.ars_id = a.id AND a.tenant_id = pp.tenant_id
        LEFT JOIN medicos m
          ON pp.medico_id = m.id AND m.tenant_id = pp.tenant_id
        WHERE pp.id IN ({placeholders}) AND pp.tenant_id = %s
          AND pp.estado = 'Pendiente'
        ORDER BY pp.fecha_servicio
    ''', tuple(pacientes_ids) + (tenant_id,), fetch='all') or []
    
    if len(pacientes_raw) != len(set(pacientes_ids)):
        flash(
            'Uno o más pacientes ya fueron facturados o dejaron de estar disponibles',
            'error'
        )
        return redirect(url_for('facturacion_generar'))
    
    # Calcular totales
    subtotal = sum(
        (Decimal(str(p.get('monto_estimado', 0) or 0)) for p in pacientes_raw),
        Decimal('0.00'),
    )
    total = subtotal
    
    conn = None
    cursor = None
    try:
        # Obtener centro médico
        centro_medico_id = None
        centro_medico_nombre = None
        if medico_factura.get('centro_medico_id'):
            centro_medico = execute_query('SELECT * FROM centros_medicos WHERE id = %s AND tenant_id = %s', 
                                         (medico_factura['centro_medico_id'], tenant_id))
            if centro_medico:
                centro_medico_id = centro_medico['id']
                centro_medico_nombre = centro_medico.get('nombre', '')
        
        # Usar el primer paciente como referencia para datos generales
        primer_paciente = pacientes_raw[0]

        # La factura y su consecutivo se confirman o revierten como una unidad.
        conn = get_db_connection()
        conn.begin()
        cursor = conn.cursor()
        fecha_actual = datetime.now()
        reserva_ecf = None
        factura_ecf_id = None
        ecf_build_error = None
        envio_ecf_pendiente = False

        if tipo_factura == 'ELECTRONICA':
            fecha_documento = datetime.strptime(
                fecha_factura,
                '%Y-%m-%d'
            ).date()
            reserva_ecf = reserve_encf(
                cursor,
                tenant_id,
                ecf_type='31',
                issue_date=fecha_documento
            )
            ncf_numero = reserva_ecf.value
            numero_factura = (
                f"FAC-E-{tenant_id}-{fecha_actual.strftime('%Y%m%d')}-"
                f"{reserva_ecf.number:010d}"
            )
        else:
            cursor.execute(
                'SELECT * FROM ncf WHERE id = %s AND tenant_id = %s FOR UPDATE',
                (ncf_id, tenant_id)
            )
            ncf_bloqueado = cursor.fetchone()
            if not ncf_bloqueado or not ncf_bloqueado.get('activo'):
                raise ValueError('La secuencia NCF ya no está disponible')

            proximo_numero = (
                int(ncf_bloqueado.get('ultimo_numero', 0) or 0) + 1
            )
            tamano_secuencia = int(
                ncf_bloqueado.get('tamano_secuencia', 8) or 8
            )
            ncf_numero = (
                f"{ncf_bloqueado['prefijo']}"
                f"{proximo_numero:0{tamano_secuencia}d}"
            )
            numero_factura = (
                f"FAC-{fecha_actual.strftime('%Y%m%d')}-{proximo_numero:04d}"
            )

        cursor.execute(
            'SELECT id FROM facturas WHERE tenant_id = %s AND ncf = %s LIMIT 1',
            (tenant_id, ncf_numero)
        )
        if cursor.fetchone():
            raise ValueError(f'El NCF {ncf_numero} ya fue utilizado')

        cursor.execute('''
            INSERT INTO facturas 
            (tenant_id, numero_factura, tipo_factura, ncf, fecha_emision, paciente_id, nombre_paciente,
             cedula_paciente, nss_paciente, ars_id, nombre_ars, medico_id, nombre_medico,
             centro_medico_id, nombre_centro_medico, subtotal, itbis, total, estado, created_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'Pendiente', %s)
        ''', (tenant_id, numero_factura, tipo_factura, ncf_numero, fecha_factura,
              primer_paciente.get('paciente_id'), primer_paciente.get('nombre_paciente', ''),
              primer_paciente.get('cedula'), primer_paciente.get('nss'),
              ars_id, ars.get('nombre', ''), medico_factura_id, medico_factura.get('nombre', ''),
              centro_medico_id, centro_medico_nombre, subtotal, 0, total, current_user.id))

        factura_id = cursor.lastrowid

        if reserva_ecf:
            cursor.execute('''
                INSERT INTO facturas_ecf
                (tenant_id, factura_id, tipo_ecf, e_ncf, estado,
                 idempotency_key)
                VALUES (%s, %s, %s, %s, 'PENDIENTE_ENVIO', %s)
            ''', (
                tenant_id,
                factura_id,
                reserva_ecf.ecf_type,
                reserva_ecf.value,
                idempotency_key
            ))
            factura_ecf_id = cursor.lastrowid
            cursor.execute('''
                INSERT INTO ecf_eventos
                (tenant_id, factura_ecf_id, estado_anterior, estado_nuevo,
                 evento, detalle, usuario_id)
                VALUES (%s, %s, NULL, 'PENDIENTE_ENVIO',
                        'ENCF_RESERVADO', %s, %s)
            ''', (
                tenant_id,
                factura_ecf_id,
                f'e-NCF {reserva_ecf.value} reservado localmente',
                current_user.id
            ))

        # Crear detalles de factura para cada paciente
        detalles_ecf = []
        for paciente in pacientes_raw:
            servicio_completo = paciente.get('servicios_realizados', '') or ''
            if ' - Autorización:' in servicio_completo:
                descripcion_servicio = servicio_completo.split(' - Autorización:')[0].strip()
            else:
                descripcion_servicio = servicio_completo.strip()
            
            monto = float(paciente.get('monto_estimado', 0) or 0)
            
            cursor.execute('''
                INSERT INTO factura_detalles
                (tenant_id, factura_id, descripcion, cantidad, precio_unitario, subtotal)
                VALUES (%s, %s, %s, 1, %s, %s)
            ''', (tenant_id, factura_id, descripcion_servicio, monto, monto))

            detalles_ecf.append({
                'descripcion': descripcion_servicio,
                'cantidad': 1,
                'precio_unitario': monto,
                'subtotal': monto,
                # Los servicios médicos del flujo actual se registran sin ITBIS.
                'indicador_facturacion': 4,
                'indicador_bien_servicio': 2
            })

        if reserva_ecf:
            cursor.execute('''
                UPDATE facturas_ecf
                SET estado='GENERANDO_XML', ultimo_error=NULL
                WHERE id=%s AND tenant_id=%s
            ''', (factura_ecf_id, tenant_id))
            cursor.execute('''
                INSERT INTO ecf_eventos
                (tenant_id, factura_ecf_id, estado_anterior, estado_nuevo,
                 evento, detalle, usuario_id)
                VALUES (%s, %s, 'PENDIENTE_ENVIO', 'GENERANDO_XML',
                        'GENERACION_XML_INICIADA', %s, %s)
            ''', (
                tenant_id,
                factura_ecf_id,
                'Construcción local del XML E31 iniciada',
                current_user.id
            ))

            try:
                resultado_xml = ECFBuilder().build_e31(
                    invoice={
                        'numero_factura': numero_factura,
                        'fecha_emision': fecha_factura,
                        'total': total
                    },
                    electronic={
                        'tipo_ecf': reserva_ecf.ecf_type,
                        'e_ncf': reserva_ecf.value,
                        # Facturas a ARS: operación ordinaria emitida a crédito.
                        'tipo_ingresos': '01',
                        'tipo_pago': '2'
                    },
                    sequence_expires_at=reserva_ecf.expires_at,
                    issuer=empresa_info or {},
                    buyer=ars,
                    items=detalles_ecf,
                    generated_at=fecha_actual
                )
                cursor.execute('''
                    UPDATE facturas_ecf
                    SET estado='XML_GENERADO', xml_generado=%s,
                        hash_xml_generado=%s, fecha_generacion=%s,
                        ultimo_error=NULL
                    WHERE id=%s AND tenant_id=%s
                ''', (
                    resultado_xml.xml,
                    resultado_xml.sha256,
                    resultado_xml.generated_at,
                    factura_ecf_id,
                    tenant_id
                ))
                cursor.execute('''
                    INSERT INTO ecf_eventos
                    (tenant_id, factura_ecf_id, estado_anterior, estado_nuevo,
                     evento, detalle, usuario_id)
                    VALUES (%s, %s, 'GENERANDO_XML', 'XML_GENERADO',
                            'XML_GENERADO', %s, %s)
                ''', (
                    tenant_id,
                    factura_ecf_id,
                    f'XML E31 generado; SHA-256 {resultado_xml.sha256}',
                    current_user.id
                ))

                resultado_validacion = ECFValidator().validate_unsigned_e31(
                    resultado_xml.xml
                )
                ajustes_xsd = ', '.join(
                    resultado_validacion.compatibility_adjustments
                )
                cursor.execute('''
                    UPDATE facturas_ecf
                    SET estado='XML_VALIDADO', ultimo_error=NULL
                    WHERE id=%s AND tenant_id=%s
                ''', (factura_ecf_id, tenant_id))
                cursor.execute('''
                    INSERT INTO ecf_eventos
                    (tenant_id, factura_ecf_id, estado_anterior, estado_nuevo,
                     evento, detalle, usuario_id)
                    VALUES (%s, %s, 'XML_GENERADO', 'XML_VALIDADO',
                            'XML_VALIDADO_XSD', %s, %s)
                ''', (
                    tenant_id,
                    factura_ecf_id,
                    (
                        'XML E31 validado antes de firma; '
                        f'XSD SHA-256 {resultado_validacion.schema_sha256}; '
                        f'ajustes en memoria: {ajustes_xsd}'
                    ),
                    current_user.id
                ))

                cursor.execute('''
                    INSERT INTO ecf_eventos
                    (tenant_id, factura_ecf_id, estado_anterior, estado_nuevo,
                     evento, detalle, usuario_id)
                    VALUES (%s, %s, 'XML_VALIDADO', 'XML_VALIDADO',
                            'FIRMA_INICIADA', %s, %s)
                ''', (
                    tenant_id,
                    factura_ecf_id,
                    'Firma local XMLDSig RSA-SHA256 iniciada',
                    current_user.id
                ))
                try:
                    certificado_resuelto, certificado_metadata = (
                        TenantCertificateProvider(
                            current_app.config['ECF_CONFIG']
                        ).inspect(
                            tenant_id,
                            (empresa_info or {}).get('rnc'),
                            obtener_configuracion_ecf_tenant(tenant_id),
                        )
                    )
                    resultado_firma = certificado_resuelto.signer().sign_e31(
                        resultado_xml.xml,
                        expected_signer_id=(empresa_info or {}).get('rnc'),
                        signed_at=datetime.now()
                    )
                    validacion_firmada = ECFValidator().validate_signed_e31(
                        resultado_firma.signed_xml
                    )
                    cursor.execute('''
                        UPDATE facturas_ecf
                        SET estado='FIRMADO', xml_firmado=%s,
                            hash_xml_firmado=%s, fecha_firma=%s,
                            ultimo_error=NULL
                        WHERE id=%s AND tenant_id=%s
                    ''', (
                        resultado_firma.signed_xml,
                        resultado_firma.sha256,
                        resultado_firma.signed_at,
                        factura_ecf_id,
                        tenant_id
                    ))
                    cursor.execute('''
                        UPDATE ecf_configuraciones
                        SET certificado_huella=%s,
                            certificado_vence=%s,
                            certificado_validado_en=NOW()
                        WHERE tenant_id=%s
                    ''', (
                        certificado_metadata.fingerprint,
                        certificado_metadata.valid_until.date(),
                        tenant_id
                    ))
                    cursor.execute('''
                        INSERT INTO ecf_eventos
                        (tenant_id, factura_ecf_id,
                         estado_anterior, estado_nuevo,
                         evento, detalle, usuario_id)
                        VALUES (%s, %s, 'XML_VALIDADO', 'FIRMADO',
                                'XML_FIRMADO', %s, %s)
                    ''', (
                        tenant_id,
                        factura_ecf_id,
                        (
                            'Firma RSA-SHA256 verificada; '
                            f'XML SHA-256 {resultado_firma.sha256}; '
                            'certificado SHA-256 '
                            f'{resultado_firma.certificate_fingerprint}; '
                            'XSD SHA-256 '
                            f'{validacion_firmada.schema_sha256}'
                        ),
                        current_user.id
                    ))
                    cursor.execute('''
                        INSERT INTO ecf_outbox
                        (tenant_id, factura_ecf_id, clave_evento,
                         tipo_evento, estado, payload, proximo_intento)
                        VALUES (%s, %s, %s, 'ENVIAR_ECF',
                                'PENDIENTE', %s, NOW())
                    ''', (
                        tenant_id,
                        factura_ecf_id,
                        f'ENVIAR_ECF:{factura_ecf_id}',
                        json.dumps({
                            'factura_ecf_id': factura_ecf_id,
                            'e_ncf': reserva_ecf.value
                        })
                    ))
                    envio_ecf_pendiente = True
                except (
                    ECFCertificateResolutionError,
                    ECFSigningError,
                    ECFValidationError,
                    ECFSchemaError
                ) as signing_error:
                    ecf_build_error = str(signing_error)
                    cursor.execute('''
                        UPDATE facturas_ecf
                        SET estado='ERROR_FIRMA', ultimo_error=%s
                        WHERE id=%s AND tenant_id=%s
                    ''', (ecf_build_error, factura_ecf_id, tenant_id))
                    cursor.execute('''
                        INSERT INTO ecf_eventos
                        (tenant_id, factura_ecf_id,
                         estado_anterior, estado_nuevo,
                         evento, detalle, usuario_id)
                        VALUES (%s, %s, 'XML_VALIDADO', 'ERROR_FIRMA',
                                'ERROR_FIRMA', %s, %s)
                    ''', (
                        tenant_id,
                        factura_ecf_id,
                        ecf_build_error,
                        current_user.id
                    ))
            except ECFBuildError as build_error:
                ecf_build_error = str(build_error)
                cursor.execute('''
                    UPDATE facturas_ecf
                    SET estado='ERROR_VALIDACION', ultimo_error=%s
                    WHERE id=%s AND tenant_id=%s
                ''', (ecf_build_error, factura_ecf_id, tenant_id))
                cursor.execute('''
                    INSERT INTO ecf_eventos
                    (tenant_id, factura_ecf_id, estado_anterior, estado_nuevo,
                     evento, detalle, usuario_id)
                    VALUES (%s, %s, 'GENERANDO_XML', 'ERROR_VALIDACION',
                            'ERROR_DATOS_XML', %s, %s)
                ''', (
                    tenant_id,
                    factura_ecf_id,
                    ecf_build_error,
                    current_user.id
                ))
            except (ECFValidationError, ECFSchemaError) as validation_error:
                ecf_build_error = str(validation_error)
                cursor.execute('''
                    UPDATE facturas_ecf
                    SET estado='ERROR_VALIDACION', ultimo_error=%s
                    WHERE id=%s AND tenant_id=%s
                ''', (ecf_build_error, factura_ecf_id, tenant_id))
                cursor.execute('''
                    INSERT INTO ecf_eventos
                    (tenant_id, factura_ecf_id, estado_anterior, estado_nuevo,
                     evento, detalle, usuario_id)
                    VALUES (%s, %s, 'XML_GENERADO', 'ERROR_VALIDACION',
                            'ERROR_VALIDACION_XSD', %s, %s)
                ''', (
                    tenant_id,
                    factura_ecf_id,
                    ecf_build_error,
                    current_user.id
                ))
        
        # Actualizar estado de pacientes_pendientes a 'Facturado'
        cursor.execute(f'''
            UPDATE pacientes_pendientes 
            SET estado = 'Facturado' 
            WHERE id IN ({placeholders}) AND tenant_id = %s
              AND estado = 'Pendiente'
        ''', tuple(pacientes_ids) + (tenant_id,))

        if cursor.rowcount != len(set(pacientes_ids)):
            raise RuntimeError(
                'Cambió la disponibilidad de los pacientes durante la generación'
            )

        # El e-NCF ya fue reservado por reserve_encf dentro de esta transacción.
        if tipo_factura == 'TRADICIONAL':
            cursor.execute('''
                UPDATE ncf
                SET ultimo_numero = %s, proximo_numero = %s
                WHERE id = %s AND tenant_id = %s
            ''', (proximo_numero, proximo_numero + 1, ncf_id, tenant_id))

        conn.commit()
        envio_ecf_exitoso = False
        envio_ecf_resultado = ''
        estado_consultado_dgii = None
        mensaje_consultado_dgii = ''
        if tipo_factura == 'ELECTRONICA' and envio_ecf_pendiente:
            try:
                envio_ecf_exitoso, envio_ecf_resultado = (
                    procesar_envio_ecf_dgii(
                        factura_ecf_id,
                        tenant_id,
                        current_user.id
                    )
                )
                if envio_ecf_exitoso:
                    (
                        _,
                        estado_consultado_dgii,
                        mensaje_consultado_dgii
                    ) = consultar_resultado_ecf_dgii(
                        factura_ecf_id,
                        tenant_id,
                        current_user.id
                    )
            except Exception as dispatch_error:
                logger.error(
                    'La factura e-CF %s quedó creada, pero falló el '
                    'procesamiento de salida: %s',
                    factura_ecf_id,
                    dispatch_error,
                    exc_info=True
                )
                envio_ecf_resultado = (
                    'El documento quedó firmado y pendiente de envío'
                )

        if tipo_factura == 'ELECTRONICA':
            if ecf_build_error:
                flash(
                    f'Factura {numero_factura} creada con {ncf_numero}, pero '
                    f'el XML requiere corrección: {ecf_build_error}',
                    'warning'
                )
            elif envio_ecf_exitoso:
                if estado_consultado_dgii == 'ACEPTADO':
                    flash(
                        f'Factura {numero_factura} aceptada por DGII. '
                        f'TrackID: {envio_ecf_resultado}.',
                        'success'
                    )
                elif estado_consultado_dgii == 'RECHAZADO':
                    flash(
                        f'Factura {numero_factura} rechazada por DGII: '
                        f'{mensaje_consultado_dgii}',
                        'error'
                    )
                else:
                    flash(
                        f'Factura {numero_factura} enviada a DGII. '
                        f'TrackID: {envio_ecf_resultado}. '
                        'Pendiente de respuesta de validación.',
                        'success'
                    )
            else:
                flash(
                    f'Factura {numero_factura} creada con {ncf_numero}. '
                    f'{envio_ecf_resultado or "Pendiente de envío a DGII"}.',
                    'warning'
                )
        else:
            flash(f'Factura {numero_factura} generada exitosamente', 'success')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))
        
    except Exception as e:
        if conn:
            conn.rollback()
        import traceback
        error_trace = traceback.format_exc()
        logger.error(f"Error al generar factura: {error_trace}")
        flash(f'Error al generar la factura: {str(e)}', 'error')
        return redirect(url_for('facturacion_generar'))
    finally:
        if cursor:
            cursor.close()

def register_billing_routes(app):
    """Registrar facturación conservando endpoints legacy."""
    app.add_url_rule('/facturacion', endpoint='facturacion_menu', view_func=facturacion_menu)
    app.add_url_rule('/facturacion/reclamaciones', endpoint='facturacion_reclamaciones', view_func=facturacion_reclamaciones)
    app.add_url_rule('/facturacion/reclamaciones/nueva', endpoint='facturacion_reclamaciones_nueva', view_func=facturacion_reclamaciones_nueva, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/reclamaciones/<int:reclamacion_id>', endpoint='facturacion_reclamacion_detalle', view_func=facturacion_reclamacion_detalle)
    app.add_url_rule('/facturacion/reclamaciones/<int:reclamacion_id>/editar', endpoint='facturacion_reclamacion_editar', view_func=facturacion_reclamacion_editar, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/reclamaciones/<int:reclamacion_id>/estado', endpoint='facturacion_reclamacion_cambiar_estado', view_func=facturacion_reclamacion_cambiar_estado, methods=['POST'])
    app.add_url_rule('/facturacion/pagos', endpoint='facturacion_pagos', view_func=facturacion_pagos)
    app.add_url_rule('/facturacion/pagos/nuevo', endpoint='facturacion_pagos_nuevo', view_func=facturacion_pagos_nuevo, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/pagos/<int:pago_id>', endpoint='facturacion_pago_detalle', view_func=facturacion_pago_detalle)
    app.add_url_rule('/facturacion/pagos/<int:pago_id>/editar', endpoint='facturacion_pago_editar', view_func=facturacion_pago_editar, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/historico', endpoint='facturacion_historico', view_func=facturacion_historico)
    app.add_url_rule('/facturacion/facturas/<int:factura_id>/ver', endpoint='facturacion_ver_factura', view_func=facturacion_ver_factura)
    app.add_url_rule('/facturacion/facturas/<int:factura_id>/ecf/xml', endpoint='facturacion_ver_xml_ecf', view_func=facturacion_ver_xml_ecf)
    app.add_url_rule('/facturacion/facturas/<int:factura_id>/ecf/qr', endpoint='facturacion_qr_ecf', view_func=facturacion_qr_ecf)
    app.add_url_rule('/facturacion/facturas/<int:factura_id>/ecf/representacion-impresa', endpoint='facturacion_representacion_impresa_ecf', view_func=facturacion_representacion_impresa_ecf)
    app.add_url_rule('/facturacion/facturas/<int:factura_id>/ecf/consultar-estado', endpoint='facturacion_consultar_estado_ecf', view_func=facturacion_consultar_estado_ecf, methods=['POST'])
    app.add_url_rule('/facturacion/facturas/<int:factura_id>/editar', endpoint='facturacion_editar_factura', view_func=facturacion_editar_factura, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/facturas/<int:factura_id>/pdf', endpoint='facturacion_descargar_pdf', view_func=facturacion_descargar_pdf)
    app.add_url_rule('/facturacion/facturas/<int:factura_id>/enviar-email', endpoint='facturacion_enviar_email', view_func=facturacion_enviar_email, methods=['POST'])
    app.add_url_rule('/facturacion/dashboard', endpoint='facturacion_dashboard', view_func=facturacion_dashboard)
    app.add_url_rule('/facturacion/facturas/nueva', endpoint='facturacion_facturas_nueva', view_func=facturacion_facturas_nueva, methods=['GET', 'POST'])
    app.add_url_rule('/descargar-plantilla-excel', endpoint='descargar_plantilla_excel', view_func=descargar_plantilla_excel)
    app.add_url_rule('/facturacion/procesar-excel', endpoint='facturacion_procesar_excel', view_func=facturacion_procesar_excel, methods=['POST'])
    app.add_url_rule('/facturacion/generar', endpoint='facturacion_generar', view_func=facturacion_generar, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/generar/step2', endpoint='facturacion_generar_step2', view_func=facturacion_generar_step2, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/vista-previa', endpoint='facturacion_vista_previa', view_func=facturacion_vista_previa)
    app.add_url_rule('/facturacion/generar/final', endpoint='facturacion_generar_final', view_func=facturacion_generar_final, methods=['POST'])
