"""Pagos de ARS y conciliación contra facturas."""
import logging
import secrets
from datetime import datetime
from decimal import Decimal, InvalidOperation
from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from auth import permission_required
from core.database import database_transaction, execute_query, execute_update
from core.tenant import get_current_tenant_id
from routes.support import execute_paginated_query, sanitize_input, validate_int
from routes.billing_common import _monto

logger = logging.getLogger(__name__)


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
          AND f.destinatario = 'ARS'
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
            monto = _monto(montos[indice])
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
                      AND estado != 'Anulada' AND destinatario = 'ARS'
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
                      AND estado != 'Anulada' AND destinatario = 'ARS'
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
