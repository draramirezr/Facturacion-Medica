"""Edición y anulación de facturas."""
import logging
import json
from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from auth import permission_required
from core.database import database_transaction, execute_query, execute_update
from core.tenant import get_current_tenant_id, validate_tenant_access
from routes.support import sanitize_input
from routes.billing_common import _monto

logger = logging.getLogger(__name__)


def _fecha_creacion_factura(factura):
    from datetime import date, datetime
    fecha_creacion = factura.get('created_at') or factura.get('fecha_emision')
    if isinstance(fecha_creacion, str):
        for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d'):
            try:
                return datetime.strptime(fecha_creacion[:19], fmt).date()
            except ValueError:
                continue
        return date.today()
    if isinstance(fecha_creacion, datetime):
        return fecha_creacion.date()
    if isinstance(fecha_creacion, date):
        return fecha_creacion
    return date.today()


def _dias_edicion_factura(factura):
    from datetime import date
    dias = (date.today() - _fecha_creacion_factura(factura)).days
    return dias, 30 - dias


def _factura_modificable(factura, tenant_id):
    """Reglas para editar o anular dentro de 30 días."""
    if not factura:
        return False, 'Factura no encontrada'
    if (factura.get('estado') or '') == 'Anulada':
        return False, 'La factura ya está anulada'
    if (factura.get('destinatario') or 'ARS') == 'PACIENTE':
        return False, 'Las facturas de pacientes se anulan desde Facturación → Facturas de pacientes'
    dias, _restantes = _dias_edicion_factura(factura)
    if dias >= 30:
        return False, 'Han pasado más de 30 días desde su creación'
    pagos = execute_query(
        '''
        SELECT COUNT(*) AS total
        FROM pago_facturas
        WHERE factura_id=%s AND tenant_id=%s
        ''',
        (factura['id'], tenant_id),
    ) or {}
    if int(pagos.get('total') or 0) > 0:
        return False, 'La factura tiene pagos aplicados'
    return True, None


def _cargar_factura_edicion(factura_id, tenant_id):
    return execute_query(
        '''
        SELECT f.*, a.nombre as nombre_ars, a.rnc as ars_rnc,
               m.nombre as medico_nombre, m.especialidad as medico_especialidad,
               m.cedula as medico_cedula, m.exequatur as medico_exequatur
        FROM facturas f
        LEFT JOIN ars a
          ON f.ars_id = a.id AND a.tenant_id = f.tenant_id
        LEFT JOIN medicos m
          ON f.medico_id = m.id AND m.tenant_id = f.tenant_id
        WHERE f.id = %s AND f.tenant_id = %s
        ''',
        (factura_id, tenant_id),
    )


def _vincular_detalles_sin_pendiente(factura, detalles, tenant_id):
    """Empareja detalles viejos con pendientes Facturado de la misma ARS/fecha."""
    sin = [d for d in detalles if not d.get('paciente_pendiente_id')]
    if not sin or not factura.get('ars_id'):
        return
    fecha = factura.get('fecha_emision')
    candidatos = execute_query(
        '''
        SELECT pp.id
        FROM pacientes_pendientes pp
        WHERE pp.tenant_id=%s AND pp.ars_id=%s AND pp.estado='Facturado'
          AND DATE(pp.updated_at)=%s
          AND pp.id NOT IN (
              SELECT COALESCE(fd.paciente_pendiente_id, 0)
              FROM factura_detalles fd
              WHERE fd.tenant_id=%s AND fd.factura_id=%s
                AND fd.paciente_pendiente_id IS NOT NULL
          )
        ORDER BY pp.id
        ''',
        (tenant_id, factura['ars_id'], fecha, tenant_id, factura['id']),
        fetch='all',
    ) or []
    for detalle, candidato in zip(sin, candidatos):
        execute_update(
            '''
            UPDATE factura_detalles
            SET paciente_pendiente_id=%s
            WHERE id=%s AND tenant_id=%s AND factura_id=%s
            ''',
            (candidato['id'], detalle['id'], tenant_id, factura['id']),
        )
        detalle['paciente_pendiente_id'] = candidato['id']


def _pacientes_en_factura(factura_id, tenant_id):
    filas = execute_query(
        '''
        SELECT fd.id, fd.descripcion, fd.precio_unitario, fd.subtotal,
               fd.paciente_pendiente_id,
               COALESCE(pp.nombre_paciente, f.nombre_paciente) AS nombre_paciente,
               COALESCE(pp.nss, f.nss_paciente) AS nss,
               COALESCE(pp.fecha_servicio, f.fecha_emision) AS fecha_servicio,
               COALESCE(m.nombre, f.nombre_medico) AS medico_nombre,
               pp.servicios_realizados
        FROM factura_detalles fd
        JOIN facturas f
          ON f.id=fd.factura_id AND f.tenant_id=fd.tenant_id
        LEFT JOIN pacientes_pendientes pp
          ON pp.id=fd.paciente_pendiente_id AND pp.tenant_id=fd.tenant_id
        LEFT JOIN medicos m
          ON m.id=pp.medico_id AND m.tenant_id=pp.tenant_id
        WHERE fd.factura_id=%s AND fd.tenant_id=%s
        ORDER BY fd.id
        ''',
        (factura_id, tenant_id),
        fetch='all',
    ) or []
    pacientes = []
    for fila in filas:
        descripcion = fila.get('descripcion') or ''
        servicio = descripcion
        if ' - Autorización:' in descripcion:
            servicio = descripcion.split(' - Autorización:')[0].strip()
        elif fila.get('servicios_realizados'):
            servicio = str(fila['servicios_realizados']).split(' - Autorización:')[0].strip()
        monto = float(fila.get('precio_unitario') or fila.get('subtotal') or 0)
        pacientes.append({
            'id': fila['id'],
            'pendiente_id': fila.get('paciente_pendiente_id'),
            'nombre_paciente': fila.get('nombre_paciente') or 'N/A',
            'nss': fila.get('nss') or '',
            'fecha_servicio': fila.get('fecha_servicio') or '',
            'medico_nombre': fila.get('medico_nombre') or 'N/A',
            'servicio_nombre': servicio or 'N/A',
            'monto': monto,
            'monto_estimado': monto,
        })
    return pacientes


def _pendientes_misma_ars(factura, tenant_id):
    if not factura.get('ars_id'):
        return []
    filas = execute_query(
        '''
        SELECT pp.*, m.nombre AS medico_nombre,
               COALESCE(p.nombre, pp.nombre_paciente) AS paciente_nombre_completo
        FROM pacientes_pendientes pp
        LEFT JOIN medicos m
          ON m.id=pp.medico_id AND m.tenant_id=pp.tenant_id
        LEFT JOIN pacientes p
          ON p.id=pp.paciente_id AND p.tenant_id=pp.tenant_id
        WHERE pp.tenant_id=%s
          AND pp.ars_id=%s
          AND pp.estado='Pendiente'
        ORDER BY pp.fecha_servicio DESC, pp.id DESC
        ''',
        (tenant_id, factura['ars_id']),
        fetch='all',
    ) or []
    for fila in filas:
        servicio = fila.get('servicios_realizados') or ''
        if ' - Autorización:' in servicio:
            servicio = servicio.split(' - Autorización:')[0].strip()
        fila['servicio_nombre'] = servicio or 'N/A'
        fila['monto'] = float(fila.get('monto_estimado') or 0)
    return filas


@login_required
@permission_required('facturacion.editar')
def facturacion_editar_factura(factura_id):
    """Editar pacientes de una factura (máximo 30 días desde su creación)."""
    tenant_id = get_current_tenant_id()
    if not validate_tenant_access('facturas', factura_id):
        flash('No tienes acceso a esta factura', 'error')
        return redirect(url_for('facturacion_historico'))

    factura = _cargar_factura_edicion(factura_id, tenant_id)
    if not factura:
        flash('Factura no encontrada', 'error')
        return redirect(url_for('facturacion_historico'))

    ok, motivo = _factura_modificable(factura, tenant_id)
    dias_transcurridos, dias_restantes = _dias_edicion_factura(factura)
    if not ok:
        flash(motivo, 'error')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))

    if request.method == 'POST':
        try:
            agregar_ids = json.loads(
                request.form.get('pacientes_agregar_ids') or '[]'
            )
            eliminar_ids = json.loads(
                request.form.get('pacientes_eliminar_ids') or '[]'
            )
            agregar_ids = [int(x) for x in agregar_ids]
            eliminar_ids = [int(x) for x in eliminar_ids]
        except (TypeError, ValueError, json.JSONDecodeError):
            flash('Los cambios enviados no son válidos', 'error')
            return redirect(url_for('facturacion_editar_factura', factura_id=factura_id))

        if not agregar_ids and not eliminar_ids:
            flash('No hay cambios para guardar', 'info')
            return redirect(url_for('facturacion_editar_factura', factura_id=factura_id))

        try:
            with database_transaction():
                detalles = execute_query(
                    '''
                    SELECT id, paciente_pendiente_id, precio_unitario, subtotal
                    FROM factura_detalles
                    WHERE factura_id=%s AND tenant_id=%s
                    FOR UPDATE
                    ''',
                    (factura_id, tenant_id),
                    fetch='all',
                ) or []
                _vincular_detalles_sin_pendiente(factura, detalles, tenant_id)
                detalles = execute_query(
                    '''
                    SELECT id, paciente_pendiente_id, precio_unitario, subtotal
                    FROM factura_detalles
                    WHERE factura_id=%s AND tenant_id=%s
                    ''',
                    (factura_id, tenant_id),
                    fetch='all',
                ) or []
                detalle_map = {int(d['id']): d for d in detalles}

                if eliminar_ids:
                    restantes = len(detalles) - len(set(eliminar_ids)) + len(agregar_ids)
                    if restantes < 1:
                        raise ValueError(
                            'La factura debe quedar con al menos un paciente'
                        )
                    for detalle_id in eliminar_ids:
                        detalle = detalle_map.get(detalle_id)
                        if not detalle:
                            raise ValueError('Uno de los pacientes a eliminar no está en la factura')
                        pendiente_id = detalle.get('paciente_pendiente_id')
                        execute_update(
                            '''
                            DELETE FROM factura_detalles
                            WHERE id=%s AND factura_id=%s AND tenant_id=%s
                            ''',
                            (detalle_id, factura_id, tenant_id),
                        )
                        if pendiente_id:
                            execute_update(
                                '''
                                UPDATE pacientes_pendientes
                                SET estado='Pendiente'
                                WHERE id=%s AND tenant_id=%s AND estado='Facturado'
                                ''',
                                (pendiente_id, tenant_id),
                            )

                if agregar_ids:
                    placeholders = ','.join(['%s'] * len(agregar_ids))
                    nuevos = execute_query(
                        f'''
                        SELECT *
                        FROM pacientes_pendientes
                        WHERE tenant_id=%s
                          AND ars_id=%s
                          AND estado='Pendiente'
                          AND id IN ({placeholders})
                        FOR UPDATE
                        ''',
                        (tenant_id, factura['ars_id'], *agregar_ids),
                        fetch='all',
                    ) or []
                    if len(nuevos) != len(set(agregar_ids)):
                        raise ValueError(
                            'Solo se pueden agregar pendientes de la misma ARS'
                        )
                    for pendiente in nuevos:
                        servicio = pendiente.get('servicios_realizados') or ''
                        if ' - Autorización:' in servicio:
                            servicio = servicio.split(' - Autorización:')[0].strip()
                        monto = _monto(pendiente.get('monto_estimado'))
                        execute_update(
                            '''
                            INSERT INTO factura_detalles
                            (tenant_id, factura_id, paciente_pendiente_id,
                             descripcion, cantidad, precio_unitario, subtotal)
                            VALUES (%s, %s, %s, %s, 1, %s, %s)
                            ''',
                            (
                                tenant_id, factura_id, pendiente['id'],
                                servicio or 'Servicio', monto, monto,
                            ),
                        )
                        execute_update(
                            '''
                            UPDATE pacientes_pendientes
                            SET estado='Facturado'
                            WHERE id=%s AND tenant_id=%s
                            ''',
                            (pendiente['id'], tenant_id),
                        )

                totales = execute_query(
                    '''
                    SELECT COALESCE(SUM(subtotal), 0) AS subtotal,
                           COUNT(*) AS lineas
                    FROM factura_detalles
                    WHERE factura_id=%s AND tenant_id=%s
                    ''',
                    (factura_id, tenant_id),
                ) or {}
                if int(totales.get('lineas') or 0) < 1:
                    raise ValueError('La factura quedó sin pacientes')
                nuevo_total = _monto(totales.get('subtotal'))
                primer = execute_query(
                    '''
                    SELECT pp.paciente_id, pp.nombre_paciente, pp.cedula, pp.nss
                    FROM factura_detalles fd
                    LEFT JOIN pacientes_pendientes pp
                      ON pp.id=fd.paciente_pendiente_id
                     AND pp.tenant_id=fd.tenant_id
                    WHERE fd.factura_id=%s AND fd.tenant_id=%s
                    ORDER BY fd.id
                    LIMIT 1
                    ''',
                    (factura_id, tenant_id),
                ) or {}
                execute_update(
                    '''
                    UPDATE facturas
                    SET subtotal=%s, itbis=0, total=%s,
                        paciente_id=COALESCE(%s, paciente_id),
                        nombre_paciente=COALESCE(%s, nombre_paciente),
                        cedula_paciente=COALESCE(%s, cedula_paciente),
                        nss_paciente=COALESCE(%s, nss_paciente)
                    WHERE id=%s AND tenant_id=%s
                    ''',
                    (
                        nuevo_total, nuevo_total,
                        primer.get('paciente_id'),
                        primer.get('nombre_paciente'),
                        primer.get('cedula'),
                        primer.get('nss'),
                        factura_id, tenant_id,
                    ),
                )
        except ValueError as error:
            flash(str(error), 'error')
            return redirect(url_for('facturacion_editar_factura', factura_id=factura_id))
        except Exception:
            logger.exception('Error al editar factura %s', factura_id)
            flash('No se pudieron guardar los cambios de la factura', 'error')
            return redirect(url_for('facturacion_editar_factura', factura_id=factura_id))

        flash('Factura actualizada correctamente', 'success')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))

    detalles = execute_query(
        '''
        SELECT id, paciente_pendiente_id, descripcion, precio_unitario, subtotal
        FROM factura_detalles
        WHERE factura_id=%s AND tenant_id=%s
        ORDER BY id
        ''',
        (factura_id, tenant_id),
        fetch='all',
    ) or []
    _vincular_detalles_sin_pendiente(factura, detalles, tenant_id)
    pacientes_factura = _pacientes_en_factura(factura_id, tenant_id)
    pacientes_pendientes = _pendientes_misma_ars(factura, tenant_id)
    factura['fecha_factura'] = factura.get('fecha_emision', '')
    factura['ncf_numero'] = factura.get('ncf', '')

    return render_template(
        'facturacion/editar_factura.html',
        factura=factura,
        pacientes_factura=pacientes_factura,
        pacientes_pendientes=pacientes_pendientes,
        dias_transcurridos=dias_transcurridos,
        dias_restantes=max(dias_restantes, 0),
    )


@login_required
@permission_required('facturacion.anular')
def facturacion_anular_factura(factura_id):
    """Anular factura dentro de los 30 días y devolver pacientes a pendientes."""
    tenant_id = get_current_tenant_id()
    if not validate_tenant_access('facturas', factura_id):
        flash('No tienes acceso a esta factura', 'error')
        return redirect(url_for('facturacion_historico'))

    factura = _cargar_factura_edicion(factura_id, tenant_id)
    ok, motivo = _factura_modificable(factura, tenant_id)
    if not ok:
        flash(motivo, 'error')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))

    motivo_anulacion = sanitize_input(
        request.form.get('motivo_anulacion', ''), 500
    )
    if not motivo_anulacion:
        flash('Indica el motivo de la anulación', 'error')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))

    try:
        with database_transaction():
            detalles = execute_query(
                '''
                SELECT id, paciente_pendiente_id
                FROM factura_detalles
                WHERE factura_id=%s AND tenant_id=%s
                FOR UPDATE
                ''',
                (factura_id, tenant_id),
                fetch='all',
            ) or []
            _vincular_detalles_sin_pendiente(factura, detalles, tenant_id)
            detalles = execute_query(
                '''
                SELECT id, paciente_pendiente_id
                FROM factura_detalles
                WHERE factura_id=%s AND tenant_id=%s
                ''',
                (factura_id, tenant_id),
                fetch='all',
            ) or []
            for detalle in detalles:
                pendiente_id = detalle.get('paciente_pendiente_id')
                if pendiente_id:
                    execute_update(
                        '''
                        UPDATE pacientes_pendientes
                        SET estado='Pendiente'
                        WHERE id=%s AND tenant_id=%s AND estado='Facturado'
                        ''',
                        (pendiente_id, tenant_id),
                    )
            execute_update(
                '''
                UPDATE facturas
                SET estado='Anulada',
                    motivo_anulacion=%s,
                    anulado_por=%s,
                    fecha_anulacion=NOW()
                WHERE id=%s AND tenant_id=%s
                ''',
                (motivo_anulacion, current_user.id, factura_id, tenant_id),
            )
    except Exception:
        logger.exception('Error al anular factura %s', factura_id)
        flash('No se pudo anular la factura', 'error')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))

    flash('Factura anulada. Los pacientes volvieron a pendientes.', 'success')
    return redirect(url_for('facturacion_historico', tipo='facturas'))
