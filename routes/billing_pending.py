"""Registro de consultas pendientes de facturar (manual y por Excel)."""
import logging
from datetime import date
from decimal import InvalidOperation
from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from auth import permission_required
from core.database import database_transaction, execute_query, execute_update
from core.tenant import get_current_tenant_id, validate_tenant_access
from core.clock import fecha_clinica
from routes.patients import paciente_adulto_sin_cedula
from routes.support import validate_int
from routes.billing_common import FECHA_MIN_CONSULTA_DIAS, _RE_AUTORIZACION, _RE_NOMBRE, _RE_NSS, _RE_TEXTO_GENERAL, _extraer_autorizacion_servicios, _monto, _validate_or_raise, fecha_minima_consulta_rd

logger = logging.getLogger(__name__)


def registrar_consultas_pendientes_atomico(
    lineas,
    tenant_id,
    ars_id,
    medico_id,
    centro_medico_id,
    usuario_id,
):
    """Crear pacientes/pendientes como una unidad, con validaciones de integridad."""
    fecha_hoy_rd = fecha_clinica()
    fecha_minima_rd = fecha_minima_consulta_rd(fecha_hoy_rd)
    errores_validacion = []
    candidatos = []
    claves_lote = set()

    for idx, linea in enumerate(lineas or [], start=1):
        nss_raw = linea.get('nss', '')
        nombre_raw = linea.get('nombre', '')
        fecha_raw = linea.get('fecha', '')
        autorizacion_raw = linea.get('autorizacion', '')
        servicio_raw = linea.get('servicio', '')
        monto_raw = linea.get('monto', 0)

        try:
            nss = _validate_or_raise(nss_raw, _RE_NSS, 'NSS', idx=idx, max_len=20)
            nombre = _validate_or_raise(
                nombre_raw, _RE_NOMBRE, 'Nombre del paciente', idx=idx, max_len=200
            )
            servicio = _validate_or_raise(
                servicio_raw, _RE_TEXTO_GENERAL, 'Servicio', idx=idx, max_len=200
            )
            autorizacion = _validate_or_raise(
                autorizacion_raw,
                _RE_AUTORIZACION,
                'Autorización',
                idx=idx,
                max_len=50,
                required=True,
            )
        except ValueError as error:
            errores_validacion.append(str(error))
            continue

        try:
            monto = _monto(monto_raw)
        except (InvalidOperation, TypeError, ValueError):
            errores_validacion.append(f'Línea {idx}: Monto inválido')
            continue
        if monto <= 0:
            errores_validacion.append(f'Línea {idx}: El monto debe ser mayor a cero')
            continue

        fecha_str = str(fecha_raw or '').strip()
        try:
            fecha_obj = date.fromisoformat(fecha_str[:10]) if fecha_str else None
        except ValueError:
            fecha_obj = None
        if not fecha_obj:
            errores_validacion.append(
                f'Línea {idx}: Fecha de consulta inválida (use YYYY-MM-DD)'
            )
            continue
        if fecha_obj > fecha_hoy_rd:
            errores_validacion.append(
                f'Línea {idx}: La fecha de consulta no puede ser futura'
            )
            continue
        if fecha_obj < fecha_minima_rd:
            errores_validacion.append(
                f'Línea {idx}: La fecha de consulta no puede ser anterior a '
                f'{FECHA_MIN_CONSULTA_DIAS} días '
                f'(mínimo {fecha_minima_rd.strftime("%Y-%m-%d")})'
            )
            continue

        clave = (nss, fecha_obj.isoformat(), autorizacion)
        candidatos.append({
            'idx': idx,
            'nss': nss,
            'nombre': nombre,
            'fecha': fecha_obj,
            'autorizacion': autorizacion,
            'servicio': servicio,
            'monto': monto,
            'clave': clave,
            'duplicado_lote': clave in claves_lote,
        })
        claves_lote.add(clave)

    if errores_validacion:
        raise ValueError('\n'.join(errores_validacion[:12]))

    if not candidatos:
        raise ValueError('No hay pacientes válidos para registrar')

    omitidos = []
    a_insertar = []

    with database_transaction():
        nss_unicos = list({item['nss'] for item in candidatos})
        placeholders = ','.join(['%s'] * len(nss_unicos))
        existentes = execute_query(f'''
            SELECT id, nss, cedula, fecha_nacimiento
            FROM pacientes
            WHERE tenant_id = %s AND ars_id = %s
              AND nss IN ({placeholders})
            FOR UPDATE
        ''', (tenant_id, ars_id, *nss_unicos), fetch='all') or []
        pacientes_por_nss = {paciente['nss']: paciente for paciente in existentes}

        fechas = list({item['fecha'] for item in candidatos})
        fecha_placeholders = ','.join(['%s'] * len(fechas))
        pendientes_existentes = execute_query(f'''
            SELECT id, nss, fecha_servicio, servicios_realizados
            FROM pacientes_pendientes
            WHERE tenant_id = %s AND ars_id = %s
              AND nss IN ({placeholders})
              AND fecha_servicio IN ({fecha_placeholders})
        ''', (tenant_id, ars_id, *nss_unicos, *fechas), fetch='all') or []

        duplicados_bd = set()
        for pendiente in pendientes_existentes:
            fecha_pend = pendiente.get('fecha_servicio')
            if hasattr(fecha_pend, 'isoformat'):
                fecha_clave = fecha_pend.isoformat()
            else:
                fecha_clave = str(fecha_pend or '')[:10]
            autorizacion_pend = _extraer_autorizacion_servicios(
                pendiente.get('servicios_realizados')
            )
            duplicados_bd.add((pendiente.get('nss'), fecha_clave, autorizacion_pend))

        for linea in candidatos:
            clave = linea['clave']
            if linea.get('duplicado_lote') or clave in duplicados_bd:
                omitidos.append(
                    f"Línea {linea['idx']}: Registro duplicado - NSS {linea['nss']}, "
                    f"Fecha {linea['fecha'].isoformat()}, "
                    f"Autorización {linea['autorizacion'] or '(vacía)'} ya existe"
                )
                continue
            a_insertar.append(linea)
            duplicados_bd.add(clave)

        if not a_insertar:
            raise ValueError(
                'No se agregó ningún paciente. '
                + (
                    f'Se detectaron {len(omitidos)} registro(s) duplicado(s).'
                    if omitidos
                    else 'Verifique los datos e intente nuevamente.'
                )
            )

        for linea in a_insertar:
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

    return {
        'creados': len(a_insertar),
        'omitidos': omitidos,
        'total_enviado': len(lineas or []),
    }


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
            resultado = registrar_consultas_pendientes_atomico(
                lineas,
                tenant_id,
                ars_id,
                medico_id,
                centro_medico_id,
                current_user.id,
            )
        except ValueError as error:
            for mensaje in str(error).split('\n'):
                if mensaje.strip():
                    flash(mensaje.strip(), 'error')
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

        creados = resultado.get('creados', 0)
        total_enviado = resultado.get('total_enviado', creados)
        omitidos = resultado.get('omitidos') or []
        flash(
            f'{creados} de {total_enviado} paciente(s) agregado(s) '
            'como pendientes de facturación',
            'success',
        )
        if omitidos:
            flash(
                f'Se omitieron {len(omitidos)} registro(s) por duplicados.',
                'warning',
            )
            for mensaje in omitidos[:5]:
                flash(mensaje, 'warning')
            if len(omitidos) > 5:
                flash(f'... y {len(omitidos) - 5} más.', 'warning')
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

    hoy_rd = fecha_clinica()
    return render_template(
        'facturacion/facturas_form.html',
        ars_list=ars_list,
        medicos=medicos,
        centros_medicos=centros_medicos,
        servicios_list=servicios_list,
        paciente_preseleccionado=paciente_preseleccionado,
        fecha_hoy_rd=hoy_rd.strftime('%Y-%m-%d'),
        fecha_min_rd=fecha_minima_consulta_rd(hoy_rd).strftime('%Y-%m-%d'),
    )
