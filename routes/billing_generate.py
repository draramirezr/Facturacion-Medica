"""Generación de facturas (paso a paso, NCF y e-CF)."""
import re
import secrets
from datetime import datetime
from decimal import Decimal
from flask import current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from auth import permission_required
from core.database import execute_query
from core.tenant import get_current_tenant_id, validate_tenant_access
from ecf import build_encf
from routes.support import validate_int
from services.subscriptions import get_empresa_info
from services.ecf_operations import ecf_habilitado_para_tenant
from routes.billing_common import _monto


def _flash_ecf_no_habilitado():
    if not current_app.config['ECF_CONFIG'].enabled:
        flash(
            'e-CF está desactivado en el servidor (ECF_ENABLED). '
            'En PRUEBAS póngalo en true para emitir E31.',
            'error',
        )
        return
    flash('La cuenta no está habilitada para facturación electrónica', 'error')


def _tipo_factura_por_defecto(tenant_id=None):
    tid = tenant_id or get_current_tenant_id()
    return 'ELECTRONICA' if ecf_habilitado_para_tenant(tid) else 'TRADICIONAL'


def _medico_factura_defecto_id(empresa_info, medicos_list, usuario=None):
    """Médico titular del consultorio (tipo_empresa=medico), no centro de salud."""
    if not empresa_info or empresa_info.get('tipo_empresa') == 'centro_salud':
        return None
    if not medicos_list:
        return None

    def _digits(value):
        return re.sub(r'\D', '', str(value or ''))

    doc_empresa = _digits(empresa_info.get('rnc'))
    if doc_empresa:
        for medico in medicos_list:
            if _digits(medico.get('cedula')) == doc_empresa:
                return medico.get('id')

    razon = (empresa_info.get('razon_social') or empresa_info.get('nombre') or '').strip().casefold()
    if razon:
        for medico in medicos_list:
            if (medico.get('nombre') or '').strip().casefold() == razon:
                return medico.get('id')

    medico_usuario = getattr(usuario, 'medico_id', None) if usuario else None
    if medico_usuario:
        for medico in medicos_list:
            if int(medico.get('id') or 0) == int(medico_usuario):
                return medico.get('id')

    facturadores = [
        medico for medico in medicos_list
        if int(medico.get('factura') or 0) == 1
    ]
    if len(facturadores) == 1:
        return facturadores[0].get('id')
    if len(medicos_list) == 1:
        return medicos_list[0].get('id')
    return None


@login_required
@permission_required('facturacion.crear')
def facturacion_generar():
    """Generar factura"""
    
    # Si es POST, redirigir al step 2
    if request.method == 'POST':
        # Validar y sanitizar entrada
        tenant_id = get_current_tenant_id()
        tipo_factura = request.form.get(
            'tipo_factura', _tipo_factura_por_defecto(tenant_id)
        ).strip().upper()
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
            and not ecf_habilitado_para_tenant(tenant_id)
        ):
            _flash_ecf_no_habilitado()
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

    medico_factura_defecto_id = _medico_factura_defecto_id(
        empresa_info,
        medicos_habilitados,
        current_user,
    )
    
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
                          medico_factura_defecto_id=medico_factura_defecto_id,
                          fecha_actual=fecha_actual,
                          tipo_empresa=tipo_empresa,
                          ecf_habilitado=ecf_habilitado_para_tenant(tenant_id))


@login_required
@permission_required('facturacion.crear')
def facturacion_generar_step2():
    """Generar factura - Paso 2: Selección de pacientes"""
    
    # Si es POST, redirigir a vista previa
    if request.method == 'POST':
        tenant_id = get_current_tenant_id()
        tipo_factura = request.form.get(
            'tipo_factura', _tipo_factura_por_defecto(tenant_id)
        ).strip().upper()
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
            and not ecf_habilitado_para_tenant(tenant_id)
        ):
            _flash_ecf_no_habilitado()
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
    tenant_id = get_current_tenant_id()
    tipo_factura = request.args.get(
        'tipo_factura', _tipo_factura_por_defecto(tenant_id)
    ).strip().upper()
    ars_id = request.args.get('ars_id')
    ncf_id = request.args.get('ncf_id')
    medico_factura_id = request.args.get('medico_factura_id')
    fecha_factura = request.args.get('fecha_factura')
    
    if tipo_factura not in ['TRADICIONAL', 'ELECTRONICA']:
        flash('Tipo de factura inválido', 'error')
        return redirect(url_for('facturacion_generar'))
    if (
        tipo_factura == 'ELECTRONICA'
        and not ecf_habilitado_para_tenant(tenant_id)
    ):
        _flash_ecf_no_habilitado()
        return redirect(url_for('facturacion_generar'))

    if not all([ars_id, medico_factura_id, fecha_factura]) or (
        tipo_factura == 'TRADICIONAL' and not ncf_id
    ):
        flash('Faltan parámetros obligatorios', 'error')
        return redirect(url_for('facturacion_generar'))
    
    
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
    tenant_id = get_current_tenant_id()
    tipo_factura = request.args.get(
        'tipo_factura', _tipo_factura_por_defecto(tenant_id)
    ).strip().upper()
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
        and not ecf_habilitado_para_tenant(tenant_id)
    ):
        _flash_ecf_no_habilitado()
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
    subtotal = sum((_monto(p.get('monto_estimado')) for p in pacientes), Decimal('0.00'))
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
