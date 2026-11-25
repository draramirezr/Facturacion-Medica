"""Histórico, consulta de facturas y documentos e-CF (XML, QR, representación impresa)."""
import logging
from flask import current_app, flash, make_response, redirect, render_template, send_file, url_for
from flask_login import current_user, login_required
from auth import permission_required, user_has_permission
from core.database import execute_query
from core.tenant import get_current_tenant_id, validate_tenant_access
from ecf import ECFPrintableError, ECFStampError, build_stamp, generate_e31_pdf, generate_qr
from routes.support import validate_int
from services.subscriptions import get_empresa_info
from services.ecf_operations import consultar_resultado_ecf_dgii, ecf_habilitado_para_tenant
from services.notas_credito import listar_notas_factura, puede_emitir_nota_credito, saldo_creditable_factura
from routes.billing_invoice_edit import _factura_modificable

logger = logging.getLogger(__name__)


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
    
    ok_editar, _motivo_editar = _factura_modificable(factura, tenant_id)
    puede_nc, _motivo_nc = puede_emitir_nota_credito(tenant_id, factura_id)
    saldo_nc = saldo_creditable_factura(tenant_id, factura_id) if puede_nc else 0
    notas_credito_list = listar_notas_factura(tenant_id, factura_id)
    puede_crear_nota = (
        puede_nc
        and user_has_permission(current_user, 'facturacion.nota_credito')
        and (factura.get('estado') or '') != 'Anulada'
    )
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
                          factura_ecf=factura_ecf,
                          ecf_timbre=_ecf_timbre_desde_factura(factura_ecf),
                          mostrar_qr_ecf=_factura_tiene_qr_ecf(factura_ecf),
                          factura_editable=ok_editar,
                          factura_anulable=ok_editar,
                          puede_crear_nota_credito=puede_crear_nota,
                          saldo_creditable_nc=saldo_nc,
                          notas_credito_list=notas_credito_list)


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


def _ecf_timbre_desde_factura(factura_ecf):
    """Timbre fiscal (QR, código de seguridad, firma) desde el XML firmado."""
    if not factura_ecf or not factura_ecf.get('xml_firmado'):
        return None
    if factura_ecf.get('estado') == 'RECHAZADO':
        return None
    try:
        stamp_url = current_app.config['ECF_CONFIG'].stamp_url
        stamp = build_stamp(factura_ecf['xml_firmado'], stamp_url)
    except (ECFStampError, KeyError, AttributeError):
        return None
    return {
        'codigo_seguridad': stamp.security_code,
        'firma_digital': stamp.signature_date,
    }


def _factura_tiene_qr_ecf(factura_ecf):
    return _ecf_timbre_desde_factura(factura_ecf) is not None


def _obtener_ecf_firmado_para_qr(factura_id, tenant_id):
    document = execute_query('''
        SELECT e_ncf, estado, xml_firmado, track_id
        FROM facturas_ecf
        WHERE factura_id=%s AND tenant_id=%s
        LIMIT 1
    ''', (factura_id, tenant_id))
    if not document or not document.get('xml_firmado'):
        raise ECFPrintableError(
            'El QR se habilita cuando el e-CF tiene XML firmado'
        )
    if document.get('estado') == 'RECHAZADO':
        raise ECFPrintableError('El e-CF fue rechazado y no admite QR fiscal')
    return document


@login_required
@permission_required('facturacion.imprimir')
def facturacion_qr_ecf(factura_id):
    """Mostrar el QR fiscal de un e-CF aceptado por DGII."""
    if not validate_tenant_access('facturas', factura_id):
        flash('No tienes acceso a esta factura', 'error')
        return redirect(url_for('facturacion_historico'))

    try:
        document = _obtener_ecf_firmado_para_qr(
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
@permission_required('configuracion.editar')
def facturacion_dgii_certificado():
    """La UI vive en Configuración; se conserva la ruta por compatibilidad."""
    return redirect(url_for('perfil_configuracion', _anchor='certificado-ecf'))
