"""Emisión final de la factura: NCF o e-NCF, detalle, XML e-CF y envío a DGII."""
import logging
import json
import re
from datetime import datetime
from decimal import Decimal
from flask import current_app, flash, redirect, request, url_for
from flask_login import current_user, login_required
from auth import permission_required
from core.database import execute_query, get_db_connection
from core.tenant import get_current_tenant_id
from ecf import ECFBuildError, ECFBuilder, ECFCertificateResolutionError, ECFSchemaError, ECFSigningError, ECFValidationError, ECFValidator, TenantCertificateProvider, reserve_encf
from services.subscriptions import get_empresa_info
from services.ecf_operations import consultar_resultado_ecf_dgii, ecf_habilitado_para_tenant, emisor_ecf_para_xml, fecha_vencimiento_secuencia_ecf, obtener_configuracion_ecf_tenant, procesar_envio_ecf_dgii
from routes.billing_common import _monto
from routes.billing_generate import _flash_ecf_no_habilitado, _tipo_factura_por_defecto

logger = logging.getLogger(__name__)


@login_required
@permission_required('facturacion.crear')
def facturacion_generar_final():
    """Generar factura final en la base de datos"""
    
    tenant_id = get_current_tenant_id()
    
    # Obtener datos del formulario
    tipo_factura = request.form.get(
        'tipo_factura', _tipo_factura_por_defecto(tenant_id)
    ).strip().upper()
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
        _flash_ecf_no_habilitado()
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
            vence_ncf = ncf_bloqueado.get('fecha_fin')
            if vence_ncf:
                if isinstance(vence_ncf, str):
                    vence_ncf = datetime.strptime(vence_ncf[:10], '%Y-%m-%d').date()
                elif isinstance(vence_ncf, datetime):
                    vence_ncf = vence_ncf.date()
                if vence_ncf < fecha_actual.date():
                    raise ValueError(
                        f"La secuencia NCF {ncf_bloqueado.get('tipo') or ''} venció el "
                        f"{vence_ncf.strftime('%d/%m/%Y')}. Registre una secuencia vigente."
                    )

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
            
            monto = _monto(paciente.get('monto_estimado'))
            
            cursor.execute('''
                INSERT INTO factura_detalles
                (tenant_id, factura_id, paciente_pendiente_id, descripcion,
                 cantidad, precio_unitario, subtotal)
                VALUES (%s, %s, %s, %s, 1, %s, %s)
            ''', (
                tenant_id, factura_id, paciente.get('id'),
                descripcion_servicio, monto, monto,
            ))

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
                    sequence_expires_at=fecha_vencimiento_secuencia_ecf(
                        tenant_id, reserva_ecf.expires_at
                    ),
                    issuer=emisor_ecf_para_xml(tenant_id, empresa_info or {}),
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
                            emisor_ecf_para_xml(
                                tenant_id, empresa_info or {}
                            ).get('rnc'),
                            obtener_configuracion_ecf_tenant(tenant_id),
                        )
                    )
                    resultado_firma = certificado_resuelto.signer().sign_e31(
                        resultado_xml.xml,
                        expected_signer_id=emisor_ecf_para_xml(
                            tenant_id, empresa_info or {}
                        ).get('rnc'),
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
        if 'uq_facturas_tenant_ncf' in str(e):
            flash(
                'Otro usuario acaba de usar ese número de comprobante. '
                'No se guardó nada; intente generar la factura de nuevo.',
                'error',
            )
        else:
            flash(f'Error al generar la factura: {str(e)}', 'error')
        return redirect(url_for('facturacion_generar'))
    finally:
        if cursor:
            cursor.close()
