"""Operaciones de env?o y consulta e-CF/DGII."""

import json
import logging
import os
import re
from datetime import datetime

from flask import current_app

from core.database import execute_query, execute_update, get_db_connection
from ecf import (
    DGIIClient, DGIIClientError, ECFCertificateResolutionError,
    TenantCertificateProvider, classify_dgii_status,
)
from ecf.fecha_secuencia import parse_fecha_vencimiento_secuencia

logger = logging.getLogger(__name__)

def ecf_habilitado_para_tenant(tenant_id, solo_consulta=False):
    """Aplicar interruptor global y autorización e-CF específica por cuenta."""
    config = current_app.config['ECF_CONFIG']
    if not config.enabled:
        return False

    tenant_config = execute_query('''
        SELECT habilitado, ambiente, produccion_confirmada
        FROM ecf_configuraciones
        WHERE tenant_id=%s
        LIMIT 1
    ''', (tenant_id,))

    # En PRUEBAS/CERTIFICACION basta el interruptor global. Guardar el
    # certificado o el emisor no debe bloquear la cuenta (habilitado=0).
    # Producción exige fila, ambiente, habilitado y confirmación explícita.
    if config.environment == 'PRODUCCION':
        if not tenant_config:
            return False
        if str(tenant_config.get('ambiente') or '').upper() != 'PRODUCCION':
            return False
        return bool(tenant_config.get('habilitado')) and bool(
            tenant_config.get('produccion_confirmada')
        )

    if tenant_config:
        ambiente_cuenta = str(tenant_config.get('ambiente') or '').upper()
        if ambiente_cuenta and ambiente_cuenta != config.environment:
            return False
    return True

def obtener_configuracion_ecf_tenant(tenant_id):
    return execute_query('''
        SELECT *
        FROM ecf_configuraciones
        WHERE tenant_id=%s
        LIMIT 1
    ''', (tenant_id,)) or {}


def emisor_ecf_para_xml(tenant_id, empresa_info=None):
    """RNC, razón y dirección del emisor: config e-CF con fallback a empresa."""
    cfg = obtener_configuracion_ecf_tenant(tenant_id) or {}
    empresa = empresa_info or {}
    razon = (
        (cfg.get('razon_social_emisor') or '').strip()
        or (empresa.get('razon_social') or '').strip()
        or (empresa.get('nombre') or '').strip()
    )
    return {
        'rnc': (cfg.get('rnc_emisor') or empresa.get('rnc') or '').strip(),
        'razon_social': razon,
        'nombre': razon,
        'direccion': (
            (cfg.get('direccion_emisor') or '').strip()
            or (empresa.get('direccion') or '').strip()
        ),
    }


def fecha_vencimiento_secuencia_ecf(tenant_id, fallback=None):
    cfg = obtener_configuracion_ecf_tenant(tenant_id) or {}
    parsed = parse_fecha_vencimiento_secuencia(
        cfg.get('fecha_vencimiento_secuencia')
    )
    return parsed or fallback


def upsert_configuracion_ecf_tenant(tenant_id, campos, usuario_id=None):
    """Insertar o actualizar la fila de e-CF de la cuenta."""
    existing = obtener_configuracion_ecf_tenant(tenant_id)
    allowed = {
        'habilitado',
        'ambiente',
        'certificado_referencia',
        'secreto_referencia',
        'certificado_huella',
        'certificado_vence',
        'certificado_validado_en',
        'rnc_emisor',
        'razon_social_emisor',
        'direccion_emisor',
        'fecha_vencimiento_secuencia',
        'last_test_at',
        'last_test_json',
        'produccion_confirmada',
    }
    payload = {
        key: value
        for key, value in (campos or {}).items()
        if key in allowed
    }
    if existing:
        payload['actualizado_por'] = usuario_id
        assignments = ', '.join(f'`{key}`=%s' for key in payload)
        execute_update(
            f'''
            UPDATE ecf_configuraciones
            SET {assignments}
            WHERE tenant_id=%s
            ''',
            tuple(payload.values()) + (tenant_id,),
        )
        return obtener_configuracion_ecf_tenant(tenant_id)
    payload.setdefault('ambiente', 'PRUEBAS')
    payload.setdefault('habilitado', 0)
    payload['tenant_id'] = tenant_id
    payload['creado_por'] = usuario_id
    payload['actualizado_por'] = usuario_id
    columns = ', '.join(f'`{key}`' for key in payload)
    placeholders = ', '.join(['%s'] * len(payload))
    execute_update(
        f'''
        INSERT INTO ecf_configuraciones ({columns})
        VALUES ({placeholders})
        ''',
        tuple(payload.values()),
    )
    return obtener_configuracion_ecf_tenant(tenant_id)


def guardar_resultado_pruebas_ecf(tenant_id, resultado, usuario_id=None):
    campos = {
        'last_test_at': datetime.now(),
        'last_test_json': json.dumps(resultado, ensure_ascii=False),
    }
    if resultado.get('ok'):
        campos['habilitado'] = 1
    upsert_configuracion_ecf_tenant(tenant_id, campos, usuario_id)


def contexto_certificado_ecf_configuracion(tenant_id, empresa_info=None):
    """Datos para la tarjeta de certificado en Configuración."""
    from ecf.fecha_secuencia import normalize_fecha_vencimiento_secuencia

    cfg = obtener_configuracion_ecf_tenant(tenant_id) or {}
    config = current_app.config['ECF_CONFIG']
    fecha_parts = ['', '', '']
    fecha_cfg = (cfg.get('fecha_vencimiento_secuencia') or '').strip()
    if fecha_cfg:
        normalized = normalize_fecha_vencimiento_secuencia(fecha_cfg)
        if normalized:
            fecha_parts = normalized.split('-')
    pruebas = None
    raw = cfg.get('last_test_json') or ''
    if raw:
        try:
            pruebas = json.loads(raw)
        except (TypeError, ValueError):
            pruebas = None
    return {
        'cfg': cfg,
        'pruebas': pruebas,
        'vence_dia': fecha_parts[0],
        'vence_mes': fecha_parts[1],
        'vence_anio': fecha_parts[2],
        'ambiente_form': cfg.get('ambiente') or config.environment,
        'empresa_info': empresa_info or {},
    }


def procesar_formulario_certificado_ecf(tenant_id, usuario_id, empresa_info=None):
    """Guardar emisor, PKCS#12 por tenant o repetir pruebas DGII."""
    from flask import request

    from ecf.fecha_secuencia import normalize_fecha_vencimiento_secuencia
    from ecf.tests_runner import run_dgii_pruebas
    from routes.support import sanitize_input

    empresa_info = empresa_info or {}
    config = current_app.config['ECF_CONFIG']
    accion = (request.form.get('accion') or '').strip()
    if accion == 'certificado_ecf_guardar':
        accion = 'guardar'
    elif accion == 'certificado_ecf_pruebas':
        accion = 'pruebas'
    elif accion == 'certificado_ecf':
        accion = 'certificado'

    rnc = re.sub(r'\D', '', request.form.get('rnc_emisor') or '')
    razon = sanitize_input(request.form.get('razon_social_emisor') or '', 200)
    direccion = sanitize_input(request.form.get('direccion_emisor') or '', 255)
    fecha_seq = normalize_fecha_vencimiento_secuencia(
        f"{request.form.get('vence_dia', '').strip()}-"
        f"{request.form.get('vence_mes', '').strip()}-"
        f"{request.form.get('vence_anio', '').strip()}"
    )
    ambiente = str(request.form.get('ambiente') or config.environment).strip().upper()
    if ambiente not in {'PRUEBAS', 'CERTIFICACION', 'PRODUCCION'}:
        ambiente = config.environment
    if not fecha_seq and (
        request.form.get('vence_dia')
        or request.form.get('vence_mes')
        or request.form.get('vence_anio')
    ):
        return (
            False,
            'La fecha de vencimiento de secuencia debe ser día-mes-año válido (formato DGII).',
            'error',
        )

    campos = {
        'rnc_emisor': rnc or None,
        'razon_social_emisor': razon or None,
        'direccion_emisor': direccion or None,
        'fecha_vencimiento_secuencia': fecha_seq or None,
        'ambiente': ambiente,
    }
    if ambiente == 'PRODUCCION' and request.form.get('produccion_confirmada') == '1':
        campos['produccion_confirmada'] = 1

    if accion == 'certificado':
        archivo = request.files.get('certificado_p12')
        password = request.form.get('certificado_password', '')
        nombre = (archivo.filename or '').lower() if archivo else ''
        if not archivo or not nombre.endswith(('.p12', '.pfx')):
            return False, 'Sube un certificado PKCS#12 (.p12 o .pfx).', 'error'
        firmante = rnc or str(empresa_info.get('rnc') or '').strip()
        if not firmante:
            return False, 'Indica el RNC emisor antes de cargar el certificado.', 'error'
        try:
            metadata = TenantCertificateProvider(config).store(
                tenant_id, archivo.read(), password, firmante
            )
        except ECFCertificateResolutionError as error:
            return False, str(error), 'error'
        campos.update({
            'certificado_referencia': f'tenant-{tenant_id}/certificate.p12',
            'secreto_referencia': f'tenant-{tenant_id}/password.txt',
            'certificado_huella': metadata.fingerprint,
            'certificado_vence': metadata.valid_until.date(),
            'certificado_validado_en': datetime.now(),
        })
        upsert_configuracion_ecf_tenant(tenant_id, campos, usuario_id)
        resultado = run_dgii_pruebas(
            config=config,
            tenant_id=tenant_id,
            tenant_config=obtener_configuracion_ecf_tenant(tenant_id),
            issuer_rnc=firmante,
        )
        guardar_resultado_pruebas_ecf(tenant_id, resultado, usuario_id)
        if resultado.get('ok'):
            return True, 'Certificado guardado. Pruebas DGII correctas.', 'success'
        return True, 'Certificado guardado. Revise los pasos de prueba con DGII.', 'warning'

    upsert_configuracion_ecf_tenant(tenant_id, campos, usuario_id)
    if accion == 'pruebas':
        firmante = rnc or str(empresa_info.get('rnc') or '').strip()
        resultado = run_dgii_pruebas(
            config=config,
            tenant_id=tenant_id,
            tenant_config=obtener_configuracion_ecf_tenant(tenant_id),
            issuer_rnc=firmante,
        )
        guardar_resultado_pruebas_ecf(tenant_id, resultado, usuario_id)
        if resultado.get('ok'):
            return True, 'Pruebas DGII correctas.', 'success'
        return True, 'Algún paso de prueba falló.', 'warning'
    return True, 'Datos del emisor e-CF guardados.', 'success'

def obtener_firmante_ecf_tenant(tenant_id):
    """Resolver el firmante aislado correspondiente a una sola cuenta."""
    provider = TenantCertificateProvider(current_app.config['ECF_CONFIG'])
    resolved = provider.resolve(
        tenant_id,
        obtener_configuracion_ecf_tenant(tenant_id),
    )
    return resolved.signer()

def procesar_envio_ecf_dgii(factura_ecf_id, tenant_id, usuario_id):
    """Procesar una sola entrega pendiente sin reintentos automáticos."""
    if not ecf_habilitado_para_tenant(tenant_id):
        return False, 'La cuenta no está habilitada para enviar e-CF'
    try:
        tenant_signer = obtener_firmante_ecf_tenant(tenant_id)
    except ECFCertificateResolutionError as error:
        return False, str(error)
    conn = get_db_connection()
    cursor = None
    outbox_key = f'ENVIAR_ECF:{factura_ecf_id}'
    try:
        conn.begin()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE ecf_outbox
            SET estado='PROCESANDO', intentos=intentos+1,
                bloqueado_en=NOW(), bloqueado_por=%s,
                ultimo_error=NULL
            WHERE clave_evento=%s AND tenant_id=%s
              AND estado='PENDIENTE'
        ''', (f'web:{os.getpid()}', outbox_key, tenant_id))
        if cursor.rowcount != 1:
            conn.rollback()
            return False, 'El envío no está pendiente o ya fue procesado'

        cursor.execute('''
            SELECT fe.id, fe.e_ncf, fe.xml_firmado, fe.estado,
                   e.rnc AS rnc_emisor
            FROM facturas_ecf fe
            INNER JOIN empresas e ON e.id=fe.tenant_id
            WHERE fe.id=%s AND fe.tenant_id=%s
            LIMIT 1
            FOR UPDATE
        ''', (factura_ecf_id, tenant_id))
        document = cursor.fetchone()
        if (
            not document
            or document.get('estado') != 'FIRMADO'
            or not document.get('xml_firmado')
        ):
            cursor.execute('''
                UPDATE ecf_outbox
                SET estado='ERROR', ultimo_error=%s,
                    bloqueado_en=NULL, bloqueado_por=NULL
                WHERE clave_evento=%s AND tenant_id=%s
            ''', (
                'El documento no está firmado y listo para envío',
                outbox_key,
                tenant_id
            ))
            conn.commit()
            return False, 'El documento no está firmado y listo para envío'

        cursor.execute('''
            INSERT INTO ecf_eventos
            (tenant_id, factura_ecf_id, estado_anterior, estado_nuevo,
             evento, detalle, usuario_id)
            VALUES (%s, %s, 'FIRMADO', 'FIRMADO',
                    'ENVIO_DGII_INICIADO', %s, %s)
        ''', (
            tenant_id,
            factura_ecf_id,
            'Autenticación y envío al ambiente DGII no productivo iniciados',
            usuario_id
        ))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        if cursor:
            cursor.close()

    try:
        reception = DGIIClient(
            current_app.config['ECF_CONFIG'],
            signer=tenant_signer,
        ).submit_e31(
            document['xml_firmado'],
            document['rnc_emisor'],
            document['e_ncf']
        )
    except DGIIClientError as error:
        outbox_status = (
            'REQUIERE_CONSULTA'
            if error.delivery_uncertain
            else 'ERROR'
        )
        error_message = str(error)
        response_text = error.response_text
        cursor = None
        try:
            conn.begin()
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE facturas_ecf
                SET estado='ERROR_ENVIO', intentos=intentos+1,
                    ultimo_error=%s, codigo_respuesta=%s,
                    mensaje_respuesta=%s,
                    respuesta_dgii=COALESCE(%s, respuesta_dgii)
                WHERE id=%s AND tenant_id=%s
            ''', (
                error_message,
                f'HTTP_{error.http_status}' if error.http_status else None,
                error_message,
                response_text,
                factura_ecf_id,
                tenant_id
            ))
            cursor.execute('''
                UPDATE ecf_outbox
                SET estado=%s, ultimo_error=%s,
                    bloqueado_en=NULL, bloqueado_por=NULL
                WHERE clave_evento=%s AND tenant_id=%s
            ''', (
                outbox_status,
                error_message,
                outbox_key,
                tenant_id
            ))
            cursor.execute('''
                INSERT INTO ecf_eventos
                (tenant_id, factura_ecf_id,
                 estado_anterior, estado_nuevo,
                 evento, detalle, usuario_id)
                VALUES (%s, %s, 'FIRMADO', 'ERROR_ENVIO',
                        %s, %s, %s)
            ''', (
                tenant_id,
                factura_ecf_id,
                (
                    'ENVIO_INCIERTO_REQUIERE_CONSULTA'
                    if error.delivery_uncertain
                    else 'ERROR_ENVIO_DGII'
                ),
                error_message,
                usuario_id
            ))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            if cursor:
                cursor.close()
        logger.warning(
            'Falló el envío e-CF %s a DGII: %s',
            factura_ecf_id,
            error_message
        )
        return False, error_message

    cursor = None
    try:
        conn.begin()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE facturas_ecf
            SET estado='ENVIADO', track_id=%s, fecha_envio=NOW(6),
                respuesta_dgii=%s, intentos=intentos+1,
                codigo_respuesta=%s, mensaje_respuesta=%s,
                ultimo_error=NULL
            WHERE id=%s AND tenant_id=%s AND estado='FIRMADO'
        ''', (
            reception.track_id,
            reception.raw_response,
            f'HTTP_{reception.http_status}',
            reception.message or reception.error or 'Recibido por DGII',
            factura_ecf_id,
            tenant_id
        ))
        if cursor.rowcount != 1:
            raise RuntimeError('El estado del e-CF cambió durante el envío')
        cursor.execute('''
            UPDATE ecf_outbox
            SET estado='COMPLETADO', ultimo_error=NULL,
                bloqueado_en=NULL, bloqueado_por=NULL
            WHERE clave_evento=%s AND tenant_id=%s
        ''', (outbox_key, tenant_id))
        cursor.execute('''
            INSERT INTO ecf_eventos
            (tenant_id, factura_ecf_id, estado_anterior, estado_nuevo,
             evento, detalle, usuario_id)
            VALUES (%s, %s, 'FIRMADO', 'ENVIADO',
                    'ECF_RECIBIDO_DGII', %s, %s)
        ''', (
            tenant_id,
            factura_ecf_id,
            f'TrackID recibido: {reception.track_id}',
            usuario_id
        ))
        conn.commit()
        return True, reception.track_id
    except Exception:
        conn.rollback()
        raise
    finally:
        if cursor:
            cursor.close()

def consultar_resultado_ecf_dgii(factura_ecf_id, tenant_id, usuario_id):
    """Consultar una vez el resultado; nunca reenvía el comprobante."""
    document = execute_query('''
        SELECT fe.id, fe.e_ncf, fe.track_id, fe.estado,
               e.rnc AS rnc_emisor
        FROM facturas_ecf fe
        INNER JOIN empresas e ON e.id=fe.tenant_id
        WHERE fe.id=%s AND fe.tenant_id=%s
        LIMIT 1
    ''', (factura_ecf_id, tenant_id))
    if not document:
        return False, None, 'Documento e-CF no encontrado'
    if document.get('estado') not in {
        'ENVIADO', 'ERROR_ENVIO', 'ACEPTADO', 'RECHAZADO'
    }:
        return (
            False,
            document.get('estado'),
            'El documento todavía no está listo para consultar en DGII'
        )

    try:
        client = DGIIClient(
            current_app.config['ECF_CONFIG'],
            signer=obtener_firmante_ecf_tenant(tenant_id),
        )
        token = client.authenticate(document['rnc_emisor'])
        track_id = str(document.get('track_id') or '').strip()
        recovered_track = False
        if not track_id:
            tracks = client.find_track_ids(
                document['rnc_emisor'],
                document['e_ncf'],
                token=token
            )
            if len(tracks) == 0:
                message = (
                    'DGII todavía no reporta un TrackID para este e-NCF; '
                    'no se realizará un reenvío automático'
                )
                _registrar_error_consulta_ecf(
                    factura_ecf_id,
                    tenant_id,
                    document['estado'],
                    message,
                    usuario_id
                )
                return False, document['estado'], message
            if len(tracks) > 1:
                message = (
                    'DGII reportó varios TrackID para el mismo e-NCF; '
                    'se requiere revisión manual'
                )
                _registrar_error_consulta_ecf(
                    factura_ecf_id,
                    tenant_id,
                    document['estado'],
                    message,
                    usuario_id
                )
                return False, document['estado'], message
            track_id = tracks[0].track_id
            recovered_track = True

        result = client.query_result(
            track_id,
            document['rnc_emisor'],
            token=token
        )
        expected_rnc = re.sub(r'\D', '', document['rnc_emisor'] or '')
        returned_rnc = re.sub(r'\D', '', result.rnc or '')
        if returned_rnc and returned_rnc != expected_rnc:
            raise DGIIClientError(
                'La respuesta DGII pertenece a otro RNC emisor'
            )
        if result.encf and result.encf.upper() != document['e_ncf'].upper():
            raise DGIIClientError(
                'La respuesta DGII pertenece a otro e-NCF'
            )

        local_status = classify_dgii_status(result.code, result.status)
        detail_message = ' | '.join(result.messages)
        if not detail_message:
            detail_message = result.status or 'Respuesta recibida de DGII'
        if result.sequence_used is not None:
            detail_message += (
                ' | Secuencia marcada como utilizada: '
                f'{"Sí" if result.sequence_used else "No"}'
            )

        conn = get_db_connection()
        cursor = None
        try:
            conn.begin()
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE facturas_ecf
                SET estado=%s, track_id=%s, fecha_respuesta=NOW(6),
                    codigo_respuesta=%s, mensaje_respuesta=%s,
                    respuesta_dgii=%s, ultimo_error=NULL
                WHERE id=%s AND tenant_id=%s
            ''', (
                local_status,
                track_id,
                result.code or f'HTTP_{result.http_status}',
                detail_message,
                result.raw_response,
                factura_ecf_id,
                tenant_id
            ))
            if recovered_track:
                cursor.execute('''
                    UPDATE ecf_outbox
                    SET estado='COMPLETADO', ultimo_error=NULL,
                        bloqueado_en=NULL, bloqueado_por=NULL
                    WHERE factura_ecf_id=%s AND tenant_id=%s
                      AND tipo_evento='ENVIAR_ECF'
                ''', (factura_ecf_id, tenant_id))
            cursor.execute('''
                INSERT INTO ecf_eventos
                (tenant_id, factura_ecf_id,
                 estado_anterior, estado_nuevo,
                 evento, detalle, usuario_id)
                VALUES (%s, %s, %s, %s,
                        'RESULTADO_DGII_CONSULTADO', %s, %s)
            ''', (
                tenant_id,
                factura_ecf_id,
                document['estado'],
                local_status,
                (
                    f'Estado DGII: {result.status or result.code}; '
                    f'TrackID: {track_id}; {detail_message}'
                ),
                usuario_id
            ))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            if cursor:
                cursor.close()
        return True, local_status, detail_message
    except (DGIIClientError, ECFCertificateResolutionError) as error:
        message = str(error)
        _registrar_error_consulta_ecf(
            factura_ecf_id,
            tenant_id,
            document['estado'],
            message,
            usuario_id
        )
        return False, document['estado'], message

def _registrar_error_consulta_ecf(
    factura_ecf_id,
    tenant_id,
    current_status,
    message,
    usuario_id
):
    """Registrar fallo de consulta sin alterar el estado fiscal conocido."""
    conn = get_db_connection()
    cursor = None
    try:
        conn.begin()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE facturas_ecf
            SET ultimo_error=%s
            WHERE id=%s AND tenant_id=%s
        ''', (message, factura_ecf_id, tenant_id))
        cursor.execute('''
            INSERT INTO ecf_eventos
            (tenant_id, factura_ecf_id,
             estado_anterior, estado_nuevo,
             evento, detalle, usuario_id)
            VALUES (%s, %s, %s, %s,
                    'ERROR_CONSULTA_DGII', %s, %s)
        ''', (
            tenant_id,
            factura_ecf_id,
            current_status,
            current_status,
            message,
            usuario_id
        ))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        if cursor:
            cursor.close()

