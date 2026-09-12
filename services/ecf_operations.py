"""Operaciones de env?o y consulta e-CF/DGII."""

import logging
import os
import re

from flask import current_app

from core.database import execute_query, get_db_connection
from ecf import (
    DGIIClient, DGIIClientError, ECFCertificateResolutionError,
    TenantCertificateProvider, classify_dgii_status,
)

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

    # En pruebas se conserva la habilitación global para facilitar el proceso
    # de certificación. Producción siempre exige un registro por cuenta.
    if not tenant_config:
        return config.environment != 'PRODUCCION'
    if not solo_consulta and not bool(tenant_config.get('habilitado')):
        return False
    if str(tenant_config.get('ambiente') or '').upper() != config.environment:
        return False
    if config.environment == 'PRODUCCION':
        return bool(tenant_config.get('produccion_confirmada'))
    return True

def obtener_configuracion_ecf_tenant(tenant_id):
    return execute_query('''
        SELECT *
        FROM ecf_configuraciones
        WHERE tenant_id=%s
        LIMIT 1
    ''', (tenant_id,)) or {}

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

