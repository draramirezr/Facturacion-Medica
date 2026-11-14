"""POST /api/Enviar — recepción y registro (sin envío a DGII en Fase 2)."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import pymysql
from flask import request

from integrations.external_ecf_service.adapters.hka.mapper import (
    HkaMapperError,
    map_hka_documento_electronico,
)
from integrations.external_ecf_service.auth.token_authorization import (
    AuthorizedIntegrationContext,
    TokenAuthFailure,
    authorize_bearer_token,
)
from integrations.external_ecf_service.domain.canonical import canonical_to_json_dict
from integrations.external_ecf_service.repositories.document_repository import (
    DocumentRepository,
)
from integrations.external_ecf_service.repositories.emitter_repository import (
    EmitterRepository,
)
from integrations.external_ecf_service.repositories.integration_repository import (
    IntegrationRepository,
)
from integrations.external_ecf_service.services.external_emit_orchestrator import (
    ExternalEmitOrchestrator,
)
from integrations.external_ecf_service.services.payload_hash import (
    compute_document_payload_hash,
)

logger = logging.getLogger(__name__)

# Fase 2: registro sin firma/XML. ``procesado`` debe reflejar emisión fiscal completa
# (ver analisis_contrato_hka.md §RespuestaEnviar / política procesado).
_RECEPTION_MENSAJE = 'Documento recibido; emisión fiscal pendiente'


@dataclass(frozen=True)
class EnviarSuccess:
    codigo: int
    mensaje: str
    xml_base64: str | None
    procesado: bool
    codigo_seguridad: str | None
    fecha_firma: str | None
    fecha_emision: str | None
    document_id: int | None = None
    idempotent_replay: bool = False


@dataclass(frozen=True)
class EnviarFailure:
    codigo: int
    mensaje: str
    xml_base64: str | None = None
    procesado: bool = False
    codigo_seguridad: str | None = None
    fecha_firma: str | None = None
    fecha_emision: str | None = None


def _response_from_snapshot(snapshot: dict | None) -> EnviarSuccess | None:
    if not snapshot or not isinstance(snapshot, dict):
        return None
    try:
        return EnviarSuccess(
            codigo=int(snapshot.get('codigo', 0)),
            mensaje=str(snapshot.get('mensaje') or ''),
            xml_base64=snapshot.get('xmlBase64'),
            procesado=bool(snapshot.get('procesado')),
            codigo_seguridad=snapshot.get('codigoSeguridad'),
            fecha_firma=snapshot.get('fechaFirma'),
            fecha_emision=snapshot.get('fechaEmision'),
            document_id=snapshot.get('document_id'),
            idempotent_replay=True,
        )
    except (TypeError, ValueError):
        return None


def _reception_success(
    *,
    fecha_emision: str | None,
    document_id: int | None = None,
    mensaje: str | None = None,
):
    """Respuesta HKA-compatible para recepción sin envío a DGII."""
    return EnviarSuccess(
        codigo=0,
        mensaje=mensaje or _RECEPTION_MENSAJE,
        xml_base64=None,
        procesado=False,
        codigo_seguridad=None,
        fecha_firma=None,
        fecha_emision=fecha_emision,
        document_id=document_id,
    )


def _idempotent_success_from_row(row: dict) -> EnviarSuccess:
    replay = _response_from_snapshot(_parse_json_field(row.get('response_snapshot')))
    if replay:
        return replay
    return EnviarSuccess(
        codigo=0,
        mensaje='Documento ya registrado',
        xml_base64=None,
        procesado=False,
        codigo_seguridad=None,
        fecha_firma=None,
        fecha_emision=None,
        document_id=int(row['id']),
        idempotent_replay=True,
    )


def _build_hka_snapshot(success: EnviarSuccess) -> dict[str, Any]:
    return {
        'codigo': success.codigo,
        'mensaje': success.mensaje,
        'xmlBase64': success.xml_base64,
        'procesado': success.procesado,
        'codigoSeguridad': success.codigo_seguridad,
        'fechaFirma': success.fecha_firma,
        'fechaEmision': success.fecha_emision,
        'document_id': success.document_id,
    }


class SendService:
    def __init__(
        self,
        config,
        integration_repo: IntegrationRepository | None = None,
        emitter_repo: EmitterRepository | None = None,
        document_repo: DocumentRepository | None = None,
    ):
        self._config = config
        self._integration_repo = integration_repo or IntegrationRepository()
        self._emitter_repo = emitter_repo or EmitterRepository()
        self._document_repo = document_repo or DocumentRepository()

    def enviar(self, token: str, documento_electronico: dict):
        auth = authorize_bearer_token(
            token=token,
            config=self._config,
            get_client=self._integration_repo.get_client_by_id,
            get_emitter=self._emitter_repo.get_by_id_for_client,
        )
        if isinstance(auth, TokenAuthFailure):
            return EnviarFailure(codigo=auth.codigo, mensaje=auth.mensaje)

        if not isinstance(documento_electronico, dict):
            return EnviarFailure(codigo=2, mensaje='documentoElectronico inválido')

        payload_hash = compute_document_payload_hash(documento_electronico)

        existing = self._document_repo.find_by_emitter_and_hash(
            auth.emitter_id, payload_hash
        )
        if existing:
            result = _idempotent_success_from_row(existing)
            result = EnviarSuccess(
                codigo=result.codigo,
                mensaje=result.mensaje,
                xml_base64=result.xml_base64,
                procesado=result.procesado,
                codigo_seguridad=result.codigo_seguridad,
                fecha_firma=result.fecha_firma,
                fecha_emision=result.fecha_emision,
                document_id=result.document_id,
                idempotent_replay=True,
            )
            return result

        try:
            mapped = map_hka_documento_electronico(
                documento_electronico,
                authorized_rnc=auth.rnc,
            )
        except HkaMapperError as error:
            self._audit(auth, 'ENVIAR', 'VALIDACION_FALLIDA')
            return EnviarFailure(codigo=error.audit_code, mensaje=str(error))

        if mapped.encf:
            by_encf = self._document_repo.find_by_emitter_and_encf(
                auth.emitter_id, mapped.encf
            )
            if by_encf and by_encf.get('payload_hash') != payload_hash:
                return EnviarFailure(
                    codigo=2,
                    mensaje=(
                        f'e-NCF {mapped.encf} ya registrado para este emisor '
                        'con otro contenido'
                    ),
                )

        estado_doc = 'recibido'
        mensaje_resp = _RECEPTION_MENSAJE
        fiscal_procesado = False
        xml_base64 = None
        codigo_seguridad = None
        fecha_firma = None
        if getattr(self._config, 'emit_enabled', False):
            intento = ExternalEmitOrchestrator().attempt(
                tenant_id=auth.tenant_id,
                mapped=mapped,
                emit_fiscal=True,
            )
            estado_doc = intento.estado_documento
            mensaje_resp = intento.mensaje_respuesta
            if intento.procesado:
                fiscal_procesado = True
                xml_base64 = intento.xml_base64
                codigo_seguridad = intento.codigo_seguridad
                fecha_firma = intento.fecha_firma

        if fiscal_procesado:
            success = EnviarSuccess(
                codigo=0,
                mensaje=mensaje_resp,
                xml_base64=xml_base64,
                procesado=True,
                codigo_seguridad=codigo_seguridad,
                fecha_firma=fecha_firma,
                fecha_emision=mapped.fecha_documento,
            )
        else:
            success = _reception_success(
                fecha_emision=mapped.fecha_documento,
                mensaje=mensaje_resp,
            )
        snapshot = _build_hka_snapshot(success)
        canonical_json = canonical_to_json_dict(mapped.canonical)

        try:
            doc_id = self._document_repo.insert_document(
                client_id=auth.client_id,
                emitter_id=auth.emitter_id,
                tenant_id=auth.tenant_id,
                external_document_id=mapped.external_document_id,
                tipo_ecf=mapped.tipo_ecf,
                encf=mapped.encf,
                rnc_emisor=mapped.rnc_emisor,
                rnc_comprador=mapped.rnc_comprador,
                fecha_documento=mapped.fecha_documento,
                moneda=mapped.moneda,
                total=mapped.total,
                payload_original=documento_electronico,
                payload_hash=payload_hash,
                canonical_document=canonical_json,
                estado=estado_doc,
                error_codigo=None,
                error_mensaje=None,
                response_snapshot=snapshot,
            )
        except pymysql.IntegrityError:
            duplicate = self._document_repo.find_by_emitter_and_hash(
                auth.emitter_id, payload_hash
            )
            if duplicate:
                self._audit(auth, 'ENVIAR', 'IDEMPOTENTE')
                result = _idempotent_success_from_row(duplicate)
                return EnviarSuccess(
                    codigo=result.codigo,
                    mensaje=result.mensaje,
                    xml_base64=result.xml_base64,
                    procesado=result.procesado,
                    codigo_seguridad=result.codigo_seguridad,
                    fecha_firma=result.fecha_firma,
                    fecha_emision=result.fecha_emision,
                    document_id=result.document_id,
                    idempotent_replay=True,
                )
            encf_dup = None
            if mapped.encf:
                encf_dup = self._document_repo.find_by_emitter_and_encf(
                    auth.emitter_id, mapped.encf
                )
            if encf_dup:
                return EnviarFailure(
                    codigo=2,
                    mensaje=(
                        f'e-NCF {mapped.encf} ya registrado para este emisor'
                    ),
                )
            logger.exception('Conflicto de unicidad sin fila recuperable')
            self._audit(auth, 'ENVIAR', 'ERROR_PERSISTENCIA')
            return EnviarFailure(codigo=99, mensaje='Error al registrar documento')
        except Exception:
            logger.exception('Error al persistir documento e-CF externo')
            self._audit(auth, 'ENVIAR', 'ERROR_PERSISTENCIA')
            return EnviarFailure(codigo=99, mensaje='Error al registrar documento')

        success = EnviarSuccess(
            codigo=success.codigo,
            mensaje=success.mensaje,
            xml_base64=success.xml_base64,
            procesado=success.procesado,
            codigo_seguridad=success.codigo_seguridad,
            fecha_firma=success.fecha_firma,
            fecha_emision=success.fecha_emision,
            document_id=doc_id,
        )
        snapshot = _build_hka_snapshot(success)
        self._document_repo.update_response_snapshot(doc_id, snapshot)
        self._audit(auth, 'ENVIAR', 'OK')
        return success

    def _audit(self, auth: AuthorizedIntegrationContext, evento: str, resultado: str):
        ip = request.remote_addr if request else None
        try:
            self._integration_repo.insert_audit(
                client_id=auth.client_id,
                emitter_id=auth.emitter_id,
                evento=evento,
                resultado=resultado,
                ip_origen=ip,
            )
        except Exception:
            logger.warning(
                'No se pudo registrar auditoría de envío externo',
                exc_info=True,
            )


def _parse_json_field(value):
    import json

    if value is None:
        return None
    if isinstance(value, dict):
        return value
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return None
