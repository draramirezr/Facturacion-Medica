"""Orquestación de emisión fiscal para documentos del API externo (Fase 3)."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from integrations.external_ecf_service.adapters.hka.mapper import HkaMappedDocument

logger = logging.getLogger(__name__)

_MENSAJE_COLA_E32 = (
    'Documento validado; emisión fiscal E32 en preparación (Fase 3.2)'
)
_MENSAJE_COLA_E31 = (
    'Documento validado; emisión fiscal pendiente de motor E31 externo'
)


@dataclass(frozen=True)
class EmitAttemptResult:
    """Resultado del intento de emisión tras registrar el documento."""

    estado_documento: str
    mensaje_respuesta: str
    emit_attempted: bool
    tipo_ecf: str | None
    procesado: bool = False
    xml_base64: str | None = None
    codigo_seguridad: str | None = None
    fecha_firma: str | None = None


class ExternalEmitOrchestrator:
    """Punto único para evolucionar hacia build → firma → DGII."""

    def attempt(
        self,
        *,
        tenant_id: int,
        mapped: HkaMappedDocument,
        emit_fiscal: bool = False,
    ) -> EmitAttemptResult:
        tipo = (mapped.tipo_ecf or mapped.canonical.document_type or '').upper()
        if not tipo:
            return EmitAttemptResult(
                estado_documento='recibido',
                mensaje_respuesta='Documento recibido; emisión fiscal pendiente',
                emit_attempted=False,
                tipo_ecf=None,
            )

        if tipo == 'E32':
            if emit_fiscal and mapped.canonical.dgii_motor_ready:
                from integrations.external_ecf_service.services.e32_fiscal_emitter import (
                    ExternalE32FiscalEmitter,
                )

                emitted = ExternalE32FiscalEmitter().try_emit(
                    tenant_id=tenant_id,
                    mapped=mapped,
                )
                if emitted and emitted.procesado:
                    return EmitAttemptResult(
                        estado_documento=emitted.estado_documento,
                        mensaje_respuesta=emitted.mensaje,
                        emit_attempted=True,
                        tipo_ecf=tipo,
                        procesado=True,
                        xml_base64=emitted.xml_base64,
                        codigo_seguridad=emitted.codigo_seguridad,
                        fecha_firma=emitted.fecha_firma,
                    )
            logger.info(
                'Cola emisión E32 tenant_id=%s encf=%s total=%s',
                tenant_id,
                mapped.encf,
                mapped.total,
            )
            return EmitAttemptResult(
                estado_documento='pendiente_emision',
                mensaje_respuesta=_MENSAJE_COLA_E32,
                emit_attempted=True,
                tipo_ecf=tipo,
            )

        if tipo == 'E31' and mapped.canonical.dgii_motor_ready:
            logger.info(
                'Cola emisión E31 externa tenant_id=%s encf=%s',
                tenant_id,
                mapped.encf,
            )
            return EmitAttemptResult(
                estado_documento='pendiente_emision',
                mensaje_respuesta=_MENSAJE_COLA_E31,
                emit_attempted=True,
                tipo_ecf=tipo,
            )

        notas = mapped.canonical.dgii_motor_notes or []
        detalle = notas[0] if notas else f'Tipo {tipo} sin motor de emisión'
        return EmitAttemptResult(
            estado_documento='recibido',
            mensaje_respuesta=f'Documento recibido; {detalle}',
            emit_attempted=False,
            tipo_ecf=tipo,
        )