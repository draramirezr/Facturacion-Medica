"""Emisión fiscal síncrona E32 para API externa (build → firma → DGII)."""

from __future__ import annotations

import base64
import logging
import re
from dataclasses import dataclass

from flask import current_app

from ecf.builder import ECFBuildError
from ecf.builder_e32 import ECFBuilderE32
from ecf import (
    DGIIClient,
    DGIIClientError,
    ECFCertificateResolutionError,
    ECFSigningError,
    ECFStampError,
    ECFValidationError,
    ECFValidator,
    TenantCertificateProvider,
    build_stamp,
)
from integrations.external_ecf_service.adapters.hka.canonical_e32_inputs import (
    mapped_document_to_e32_build_kwargs,
)
from integrations.external_ecf_service.adapters.hka.mapper import HkaMappedDocument
from services.ecf_operations import (
    ecf_habilitado_para_tenant,
    emisor_ecf_para_xml,
    fecha_vencimiento_secuencia_ecf,
    obtener_configuracion_ecf_tenant,
)

logger = logging.getLogger(__name__)

_E32_ENCf = re.compile(r"E32\d{10}")


@dataclass(frozen=True)
class E32EmitSuccess:
    procesado: bool
    mensaje: str
    xml_base64: str
    codigo_seguridad: str
    fecha_firma: str
    estado_documento: str = "recibido"


class ExternalE32FiscalEmitter:
    """Intenta emitir un E32 completo cuando el stack e-CF del tenant está listo."""

    def try_emit(self, *, tenant_id: int, mapped: HkaMappedDocument) -> E32EmitSuccess | None:
        if not _E32_ENCf.fullmatch(str(mapped.encf or "")):
            logger.warning("E32 omitido: e-NCF inválido %s", mapped.encf)
            return None
        if not mapped.canonical.dgii_motor_ready:
            return None

        try:
            app = current_app._get_current_object()
        except RuntimeError:
            logger.info("E32 emisión omitida: sin contexto Flask")
            return None

        ecf_config = app.config.get("ECF_CONFIG")
        if not ecf_config or not getattr(ecf_config, "enabled", False):
            logger.info("E32 emisión omitida: ECF_ENABLED global inactivo")
            return None
        if not ecf_habilitado_para_tenant(tenant_id):
            logger.info("E32 emisión omitida: tenant_id=%s sin e-CF habilitado", tenant_id)
            return None

        tenant_cfg = obtener_configuracion_ecf_tenant(tenant_id)
        issuer_xml = emisor_ecf_para_xml(tenant_id)
        if not (issuer_xml.get("direccion") or "").strip():
            logger.warning(
                "E32 emisión omitida: dirección emisor vacía tenant_id=%s", tenant_id
            )
            return None

        build_kwargs = mapped_document_to_e32_build_kwargs(mapped)
        build_kwargs["issuer"].setdefault("rnc", mapped.rnc_emisor)
        build_kwargs["issuer"].setdefault("razon_social", issuer_xml.get("razon_social"))
        build_kwargs["issuer"]["direccion"] = (
            build_kwargs["issuer"].get("direccion") or issuer_xml.get("direccion")
        )

        seq_exp = fecha_vencimiento_secuencia_ecf(
            tenant_id, fallback=build_kwargs.get("sequence_expires_at")
        )
        build_kwargs["sequence_expires_at"] = seq_exp

        try:
            built = ECFBuilderE32().build_e32(**build_kwargs)
        except ECFBuildError as error:
            logger.warning(
                "E32 build falló tenant_id=%s encf=%s: %s",
                tenant_id,
                mapped.encf,
                "; ".join(error.errors),
            )
            return None

        try:
            ECFValidator().validate_unsigned_e32(built.xml)
        except ECFValidationError as error:
            logger.warning(
                "E32 validación previa a firma falló tenant_id=%s: %s",
                tenant_id,
                error,
            )
            return None

        try:
            cert = TenantCertificateProvider(ecf_config).resolve(
                tenant_id, tenant_config=tenant_cfg
            )
            signer = cert.signer()
            signed = signer.sign(built.xml)
        except (ECFCertificateResolutionError, ECFSigningError) as error:
            logger.warning(
                "E32 firma falló tenant_id=%s: %s", tenant_id, error
            )
            return None

        try:
            ECFValidator().validate_signed_e32(signed.signed_xml)
        except ECFValidationError as error:
            logger.warning(
                "E32 validación XSD falló tenant_id=%s: %s", tenant_id, error
            )
            return None

        stamp_url = str(getattr(ecf_config, "stamp_url", "") or "").strip()
        if not stamp_url:
            logger.warning("E32 emisión omitida: ECF stamp_url no configurada")
            return None

        try:
            stamp = build_stamp(signed.signed_xml, stamp_url)
        except ECFStampError as error:
            logger.warning("E32 timbre falló tenant_id=%s: %s", tenant_id, error)
            return None

        try:
            dgii = DGIIClient(ecf_config, signer=signer)
            dgii.submit_e31(signed.signed_xml, mapped.rnc_emisor, mapped.encf)
        except DGIIClientError as error:
            logger.warning(
                "E32 envío DGII falló tenant_id=%s encf=%s: %s",
                tenant_id,
                mapped.encf,
                error,
            )
            return None

        fecha_firma = signed.signed_at.strftime("%d-%m-%Y %H:%M:%S")
        xml_b64 = base64.b64encode(signed.signed_xml.encode("utf-8")).decode("ascii")
        return E32EmitSuccess(
            procesado=True,
            mensaje="Documento fiscal E32 emitido",
            xml_base64=xml_b64,
            codigo_seguridad=stamp.security_code,
            fecha_firma=fecha_firma,
            estado_documento="recibido",
        )