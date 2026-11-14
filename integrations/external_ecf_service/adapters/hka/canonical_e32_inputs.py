"""Mapeo documento canónico (HKA) → parámetros de `ECFBuilderE32`."""

from __future__ import annotations

import re
from datetime import date, datetime
from decimal import Decimal

from integrations.external_ecf_service.adapters.hka.dates import parse_hka_date
from integrations.external_ecf_service.adapters.hka.mapper import HkaMappedDocument
from integrations.external_ecf_service.domain.canonical import CanonicalElectronicDocument

_CONSUMIDOR_FINAL_RNC = "00000000000"
_CONSUMIDOR_FINAL_NOMBRE = "CONSUMIDOR FINAL"


def _buyer_payload(canonical: CanonicalElectronicDocument) -> dict:
    buyer = dict(canonical.buyer or {})
    rnc = re.sub(
        r"\D",
        "",
        str(buyer.get("rncComprador") or buyer.get("rnc") or ""),
    )
    if not rnc or len(rnc) not in {9, 11}:
        rnc = _CONSUMIDOR_FINAL_RNC
    name = (
        (buyer.get("razonSocialComprador") or buyer.get("razonSocial") or "").strip()
        or _CONSUMIDOR_FINAL_NOMBRE
    )
    return {
        "rnc": rnc,
        "razon_social": name,
        "nombre": name,
    }


def _issuer_payload(canonical: CanonicalElectronicDocument) -> dict:
    emisor = dict(canonical.issuer or {})
    return {
        "rnc": canonical.issuer_rnc or emisor.get("rnc"),
        "razon_social": (
            emisor.get("razonSocial")
            or emisor.get("razonSocialEmisor")
            or emisor.get("nombre")
        ),
        "nombre": emisor.get("nombre"),
        "direccion": emisor.get("direccionEmisor") or emisor.get("direccion"),
    }


def _parse_issue_date(canonical: CanonicalElectronicDocument) -> date:
    raw = (canonical.fiscal_dates or {}).get("fecha_emision")
    if raw:
        parsed = parse_hka_date(raw) if isinstance(raw, str) else raw
        if isinstance(parsed, datetime):
            return parsed.date()
        if isinstance(parsed, date):
            return parsed
    emisor = dict(canonical.issuer or {})
    emisor_fecha = emisor.get("fechaEmision")
    if emisor_fecha:
        return parse_hka_date(str(emisor_fecha))
    return date.today()


def _sequence_expiration(canonical: CanonicalElectronicDocument) -> date:
    raw = (canonical.fiscal_dates or {}).get("fecha_vencimiento_secuencia")
    if not raw:
        ident = dict(canonical.identification or {})
        raw = ident.get("fechaVencimientoSecuencia")
    if raw:
        try:
            return parse_hka_date(str(raw))
        except ValueError:
            pass
    issue = _parse_issue_date(canonical)
    return issue.replace(year=issue.year + 1)


def mapped_document_to_e32_build_kwargs(mapped: HkaMappedDocument) -> dict:
    """Construye kwargs para `ECFBuilderE32.build_e32`."""
    canonical = mapped.canonical
    ident = dict(canonical.identification or {})
    totales = dict(canonical.totals or {})

    items = []
    for line in canonical.lines or []:
        indicator = line.get("billing_indicator")
        try:
            indicator_int = int(indicator) if indicator is not None else 1
        except (TypeError, ValueError):
            indicator_int = 1
        gos = line.get("good_or_service")
        try:
            gos_int = int(gos) if gos is not None else 1
        except (TypeError, ValueError):
            gos_int = 1
        items.append(
            {
                "descripcion": line.get("name") or line.get("description"),
                "nombre": line.get("name"),
                "cantidad": line.get("quantity") or 1,
                "precio_unitario": line.get("unit_price") or 0,
                "subtotal": line.get("amount") or 0,
                "monto": line.get("amount") or 0,
                "indicador_facturacion": indicator_int,
                "indicador_bien_servicio": gos_int,
                "itbis": line.get("itbis_amount"),
            }
        )

    emisor = dict(canonical.issuer or {})
    invoice_number = (
        (emisor.get("numeroFacturaInterna") or emisor.get("numeroPedidoInterno") or "")
        .strip()
        or mapped.external_document_id
    )

    tipo_pago = str(ident.get("tipoPago") or "1")
    issue = _parse_issue_date(canonical)

    return {
        "invoice": {
            "numero_factura": invoice_number,
            "fecha_emision": issue,
            "total": str(mapped.total or totales.get("montoTotal") or "0"),
        },
        "electronic": {
            "tipo_ecf": "32",
            "e_ncf": canonical.encf or mapped.encf,
            "tipo_ingresos": str(ident.get("tipoIngresos") or "01"),
            "tipo_pago": tipo_pago,
            "fecha_limite_pago": ident.get("fechaLimitePago"),
            "indicador_monto_gravado": str(
                ident.get("indicadorMontoGravado") or "0"
            ),
        },
        "sequence_expires_at": _sequence_expiration(canonical),
        "issuer": _issuer_payload(canonical),
        "buyer": _buyer_payload(canonical),
        "items": items,
        "totals": {
            "monto_total": totales.get("montoTotal") or mapped.total,
            "monto_gravado_total": totales.get("montoGravadoTotal"),
            "monto_gravado_i1": totales.get("montoGravadoI1"),
            "monto_gravado_i2": totales.get("montoGravadoI2"),
            "monto_gravado_i3": totales.get("montoGravadoI3"),
            "total_itbis": totales.get("totalITBIS"),
            "total_itbis_1": totales.get("totalITBIS1"),
            "total_itbis_2": totales.get("totalITBIS2"),
            "total_itbis_3": totales.get("totalITBIS3"),
        },
    }