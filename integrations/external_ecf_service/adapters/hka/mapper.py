"""Transformación DocumentoElectronico (HKA) → modelo canónico ClinicRD."""

from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from integrations.external_ecf_service.adapters.hka.dates import parse_hka_date
from integrations.external_ecf_service.adapters.hka.numerics import parse_amount
from integrations.external_ecf_service.domain.canonical import CanonicalElectronicDocument

KNOWN_ECF_TYPES = frozenset(
    {
        'E31',
        'E32',
        'E33',
        'E34',
        'E41',
        'E42',
        'E43',
        'E44',
        'E45',
        'E46',
        'E47',
    }
)

# Motor médico actual (ecf/builder) — solo referencia; Fase 2 no lo invoca.
_CLINICRD_MOTOR_TYPES = frozenset({'E31'})


class HkaMapperError(ValueError):
    """Error de validación o mapeo auditable."""

    def __init__(self, message: str, *, audit_code: int = 2):
        super().__init__(message)
        self.audit_code = audit_code


@dataclass(frozen=True)
class HkaMappedDocument:
    canonical: CanonicalElectronicDocument
    external_document_id: str | None
    fecha_documento: str | None
    moneda: str | None
    total: Decimal
    tipo_ecf: str | None
    encf: str | None
    rnc_emisor: str
    rnc_comprador: str | None


def _normalize_rnc(value) -> str:
    return re.sub(r'\D', '', str(value or ''))


def _resolve_document_type(identificacion: dict) -> str | None:
    tipo = (identificacion.get('tipoDocumento') or '').strip().upper()
    if tipo:
        return tipo
    ncf = (identificacion.get('ncf') or '').strip().upper()
    if len(ncf) >= 3 and ncf[0] == 'E':
        return ncf[:3]
    if len(ncf) >= 3:
        candidate = f'E{ncf[:2]}'
        if candidate in KNOWN_ECF_TYPES:
            return candidate
    return None


def _map_line(raw: dict) -> dict[str, Any]:
    qty = parse_amount(raw.get('cantidad'))
    unit = parse_amount(raw.get('precioUnitario'))
    line_total = parse_amount(raw.get('montoItem'))
    return {
        'line_number': raw.get('numeroLinea'),
        'name': raw.get('nombre'),
        'description': raw.get('descripcion'),
        'billing_indicator': raw.get('indicadorFacturacion'),
        'good_or_service': raw.get('indicadorBienoServicio'),
        'quantity': qty,
        'unit_measure': raw.get('unidadMedida'),
        'unit_price': unit,
        'amount': line_total,
        'discount': raw.get('tablaDescuento'),
        'itbis_rate': raw.get('tasaITBIS'),
        'itbis_amount': parse_amount(raw.get('itbis')),
        'additional_taxes': raw.get('tablaImpuestoAdicional'),
        'other_currency': raw.get('otraMonedaDetalle'),
        'hka_raw': raw,
    }


def _assess_motor_readiness(
    document_type: str | None, lines: list[dict]
) -> tuple[bool, list[str]]:
    notes: list[str] = []
    if not document_type:
        notes.append('Tipo de comprobante no identificado.')
        return False, notes
    if document_type not in KNOWN_ECF_TYPES:
        notes.append(f'Tipo {document_type} no reconocido en catálogo e-CF.')
        return False, notes
    if document_type not in _CLINICRD_MOTOR_TYPES:
        notes.append(
            f'Tipo {document_type}: el motor e-CF actual de ClinicRD '
            'aún no implementa emisión para este comprobante.'
        )
        return False, notes
    for line in lines:
        indicator = str(line.get('billing_indicator') or '').strip()
        if indicator and indicator not in {'0', '1', '2', '3', '4'}:
            notes.append(
                f'Indicador de facturación {indicator} requiere revisión.'
            )
        if indicator in {'1', '2', '3'}:
            notes.append(
                'Línea con ITBIS gravado: motor médico actual solo cubre '
                'escenarios exentos sin conversión automática.'
            )
            return False, notes
    return True, notes


def _validate_totals_coherence(totales: dict, total: Decimal | None) -> None:
    if total is None:
        return
    declared = parse_amount(totales.get('montoTotal'))
    if declared is None:
        return
    if (declared - total).copy_abs() > Decimal('0.05'):
        raise HkaMapperError(
            'Inconsistencia: montoTotal del encabezado no coincide con '
            'el total calculado del documento.'
        )


def map_hka_documento_electronico(
    documento: dict,
    *,
    authorized_rnc: str,
) -> HkaMappedDocument:
    if not isinstance(documento, dict):
        raise HkaMapperError('documentoElectronico inválido')

    encabezado = documento.get('encabezado')
    if not isinstance(encabezado, dict):
        raise HkaMapperError('encabezado es obligatorio')

    emisor = encabezado.get('emisor') or {}
    if not isinstance(emisor, dict):
        raise HkaMapperError('emisor es obligatorio')

    rnc_emisor = _normalize_rnc(emisor.get('rnc'))
    auth_rnc = _normalize_rnc(authorized_rnc)
    if not rnc_emisor:
        raise HkaMapperError('RNC del emisor es obligatorio')
    if rnc_emisor != auth_rnc:
        raise HkaMapperError('RNC del emisor no coincide con el token')

    identificacion = encabezado.get('identificacionDocumento') or {}
    comprador = encabezado.get('comprador') or {}
    totales = encabezado.get('totales') or {}
    otra_moneda = encabezado.get('otraMoneda')

    detalles_raw = documento.get('detallesItems') or []
    if not isinstance(detalles_raw, list) or not detalles_raw:
        raise HkaMapperError('detallesItems debe incluir al menos una línea')

    lines = []
    for item in detalles_raw:
        if not isinstance(item, dict):
            raise HkaMapperError('Cada línea de detallesItems debe ser un objeto')
        lines.append(_map_line(item))

    tipo_ecf = _resolve_document_type(identificacion)
    encf = (identificacion.get('ncf') or '').strip() or None

    total = parse_amount(totales.get('montoTotal')) or Decimal('0')
    _validate_totals_coherence(totales, total)

    dgii_ready, motor_notes = _assess_motor_readiness(tipo_ecf, lines)

    fecha_emision = None
    try:
        parsed = parse_hka_date(emisor.get('fechaEmision'))
        fecha_emision = parsed.isoformat() if parsed else None
    except ValueError as error:
        raise HkaMapperError(str(error)) from error

    fiscal_dates = {
        'fecha_emision': fecha_emision,
        'fecha_vencimiento_secuencia': identificacion.get('fechaVencimientoSecuencia'),
        'fecha_limite_pago': identificacion.get('fechaLimitePago'),
        'fecha_desde': identificacion.get('fechaDesde'),
        'fecha_hasta': identificacion.get('fechaHasta'),
    }

    payment_forms = []
    for fp in identificacion.get('tablaFormasPago') or []:
        if isinstance(fp, dict):
            payment_forms.append(
                {
                    'forma': fp.get('forma'),
                    'monto': fp.get('monto'),
                }
            )

    buyer = dict(comprador) if isinstance(comprador, dict) else {}
    rnc_comprador = _normalize_rnc(
        buyer.get('rncComprador') or buyer.get('rnc') or ''
    ) or None

    moneda = None
    exchange_rate = None
    if isinstance(otra_moneda, dict):
        moneda = (otra_moneda.get('tipoMoneda') or '').strip() or None
        exchange_rate = parse_amount(otra_moneda.get('tipoCambio'))
    if not moneda:
        moneda = 'DOP'

    canonical = CanonicalElectronicDocument(
        schema_version='1',
        document_type=tipo_ecf,
        encf=encf,
        issuer_rnc=rnc_emisor,
        issuer=dict(emisor),
        buyer=buyer,
        currency_code=moneda,
        exchange_rate=exchange_rate,
        lines=lines,
        subtotals=list(documento.get('subtotales') or []),
        discounts_surcharges=list(documento.get('descuentosORecargos') or []),
        totals=dict(totales),
        payment_forms=payment_forms,
        reference=documento.get('informacionReferencia'),
        fiscal_dates=fiscal_dates,
        branch=(emisor.get('sucursal') or '').strip() or None,
        identification=dict(identificacion),
        other_currency=otra_moneda if isinstance(otra_moneda, dict) else None,
        transport=encabezado.get('transporte'),
        additional_info=encabezado.get('informacionesAdicionales'),
        pagination=list(documento.get('paginacion') or []),
        observations=list(documento.get('observaciones') or []),
        installments=list(documento.get('cuotas') or []),
        serial_device=documento.get('serialDevice'),
        dgii_motor_ready=dgii_ready,
        dgii_motor_notes=motor_notes,
    )

    external_id = (
        (emisor.get('numeroFacturaInterna') or '').strip()
        or (emisor.get('numeroPedidoInterno') or '').strip()
        or None
    )

    return HkaMappedDocument(
        canonical=canonical,
        external_document_id=external_id,
        fecha_documento=fecha_emision,
        moneda=moneda,
        total=total,
        tipo_ecf=tipo_ecf,
        encf=encf,
        rnc_emisor=rnc_emisor,
        rnc_comprador=rnc_comprador,
    )
