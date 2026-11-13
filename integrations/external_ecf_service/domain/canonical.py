"""Modelo canónico neutral para documentos e-CF externos."""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any


def _decimal_to_str(value: Decimal | None) -> str | None:
    if value is None:
        return None
    return format(value, 'f')


@dataclass
class CanonicalElectronicDocument:
    """Representación interna independiente del proveedor HKA."""

    schema_version: str
    document_type: str | None
    encf: str | None
    issuer_rnc: str
    issuer: dict[str, Any]
    buyer: dict[str, Any]
    currency_code: str | None
    exchange_rate: Decimal | None
    lines: list[dict[str, Any]]
    subtotals: list[dict[str, Any]]
    discounts_surcharges: list[dict[str, Any]]
    totals: dict[str, Any]
    payment_forms: list[dict[str, Any]]
    reference: dict[str, Any] | None
    fiscal_dates: dict[str, Any]
    branch: str | None
    identification: dict[str, Any]
    other_currency: dict[str, Any] | None
    transport: dict[str, Any] | None
    additional_info: dict[str, Any] | None
    pagination: list[dict[str, Any]]
    observations: list[dict[str, Any]]
    installments: list[dict[str, Any]]
    serial_device: str | None
    dgii_motor_ready: bool
    dgii_motor_notes: list[str] = field(default_factory=list)
    source_provider: str = 'hka'


def canonical_to_json_dict(document: CanonicalElectronicDocument) -> dict[str, Any]:
    """Serializar a JSON-compatible (decimales como string)."""
    totals = dict(document.totals or {})
    for key, value in list(totals.items()):
        if isinstance(value, Decimal):
            totals[key] = _decimal_to_str(value)

    lines = []
    for line in document.lines:
        row = dict(line)
        for key in ('quantity', 'unit_price', 'amount', 'discount', 'itbis_amount'):
            if isinstance(row.get(key), Decimal):
                row[key] = _decimal_to_str(row[key])
        lines.append(row)

    return {
        'schema_version': document.schema_version,
        'document_type': document.document_type,
        'encf': document.encf,
        'issuer_rnc': document.issuer_rnc,
        'issuer': document.issuer,
        'buyer': document.buyer,
        'currency_code': document.currency_code,
        'exchange_rate': _decimal_to_str(document.exchange_rate),
        'lines': lines,
        'subtotals': document.subtotals,
        'discounts_surcharges': document.discounts_surcharges,
        'totals': totals,
        'payment_forms': document.payment_forms,
        'reference': document.reference,
        'fiscal_dates': document.fiscal_dates,
        'branch': document.branch,
        'identification': document.identification,
        'other_currency': document.other_currency,
        'transport': document.transport,
        'additional_info': document.additional_info,
        'pagination': document.pagination,
        'observations': document.observations,
        'installments': document.installments,
        'serial_device': document.serial_device,
        'dgii_motor_ready': document.dgii_motor_ready,
        'dgii_motor_notes': document.dgii_motor_notes,
        'source_provider': document.source_provider,
    }
