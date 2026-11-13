"""Normalización de montos HKA (strings) sin pérdida de precisión."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation


def parse_amount(value) -> Decimal | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    normalized = text.replace(',', '')
    try:
        return Decimal(normalized)
    except InvalidOperation as error:
        raise ValueError(f'Monto inválido: {value!r}') from error
