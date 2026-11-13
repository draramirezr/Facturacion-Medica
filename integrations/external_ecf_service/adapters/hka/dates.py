"""Fechas del contrato HKA."""

from __future__ import annotations

from datetime import date, datetime

_HKA_DATE_FORMATS = ('%d-%m-%Y', '%Y-%m-%d', '%d/%m/%Y', '%Y-%m-%dT%H:%M:%S')


def parse_hka_date(value) -> date | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    for fmt in _HKA_DATE_FORMATS:
        try:
            if 'T' in text and fmt == '%Y-%m-%dT%H:%M:%S':
                return datetime.strptime(text[:19], fmt).date()
            if 'T' not in text and fmt == '%Y-%m-%dT%H:%M:%S':
                continue
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue
    raise ValueError(f'Fecha inválida: {value!r}')
