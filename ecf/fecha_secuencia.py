"""Normalizar FechaVencimientoSecuencia al formato DGII dd-mm-yyyy."""

from datetime import date, datetime


def normalize_fecha_vencimiento_secuencia(value):
    """Devolver dd-mm-yyyy o cadena vacía si no hay fecha usable."""
    if value is None:
        return ""
    if isinstance(value, datetime):
        value = value.date()
    if isinstance(value, date):
        return value.strftime("%d-%m-%Y")
    text = str(value).strip()
    if not text:
        return ""
    for fmt in ("%d-%m-%Y", "%d/%m/%Y", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt).strftime("%d-%m-%Y")
        except ValueError:
            continue
    return ""


def parse_fecha_vencimiento_secuencia(value):
    """Devolver date o None."""
    normalized = normalize_fecha_vencimiento_secuencia(value)
    if not normalized:
        return None
    return datetime.strptime(normalized, "%d-%m-%Y").date()
