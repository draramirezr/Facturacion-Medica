"""Construcción y reserva transaccional de secuencias e-NCF."""

from dataclasses import dataclass
from datetime import date


ECF_SEQUENCE_DIGITS = 10
MAX_ECF_SEQUENCE = (10 ** ECF_SEQUENCE_DIGITS) - 1
ECF_TYPE_CATALOG = {
    "31": "Factura de Crédito Fiscal Electrónica",
    "32": "Factura de Consumo Electrónica",
    "33": "Nota de Débito Electrónica",
    "34": "Nota de Crédito Electrónica",
    "41": "Comprobante Electrónico de Compras",
    "43": "Comprobante Electrónico para Gastos Menores",
    "44": "Comprobante Electrónico para Regímenes Especiales",
    "45": "Comprobante Electrónico Gubernamental",
    "46": "Comprobante Electrónico para Exportaciones",
    "47": "Comprobante Electrónico para Pagos al Exterior",
}
REGISTERABLE_ECF_TYPES = frozenset(ECF_TYPE_CATALOG)
# Solo estos tipos cuentan hoy con builder y XSD integrados para emitir.
SUPPORTED_ECF_TYPES = {"31"}


class ECFSequenceError(ValueError):
    """Error base de una secuencia electrónica."""


class ECFSequenceNotConfigured(ECFSequenceError):
    """No existe un rango activo y vigente."""


class ECFSequenceExhausted(ECFSequenceError):
    """El rango autorizado no tiene números disponibles."""


@dataclass(frozen=True)
class ReservedENCF:
    sequence_id: int
    ecf_type: str
    number: int
    value: str
    expires_at: date


def build_encf(ecf_type, number):
    """Construir las 13 posiciones oficiales: E + tipo + 10 dígitos."""
    ecf_type = str(ecf_type).strip()
    if len(ecf_type) != 2 or not ecf_type.isdigit():
        raise ECFSequenceError("El tipo e-CF debe contener dos dígitos")
    try:
        number = int(number)
    except (TypeError, ValueError) as error:
        raise ECFSequenceError("El número de secuencia no es válido") from error
    if number < 1 or number > MAX_ECF_SEQUENCE:
        raise ECFSequenceError(
            f"La secuencia debe estar entre 1 y {MAX_ECF_SEQUENCE}"
        )
    return f"E{ecf_type}{number:0{ECF_SEQUENCE_DIGITS}d}"


def reserve_encf(cursor, tenant_id, ecf_type="31", issue_date=None):
    """Reservar un e-NCF usando el cursor de una transacción existente.

    La transacción que recibe el cursor es responsable de confirmar o revertir.
    """
    ecf_type = str(ecf_type).strip()
    if ecf_type not in SUPPORTED_ECF_TYPES:
        raise ECFSequenceError(
            f"El tipo e-CF {ecf_type} todavía no está habilitado"
        )
    issue_date = issue_date or date.today()

    cursor.execute(
        """
        SELECT *
        FROM ecf_secuencias
        WHERE tenant_id=%s AND tipo_ecf=%s AND activo=1
        ORDER BY fecha_vencimiento, id
        FOR UPDATE
        """,
        (tenant_id, ecf_type),
    )
    sequences = cursor.fetchall() or []

    valid_sequence = None
    exhausted = False
    for sequence in sequences:
        authorized_at = sequence.get("fecha_autorizacion")
        expires_at = sequence.get("fecha_vencimiento")
        if authorized_at and issue_date < authorized_at:
            continue
        if not expires_at or issue_date > expires_at:
            continue

        first = int(sequence["secuencia_inicial"])
        last_used = int(sequence.get("ultimo_numero") or 0)
        last_allowed = int(sequence["secuencia_final"])
        next_number = max(last_used, first - 1) + 1
        if next_number > last_allowed:
            exhausted = True
            continue
        valid_sequence = (sequence, next_number)
        break

    if not valid_sequence:
        if exhausted:
            raise ECFSequenceExhausted(
                f"El rango e-CF {ecf_type} está agotado"
            )
        raise ECFSequenceNotConfigured(
            f"No existe una secuencia E{ecf_type} activa y vigente"
        )

    sequence, next_number = valid_sequence
    encf = build_encf(ecf_type, next_number)

    cursor.execute(
        """
        SELECT id
        FROM facturas_ecf
        WHERE tenant_id=%s AND e_ncf=%s
        LIMIT 1
        """,
        (tenant_id, encf),
    )
    if cursor.fetchone():
        raise ECFSequenceError(f"El e-NCF {encf} ya está registrado")

    cursor.execute(
        """
        UPDATE ecf_secuencias
        SET ultimo_numero=%s
        WHERE id=%s AND tenant_id=%s
        """,
        (next_number, sequence["id"], tenant_id),
    )
    if cursor.rowcount != 1:
        raise ECFSequenceError("No se pudo reservar la secuencia e-NCF")

    return ReservedENCF(
        sequence_id=sequence["id"],
        ecf_type=ecf_type,
        number=next_number,
        value=encf,
        expires_at=sequence["fecha_vencimiento"],
    )
