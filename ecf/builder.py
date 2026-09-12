"""Construcción del XML e-CF 31 según el XSD oficial de la DGII.

Esta fase construye el documento sin la firma XMLDSig. La firma se agregará
en la fase de firmado digital.
"""

from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
import hashlib
import re

from lxml import etree


class ECFBuildError(ValueError):
    """Los datos de la factura no permiten construir un E31."""

    def __init__(self, errors):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


@dataclass(frozen=True)
class ECFBuildResult:
    xml: str
    sha256: str
    generated_at: datetime


def _required_text(value, field, max_length):
    text = str(value or "").strip()
    if not text:
        raise ECFBuildError([f"{field} es obligatorio"])
    if len(text) > max_length:
        raise ECFBuildError(
            [f"{field} supera el máximo de {max_length} caracteres"]
        )
    return text


def _rnc(value, field):
    number = re.sub(r"\D", "", str(value or ""))
    if len(number) not in {9, 11}:
        raise ECFBuildError([f"{field} debe contener 9 u 11 dígitos"])
    return number


def _date(value, field):
    if isinstance(value, datetime):
        value = value.date()
    if isinstance(value, str):
        try:
            value = datetime.strptime(value, "%Y-%m-%d").date()
        except ValueError as error:
            raise ECFBuildError([f"{field} no es una fecha válida"]) from error
    if not isinstance(value, date):
        raise ECFBuildError([f"{field} es obligatorio"])
    return value.strftime("%d-%m-%Y")


def _decimal(value, field, places=2, allow_zero=True):
    try:
        number = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as error:
        raise ECFBuildError([f"{field} no es un monto válido"]) from error
    if number < 0 or (not allow_zero and number == 0):
        comparator = "mayor que cero" if not allow_zero else "igual o mayor que cero"
        raise ECFBuildError([f"{field} debe ser {comparator}"])
    quantum = Decimal("1").scaleb(-places)
    return format(number.quantize(quantum, rounding=ROUND_HALF_UP), f".{places}f")


def _element(parent, name, value):
    node = etree.SubElement(parent, name)
    node.text = str(value)
    return node


class ECFBuilder:
    """Construye la estructura E31 sin acceder a base de datos."""

    def build_e31(
        self,
        *,
        invoice,
        electronic,
        sequence_expires_at,
        issuer,
        buyer,
        items,
        generated_at=None,
    ):
        generated_at = generated_at or datetime.now()
        errors = []

        encf = str(electronic.get("e_ncf") or "").strip()
        if not re.fullmatch(r"E31\d{10}", encf):
            errors.append("El e-NCF debe tener el formato E31 más 10 dígitos")

        if str(electronic.get("tipo_ecf") or "") != "31":
            errors.append("El constructor actual solo admite e-CF tipo 31")

        income_type = str(electronic.get("tipo_ingresos") or "01")
        if income_type not in {"01", "02", "03", "04", "05", "06"}:
            errors.append("Tipo de ingresos inválido para e-CF")
        payment_type = str(electronic.get("tipo_pago") or "2")
        if payment_type not in {"1", "2", "3"}:
            errors.append("Tipo de pago inválido para e-CF")

        try:
            issue_date = _date(invoice.get("fecha_emision"), "Fecha de emisión")
            expiration_date = _date(
                sequence_expires_at, "Fecha de vencimiento de la secuencia"
            )
            issuer_rnc = _rnc(issuer.get("rnc"), "RNC del emisor")
            issuer_name = _required_text(
                issuer.get("razon_social") or issuer.get("nombre"),
                "Razón social del emisor",
                150,
            )
            issuer_address = _required_text(
                issuer.get("direccion"), "Dirección del emisor", 100
            )
            buyer_rnc = _rnc(buyer.get("rnc"), "RNC del comprador")
            buyer_name = _required_text(
                buyer.get("razon_social") or buyer.get("nombre"),
                "Razón social del comprador",
                150,
            )
            invoice_number = str(invoice.get("numero_factura") or "").strip()
            if len(invoice_number) > 20:
                invoice_number = ""
            invoice_total = _decimal(
                invoice.get("total"), "Monto total de factura"
            )
        except ECFBuildError as error:
            errors.extend(error.errors)

        if not items:
            errors.append("La factura debe contener al menos un detalle")
        if len(items) > 1000:
            errors.append("El E31 admite un máximo de 1000 detalles")

        normalized_items = []
        for index, item in enumerate(items or [], start=1):
            try:
                indicator = int(item.get("indicador_facturacion", 4))
                if indicator not in {0, 1, 2, 3, 4}:
                    raise ECFBuildError(
                        [f"Indicador de facturación inválido en la línea {index}"]
                    )
                if indicator != 4:
                    raise ECFBuildError(
                        [
                            f"La línea {index} requiere desglose fiscal de ITBIS; "
                            "esta fase solo genera servicios exentos"
                        ]
                    )
                good_or_service = int(item.get("indicador_bien_servicio", 2))
                if good_or_service not in {1, 2}:
                    raise ECFBuildError(
                        [f"Indicador bien/servicio inválido en la línea {index}"]
                    )
                name = _required_text(
                    item.get("descripcion"), f"Nombre de la línea {index}", 80
                )
                quantity = _decimal(
                    item.get("cantidad", 1),
                    f"Cantidad de la línea {index}",
                    allow_zero=False,
                )
                unit_price = _decimal(
                    item.get("precio_unitario", 0),
                    f"Precio unitario de la línea {index}",
                    places=4,
                )
                amount = _decimal(
                    item.get("subtotal", 0), f"Monto de la línea {index}"
                )
                normalized_items.append(
                    {
                        "indicator": indicator,
                        "good_or_service": good_or_service,
                        "name": name,
                        "quantity": quantity,
                        "unit_price": unit_price,
                        "amount": amount,
                    }
                )
            except ECFBuildError as error:
                errors.extend(error.errors)

        if errors:
            raise ECFBuildError(errors)

        details_total = sum(
            Decimal(item["amount"]) for item in normalized_items
        ).quantize(Decimal("0.01"))
        if details_total != Decimal(invoice_total):
            raise ECFBuildError(
                [
                    "El total de los detalles no coincide con el total de la "
                    "factura"
                ]
            )

        root = etree.Element("ECF")
        header = etree.SubElement(root, "Encabezado")
        _element(header, "Version", "1.0")

        document_id = etree.SubElement(header, "IdDoc")
        _element(document_id, "TipoeCF", "31")
        _element(document_id, "eNCF", encf)
        _element(document_id, "FechaVencimientoSecuencia", expiration_date)
        _element(
            document_id,
            "TipoIngresos",
            income_type,
        )
        _element(
            document_id,
            "TipoPago",
            payment_type,
        )

        issuer_node = etree.SubElement(header, "Emisor")
        _element(issuer_node, "RNCEmisor", issuer_rnc)
        _element(issuer_node, "RazonSocialEmisor", issuer_name)
        _element(issuer_node, "DireccionEmisor", issuer_address)
        if invoice_number:
            _element(issuer_node, "NumeroFacturaInterna", invoice_number)
        _element(issuer_node, "FechaEmision", issue_date)

        buyer_node = etree.SubElement(header, "Comprador")
        _element(buyer_node, "RNCComprador", buyer_rnc)
        _element(buyer_node, "RazonSocialComprador", buyer_name)

        totals = etree.SubElement(header, "Totales")
        exempt_total = sum(
            Decimal(item["amount"])
            for item in normalized_items
            if item["indicator"] == 4
        )
        if exempt_total:
            _element(totals, "MontoExento", _decimal(exempt_total, "Monto exento"))
        _element(totals, "MontoTotal", invoice_total)

        details = etree.SubElement(root, "DetallesItems")
        for index, item in enumerate(normalized_items, start=1):
            item_node = etree.SubElement(details, "Item")
            _element(item_node, "NumeroLinea", index)
            _element(item_node, "IndicadorFacturacion", item["indicator"])
            _element(item_node, "NombreItem", item["name"])
            _element(item_node, "IndicadorBienoServicio", item["good_or_service"])
            _element(item_node, "CantidadItem", item["quantity"])
            _element(item_node, "PrecioUnitarioItem", item["unit_price"])
            _element(item_node, "MontoItem", item["amount"])

        _element(root, "FechaHoraFirma", generated_at.strftime("%d-%m-%Y %H:%M:%S"))

        xml_bytes = etree.tostring(
            root,
            encoding="UTF-8",
            xml_declaration=True,
            pretty_print=False,
        )
        return ECFBuildResult(
            xml=xml_bytes.decode("utf-8"),
            sha256=hashlib.sha256(xml_bytes).hexdigest(),
            generated_at=generated_at,
        )
