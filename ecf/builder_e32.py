"""Construcción del XML e-CF 32 (consumo con ITBIS) sin firma XMLDSig."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta
from decimal import Decimal
import hashlib
import re

from lxml import etree

from ecf.builder import (
    DIAS_CREDITO_DEFAULT,
    ECFBuildError,
    ECFBuildResult,
    _as_date,
    _date,
    _decimal,
    _element,
    _required_text,
    _rnc,
)


_ITBIS_RATES = {
    1: Decimal("0.18"),
    2: Decimal("0.16"),
    3: Decimal("0"),
}


class ECFBuilderE32:
    """Construye factura de consumo electrónica (tipo 32) desde datos normalizados."""

    def build_e32(
        self,
        *,
        invoice,
        electronic,
        sequence_expires_at,
        issuer,
        buyer,
        items,
        totals=None,
        generated_at=None,
    ):
        generated_at = generated_at or datetime.now()
        errors: list[str] = []
        totals = totals or {}

        encf = str(electronic.get("e_ncf") or "").strip()
        if not re.fullmatch(r"E32\d{10}", encf):
            errors.append("El e-NCF debe tener el formato E32 más 10 dígitos")

        if str(electronic.get("tipo_ecf") or "") != "32":
            errors.append("El constructor E32 requiere tipo_ecf 32")

        income_type = str(electronic.get("tipo_ingresos") or "01")
        if income_type not in {"01", "02", "03", "04", "05", "06"}:
            errors.append("Tipo de ingresos inválido para e-CF")

        payment_type = str(electronic.get("tipo_pago") or "1")
        if payment_type not in {"1", "2", "3"}:
            errors.append("Tipo de pago inválido para e-CF")

        payment_limit_date = None
        issue_date_obj = None
        issue_date = None
        expiration_date = None
        issuer_rnc = issuer_name = issuer_address = None
        buyer_rnc = buyer_name = None
        invoice_number = ""
        invoice_total = None

        try:
            issue_date_obj = _as_date(
                invoice.get("fecha_emision"), "Fecha de emisión"
            )
            issue_date = issue_date_obj.strftime("%d-%m-%Y")
            expiration_date = _date(
                sequence_expires_at, "Fecha de vencimiento de la secuencia"
            )
            if payment_type == "2":
                limit_raw = electronic.get("fecha_limite_pago")
                if limit_raw not in (None, ""):
                    payment_limit_date = _as_date(
                        limit_raw, "Fecha límite de pago"
                    )
                else:
                    try:
                        credit_days = int(
                            electronic.get("dias_credito") or DIAS_CREDITO_DEFAULT
                        )
                    except (TypeError, ValueError) as error:
                        raise ECFBuildError(
                            ["Días de crédito no es un número válido"]
                        ) from error
                    payment_limit_date = issue_date_obj + timedelta(days=credit_days)
                if payment_limit_date < issue_date_obj:
                    raise ECFBuildError(
                        [
                            "Fecha límite de pago debe ser mayor o igual "
                            "a la fecha de emisión"
                        ]
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
            buyer_rnc = _rnc(
                buyer.get("rnc") or buyer.get("rnc_comprador"),
                "RNC del comprador",
            )
            buyer_name = _required_text(
                buyer.get("razon_social")
                or buyer.get("nombre")
                or buyer.get("razon_social_comprador"),
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

        gravado = {1: Decimal("0"), 2: Decimal("0"), 3: Decimal("0")}
        exento = Decimal("0")
        itbis = {1: Decimal("0"), 2: Decimal("0"), 3: Decimal("0")}
        normalized_items = []

        for index, item in enumerate(items or [], start=1):
            try:
                indicator = int(item.get("indicador_facturacion", 1))
                if indicator not in {1, 2, 3, 4}:
                    raise ECFBuildError(
                        [f"Indicador de facturación inválido en la línea {index}"]
                    )
                good_or_service = int(item.get("indicador_bien_servicio", 1))
                if good_or_service not in {1, 2}:
                    raise ECFBuildError(
                        [f"Indicador bien/servicio inválido en la línea {index}"]
                    )
                name = _required_text(
                    item.get("descripcion") or item.get("nombre"),
                    f"Nombre de la línea {index}",
                    80,
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
                    item.get("subtotal") or item.get("monto"),
                    f"Monto de la línea {index}",
                )
                line_itbis = item.get("itbis")
                if line_itbis is not None and str(line_itbis).strip() != "":
                    line_itbis_amt = Decimal(str(_decimal(line_itbis, "ITBIS línea")))
                elif indicator in _ITBIS_RATES and indicator != 4:
                    rate = _ITBIS_RATES[indicator]
                    line_itbis_amt = (
                        Decimal(amount) * rate
                    ).quantize(Decimal("0.01"))
                else:
                    line_itbis_amt = Decimal("0")

                if indicator == 4:
                    exento += Decimal(amount)
                else:
                    gravado[indicator] += Decimal(amount)
                    itbis[indicator] += line_itbis_amt

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

        header_gravado_total = sum(gravado.values())
        header_itbis_total = sum(itbis.values())

        if totals:
            declared_total = totals.get("monto_total")
            if declared_total is not None:
                declared = Decimal(str(declared_total))
                if (declared - Decimal(invoice_total)).copy_abs() > Decimal("0.05"):
                    raise ECFBuildError(
                        ["montoTotal del encabezado no coincide con el total calculado"]
                    )

        details_total = sum(Decimal(item["amount"]) for item in normalized_items)
        details_total = details_total.quantize(Decimal("0.01"))
        if details_total != Decimal(invoice_total) and header_itbis_total == 0:
            if (details_total - Decimal(invoice_total)).copy_abs() > Decimal("0.05"):
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
        _element(document_id, "TipoeCF", "32")
        _element(document_id, "eNCF", encf)
        # XSD E32: no incluye FechaVencimientoSecuencia en IdDoc (a diferencia del E31).
        _ = expiration_date
        incluido = str(electronic.get("indicador_monto_gravado") or "0").strip()
        if incluido not in {"0", "1"}:
            incluido = "0"
        _element(document_id, "IndicadorMontoGravado", incluido)
        _element(document_id, "TipoIngresos", income_type)
        _element(document_id, "TipoPago", payment_type)
        if payment_type == "2" and payment_limit_date is not None:
            _element(
                document_id,
                "FechaLimitePago",
                payment_limit_date.strftime("%d-%m-%Y"),
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

        totals_node = etree.SubElement(header, "Totales")
        header_gravado = header_gravado_total
        header_itbis = header_itbis_total
        if totals.get("monto_gravado_total") is not None:
            header_gravado = Decimal(str(totals.get("monto_gravado_total")))
        if totals.get("total_itbis") is not None:
            header_itbis = Decimal(str(totals.get("total_itbis")))

        if header_gravado > 0:
            _element(
                totals_node,
                "MontoGravadoTotal",
                _decimal(header_gravado, "Monto gravado total"),
            )
        for bucket in (1, 2, 3):
            key_g = f"monto_gravado_i{bucket}"
            gravado_val = gravado[bucket]
            if totals.get(key_g) is not None:
                gravado_val = Decimal(str(totals.get(key_g)))
            if gravado_val > 0:
                _element(
                    totals_node,
                    f"MontoGravadoI{bucket}",
                    _decimal(gravado_val, f"Monto gravado I{bucket}"),
                )
                _element(totals_node, f"ITBIS{bucket}", int(_ITBIS_RATES[bucket] * 100))
        if header_itbis > 0:
            _element(
                totals_node,
                "TotalITBIS",
                _decimal(header_itbis, "Total ITBIS"),
            )
            for bucket in (1, 2, 3):
                key_t = f"total_itbis_{bucket}"
                itbis_val = itbis[bucket]
                if totals.get(key_t) is not None:
                    itbis_val = Decimal(str(totals.get(key_t)))
                elif bucket == 1 and totals.get("total_itbis_1") is None and header_itbis > 0:
                    itbis_val = header_itbis
                if itbis_val > 0:
                    _element(
                        totals_node,
                        f"TotalITBIS{bucket}",
                        _decimal(itbis_val, f"Total ITBIS {bucket}"),
                    )
        if exento > 0:
            _element(totals_node, "MontoExento", _decimal(exento, "Monto exento"))
        _element(totals_node, "MontoTotal", invoice_total)

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