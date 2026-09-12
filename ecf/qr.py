"""Timbre de consulta para la representación impresa del e-CF.

La composición sigue la sección "Consulta timbre (QR)" de la descripción
técnica de servicios DGII y la sección 18.2.3 del Formato e-CF v1.0.
"""

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from io import BytesIO
from urllib.parse import quote_plus, urlencode, urlsplit

from lxml import etree
import qrcode
from qrcode.constants import ERROR_CORRECT_L

from .signer import DSIG_NAMESPACE


class ECFStampError(ValueError):
    """El XML firmado no permite construir un timbre oficial."""


@dataclass(frozen=True)
class ECFStamp:
    issuer_rnc: str
    buyer_rnc: str
    encf: str
    issue_date: str
    total: str
    signature_date: str
    security_code: str
    url: str


@dataclass(frozen=True)
class ECFQRCode:
    png: bytes
    version: int


def _secure_root(signed_xml):
    xml_bytes = (
        signed_xml.encode("utf-8")
        if isinstance(signed_xml, str)
        else bytes(signed_xml or b"")
    )
    if not xml_bytes or b"<!DOCTYPE" in xml_bytes.upper():
        raise ECFStampError("El XML firmado no es válido")
    try:
        return etree.fromstring(
            xml_bytes,
            parser=etree.XMLParser(
                resolve_entities=False,
                no_network=True,
                load_dtd=False,
                huge_tree=False,
            ),
        )
    except etree.XMLSyntaxError as error:
        raise ECFStampError("El XML firmado está mal formado") from error


def _required_text(root, xpath, label):
    values = root.xpath(xpath, namespaces={"ds": DSIG_NAMESPACE})
    if isinstance(values, list):
        value = values[0] if values else ""
    else:
        value = values
    text = str(value or "").strip()
    if not text:
        raise ECFStampError(f"El XML firmado no contiene {label}")
    return text


def _normalized_total(value):
    try:
        total = Decimal(value).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except (InvalidOperation, TypeError, ValueError) as error:
        raise ECFStampError("MontoTotal no es válido") from error
    if total < 0:
        raise ECFStampError("MontoTotal no puede ser negativo")
    return format(total, ".2f")


def _validate_stamp_url(stamp_url):
    url = str(stamp_url or "").strip().rstrip("/")
    parsed = urlsplit(url)
    if (
        parsed.scheme.lower() != "https"
        or parsed.hostname != "ecf.dgii.gov.do"
        or not parsed.path.lower().endswith("/consultatimbre")
        or parsed.query
        or parsed.fragment
    ):
        raise ECFStampError("ECF_STAMP_URL no corresponde a ConsultaTimbre DGII")
    return url


def build_stamp(signed_xml, stamp_url):
    """Extraer datos firmados y construir la URL oficial de ConsultaTimbre."""
    root = _secure_root(signed_xml)
    if etree.QName(root).localname != "ECF":
        raise ECFStampError("El documento firmado no es un e-CF")

    signature_value = "".join(
        _required_text(
            root,
            "string(.//ds:SignatureValue)",
            "SignatureValue",
        ).split()
    )
    if len(signature_value) < 6:
        raise ECFStampError("SignatureValue no contiene el código de seguridad")

    values = {
        "rncemisor": _required_text(
            root, "string(./Encabezado/Emisor/RNCEmisor)", "RNCEmisor"
        ),
        "rnccomprador": _required_text(
            root, "string(./Encabezado/Comprador/RNCComprador)", "RNCComprador"
        ),
        "encf": _required_text(
            root, "string(./Encabezado/IdDoc/eNCF)", "eNCF"
        ),
        "fechaemision": _required_text(
            root, "string(./Encabezado/Emisor/FechaEmision)", "FechaEmision"
        ),
        "montototal": _normalized_total(
            _required_text(
                root, "string(./Encabezado/Totales/MontoTotal)", "MontoTotal"
            )
        ),
        "fechafirma": _required_text(
            root, "string(./FechaHoraFirma)", "FechaHoraFirma"
        ),
        "codigoseguridad": signature_value[:6],
    }
    base_url = _validate_stamp_url(stamp_url)
    query = urlencode(values, quote_via=quote_plus, safe=":")
    return ECFStamp(
        issuer_rnc=values["rncemisor"],
        buyer_rnc=values["rnccomprador"],
        encf=values["encf"],
        issue_date=values["fechaemision"],
        total=values["montototal"],
        signature_date=values["fechafirma"],
        security_code=values["codigoseguridad"],
        url=f"{base_url}?{query}",
    )


def generate_qr(stamp):
    """Generar el QR, comenzando en la versión 8 exigida por DGII.

    La biblioteca aumenta la versión únicamente cuando la URL oficial no cabe
    en versión 8 (principalmente por el prefijo más largo de precertificación).
    Nunca se eliminan ni truncan parámetros fiscales para forzar la capacidad.
    """
    qr = qrcode.QRCode(
        version=8,
        error_correction=ERROR_CORRECT_L,
        box_size=8,
        border=4,
    )
    qr.add_data(stamp.url, optimize=5)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white")
    output = BytesIO()
    image.save(output, format="PNG")
    return ECFQRCode(png=output.getvalue(), version=qr.version)
