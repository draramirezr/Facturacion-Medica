"""Representación impresa del e-CF 31 basada en el XML firmado."""

from dataclasses import dataclass
from io import BytesIO
from xml.sax.saxutils import escape

from lxml import etree
from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, inch
from reportlab.lib.utils import ImageReader
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from .qr import ECFStampError, _secure_root, build_stamp, generate_qr


class ECFPrintableError(ValueError):
    """No fue posible construir la representación impresa."""


@dataclass(frozen=True)
class ECFPrintableResult:
    pdf: BytesIO
    stamp_url: str
    security_code: str
    qr_version: int


def _text(root, xpath, default=""):
    value = root.xpath(f"string({xpath})")
    return str(value or default).strip()


def _money(value):
    try:
        return f"RD$ {float(value or 0):,.2f}"
    except (TypeError, ValueError):
        return "RD$ 0.00"


def _paragraph(value, style):
    return Paragraph(escape(str(value or "")), style)


def generate_e31_pdf(
    signed_xml,
    stamp_url,
    *,
    dgii_status="ACEPTADO",
    track_id="",
):
    """Crear la RI oficial del E31 usando exclusivamente el XML firmado."""
    if str(dgii_status or "").upper() != "ACEPTADO":
        raise ECFPrintableError(
            "La representación impresa fiscal solo se habilita al aceptar DGII"
        )

    try:
        root = _secure_root(signed_xml)
        stamp = build_stamp(signed_xml, stamp_url)
        qr = generate_qr(stamp)
    except ECFStampError as error:
        raise ECFPrintableError(str(error)) from error

    if _text(root, "./Encabezado/IdDoc/TipoeCF") != "31":
        raise ECFPrintableError("La representación actual solo admite e-CF 31")

    issuer_name = _text(root, "./Encabezado/Emisor/RazonSocialEmisor")
    issuer_address = _text(root, "./Encabezado/Emisor/DireccionEmisor")
    internal_number = _text(root, "./Encabezado/Emisor/NumeroFacturaInterna")
    buyer_name = _text(root, "./Encabezado/Comprador/RazonSocialComprador")
    expires_at = _text(
        root, "./Encabezado/IdDoc/FechaVencimientoSecuencia"
    )
    exempt_total = _text(root, "./Encabezado/Totales/MontoExento", "0")
    taxable_total = _text(root, "./Encabezado/Totales/MontoGravadoTotal", "0")
    itbis_total = _text(root, "./Encabezado/Totales/TotalITBIS", "0")

    items = []
    for item in root.xpath("./DetallesItems/Item"):
        indicator = _text(item, "./IndicadorFacturacion")
        items.append(
            {
                "line": _text(item, "./NumeroLinea"),
                "exempt": "E" if indicator == "4" else "",
                "description": _text(item, "./NombreItem"),
                "quantity": _text(item, "./CantidadItem"),
                "price": _text(item, "./PrecioUnitarioItem"),
                "itbis": _text(item, "./MontoITBIS", "0"),
                "amount": _text(item, "./MontoItem"),
            }
        )
    if not items:
        raise ECFPrintableError("El e-CF no contiene líneas para imprimir")

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=0.45 * inch,
        rightMargin=0.45 * inch,
        topMargin=1.95 * inch,
        bottomMargin=2.05 * inch,
        title=f"Representación impresa {stamp.encf}",
        author=issuer_name,
    )
    styles = getSampleStyleSheet()
    normal = ParagraphStyle(
        "ECFNormal",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#222222"),
    )
    small = ParagraphStyle(
        "ECFSmall",
        parent=normal,
        fontSize=7,
        leading=8,
    )
    right = ParagraphStyle(
        "ECFRight",
        parent=normal,
        alignment=TA_RIGHT,
    )
    section = ParagraphStyle(
        "ECFSection",
        parent=styles["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=11,
        textColor=colors.HexColor("#173B57"),
        spaceAfter=5,
    )

    story = [
        Paragraph("DATOS DEL CLIENTE", section),
        Table(
            [
                [
                    _paragraph(f"Razón social: {buyer_name}", normal),
                    _paragraph(f"RNC/Cédula: {stamp.buyer_rnc}", right),
                ]
            ],
            colWidths=[4.6 * inch, 3 * inch],
        ),
        Spacer(1, 0.13 * inch),
        Paragraph("DETALLE DE BIENES O SERVICIOS", section),
    ]

    table_data = [
        [
            _paragraph("No.", small),
            _paragraph("", small),
            _paragraph("Descripción", small),
            _paragraph("Cantidad", right),
            _paragraph("Precio", right),
            _paragraph("ITBIS", right),
            _paragraph("Valor", right),
        ]
    ]
    for item in items:
        table_data.append(
            [
                _paragraph(item["line"], small),
                _paragraph(item["exempt"], small),
                _paragraph(item["description"], small),
                _paragraph(item["quantity"], right),
                _paragraph(_money(item["price"]), right),
                _paragraph(_money(item["itbis"]), right),
                _paragraph(_money(item["amount"]), right),
            ]
        )
    details = Table(
        table_data,
        colWidths=[
            0.32 * inch,
            0.22 * inch,
            2.48 * inch,
            0.65 * inch,
            1.17 * inch,
            1.12 * inch,
            1.18 * inch,
        ],
        repeatRows=1,
    )
    details.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8F0F5")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#173B57")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#B8C4CC")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ALIGN", (0, 1), (1, -1), "CENTER"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.extend([details, Spacer(1, 0.15 * inch)])

    totals = Table(
        [
            [_paragraph("Subtotal gravado:", right), _paragraph(_money(taxable_total), right)],
            [_paragraph("Subtotal exento:", right), _paragraph(_money(exempt_total), right)],
            [_paragraph("Total ITBIS:", right), _paragraph(_money(itbis_total), right)],
            [
                Paragraph("<b>TOTAL:</b>", right),
                Paragraph(f"<b>{escape(_money(stamp.total))}</b>", right),
            ],
        ],
        colWidths=[1.65 * inch, 1.35 * inch],
        hAlign="RIGHT",
    )
    totals.setStyle(
        TableStyle(
            [
                ("LINEABOVE", (0, -1), (-1, -1), 0.8, colors.HexColor("#173B57")),
                ("TOPPADDING", (0, -1), (-1, -1), 6),
            ]
        )
    )
    story.append(totals)

    qr_reader = ImageReader(BytesIO(qr.png))

    def draw_page(canvas, document):
        page_width, page_height = letter
        canvas.saveState()
        canvas.setFillColor(colors.HexColor("#173B57"))
        canvas.setFont("Helvetica-Bold", 11)
        canvas.drawString(0.45 * inch, page_height - 0.48 * inch, issuer_name[:68])
        canvas.setFillColor(colors.HexColor("#222222"))
        canvas.setFont("Helvetica", 8)
        canvas.drawString(
            0.45 * inch,
            page_height - 0.66 * inch,
            f"RNC: {stamp.issuer_rnc}",
        )
        canvas.drawString(
            0.45 * inch,
            page_height - 0.82 * inch,
            issuer_address[:90],
        )
        canvas.drawString(
            0.45 * inch,
            page_height - 0.98 * inch,
            f"Fecha de emisión: {stamp.issue_date}",
        )
        if internal_number:
            canvas.drawString(
                0.45 * inch,
                page_height - 1.14 * inch,
                f"Factura interna: {internal_number[:30]}",
            )

        canvas.setFont("Helvetica-Bold", 10)
        canvas.drawRightString(
            page_width - 0.45 * inch,
            page_height - 0.48 * inch,
            "FACTURA DE CRÉDITO FISCAL ELECTRÓNICA",
        )
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawRightString(
            page_width - 0.45 * inch,
            page_height - 0.68 * inch,
            f"e-NCF: {stamp.encf}",
        )
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(
            page_width - 0.45 * inch,
            page_height - 0.86 * inch,
            f"Fecha vencimiento: {expires_at}",
        )
        canvas.setFillColor(colors.HexColor("#177245"))
        canvas.setFont("Helvetica-Bold", 8)
        canvas.drawRightString(
            page_width - 0.45 * inch,
            page_height - 1.04 * inch,
            "ACEPTADO POR DGII",
        )
        canvas.setStrokeColor(colors.HexColor("#B8C4CC"))
        canvas.line(
            0.45 * inch,
            page_height - 1.28 * inch,
            page_width - 0.45 * inch,
            page_height - 1.28 * inch,
        )

        qr_x = 2 * cm
        qr_y = 2 * cm
        qr_size = 2.8 * cm
        canvas.drawImage(
            qr_reader,
            qr_x,
            qr_y,
            qr_size,
            qr_size,
            preserveAspectRatio=True,
            mask="auto",
        )
        canvas.setFillColor(colors.HexColor("#222222"))
        canvas.setFont("Helvetica-Bold", 7)
        canvas.drawCentredString(
            qr_x + qr_size / 2,
            qr_y - 0.13 * inch,
            f"Código de seguridad: {stamp.security_code}",
        )
        canvas.setFont("Helvetica", 6.5)
        canvas.drawCentredString(
            qr_x + qr_size / 2,
            qr_y - 0.25 * inch,
            f"Fecha firma digital: {stamp.signature_date}",
        )
        canvas.setFont("Helvetica", 7)
        if track_id:
            canvas.drawRightString(
                page_width - 0.45 * inch,
                0.74 * inch,
                f"TrackID DGII: {str(track_id)[:55]}",
            )
        canvas.drawRightString(
            page_width - 0.45 * inch,
            0.57 * inch,
            f"Página {document.page}",
        )
        canvas.restoreState()

    doc.build(story, onFirstPage=draw_page, onLaterPages=draw_page)
    buffer.seek(0)
    return ECFPrintableResult(
        pdf=buffer,
        stamp_url=stamp.url,
        security_code=stamp.security_code,
        qr_version=qr.version,
    )
