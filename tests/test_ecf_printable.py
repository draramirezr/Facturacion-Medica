from datetime import date, datetime
import re
import unittest
from urllib.parse import parse_qs, urlsplit

from lxml import etree

from ecf.builder import ECFBuilder
from ecf.printable import ECFPrintableError, generate_e31_pdf
from ecf.qr import ECFStampError, build_stamp, generate_qr
from ecf.signer import DSIG_NAMESPACE


STAMP_URL = "https://ecf.dgii.gov.do/testecf/consultatimbre"


def signed_xml():
    xml = ECFBuilder().build_e31(
        invoice={
            "numero_factura": "FAC-E-001",
            "fecha_emision": date(2026, 9, 11),
            "total": "1500.00",
        },
        electronic={
            "tipo_ecf": "31",
            "e_ncf": "E310000000001",
            "tipo_ingresos": "01",
            "tipo_pago": "2",
        },
        sequence_expires_at=date(2027, 12, 31),
        issuer={
            "rnc": "123456789",
            "razon_social": "Centro Médico Ejemplo",
            "direccion": "Santo Domingo",
        },
        buyer={"rnc": "101234567", "nombre": "ARS Ejemplo"},
        items=[
            {
                "descripcion": "Consulta médica",
                "cantidad": 1,
                "precio_unitario": "1500",
                "subtotal": "1500",
                "indicador_facturacion": 4,
                "indicador_bien_servicio": 2,
            }
        ],
        generated_at=datetime(2026, 9, 11, 16, 45, 10),
    ).xml
    root = etree.fromstring(xml.encode("utf-8"))
    signature = etree.SubElement(
        root, f"{{{DSIG_NAMESPACE}}}Signature", nsmap={"ds": DSIG_NAMESPACE}
    )
    signature_value = etree.SubElement(
        signature, f"{{{DSIG_NAMESPACE}}}SignatureValue"
    )
    signature_value.text = "\n  AbC12+/firma-base64-de-prueba  \n"
    return etree.tostring(
        root, encoding="UTF-8", xml_declaration=True
    ).decode("utf-8")


class ECFStampTests(unittest.TestCase):
    def test_builds_official_stamp_parameters_from_signed_xml(self):
        stamp = build_stamp(signed_xml(), STAMP_URL)
        parsed = urlsplit(stamp.url)
        params = parse_qs(parsed.query)

        self.assertEqual(stamp.security_code, "AbC12+")
        self.assertEqual(parsed.path, "/testecf/consultatimbre")
        self.assertEqual(
            list(params),
            [
                "rncemisor",
                "rnccomprador",
                "encf",
                "fechaemision",
                "montototal",
                "fechafirma",
                "codigoseguridad",
            ],
        )
        self.assertEqual(params["rncemisor"], ["123456789"])
        self.assertEqual(params["rnccomprador"], ["101234567"])
        self.assertEqual(params["encf"], ["E310000000001"])
        self.assertEqual(params["fechaemision"], ["11-09-2026"])
        self.assertEqual(params["montototal"], ["1500.00"])
        self.assertEqual(params["fechafirma"], ["11-09-2026 16:45:10"])
        self.assertEqual(params["codigoseguridad"], ["AbC12+"])

    def test_generates_png_without_truncating_long_precertification_url(self):
        qr = generate_qr(build_stamp(signed_xml(), STAMP_URL))
        self.assertTrue(qr.png.startswith(b"\x89PNG\r\n\x1a\n"))
        self.assertGreaterEqual(qr.version, 8)

    def test_rejects_non_dgii_stamp_host(self):
        with self.assertRaisesRegex(ECFStampError, "ConsultaTimbre DGII"):
            build_stamp(
                signed_xml(),
                "https://example.com/testecf/consultatimbre",
            )


class ECFPrintableTests(unittest.TestCase):
    def test_generates_single_page_e31_representation(self):
        result = generate_e31_pdf(
            signed_xml(),
            STAMP_URL,
            dgii_status="ACEPTADO",
            track_id="TRACK-123",
        )
        pdf = result.pdf.getvalue()

        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertEqual(len(re.findall(rb"/Type\s*/Page\b", pdf)), 1)
        self.assertEqual(result.security_code, "AbC12+")
        self.assertGreaterEqual(result.qr_version, 8)

    def test_does_not_print_unaccepted_ecf_as_fiscal_document(self):
        with self.assertRaisesRegex(ECFPrintableError, "aceptar DGII"):
            generate_e31_pdf(
                signed_xml(),
                STAMP_URL,
                dgii_status="ENVIADO",
            )


if __name__ == "__main__":
    unittest.main()
