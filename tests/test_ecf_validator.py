from datetime import date, datetime
from pathlib import Path
import tempfile
import unittest

from lxml import etree

from ecf.builder import ECFBuilder
from ecf.validator import (
    ECFSchemaError,
    ECFValidationError,
    ECFValidator,
)


def build_valid_unsigned_xml():
    return ECFBuilder().build_e31(
        invoice={
            "numero_factura": "FAC-E-INTERNA",
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
        generated_at=datetime(2026, 9, 11, 14, 30, 5),
    ).xml


class ECFValidatorTests(unittest.TestCase):
    def test_validates_unsigned_e31_against_official_structure(self):
        result = ECFValidator().validate_unsigned_e31(
            build_valid_unsigned_xml()
        )
        self.assertTrue(result.unsigned)
        self.assertIn(
            "DGII_XSD_TYPE_NAME_LEADING_SPACE",
            result.compatibility_adjustments,
        )
        self.assertIn(
            "PRE_SIGNATURE_XMLDSIG_OPTIONAL",
            result.compatibility_adjustments,
        )

    def test_reports_xsd_error_with_line_and_column(self):
        root = etree.fromstring(build_valid_unsigned_xml().encode("utf-8"))
        root.find("Encabezado/IdDoc/eNCF").text = "E31"
        invalid_xml = etree.tostring(root, encoding="UTF-8")

        with self.assertRaisesRegex(
            ECFValidationError, "value has a length of '3'"
        ):
            ECFValidator().validate_unsigned_e31(invalid_xml)

    def test_signed_validation_requires_signature_slot(self):
        unsigned_xml = build_valid_unsigned_xml()
        with self.assertRaises(ECFValidationError):
            ECFValidator().validate_signed_e31(unsigned_xml)

        root = etree.fromstring(unsigned_xml.encode("utf-8"))
        etree.SubElement(root, "Signature")
        result = ECFValidator().validate_signed_e31(
            etree.tostring(root, encoding="UTF-8")
        )
        self.assertFalse(result.unsigned)
        self.assertNotIn(
            "PRE_SIGNATURE_XMLDSIG_OPTIONAL",
            result.compatibility_adjustments,
        )

    def test_refuses_unverified_schema_file(self):
        with tempfile.TemporaryDirectory() as directory:
            schema_path = Path(directory) / "schema.xsd"
            schema_path.write_text("<schema/>", encoding="utf-8")
            with self.assertRaisesRegex(ECFSchemaError, "no coincide"):
                ECFValidator(schema_path).validate_unsigned_e31(
                    build_valid_unsigned_xml()
                )

    def test_rejects_doctype(self):
        xml = '<!DOCTYPE ECF [<!ENTITY x "x">]><ECF>&x;</ECF>'
        with self.assertRaisesRegex(ECFValidationError, "DOCTYPE"):
            ECFValidator().validate_unsigned_e31(xml)


if __name__ == "__main__":
    unittest.main()
