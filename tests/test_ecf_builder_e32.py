import hashlib
from datetime import date, datetime
import unittest

from lxml import etree

from ecf.builder import ECFBuildError
from ecf.builder_e32 import ECFBuilderE32
from ecf.validator import ECFValidator


class ECFBuilderE32Tests(unittest.TestCase):
    def setUp(self):
        self.data = {
            "invoice": {
                "numero_factura": "POS-99",
                "fecha_emision": date(2026, 11, 14),
                "total": "160.00",
            },
            "electronic": {
                "tipo_ecf": "32",
                "e_ncf": "E320000000099",
                "tipo_ingresos": "01",
                "tipo_pago": "1",
            },
            "sequence_expires_at": date(2027, 12, 31),
            "issuer": {
                "rnc": "01400204101",
                "razon_social": "Rico Hot Dog",
                "direccion": "Santo Domingo",
            },
            "buyer": {
                "rnc": "00000000000",
                "razon_social": "CONSUMIDOR FINAL",
            },
            "items": [
                {
                    "descripcion": "Combo",
                    "cantidad": 1,
                    "precio_unitario": "135.59",
                    "subtotal": "135.59",
                    "indicador_facturacion": 1,
                    "indicador_bien_servicio": 1,
                    "itbis": "24.41",
                }
            ],
            "totals": {"monto_total": "160.00"},
            "generated_at": datetime(2026, 11, 14, 17, 0, 0),
        }

    def test_builds_e32_with_itbis(self):
        result = ECFBuilderE32().build_e32(**self.data)
        root = etree.fromstring(result.xml.encode("utf-8"))
        self.assertEqual(root.findtext("Encabezado/IdDoc/TipoeCF"), "32")
        self.assertEqual(
            root.findtext("Encabezado/Totales/TotalITBIS"), "24.41"
        )
        self.assertEqual(root.findtext("Encabezado/Totales/MontoTotal"), "160.00")
        self.assertEqual(
            hashlib.sha256(result.xml.encode("utf-8")).hexdigest(),
            result.sha256,
        )

    def test_rejects_invalid_encf(self):
        self.data["electronic"]["e_ncf"] = "E310000000001"
        with self.assertRaises(ECFBuildError):
            ECFBuilderE32().build_e32(**self.data)

    def test_unsigned_xml_pasa_xsd_oficial_e32(self):
        result = ECFBuilderE32().build_e32(**self.data)
        validated = ECFValidator().validate_unsigned_e32(result.xml)
        self.assertEqual(validated.ecf_type, "E32")


if __name__ == "__main__":
    unittest.main()