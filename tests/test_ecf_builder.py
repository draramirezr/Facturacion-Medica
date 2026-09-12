import hashlib
from datetime import date, datetime
from pathlib import Path
import unittest

from lxml import etree

from ecf.builder import ECFBuildError, ECFBuilder


class ECFBuilderTests(unittest.TestCase):
    def setUp(self):
        self.data = {
            "invoice": {
                "numero_factura": "FAC-E-INTERNA",
                "fecha_emision": date(2026, 9, 11),
                "total": "1500.00",
            },
            "electronic": {
                "tipo_ecf": "31",
                "e_ncf": "E310000000001",
                "tipo_ingresos": "01",
                "tipo_pago": "2",
            },
            "sequence_expires_at": date(2027, 12, 31),
            "issuer": {
                "rnc": "123456789",
                "razon_social": "Centro Médico Ejemplo",
                "direccion": "Santo Domingo",
            },
            "buyer": {
                "rnc": "101234567",
                "nombre": "ARS Ejemplo",
            },
            "items": [
                {
                    "descripcion": "Consulta médica",
                    "cantidad": 1,
                    "precio_unitario": "1500",
                    "subtotal": "1500",
                    "indicador_facturacion": 4,
                    "indicador_bien_servicio": 2,
                }
            ],
            "generated_at": datetime(2026, 9, 11, 14, 30, 5),
        }

    def test_builds_required_e31_structure(self):
        result = ECFBuilder().build_e31(**self.data)
        root = etree.fromstring(result.xml.encode("utf-8"))

        self.assertEqual(root.tag, "ECF")
        self.assertEqual(root.findtext("Encabezado/Version"), "1.0")
        self.assertEqual(
            root.findtext("Encabezado/IdDoc/eNCF"), "E310000000001"
        )
        self.assertEqual(
            root.findtext("Encabezado/IdDoc/FechaVencimientoSecuencia"),
            "31-12-2027",
        )
        self.assertEqual(
            root.findtext("Encabezado/Emisor/RNCEmisor"), "123456789"
        )
        self.assertEqual(
            root.findtext("Encabezado/Comprador/RNCComprador"), "101234567"
        )
        self.assertEqual(
            root.findtext("Encabezado/Totales/MontoExento"), "1500.00"
        )
        self.assertEqual(
            root.findtext("DetallesItems/Item/IndicadorFacturacion"), "4"
        )
        self.assertEqual(
            root.findtext("FechaHoraFirma"), "11-09-2026 14:30:05"
        )
        self.assertEqual(
            result.sha256,
            hashlib.sha256(result.xml.encode("utf-8")).hexdigest(),
        )

    def test_rejects_missing_required_issuer_address(self):
        self.data["issuer"]["direccion"] = ""
        with self.assertRaisesRegex(
            ECFBuildError, "Dirección del emisor es obligatorio"
        ):
            ECFBuilder().build_e31(**self.data)

    def test_rejects_total_different_from_details(self):
        self.data["invoice"]["total"] = "1499.00"
        with self.assertRaisesRegex(
            ECFBuildError, "total de los detalles no coincide"
        ):
            ECFBuilder().build_e31(**self.data)

    def test_official_schema_integrity_is_preserved(self):
        schema = (
            Path(__file__).resolve().parents[1]
            / "ecf"
            / "schemas"
            / "e-CF-31-v1.0.xsd"
        ).read_bytes()
        self.assertEqual(
            hashlib.sha256(schema).hexdigest(),
            "6f2909a93d84919518d2ae3c77fead4b35c3e8c95996b8af67b0040c2e2be298",
        )
        self.assertIn(b'name=" IndicadorServicioTodoIncluidoType"', schema)


if __name__ == "__main__":
    unittest.main()
