import unittest
from datetime import date, datetime
from types import SimpleNamespace
from unittest.mock import patch

from ecf.dgii import DGIIToken
from ecf.fecha_secuencia import (
    normalize_fecha_vencimiento_secuencia,
    parse_fecha_vencimiento_secuencia,
)
from ecf.qr import ECFStampError
from ecf.tests_runner import run_dgii_pruebas
from routes.billing import _factura_tiene_qr_ecf
from services.ecf_operations import emisor_ecf_para_xml


class FechaVencimientoSecuenciaTests(unittest.TestCase):
    def test_normalizes_day_month_year(self):
        self.assertEqual(
            normalize_fecha_vencimiento_secuencia("31/12/2027"),
            "31-12-2027",
        )
        self.assertEqual(
            parse_fecha_vencimiento_secuencia("31-12-2027"),
            date(2027, 12, 31),
        )


class EmisorEcfXmlTests(unittest.TestCase):
    def test_prefers_config_over_empresa(self):
        with patch(
            "services.ecf_operations.obtener_configuracion_ecf_tenant",
            return_value={
                "rnc_emisor": "101672919",
                "razon_social_emisor": "Clinica Config",
                "direccion_emisor": "Calle Config",
            },
        ):
            emisor = emisor_ecf_para_xml(
                3,
                {
                    "rnc": "000000000",
                    "razon_social": "Empresa",
                    "direccion": "Otra",
                },
            )
        self.assertEqual(emisor["rnc"], "101672919")
        self.assertEqual(emisor["razon_social"], "Clinica Config")
        self.assertEqual(emisor["direccion"], "Calle Config")


class DgiiTestsRunnerTests(unittest.TestCase):
    def test_reports_five_successful_steps(self):
        metadata = SimpleNamespace(
            fingerprint="abc123def456",
            valid_until=datetime(2027, 1, 1),
        )
        resolved = SimpleNamespace(signer=lambda: object())
        client = SimpleNamespace(
            fetch_authentication_seed=lambda: b"<Semilla/>",
            sign_authentication_seed=lambda seed, rnc: SimpleNamespace(
                signed_xml="<Firmada/>"
            ),
            validate_signed_seed=lambda signed: DGIIToken(value="jwt"),
            ping_reception=lambda token: 200,
        )
        config = SimpleNamespace(environment="PRUEBAS")
        with patch(
            "ecf.tests_runner.TenantCertificateProvider"
        ) as provider_cls:
            provider_cls.return_value.inspect.return_value = (resolved, metadata)
            result = run_dgii_pruebas(
                config=config,
                tenant_id=9,
                tenant_config={},
                issuer_rnc="101672919",
                client=client,
            )
        self.assertTrue(result["ok"])
        self.assertEqual(
            [step["name"] for step in result["steps"]],
            [
                "Certificado legible",
                "Semilla DGII",
                "Firma de semilla",
                "Token obtenido",
                "Conexión recepción",
            ],
        )
        self.assertTrue(all(step["ok"] for step in result["steps"]))

    def test_stops_when_certificate_unreadable(self):
        config = SimpleNamespace(environment="PRUEBAS")
        with patch(
            "ecf.tests_runner.TenantCertificateProvider"
        ) as provider_cls:
            from ecf.certificates import ECFCertificateResolutionError

            provider_cls.return_value.inspect.side_effect = (
                ECFCertificateResolutionError("sin certificado")
            )
            result = run_dgii_pruebas(
                config=config,
                tenant_id=9,
                tenant_config={},
                issuer_rnc="101672919",
            )
        self.assertFalse(result["ok"])
        self.assertFalse(result["steps"][0]["ok"])
        self.assertEqual(len(result["steps"]), 5)


class QrFacturaContextTests(unittest.TestCase):
    def test_qr_available_when_signed_xml_exists(self):
        from flask import Flask

        factura = {"xml_firmado": "<ECF/>", "estado": "FIRMADO"}
        app = Flask(__name__)
        app.config["ECF_CONFIG"] = SimpleNamespace(
            stamp_url="https://ecf.dgii.gov.do/ecf/consultatimbre"
        )
        with app.app_context():
            with patch("routes.billing.build_stamp", return_value=object()):
                self.assertTrue(_factura_tiene_qr_ecf(factura))

    def test_qr_hidden_when_rejected_or_unsigned(self):
        from flask import Flask

        app = Flask(__name__)
        app.config["ECF_CONFIG"] = SimpleNamespace(stamp_url="https://x")
        with app.app_context():
            self.assertFalse(
                _factura_tiene_qr_ecf({"xml_firmado": None, "estado": "FIRMADO"})
            )
            self.assertFalse(
                _factura_tiene_qr_ecf(
                    {"xml_firmado": "<ECF/>", "estado": "RECHAZADO"}
                )
            )
            with patch(
                "routes.billing.build_stamp",
                side_effect=ECFStampError("sin código"),
            ):
                self.assertFalse(
                    _factura_tiene_qr_ecf(
                        {"xml_firmado": "<ECF/>", "estado": "FIRMADO"}
                    )
                )


if __name__ == "__main__":
    unittest.main()
