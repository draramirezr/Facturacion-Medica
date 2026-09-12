from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from ecf.config import ECFConfig
from ecf.readiness import assess_readiness


def create_certificate(path, password, validity_days=90):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "ARSFlow readiness test"),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, "123456789"),
    ])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=validity_days))
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(pkcs12.serialize_key_and_certificates(
        b"readiness",
        key,
        certificate,
        None,
        serialization.BestAvailableEncryption(password.encode("utf-8")),
    ))


class ECFReadinessTests(unittest.TestCase):
    def test_certification_configuration_passes_local_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            certificate = Path(directory) / "certificate.p12"
            create_certificate(certificate, "clave-prueba")
            base = "https://ecf.dgii.gov.do/certecf"
            config = ECFConfig.from_env({
                "ECF_ENABLED": "true",
                "ECF_ENVIRONMENT": "CERTIFICACION",
                "ECF_CERTIFICATE_PATH": str(certificate),
                "ECF_CERTIFICATE_PASSWORD": "clave-prueba",
                "ECF_AUTHENTICATION_URL": f"{base}/autenticacion",
                "ECF_RECEPTION_URL": f"{base}/recepcion",
                "ECF_RESULT_URL": f"{base}/consultaresultado",
                "ECF_TRACK_URL": f"{base}/consultatrackids",
                "ECF_STAMP_URL": f"{base}/consultatimbre",
            })
            report = assess_readiness(config)

        self.assertTrue(report.ready)
        self.assertTrue(all(check.passed for check in report.checks))
        self.assertGreaterEqual(len(report.manual_requirements), 5)

    def test_disabled_test_environment_is_reported_as_not_ready(self):
        report = assess_readiness(ECFConfig.from_env({
            "ECF_ENABLED": "false",
            "ECF_ENVIRONMENT": "PRUEBAS",
        }))
        self.assertFalse(report.ready)
        self.assertEqual(
            {check.code for check in report.checks if not check.passed},
            {"enabled", "environment"},
        )

    def test_production_checks_at_least_one_valid_tenant_certificate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tenant = root / "tenant-7"
            tenant.mkdir()
            create_certificate(
                tenant / "certificate.p12", "clave-tenant"
            )
            (tenant / "password.txt").write_text(
                "clave-tenant", encoding="utf-8"
            )
            base = "https://ecf.dgii.gov.do/ecf"
            config = ECFConfig.from_env({
                "ECF_ENABLED": "true",
                "ECF_ENVIRONMENT": "PRODUCCION",
                "ECF_ALLOW_PRODUCTION": "true",
                "FLASK_ENV": "production",
                "ECF_TENANT_SECRETS_ROOT": str(root),
                "ECF_AUTHENTICATION_URL": f"{base}/autenticacion",
                "ECF_RECEPTION_URL": f"{base}/recepcion",
                "ECF_RESULT_URL": f"{base}/consultaresultado",
                "ECF_TRACK_URL": f"{base}/consultatrackids",
                "ECF_STAMP_URL": f"{base}/consultatimbre",
            })
            report = assess_readiness(config)

        self.assertTrue(report.ready)
        store_check = next(
            check
            for check in report.checks
            if check.code == "tenant_certificate_store"
        )
        self.assertIn("1 cuenta", store_check.detail)


if __name__ == "__main__":
    unittest.main()
