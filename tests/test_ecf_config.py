from pathlib import Path
import tempfile
import unittest

from ecf.config import ECFConfig, ECFConfigurationError


def environment_urls(environment):
    segment = {
        "PRUEBAS": "testecf",
        "CERTIFICACION": "certecf",
        "PRODUCCION": "ecf",
    }[environment]
    base = f"https://ecf.dgii.gov.do/{segment}"
    return {
        "ECF_AUTHENTICATION_URL": f"{base}/autenticacion",
        "ECF_RECEPTION_URL": f"{base}/recepcion",
        "ECF_RESULT_URL": f"{base}/consultaresultado",
        "ECF_TRACK_URL": f"{base}/consultatrackids",
        "ECF_STAMP_URL": f"{base}/consultatimbre",
    }


class ECFConfigTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        self.certificate = root / "certificate.p12"
        self.secret = root / "certificate-password.txt"
        self.certificate.write_bytes(b"fixture")
        self.secret.write_text("clave-prueba", encoding="utf-8")

    def tearDown(self):
        self.directory.cleanup()

    def config(self, environment="PRUEBAS", **overrides):
        values = {
            "ECF_ENABLED": "true",
            "ECF_ENVIRONMENT": environment,
            "ECF_ALLOW_PRODUCTION": "false",
            "ECF_CERTIFICATE_PATH": str(self.certificate),
            "ECF_CERTIFICATE_PASSWORD": "clave-prueba",
            "FLASK_ENV": "development",
            **environment_urls(environment),
        }
        values.update(overrides)
        return ECFConfig.from_env(values)

    def test_accepts_official_pre_certification_services(self):
        config = self.config()
        self.assertTrue(config.enabled)
        self.assertEqual(config.environment, "PRUEBAS")

    def test_rejects_non_dgii_endpoint(self):
        with self.assertRaisesRegex(
            ECFConfigurationError, "servicio oficial"
        ):
            self.config(
                ECF_RECEPTION_URL="https://example.com/testecf/recepcion"
            )

    def test_rejects_urls_for_another_environment(self):
        with self.assertRaisesRegex(
            ECFConfigurationError, "CERTIFICACION"
        ):
            self.config("CERTIFICACION", **environment_urls("PRUEBAS"))

    def test_disabled_production_configuration_does_not_activate_itself(self):
        config = ECFConfig.from_env({
            "ECF_ENABLED": "false",
            "ECF_ENVIRONMENT": "PRODUCCION",
            "ECF_ALLOW_PRODUCTION": "false",
        })
        self.assertFalse(config.enabled)
        self.assertFalse(config.allow_production)

    def test_production_requires_multi_tenant_secret_store(self):
        values = {
            **environment_urls("PRODUCCION"),
            "ECF_ALLOW_PRODUCTION": "true",
            "FLASK_ENV": "production",
        }
        with self.assertRaisesRegex(
            ECFConfigurationError, "multi-tenant"
        ):
            self.config("PRODUCCION", **values)

    def test_accepts_explicit_production_gates_without_changing_env_file(self):
        config = self.config(
            "PRODUCCION",
            **environment_urls("PRODUCCION"),
            ECF_ALLOW_PRODUCTION="true",
            ECF_CERTIFICATE_PASSWORD="",
            ECF_TENANT_SECRETS_ROOT=self.directory.name,
            FLASK_ENV="production",
        )
        self.assertTrue(config.enabled)
        self.assertTrue(config.allow_production)
        self.assertEqual(config.flask_environment, "production")
        self.assertEqual(config.tenant_secrets_root, self.directory.name)

    def test_rejects_production_flag_in_test_environment(self):
        with self.assertRaisesRegex(
            ECFConfigurationError, "solo es válido"
        ):
            self.config(ECF_ALLOW_PRODUCTION="true")

    def test_rejects_non_numeric_timeout(self):
        with self.assertRaisesRegex(
            ECFConfigurationError, "números enteros"
        ):
            self.config(ECF_CONNECT_TIMEOUT_SECONDS="diez")


if __name__ == "__main__":
    unittest.main()
