from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from ecf.certificates import (
    ECFCertificateResolutionError,
    TenantCertificateProvider,
)


def create_tenant_certificate(directory, signer_id, password):
    directory.mkdir(parents=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"Tenant {signer_id}"),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, signer_id),
    ])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .sign(key, hashes.SHA256())
    )
    (directory / "certificate.p12").write_bytes(
        pkcs12.serialize_key_and_certificates(
            b"tenant-certificate",
            key,
            certificate,
            None,
            serialization.BestAvailableEncryption(password.encode("utf-8")),
        )
    )
    (directory / "password.txt").write_text(password, encoding="utf-8")


class TenantCertificateProviderTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        create_tenant_certificate(
            self.root / "tenant-1", "111111111", "clave-tenant-1"
        )
        create_tenant_certificate(
            self.root / "tenant-2", "222222222", "clave-tenant-2"
        )
        self.provider = TenantCertificateProvider(SimpleNamespace(
            tenant_secrets_root=str(self.root),
            environment="PRUEBAS",
            certificate_path="",
            certificate_password="",
        ))

    def tearDown(self):
        self.directory.cleanup()

    def test_resolves_isolated_certificate_for_each_tenant(self):
        first, first_metadata = self.provider.inspect(1, "111111111")
        second, second_metadata = self.provider.inspect(2, "222222222")

        self.assertNotEqual(first.certificate_path, second.certificate_path)
        self.assertNotEqual(
            first_metadata.fingerprint, second_metadata.fingerprint
        )
        self.assertEqual(first_metadata.signer_ids, ("111111111",))
        self.assertEqual(second_metadata.signer_ids, ("222222222",))
        self.assertNotIn("clave-tenant-1", repr(first))

    def test_never_uses_another_tenant_certificate_for_rnc(self):
        with self.assertRaisesRegex(
            ECFCertificateResolutionError, "no corresponde"
        ):
            self.provider.inspect(1, "222222222")

    def test_rejects_reference_outside_secure_root(self):
        with self.assertRaisesRegex(
            ECFCertificateResolutionError, "sale del almacén"
        ):
            self.provider.resolve(1, {
                "certificado_referencia": "../certificate.p12",
                "secreto_referencia": "tenant-1/password.txt",
            })

    def test_missing_tenant_never_falls_back_when_store_is_configured(self):
        with self.assertRaisesRegex(
            ECFCertificateResolutionError, "no tiene un certificado"
        ):
            self.provider.resolve(3)

    def test_stores_uploaded_certificate_for_tenant(self):
        tenant_dir = self.root / "tenant-9"
        create_tenant_certificate(tenant_dir, "999999999", "clave-nueva")
        payload = (tenant_dir / "certificate.p12").read_bytes()
        for leftover in tenant_dir.iterdir():
            leftover.unlink()
        tenant_dir.rmdir()

        metadata = self.provider.store(
            9, payload, "clave-nueva", "999999999"
        )
        resolved, stored = self.provider.inspect(9, "999999999")
        self.assertEqual(metadata.fingerprint, stored.fingerprint)
        self.assertTrue(resolved.certificate_path.is_file())
        self.assertEqual(
            resolved.certificate_path.parent.name, "tenant-9"
        )


if __name__ == "__main__":
    unittest.main()
