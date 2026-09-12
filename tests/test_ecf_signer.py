from datetime import date, datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from lxml import etree

from ecf.builder import ECFBuilder
from ecf.signer import DSIG_NAMESPACE, ECFSigner, ECFSigningError
from ecf.validator import ECFValidator


def build_unsigned_xml():
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


def create_pkcs12(path, password, signer_id="123456789"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "DO"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Pruebas ARSFlow"),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, signer_id),
        x509.NameAttribute(NameOID.COMMON_NAME, "Certificado de prueba"),
    ])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(
        pkcs12.serialize_key_and_certificates(
            b"arsflow-test",
            key,
            certificate,
            None,
            serialization.BestAvailableEncryption(password.encode("utf-8")),
        )
    )


class ECFSignerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.certificate_path = Path(self.directory.name) / "test.p12"
        self.password = "clave-segura-prueba"
        create_pkcs12(self.certificate_path, self.password)
        self.signer = ECFSigner(self.certificate_path, self.password)

    def tearDown(self):
        self.directory.cleanup()

    def test_signs_with_dgii_required_algorithms_and_validates(self):
        result = self.signer.sign_e31(
            build_unsigned_xml(),
            expected_signer_id="123456789",
            signed_at=datetime(2026, 9, 11, 16, 45, 10),
        )
        root = etree.fromstring(result.signed_xml.encode("utf-8"))
        namespaces = {"ds": DSIG_NAMESPACE}

        self.assertEqual(
            root.findtext("FechaHoraFirma"), "11-09-2026 16:45:10"
        )
        self.assertEqual(
            root.xpath(
                "string(ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm)",
                namespaces=namespaces,
            ),
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        )
        self.assertEqual(
            root.xpath(
                "string(ds:Signature/ds:SignedInfo/"
                "ds:CanonicalizationMethod/@Algorithm)",
                namespaces=namespaces,
            ),
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
        )
        self.assertEqual(
            root.xpath(
                "string(ds:Signature/ds:SignedInfo/ds:Reference/@URI)",
                namespaces=namespaces,
            ),
            "",
        )
        self.assertEqual(
            root.xpath(
                "string(ds:Signature/ds:SignedInfo/ds:Reference/"
                "ds:DigestMethod/@Algorithm)",
                namespaces=namespaces,
            ),
            "http://www.w3.org/2001/04/xmlenc#sha256",
        )
        self.assertEqual(
            root.xpath(
                "string(ds:Signature/ds:SignedInfo/ds:Reference/"
                "ds:Transforms/ds:Transform/@Algorithm)",
                namespaces=namespaces,
            ),
            "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
        )
        self.assertTrue(
            root.xpath("boolean(ds:Signature/ds:KeyInfo/ds:X509Data)",
                       namespaces=namespaces)
        )
        self.assertTrue(
            self.signer.verify_signed_e31(result.signed_xml, "123456789")
        )
        ECFValidator().validate_signed_e31(result.signed_xml)

    def test_rejects_certificate_for_another_signer(self):
        with self.assertRaisesRegex(ECFSigningError, "SN del certificado"):
            self.signer.sign_e31(build_unsigned_xml(), "999999999")

    def test_rejects_wrong_certificate_password_without_exposing_it(self):
        signer = ECFSigner(self.certificate_path, "incorrecta")
        with self.assertRaisesRegex(ECFSigningError, "No se pudo abrir"):
            signer.sign_e31(build_unsigned_xml(), "123456789")

    def test_detects_changes_after_signing(self):
        result = self.signer.sign_e31(
            build_unsigned_xml(), "123456789"
        )
        root = etree.fromstring(result.signed_xml.encode("utf-8"))
        root.find("Encabezado/Totales/MontoTotal").text = "1.00"
        altered = etree.tostring(root, encoding="UTF-8")
        with self.assertRaisesRegex(ECFSigningError, "no es válida"):
            self.signer.verify_signed_e31(altered, "123456789")


if __name__ == "__main__":
    unittest.main()
