"""Firma XMLDSig enveloped para documentos e-CF de la DGII."""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtensionOID, NameOID
from lxml import etree
from signxml import (
    CanonicalizationMethod,
    DigestAlgorithm,
    InvalidSignature,
    SignatureConfiguration,
    SignatureMethod,
    XMLSigner,
    XMLVerifier,
    methods,
)


DSIG_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#"
RSA_SHA256_URI = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
SHA256_URI = "http://www.w3.org/2001/04/xmlenc#sha256"
C14N_1_0_URI = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
MAX_CERTIFICATE_BYTES = 10 * 1024 * 1024


class ECFSigningError(ValueError):
    """No fue posible firmar o verificar el documento e-CF."""


@dataclass(frozen=True)
class ECFSignatureResult:
    signed_xml: str
    sha256: str
    signed_at: datetime
    certificate_fingerprint: str


@dataclass(frozen=True)
class ECFCertificateMetadata:
    fingerprint: str
    valid_from: datetime
    valid_until: datetime
    signer_ids: tuple


class ECFSigner:
    """Firma el documento completo con RSA-SHA256 y certificado PKCS#12."""

    def __init__(self, certificate_path, certificate_password):
        self.certificate_path = Path(certificate_path)
        self._certificate_password = certificate_password

    @classmethod
    def from_config(cls, config):
        return cls(config.certificate_path, config.certificate_password)

    def sign_e31(self, xml, expected_signer_id, signed_at=None):
        private_key, certificate = self._load_certificate(expected_signer_id)
        signed_at = signed_at or datetime.now()
        root = self._parse_unsigned_xml(xml, expected_root="ECF")

        signature_time = root.find("FechaHoraFirma")
        if signature_time is None:
            raise ECFSigningError("El XML no contiene FechaHoraFirma")
        signature_time.text = signed_at.strftime("%d-%m-%Y %H:%M:%S")

        return self._sign_root(root, private_key, certificate, signed_at)

    def sign_authentication_seed(self, xml, expected_signer_id):
        """Firmar la semilla entregada por DGII sin alterar su contenido."""
        private_key, certificate = self._load_certificate(expected_signer_id)
        signed_at = datetime.now()
        root = self._parse_unsigned_xml(xml)
        return self._sign_root(root, private_key, certificate, signed_at)

    def _sign_root(self, root, private_key, certificate, signed_at):
        try:
            signed_root = XMLSigner(
                method=methods.enveloped,
                signature_algorithm=SignatureMethod.RSA_SHA256,
                digest_algorithm=DigestAlgorithm.SHA256,
                c14n_algorithm=CanonicalizationMethod.CANONICAL_XML_1_0,
            ).sign(
                root,
                key=private_key,
                cert=[certificate],
            )
            self._verify(signed_root, certificate)
        except (InvalidSignature, etree.Error, ValueError) as error:
            raise ECFSigningError(
                "La firma XMLDSig no pudo generarse o verificarse"
            ) from error

        signed_bytes = etree.tostring(
            signed_root,
            encoding="UTF-8",
            xml_declaration=True,
            pretty_print=False,
        )
        return ECFSignatureResult(
            signed_xml=signed_bytes.decode("utf-8"),
            sha256=hashlib.sha256(signed_bytes).hexdigest(),
            signed_at=signed_at,
            certificate_fingerprint=certificate.fingerprint(
                hashes.SHA256()
            ).hex(),
        )

    def verify_signed_e31(self, xml, expected_signer_id):
        _, certificate = self._load_certificate(expected_signer_id)
        try:
            root = etree.fromstring(
                xml.encode("utf-8") if isinstance(xml, str) else bytes(xml),
                parser=self._secure_parser(),
            )
            self._verify(root, certificate)
        except (InvalidSignature, etree.Error, ValueError) as error:
            raise ECFSigningError("La firma XMLDSig no es válida") from error
        return True

    def inspect_certificate(self, expected_signer_id):
        """Validar el certificado y devolver solo metadatos no secretos."""
        _, certificate = self._load_certificate(expected_signer_id)
        signer_ids = tuple(sorted({
            re.sub(r"\D", "", attribute.value)
            for attribute in certificate.subject.get_attributes_for_oid(
                NameOID.SERIAL_NUMBER
            )
            if re.sub(r"\D", "", attribute.value)
        }))
        return ECFCertificateMetadata(
            fingerprint=certificate.fingerprint(hashes.SHA256()).hex(),
            valid_from=certificate.not_valid_before_utc,
            valid_until=certificate.not_valid_after_utc,
            signer_ids=signer_ids,
        )

    def _load_certificate(self, expected_signer_id):
        try:
            certificate_bytes = self.certificate_path.read_bytes()
        except OSError as error:
            raise ECFSigningError(
                "No se pudo leer el certificado digital configurado"
            ) from error
        if not certificate_bytes or len(certificate_bytes) > MAX_CERTIFICATE_BYTES:
            raise ECFSigningError("El archivo de certificado no es válido")

        password = (
            self._certificate_password.encode("utf-8")
            if self._certificate_password
            else None
        )
        try:
            private_key, certificate, _ = (
                pkcs12.load_key_and_certificates(certificate_bytes, password)
            )
        except (TypeError, ValueError) as error:
            raise ECFSigningError(
                "No se pudo abrir el certificado digital configurado"
            ) from error

        if private_key is None or certificate is None:
            raise ECFSigningError(
                "El certificado no contiene clave privada y certificado X.509"
            )
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ECFSigningError("DGII requiere una clave privada RSA para e-CF")

        now = datetime.now(timezone.utc)
        if now < certificate.not_valid_before_utc:
            raise ECFSigningError("El certificado digital todavía no es válido")
        if now > certificate.not_valid_after_utc:
            raise ECFSigningError("El certificado digital está vencido")

        try:
            key_usage = certificate.extensions.get_extension_for_oid(
                ExtensionOID.KEY_USAGE
            ).value
            if not key_usage.digital_signature:
                raise ECFSigningError(
                    "El certificado no permite generar firmas digitales"
                )
        except x509.ExtensionNotFound:
            pass

        expected = re.sub(r"\D", "", str(expected_signer_id or ""))
        serial_attributes = certificate.subject.get_attributes_for_oid(
            NameOID.SERIAL_NUMBER
        )
        certificate_ids = {
            re.sub(r"\D", "", attribute.value)
            for attribute in serial_attributes
        }
        if not expected or expected not in certificate_ids:
            raise ECFSigningError(
                "El SN del certificado no corresponde al RNC o cédula del emisor"
            )

        return private_key, certificate

    def _parse_unsigned_xml(self, xml, expected_root=None):
        xml_bytes = xml.encode("utf-8") if isinstance(xml, str) else bytes(xml)
        if b"<!DOCTYPE" in xml_bytes.upper():
            raise ECFSigningError("El XML no puede contener DOCTYPE")
        try:
            root = etree.fromstring(xml_bytes, parser=self._secure_parser())
        except etree.XMLSyntaxError as error:
            raise ECFSigningError("El XML a firmar está mal formado") from error
        local_name = etree.QName(root).localname
        if expected_root and local_name != expected_root:
            raise ECFSigningError(
                f"El documento raíz debe ser {expected_root}"
            )
        if root.xpath(".//ds:Signature", namespaces={"ds": DSIG_NAMESPACE}):
            raise ECFSigningError("El XML ya contiene una firma digital")
        return root

    @staticmethod
    def _secure_parser():
        return etree.XMLParser(
            resolve_entities=False,
            no_network=True,
            load_dtd=False,
            remove_blank_text=True,
            huge_tree=False,
        )

    @staticmethod
    def _verify(root, certificate):
        configuration = SignatureConfiguration(
            require_x509=True,
            expect_references=1,
            signature_methods=frozenset({SignatureMethod.RSA_SHA256}),
            digest_algorithms=frozenset({DigestAlgorithm.SHA256}),
            default_reference_c14n_method=(
                CanonicalizationMethod.CANONICAL_XML_1_0
            ),
        )
        XMLVerifier().verify(
            root,
            x509_cert=certificate,
            validate_schema=False,
            expect_config=configuration,
        )
