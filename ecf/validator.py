"""Validación local de e-CF contra el XSD oficial de la DGII."""

from dataclasses import dataclass
import hashlib
from pathlib import Path

from lxml import etree


OFFICIAL_E31_SCHEMA_SHA256 = (
    "6f2909a93d84919518d2ae3c77fead4b35c3e8c95996b8af67b0040c2e2be298"
)
MAX_XML_BYTES = 10 * 1024 * 1024

_INVALID_TYPE_NAME = b'name=" IndicadorServicioTodoIncluidoType"'
_VALID_TYPE_NAME = b'name="IndicadorServicioTodoIncluidoType"'
_REQUIRED_SIGNATURE_SLOT = (
    b'<xs:any processContents="skip" minOccurs="1" maxOccurs="1"  />'
)
_OPTIONAL_SIGNATURE_SLOT = (
    b'<xs:any processContents="skip" minOccurs="0" maxOccurs="1"  />'
)


class ECFSchemaError(RuntimeError):
    """El esquema oficial no puede utilizarse de manera segura."""


class ECFValidationError(ValueError):
    """El XML no cumple la estructura E31 esperada."""

    def __init__(self, errors):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


@dataclass(frozen=True)
class ECFValidationResult:
    schema_sha256: str
    compatibility_adjustments: tuple
    unsigned: bool


class ECFValidator:
    """Validador E31 con correcciones de compatibilidad solo en memoria.

    El archivo oficial nunca se reescribe. En validación previa a la firma, el
    espacio reservado para XMLDSig se vuelve opcional; la validación del
    documento firmado volverá a exigirlo.
    """

    def __init__(self, schema_path=None):
        self.schema_path = Path(schema_path or (
            Path(__file__).resolve().parent
            / "schemas"
            / "e-CF-31-v1.0.xsd"
        ))

    def validate_unsigned_e31(self, xml):
        return self._validate(xml, unsigned=True)

    def validate_signed_e31(self, xml):
        return self._validate(xml, unsigned=False)

    def _load_schema(self, unsigned):
        try:
            source = self.schema_path.read_bytes()
        except OSError as error:
            raise ECFSchemaError(
                f"No se pudo leer el XSD oficial: {error}"
            ) from error

        digest = hashlib.sha256(source).hexdigest()
        if digest != OFFICIAL_E31_SCHEMA_SHA256:
            raise ECFSchemaError(
                "El XSD E31 no coincide con la versión oficial verificada"
            )

        adjustments = []
        if source.count(_INVALID_TYPE_NAME) != 1:
            raise ECFSchemaError(
                "No se encontró exactamente una vez la errata conocida del XSD"
            )
        source = source.replace(_INVALID_TYPE_NAME, _VALID_TYPE_NAME, 1)
        adjustments.append("DGII_XSD_TYPE_NAME_LEADING_SPACE")

        if unsigned:
            if source.count(_REQUIRED_SIGNATURE_SLOT) != 1:
                raise ECFSchemaError(
                    "No se encontró el espacio de firma esperado en el XSD"
                )
            source = source.replace(
                _REQUIRED_SIGNATURE_SLOT, _OPTIONAL_SIGNATURE_SLOT, 1
            )
            adjustments.append("PRE_SIGNATURE_XMLDSIG_OPTIONAL")

        try:
            schema_document = etree.fromstring(
                source,
                parser=etree.XMLParser(
                    resolve_entities=False,
                    no_network=True,
                    load_dtd=False,
                ),
                base_url=self.schema_path.resolve().as_uri(),
            )
            schema = etree.XMLSchema(schema_document)
        except (etree.XMLSyntaxError, etree.XMLSchemaParseError) as error:
            raise ECFSchemaError(
                f"No se pudo compilar el XSD E31 oficial: {error}"
            ) from error

        return schema, digest, tuple(adjustments)

    def _validate(self, xml, unsigned):
        xml_bytes = xml.encode("utf-8") if isinstance(xml, str) else bytes(xml)
        if not xml_bytes:
            raise ECFValidationError(["El XML está vacío"])
        if len(xml_bytes) > MAX_XML_BYTES:
            raise ECFValidationError(["El XML supera el límite de 10 MB"])
        if b"<!DOCTYPE" in xml_bytes.upper():
            raise ECFValidationError(["El XML no puede contener DOCTYPE"])

        try:
            document = etree.fromstring(
                xml_bytes,
                parser=etree.XMLParser(
                    resolve_entities=False,
                    no_network=True,
                    load_dtd=False,
                    huge_tree=False,
                ),
            )
        except etree.XMLSyntaxError as error:
            raise ECFValidationError(
                [f"XML mal formado, línea {error.lineno}: {error.msg}"]
            ) from error

        schema, digest, adjustments = self._load_schema(unsigned)
        if not schema.validate(document):
            errors = [
                (
                    f"Línea {entry.line}, columna {entry.column}: "
                    f"{entry.message}"
                )
                for entry in schema.error_log
            ]
            raise ECFValidationError(errors or ["El XML no cumple el XSD E31"])

        return ECFValidationResult(
            schema_sha256=digest,
            compatibility_adjustments=adjustments,
            unsigned=unsigned,
        )
