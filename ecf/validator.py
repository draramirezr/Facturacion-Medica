"""Validación local de e-CF contra el XSD oficial de la DGII."""

from dataclasses import dataclass
import hashlib
from pathlib import Path

from lxml import etree


# Hash del XSD oficial con finales de línea LF (como en el blob de git / Linux).
OFFICIAL_E31_SCHEMA_SHA256 = (
    "cc66cbc418ceefaa6437c97607308c3e0814d73070fbbf9e9a2a331d12cb8abc"
)
OFFICIAL_E32_SCHEMA_SHA256 = (
    "ab66dff0b08d743e2f188242025a0dcef45203ad05687280860d3b07a475991b"
)
MAX_XML_BYTES = 10 * 1024 * 1024

_INVALID_TYPE_NAME = b'name=" IndicadorServicioTodoIncluidoType"'
_VALID_TYPE_NAME = b'name="IndicadorServicioTodoIncluidoType"'
_REQUIRED_SIGNATURE_SLOTS = (
    b'<xs:any processContents="skip" minOccurs="1" maxOccurs="1"  />',
    b'<xs:any processContents="skip" minOccurs="1" maxOccurs="1"/>',
)

_SCHEMAS_ROOT = Path(__file__).resolve().parent / "schemas"


def _canonical_xsd_bytes(source: bytes) -> bytes:
    """Normaliza CRLF/CR a LF para que Windows y Linux usen el mismo hash."""
    return source.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def _official_schema_spec(ecf_type: str) -> tuple[Path, str, str]:
    tipo = str(ecf_type or "31").strip()
    if tipo == "32":
        return (
            _SCHEMAS_ROOT / "e-CF-32-v1.0.xsd",
            OFFICIAL_E32_SCHEMA_SHA256,
            "E32",
        )
    return (
        _SCHEMAS_ROOT / "e-CF-31-v1.0.xsd",
        OFFICIAL_E31_SCHEMA_SHA256,
        "E31",
    )


class ECFSchemaError(RuntimeError):
    """El esquema oficial no puede utilizarse de manera segura."""


class ECFValidationError(ValueError):
    """El XML no cumple la estructura e-CF esperada."""

    def __init__(self, errors):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


@dataclass(frozen=True)
class ECFValidationResult:
    schema_sha256: str
    compatibility_adjustments: tuple
    unsigned: bool
    ecf_type: str


class ECFValidator:
    """Validador e-CF con correcciones de compatibilidad solo en memoria."""

    def __init__(self, schema_path=None, *, ecf_type: str = "31"):
        self._custom_schema = schema_path is not None
        if self._custom_schema:
            self.schema_path = Path(schema_path)
        else:
            path, digest, label = _official_schema_spec(ecf_type)
            self.schema_path = path
            self._pinned_digest = digest
            self._pinned_label = label

    def validate_unsigned_e31(self, xml):
        return self._validate(xml, unsigned=True, ecf_type="31")

    def validate_signed_e31(self, xml):
        return self._validate(xml, unsigned=False, ecf_type="31")

    def validate_unsigned_e32(self, xml):
        return self._validate(xml, unsigned=True, ecf_type="32")

    def validate_signed_e32(self, xml):
        return self._validate(xml, unsigned=False, ecf_type="32")

    def _resolve_schema(self, ecf_type: str) -> tuple[Path, str | None, str]:
        if self._custom_schema:
            _, expected, label = _official_schema_spec(ecf_type)
            return self.schema_path, expected, label
        return _official_schema_spec(ecf_type)

    def _load_schema(self, unsigned, *, ecf_type: str):
        path, expected_digest, label = self._resolve_schema(ecf_type)
        try:
            source = _canonical_xsd_bytes(path.read_bytes())
        except OSError as error:
            raise ECFSchemaError(
                f"No se pudo leer el XSD oficial: {error}"
            ) from error

        digest = hashlib.sha256(source).hexdigest()
        if expected_digest is not None and digest != expected_digest:
            raise ECFSchemaError(
                f"El XSD {label} no coincide con la versión oficial verificada"
            )

        adjustments = []
        if expected_digest is not None:
            errata_count = source.count(_INVALID_TYPE_NAME)
            if errata_count == 1:
                source = source.replace(_INVALID_TYPE_NAME, _VALID_TYPE_NAME, 1)
                adjustments.append("DGII_XSD_TYPE_NAME_LEADING_SPACE")
            elif errata_count > 1:
                raise ECFSchemaError(
                    "La errata conocida del XSD aparece más de una vez"
                )

        if unsigned and expected_digest is not None:
            replaced = False
            for required in _REQUIRED_SIGNATURE_SLOTS:
                optional = required.replace(b'minOccurs="1"', b'minOccurs="0"', 1)
                if required in source:
                    source = source.replace(required, optional, 1)
                    replaced = True
                    break
            if not replaced:
                raise ECFSchemaError(
                    "No se encontró el espacio de firma esperado en el XSD"
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
                base_url=path.resolve().as_uri(),
            )
            schema = etree.XMLSchema(schema_document)
        except (etree.XMLSyntaxError, etree.XMLSchemaParseError) as error:
            raise ECFSchemaError(
                f"No se pudo compilar el XSD {label} oficial: {error}"
            ) from error

        return schema, digest, tuple(adjustments), label

    def _validate(self, xml, unsigned, *, ecf_type: str):
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

        schema, digest, adjustments, label = self._load_schema(
            unsigned, ecf_type=ecf_type
        )
        if not schema.validate(document):
            errors = [
                (
                    f"Línea {entry.line}, columna {entry.column}: "
                    f"{entry.message}"
                )
                for entry in schema.error_log
            ]
            raise ECFValidationError(
                errors or [f"El XML no cumple el XSD {label}"]
            )

        return ECFValidationResult(
            schema_sha256=digest,
            compatibility_adjustments=adjustments,
            unsigned=unsigned,
            ecf_type=label,
        )