"""Cliente REST para servicios e-CF de DGII en ambientes no productivos."""

from dataclasses import dataclass, field
import json
import re
import unicodedata
from urllib.parse import urlparse

from lxml import etree
import requests

from .signer import ECFSigner, ECFSigningError


MAX_RESPONSE_BYTES = 2 * 1024 * 1024


def classify_dgii_status(code, status):
    """Traducir estados oficiales sin confundir recepción con aceptación."""
    code = str(code or "").strip()
    by_code = {
        "0": "ENVIADO",
        "1": "ACEPTADO",
        "2": "RECHAZADO",
        "3": "ENVIADO",
        "4": "ACEPTADO",
    }
    if code in by_code:
        return by_code[code]

    normalized = unicodedata.normalize(
        "NFKD", str(status or "")
    ).encode("ascii", "ignore").decode("ascii").casefold().strip()
    if normalized in {"aceptado", "aceptado condicional"}:
        return "ACEPTADO"
    if normalized == "rechazado":
        return "RECHAZADO"
    return "ENVIADO"


class DGIIClientError(RuntimeError):
    """Error controlado al comunicarse con DGII."""

    def __init__(
        self,
        message,
        *,
        http_status=None,
        response_text=None,
        delivery_uncertain=False,
    ):
        super().__init__(message)
        self.http_status = http_status
        self.response_text = response_text
        self.delivery_uncertain = delivery_uncertain


class DGIITimeoutError(DGIIClientError):
    """DGII no respondió dentro del tiempo configurado."""


class DGIIResponseError(DGIIClientError):
    """DGII respondió sin el contrato mínimo esperado."""


@dataclass(frozen=True)
class DGIIToken:
    value: str = field(repr=False)
    expires_at: str = ""
    issued_at: str = ""


@dataclass(frozen=True)
class DGIIReceptionResult:
    track_id: str
    error: str
    message: str
    raw_response: str
    http_status: int


@dataclass(frozen=True)
class DGIIStatusResult:
    track_id: str
    code: str
    status: str
    rnc: str
    encf: str
    sequence_used: bool | None
    received_at: str
    messages: tuple
    raw_response: str
    http_status: int


@dataclass(frozen=True)
class DGIITrackResult:
    track_id: str
    status: str
    received_at: str


class DGIIClient:
    """Autentica por semilla y remite un e-CF firmado.

    Producción requiere las dos habilitaciones explícitas de configuración.
    """

    def __init__(self, config, signer=None, session=None):
        if config.environment == "PRODUCCION" and not (
            getattr(config, "enabled", False)
            and getattr(config, "allow_production", False)
        ):
            raise DGIIClientError(
                "La configuración no permite producción"
            )
        if config.environment not in {
            "PRUEBAS", "CERTIFICACION", "PRODUCCION"
        }:
            raise DGIIClientError("Ambiente DGII no permitido")

        self.config = config
        self.signer = signer or ECFSigner.from_config(config)
        self.session = session or requests.Session()
        self.session.headers.update({
            "User-Agent": "ARSFlow-eCF/1.0",
            "Accept": "application/json, application/xml, text/xml",
        })
        self._validate_base_url(
            config.authentication_url, "autenticación", config.environment
        )
        self._validate_base_url(
            config.reception_url, "recepción", config.environment
        )
        self._validate_base_url(
            config.result_url, "consulta de resultado", config.environment
        )
        self._validate_base_url(
            config.track_url, "consulta de TrackID", config.environment
        )

    def submit_e31(self, signed_xml, issuer_rnc, encf):
        token = self.authenticate(issuer_rnc)
        return self.send_ecf(signed_xml, issuer_rnc, encf, token)

    def authenticate(self, issuer_rnc):
        seed_url = self._endpoint(
            self.config.authentication_url,
            "api/autenticacion/semilla",
        )
        seed_response = self._request("GET", seed_url)
        seed_xml = seed_response.content
        if not seed_xml:
            raise DGIIResponseError("DGII devolvió una semilla vacía")

        try:
            signed_seed = self.signer.sign_authentication_seed(
                seed_xml, expected_signer_id=issuer_rnc
            )
        except ECFSigningError as error:
            raise DGIIClientError(
                f"No se pudo firmar la semilla DGII: {error}"
            ) from error
        validation_url = self._endpoint(
            self.config.authentication_url,
            "api/autenticacion/validarsemilla",
        )
        response = self._request(
            "POST",
            validation_url,
            files={
                "xml": (
                    "semilla-firmada.xml",
                    signed_seed.signed_xml.encode("utf-8"),
                    "text/xml",
                )
            },
        )
        payload = self._payload(response)
        token = self._value(payload, "token")
        if not token:
            # La respuesta de autenticación podría contener información
            # sensible; nunca se propaga ni almacena completa.
            raise DGIIResponseError(
                "DGII no devolvió un token de autenticación",
                http_status=response.status_code,
            )
        return DGIIToken(
            value=token,
            expires_at=self._value(payload, "expira"),
            issued_at=self._value(payload, "expedido"),
        )

    def send_ecf(self, signed_xml, issuer_rnc, encf, token):
        rnc = re.sub(r"\D", "", str(issuer_rnc or ""))
        encf = str(encf or "").strip().upper()
        if len(rnc) not in {9, 11}:
            raise DGIIClientError("RNC del emisor inválido")
        if not re.fullmatch(r"E31\d{10}", encf):
            raise DGIIClientError("e-NCF E31 inválido")
        if not token or not token.value:
            raise DGIIClientError("Token DGII ausente")

        reception_url = self._endpoint(
            self.config.reception_url,
            "api/facturaselectronicas",
        )
        filename = f"{rnc}{encf}.xml"
        try:
            response = self._request(
                "POST",
                reception_url,
                headers={"Authorization": f"Bearer {token.value}"},
                files={
                    "xml": (
                        filename,
                        signed_xml.encode("utf-8"),
                        "text/xml",
                    )
                },
                delivery_uncertain=True,
            )
        except DGIIClientError as error:
            error.delivery_uncertain = True
            raise

        payload = self._payload(response)
        raw_response = self._safe_response_text(response)
        track_id = self._value(payload, "trackId", "trackid")
        error_message = self._value(payload, "error")
        message = self._value(payload, "mensaje", "message")
        if not track_id:
            raise DGIIResponseError(
                message or error_message
                or "DGII respondió sin un TrackID",
                http_status=response.status_code,
                response_text=raw_response,
                delivery_uncertain=True,
            )
        return DGIIReceptionResult(
            track_id=track_id,
            error=error_message,
            message=message,
            raw_response=raw_response,
            http_status=response.status_code,
        )

    def query_result(self, track_id, issuer_rnc, token=None):
        track_id = str(track_id or "").strip()
        if not track_id or len(track_id) > 150:
            raise DGIIClientError("TrackID inválido")
        token = token or self.authenticate(issuer_rnc)
        response = self._request(
            "GET",
            self._endpoint(
                self.config.result_url,
                "api/consultas/estado",
            ),
            headers={"Authorization": f"Bearer {token.value}"},
            params={"trackid": track_id},
        )
        payload = self._payload(response)
        messages = self._messages(payload)
        return DGIIStatusResult(
            track_id=self._value(payload, "trackId", "trackid") or track_id,
            code=self._value(payload, "codigo", "code"),
            status=self._value(payload, "estado", "status"),
            rnc=self._value(payload, "rnc", "rncEmisor"),
            encf=self._value(payload, "eNCF", "encf", "ncfElectronico"),
            sequence_used=self._boolean_value(
                payload, "secuenciaUtilizada"
            ),
            received_at=self._value(payload, "fechaRecepcion"),
            messages=messages,
            raw_response=self._safe_response_text(response),
            http_status=response.status_code,
        )

    def find_track_ids(self, issuer_rnc, encf, token=None):
        rnc = re.sub(r"\D", "", str(issuer_rnc or ""))
        encf = str(encf or "").strip().upper()
        if len(rnc) not in {9, 11}:
            raise DGIIClientError("RNC del emisor inválido")
        if not re.fullmatch(r"E31\d{10}", encf):
            raise DGIIClientError("e-NCF E31 inválido")
        token = token or self.authenticate(rnc)
        response = self._request(
            "GET",
            self._endpoint(
                self.config.track_url,
                "api/trackids/consulta",
            ),
            headers={"Authorization": f"Bearer {token.value}"},
            params={"rncemisor": rnc, "encf": encf},
        )

        try:
            payload = response.json()
        except ValueError:
            payload = self._payload(response)
        rows = payload if isinstance(payload, list) else [payload]
        results = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            track_id = self._value(row, "trackId", "trackid")
            if track_id:
                results.append(DGIITrackResult(
                    track_id=track_id,
                    status=self._value(row, "estado", "status"),
                    received_at=self._value(row, "fechaRecepcion"),
                ))
        return tuple(results)

    def _request(self, method, url, delivery_uncertain=False, **kwargs):
        try:
            response = self.session.request(
                method,
                url,
                timeout=(
                    self.config.connect_timeout_seconds,
                    self.config.read_timeout_seconds,
                ),
                **kwargs,
            )
        except requests.Timeout as error:
            raise DGIITimeoutError(
                "Tiempo de espera agotado al comunicarse con DGII",
                delivery_uncertain=delivery_uncertain,
            ) from error
        except requests.RequestException as error:
            raise DGIIClientError(
                "No fue posible conectarse con DGII",
                delivery_uncertain=delivery_uncertain,
            ) from error

        if len(response.content or b"") > MAX_RESPONSE_BYTES:
            raise DGIIResponseError(
                "La respuesta DGII supera el límite permitido",
                http_status=response.status_code,
                delivery_uncertain=delivery_uncertain,
            )
        if not 200 <= response.status_code < 300:
            raise DGIIResponseError(
                f"DGII respondió HTTP {response.status_code}",
                http_status=response.status_code,
                response_text=self._safe_response_text(response),
                delivery_uncertain=delivery_uncertain,
            )
        return response

    @staticmethod
    def _endpoint(base_url, resource):
        return f"{base_url.rstrip('/')}/{resource.lstrip('/')}"

    @staticmethod
    def _validate_base_url(url, label, environment):
        parsed = urlparse(str(url or ""))
        if parsed.scheme != "https" or not parsed.netloc:
            raise DGIIClientError(
                f"La URL de {label} DGII debe usar HTTPS"
            )
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise DGIIClientError(f"La URL de {label} DGII no es válida")
        expected_prefix = {
            "PRUEBAS": "/testecf/",
            "CERTIFICACION": "/certecf/",
            "PRODUCCION": "/ecf/",
        }[environment]
        if (
            parsed.hostname != "ecf.dgii.gov.do"
            or not parsed.path.lower().startswith(expected_prefix)
        ):
            raise DGIIClientError(
                f"La URL de {label} no corresponde al ambiente DGII"
            )

    @classmethod
    def _payload(cls, response):
        try:
            payload = response.json()
            if isinstance(payload, dict):
                return payload
        except (ValueError, json.JSONDecodeError):
            pass

        content = response.content or b""
        if not content:
            return {}
        try:
            root = etree.fromstring(
                content,
                parser=etree.XMLParser(
                    resolve_entities=False,
                    no_network=True,
                    load_dtd=False,
                ),
            )
        except etree.XMLSyntaxError:
            return {}
        return {
            etree.QName(node).localname: (node.text or "").strip()
            for node in root.iter()
            if len(node) == 0
        }

    @staticmethod
    def _value(payload, *names):
        normalized = {
            str(key).casefold(): str(value or "").strip()
            for key, value in (payload or {}).items()
        }
        for name in names:
            value = normalized.get(name.casefold(), "")
            if value:
                return value
        return ""

    @staticmethod
    def _boolean_value(payload, name):
        value = None
        for key, candidate in (payload or {}).items():
            if str(key).casefold() == name.casefold():
                value = candidate
                break
        if isinstance(value, bool):
            return value
        if str(value).strip().casefold() in {"true", "1"}:
            return True
        if str(value).strip().casefold() in {"false", "0"}:
            return False
        return None

    @classmethod
    def _messages(cls, payload):
        messages = payload.get("mensajes", []) if isinstance(payload, dict) else []
        if not isinstance(messages, list):
            messages = [messages]
        normalized = []
        for message in messages:
            if isinstance(message, dict):
                code = cls._value(message, "codigo", "code")
                value = cls._value(message, "valor", "mensaje", "message")
                text = f"{code}: {value}".strip(": ")
            else:
                text = str(message or "").strip()
            if text:
                normalized.append(text)
        return tuple(normalized)

    @staticmethod
    def _safe_response_text(response):
        text = response.text or ""
        return text[:MAX_RESPONSE_BYTES]
