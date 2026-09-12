"""Configuración centralizada y segura para la integración e-CF."""

from dataclasses import dataclass, field
import os
from pathlib import Path
from typing import Mapping, Optional
from urllib.parse import urlsplit


class ECFConfigurationError(ValueError):
    """Configuración e-CF incompleta o insegura."""


def _as_bool(value: Optional[str], default=False):
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "si", "sí", "on"}


def _read_secret(env: Mapping[str, str]):
    """Leer la clave desde archivo de secreto o variable de entorno."""
    password_file = env.get("ECF_CERTIFICATE_PASSWORD_FILE", "").strip()
    if password_file:
        path = Path(password_file)
        if not path.is_file():
            raise ECFConfigurationError(
                "ECF_CERTIFICATE_PASSWORD_FILE no existe o no es un archivo"
            )
        return path.read_text(encoding="utf-8").strip()
    return env.get("ECF_CERTIFICATE_PASSWORD", "")


@dataclass(frozen=True)
class ECFConfig:
    enabled: bool
    environment: str
    allow_production: bool
    certificate_path: str
    certificate_password: str = field(repr=False)
    certificate_password_file: str = ""
    tenant_secrets_root: str = ""
    flask_environment: str = "development"
    authentication_url: str = ""
    reception_url: str = ""
    result_url: str = ""
    track_url: str = ""
    stamp_url: str = ""
    connect_timeout_seconds: int = 10
    read_timeout_seconds: int = 30

    @classmethod
    def from_env(cls, env=None):
        source = os.environ if env is None else env
        enabled = _as_bool(source.get("ECF_ENABLED"), False)
        tenant_secrets_root = source.get(
            "ECF_TENANT_SECRETS_ROOT", ""
        ).strip()
        password_file = source.get(
            "ECF_CERTIFICATE_PASSWORD_FILE", ""
        ).strip()
        try:
            connect_timeout = int(
                source.get("ECF_CONNECT_TIMEOUT_SECONDS", "10")
            )
            read_timeout = int(
                source.get("ECF_READ_TIMEOUT_SECONDS", "30")
            )
        except (TypeError, ValueError) as error:
            raise ECFConfigurationError(
                "Los tiempos de espera e-CF deben ser números enteros"
            ) from error
        config = cls(
            enabled=enabled,
            environment=source.get("ECF_ENVIRONMENT", "PRUEBAS").strip().upper(),
            allow_production=_as_bool(
                source.get("ECF_ALLOW_PRODUCTION"), False
            ),
            certificate_path=source.get("ECF_CERTIFICATE_PATH", "").strip(),
            certificate_password=(
                _read_secret(source)
                if enabled and not tenant_secrets_root
                else ""
            ),
            certificate_password_file=password_file,
            tenant_secrets_root=tenant_secrets_root,
            flask_environment=source.get(
                "FLASK_ENV", "development"
            ).strip().lower(),
            authentication_url=source.get("ECF_AUTHENTICATION_URL", "").strip(),
            reception_url=source.get("ECF_RECEPTION_URL", "").strip(),
            result_url=source.get("ECF_RESULT_URL", "").strip(),
            track_url=source.get("ECF_TRACK_URL", "").strip(),
            stamp_url=source.get("ECF_STAMP_URL", "").strip(),
            connect_timeout_seconds=connect_timeout,
            read_timeout_seconds=read_timeout,
        )
        config.validate()
        return config

    def validate(self):
        allowed_environments = {"PRUEBAS", "CERTIFICACION", "PRODUCCION"}
        if self.environment not in allowed_environments:
            raise ECFConfigurationError(
                "ECF_ENVIRONMENT debe ser PRUEBAS, CERTIFICACION o PRODUCCION"
            )
        if self.allow_production and self.environment != "PRODUCCION":
            raise ECFConfigurationError(
                "ECF_ALLOW_PRODUCTION solo es válido en PRODUCCION"
            )
        if (
            self.enabled
            and self.environment == "PRODUCCION"
            and not self.allow_production
        ):
            raise ECFConfigurationError(
                "Producción requiere ECF_ALLOW_PRODUCTION=true explícitamente"
            )
        if self.connect_timeout_seconds <= 0 or self.read_timeout_seconds <= 0:
            raise ECFConfigurationError("Los tiempos de espera deben ser mayores a cero")
        if not self.enabled:
            return

        required = {
            "ECF_AUTHENTICATION_URL": self.authentication_url,
            "ECF_RECEPTION_URL": self.reception_url,
            "ECF_RESULT_URL": self.result_url,
            "ECF_TRACK_URL": self.track_url,
            "ECF_STAMP_URL": self.stamp_url,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise ECFConfigurationError(
                "Configuración e-CF incompleta: " + ", ".join(missing)
            )

        if self.tenant_secrets_root:
            secrets_root = Path(self.tenant_secrets_root)
            if not secrets_root.is_dir():
                raise ECFConfigurationError(
                    "ECF_TENANT_SECRETS_ROOT no existe o no es un directorio"
                )
        else:
            if not self.certificate_path or not self.certificate_password:
                raise ECFConfigurationError(
                    "Configure ECF_TENANT_SECRETS_ROOT o el certificado "
                    "global de compatibilidad"
                )
            certificate = Path(self.certificate_path)
            if not certificate.is_file():
                raise ECFConfigurationError(
                    "ECF_CERTIFICATE_PATH no apunta a un certificado existente"
                )
            if certificate.suffix.lower() not in {".p12", ".pfx"}:
                raise ECFConfigurationError(
                    "El certificado e-CF debe estar en formato PKCS#12 (.p12 o .pfx)"
                )

        self._validate_official_urls()

        if self.environment == "PRODUCCION":
            if self.flask_environment != "production":
                raise ECFConfigurationError(
                    "e-CF productivo requiere FLASK_ENV=production"
                )
            if not self.tenant_secrets_root:
                raise ECFConfigurationError(
                    "Producción multi-tenant requiere ECF_TENANT_SECRETS_ROOT"
                )
            if not Path(self.tenant_secrets_root).is_absolute():
                raise ECFConfigurationError(
                    "En producción la ruta de secretos debe ser absoluta"
                )

    def _validate_official_urls(self):
        environment_paths = {
            "PRUEBAS": "testecf",
            "CERTIFICACION": "certecf",
            "PRODUCCION": "ecf",
        }
        prefix = environment_paths[self.environment]
        services = {
            "ECF_AUTHENTICATION_URL": (
                self.authentication_url,
                "autenticacion",
            ),
            "ECF_RECEPTION_URL": (self.reception_url, "recepcion"),
            "ECF_RESULT_URL": (self.result_url, "consultaresultado"),
            "ECF_TRACK_URL": (self.track_url, "consultatrackids"),
            "ECF_STAMP_URL": (self.stamp_url, "consultatimbre"),
        }
        for name, (url, service) in services.items():
            parsed = urlsplit(url)
            expected_path = f"/{prefix}/{service}"
            try:
                port = parsed.port
            except ValueError as error:
                raise ECFConfigurationError(
                    f"{name} contiene un puerto inválido"
                ) from error
            if (
                parsed.scheme.lower() != "https"
                or parsed.hostname != "ecf.dgii.gov.do"
                or parsed.username
                or parsed.password
                or port not in {None, 443}
                or parsed.query
                or parsed.fragment
                or parsed.path.rstrip("/").lower() != expected_path
            ):
                raise ECFConfigurationError(
                    f"{name} no corresponde al servicio oficial "
                    f"{self.environment} de DGII"
                )
