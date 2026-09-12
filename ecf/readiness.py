"""Diagnóstico local previo a certificación o producción e-CF."""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from pathlib import Path
from types import SimpleNamespace

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from .validator import OFFICIAL_E31_SCHEMA_SHA256


@dataclass(frozen=True)
class ECFReadinessCheck:
    code: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class ECFReadinessReport:
    environment: str
    checks: tuple
    manual_requirements: tuple

    @property
    def ready(self):
        return all(check.passed for check in self.checks)


def _certificate_check(config):
    path = Path(config.certificate_path)
    try:
        data = path.read_bytes()
        password = (
            config.certificate_password.encode("utf-8")
            if config.certificate_password
            else None
        )
        private_key, certificate, _ = pkcs12.load_key_and_certificates(
            data, password
        )
    except (OSError, TypeError, ValueError):
        return ECFReadinessCheck(
            "certificate",
            False,
            "No se pudo abrir el certificado PKCS#12 configurado",
        )

    if private_key is None or certificate is None:
        return ECFReadinessCheck(
            "certificate",
            False,
            "El PKCS#12 no contiene certificado y clave privada",
        )
    if not isinstance(private_key, rsa.RSAPrivateKey):
        return ECFReadinessCheck(
            "certificate",
            False,
            "La clave privada no es RSA",
        )

    now = datetime.now(timezone.utc)
    if now < certificate.not_valid_before_utc:
        return ECFReadinessCheck(
            "certificate",
            False,
            "El certificado todavía no está vigente",
        )
    if now >= certificate.not_valid_after_utc:
        return ECFReadinessCheck(
            "certificate",
            False,
            "El certificado está vencido",
        )

    days = (certificate.not_valid_after_utc - now).days
    fingerprint = certificate.fingerprint(hashes.SHA256()).hex()[:16]
    return ECFReadinessCheck(
        "certificate",
        days >= 30,
        (
            f"Certificado válido; vence en {days} días; "
            f"huella SHA-256 {fingerprint}…"
            if days >= 30
            else f"El certificado vence en {days} días; debe renovarse"
        ),
    )


def assess_readiness(config):
    """Evaluar requisitos locales sin conectarse ni enviar datos a DGII."""
    checks = [
        ECFReadinessCheck(
            "enabled",
            bool(config.enabled),
            (
                "Integración e-CF habilitada"
                if config.enabled
                else "ECF_ENABLED continúa desactivado"
            ),
        ),
        ECFReadinessCheck(
            "environment",
            config.environment in {"CERTIFICACION", "PRODUCCION"},
            (
                f"Ambiente configurado: {config.environment}"
                if config.environment in {"CERTIFICACION", "PRODUCCION"}
                else "PRUEBAS no equivale a certificación ni producción"
            ),
        ),
    ]

    schema_path = (
        Path(__file__).resolve().parent
        / "schemas"
        / "e-CF-31-v1.0.xsd"
    )
    try:
        schema_digest = hashlib.sha256(schema_path.read_bytes()).hexdigest()
    except OSError:
        schema_digest = ""
    checks.append(
        ECFReadinessCheck(
            "official_schema",
            schema_digest == OFFICIAL_E31_SCHEMA_SHA256,
            (
                "XSD oficial E31 íntegro"
                if schema_digest == OFFICIAL_E31_SCHEMA_SHA256
                else "El XSD E31 falta o no coincide con la copia verificada"
            ),
        )
    )

    if config.enabled:
        if config.tenant_secrets_root:
            tenant_root = Path(config.tenant_secrets_root)
            complete_tenants = 0
            if tenant_root.is_dir():
                for directory in tenant_root.glob("tenant-*"):
                    certificate = (
                        directory / "certificate.p12"
                        if (directory / "certificate.p12").is_file()
                        else directory / "certificate.pfx"
                    )
                    secret = directory / "password.txt"
                    if not (
                        directory.is_dir()
                        and certificate.is_file()
                        and secret.is_file()
                    ):
                        continue
                    try:
                        password = secret.read_text(encoding="utf-8").strip()
                    except (OSError, UnicodeError):
                        continue
                    check = _certificate_check(SimpleNamespace(
                        certificate_path=str(certificate),
                        certificate_password=password,
                    ))
                    if check.passed:
                        complete_tenants += 1
            checks.append(
                ECFReadinessCheck(
                    "tenant_certificate_store",
                    tenant_root.is_dir() and complete_tenants > 0,
                    (
                        f"Almacén multi-tenant disponible con "
                        f"{complete_tenants} cuenta(s) con certificado válido"
                        if complete_tenants > 0
                        else "El almacén no contiene credenciales completas por cuenta"
                    ),
                )
            )
        else:
            checks.append(_certificate_check(config))
        checks.append(
            ECFReadinessCheck(
                "production_gate",
                (
                    config.environment != "PRODUCCION"
                    or (
                        config.allow_production
                        and config.flask_environment == "production"
                        and bool(config.tenant_secrets_root)
                    )
                ),
                (
                    "Doble habilitación productiva y secreto externo verificados"
                    if config.environment == "PRODUCCION"
                    else "El envío permanece fuera de producción"
                ),
            )
        )

    return ECFReadinessReport(
        environment=config.environment,
        checks=tuple(checks),
        manual_requirements=(
            "Completar y aprobar el proceso de certificación de DGII.",
            "Confirmar que el certificado está autorizado o delegado para cada emisor.",
            "Cargar rangos E31 vigentes otorgados por DGII para cada cuenta.",
            "Resolver envíos inciertos antes del corte productivo.",
            "Configurar respaldo cifrado y retención legal de XML y respuestas.",
            "Configurar monitoreo de rechazos, vencimiento de certificado y secuencias.",
        ),
    )
