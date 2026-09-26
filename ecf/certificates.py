"""Resolución aislada de certificados e-CF por tenant."""

from dataclasses import dataclass, field
from pathlib import Path

from .signer import ECFSigner, ECFSigningError, MAX_CERTIFICATE_BYTES


MAX_SECRET_BYTES = 4096


class ECFCertificateResolutionError(ValueError):
    """No existe una credencial segura y válida para la cuenta."""


@dataclass(frozen=True)
class ResolvedTenantCertificate:
    tenant_id: int
    certificate_path: Path
    certificate_password: str = field(repr=False)
    certificate_reference: str = ""
    secret_reference: str = field(default="", repr=False)
    legacy_fallback: bool = False

    def signer(self):
        return ECFSigner(
            self.certificate_path,
            self.certificate_password,
        )


class TenantCertificateProvider:
    """Resolver credenciales sin almacenar archivos ni contraseñas en la BD."""

    def __init__(self, config):
        self.config = config
        self.root = (
            Path(config.tenant_secrets_root).resolve()
            if config.tenant_secrets_root
            else None
        )

    def resolve(self, tenant_id, tenant_config=None):
        try:
            tenant_id = int(tenant_id)
        except (TypeError, ValueError) as error:
            raise ECFCertificateResolutionError(
                "La cuenta del certificado no es válida"
            ) from error
        if tenant_id <= 0:
            raise ECFCertificateResolutionError(
                "La cuenta del certificado no es válida"
            )

        if self.root is None:
            if self.config.environment == "PRODUCCION":
                raise ECFCertificateResolutionError(
                    "Producción requiere certificados aislados por cuenta"
                )
            return ResolvedTenantCertificate(
                tenant_id=tenant_id,
                certificate_path=Path(self.config.certificate_path),
                certificate_password=self.config.certificate_password,
                certificate_reference="compatibilidad-global",
                secret_reference="compatibilidad-global",
                legacy_fallback=True,
            )

        record = tenant_config or {}
        certificate_reference = str(
            record.get("certificado_referencia") or ""
        ).strip()
        secret_reference = str(
            record.get("secreto_referencia") or ""
        ).strip()

        if not certificate_reference:
            p12_reference = f"tenant-{tenant_id}/certificate.p12"
            pfx_reference = f"tenant-{tenant_id}/certificate.pfx"
            certificate_reference = (
                p12_reference
                if self._resolve_reference(p12_reference).is_file()
                else pfx_reference
            )
        if not secret_reference:
            secret_reference = f"tenant-{tenant_id}/password.txt"

        certificate_path = self._resolve_reference(certificate_reference)
        secret_path = self._resolve_reference(secret_reference)
        if (
            certificate_path.suffix.lower() not in {".p12", ".pfx"}
            or not certificate_path.is_file()
        ):
            raise ECFCertificateResolutionError(
                "La cuenta no tiene un certificado PKCS#12 configurado"
            )
        if not secret_path.is_file():
            raise ECFCertificateResolutionError(
                "La cuenta no tiene configurado el secreto del certificado"
            )
        try:
            if secret_path.stat().st_size > MAX_SECRET_BYTES:
                raise ECFCertificateResolutionError(
                    "El secreto del certificado supera el tamaño permitido"
                )
            password = secret_path.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError) as error:
            raise ECFCertificateResolutionError(
                "No se pudo leer el secreto del certificado"
            ) from error
        if not password:
            raise ECFCertificateResolutionError(
                "El secreto del certificado está vacío"
            )

        return ResolvedTenantCertificate(
            tenant_id=tenant_id,
            certificate_path=certificate_path,
            certificate_password=password,
            certificate_reference=certificate_reference,
            secret_reference=secret_reference,
        )

    def inspect(self, tenant_id, expected_signer_id, tenant_config=None):
        resolved = self.resolve(tenant_id, tenant_config)
        try:
            metadata = resolved.signer().inspect_certificate(
                expected_signer_id
            )
        except ECFSigningError as error:
            raise ECFCertificateResolutionError(str(error)) from error
        return resolved, metadata

    def store(self, tenant_id, certificate_bytes, password, expected_signer_id=None):
        """Guardar el PKCS#12 y su secreto en el almacén de esta cuenta."""
        try:
            tenant_id = int(tenant_id)
        except (TypeError, ValueError) as error:
            raise ECFCertificateResolutionError(
                "La cuenta del certificado no es válida"
            ) from error
        if tenant_id <= 0:
            raise ECFCertificateResolutionError(
                "La cuenta del certificado no es válida"
            )
        if self.root is None:
            raise ECFCertificateResolutionError(
                "El servidor no tiene almacén de certificados por cuenta. "
                "Configure ECF_TENANT_SECRETS_ROOT."
            )
        try:
            self.root.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            raise ECFCertificateResolutionError(
                "No se pudo preparar el almacén de certificados de la cuenta"
            ) from error
        if (
            not certificate_bytes
            or len(certificate_bytes) > MAX_CERTIFICATE_BYTES
        ):
            raise ECFCertificateResolutionError(
                "El archivo de certificado no es válido"
            )
        password = str(password or "").strip()
        if not password:
            raise ECFCertificateResolutionError(
                "Debe indicar la contraseña del certificado"
            )
        if len(password.encode("utf-8")) > MAX_SECRET_BYTES:
            raise ECFCertificateResolutionError(
                "El secreto del certificado supera el tamaño permitido"
            )

        tenant_dir = self._resolve_reference(f"tenant-{tenant_id}")
        tenant_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp_certificate = tenant_dir / ".certificate.p12.tmp"
        tmp_secret = tenant_dir / ".password.txt.tmp"
        try:
            tmp_certificate.write_bytes(certificate_bytes)
            tmp_certificate.chmod(0o600)
            tmp_secret.write_text(password, encoding="utf-8")
            tmp_secret.chmod(0o600)
            metadata = ECFSigner(
                tmp_certificate, password
            ).inspect_certificate(expected_signer_id)
            tmp_certificate.replace(tenant_dir / "certificate.p12")
            tmp_secret.replace(tenant_dir / "password.txt")
        except ECFSigningError as error:
            tmp_certificate.unlink(missing_ok=True)
            tmp_secret.unlink(missing_ok=True)
            raise ECFCertificateResolutionError(str(error)) from error
        except OSError as error:
            tmp_certificate.unlink(missing_ok=True)
            tmp_secret.unlink(missing_ok=True)
            raise ECFCertificateResolutionError(
                "No se pudo guardar el certificado de la cuenta"
            ) from error
        extra_pfx = tenant_dir / "certificate.pfx"
        if extra_pfx.is_file():
            extra_pfx.unlink()
        return metadata

    def _resolve_reference(self, reference):
        reference_path = Path(str(reference or "").strip())
        if not reference_path.parts or reference_path.is_absolute():
            raise ECFCertificateResolutionError(
                "La referencia del certificado no es válida"
            )
        candidate = (self.root / reference_path).resolve()
        try:
            candidate.relative_to(self.root)
        except ValueError as error:
            raise ECFCertificateResolutionError(
                "La referencia del certificado sale del almacén seguro"
            ) from error
        return candidate
