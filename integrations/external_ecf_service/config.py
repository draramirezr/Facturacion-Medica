"""Configuración del servicio e-CF externo (variables de entorno)."""

from dataclasses import dataclass
import os


class ExternalECFConfigError(RuntimeError):
    """Configuración incompleta o insegura."""


def _as_bool(value, default=False):
    if value is None:
        return default
    return str(value).strip().lower() in {'1', 'true', 'yes', 'si', 'sí', 'on'}


@dataclass(frozen=True)
class ExternalECFConfig:
    enabled: bool
    jwt_secret: str
    token_ttl_seconds: int
    environment: str
    auth_rate_limit_max: int
    auth_rate_limit_window: int

    @classmethod
    def from_env(cls, env=None):
        source = os.environ if env is None else env
        enabled = _as_bool(source.get('EXTERNAL_ECF_ENABLED'), False)
        jwt_secret = (source.get('EXTERNAL_ECF_JWT_SECRET') or '').strip()
        token_ttl = int(source.get('EXTERNAL_ECF_TOKEN_TTL', '3600') or '3600')
        environment = (
            source.get('EXTERNAL_ECF_ENVIRONMENT', 'PRUEBAS') or 'PRUEBAS'
        ).strip().upper()
        auth_max = int(source.get('EXTERNAL_ECF_AUTH_RATE_MAX', '30') or '30')
        auth_window = int(source.get('EXTERNAL_ECF_AUTH_RATE_WINDOW', '300') or '300')

        if enabled and not jwt_secret:
            raise ExternalECFConfigError(
                'EXTERNAL_ECF_JWT_SECRET es obligatorio cuando '
                'EXTERNAL_ECF_ENABLED=true'
            )
        if enabled and len(jwt_secret) < 32:
            raise ExternalECFConfigError(
                'EXTERNAL_ECF_JWT_SECRET debe tener al menos 32 caracteres'
            )
        if token_ttl < 60:
            raise ExternalECFConfigError(
                'EXTERNAL_ECF_TOKEN_TTL debe ser al menos 60 segundos'
            )
        if environment not in {'PRUEBAS', 'CERTIFICACION', 'PRODUCCION'}:
            raise ExternalECFConfigError(
                'EXTERNAL_ECF_ENVIRONMENT no permitido'
            )
        return cls(
            enabled=enabled,
            jwt_secret=jwt_secret,
            token_ttl_seconds=token_ttl,
            environment=environment,
            auth_rate_limit_max=auth_max,
            auth_rate_limit_window=auth_window,
        )
