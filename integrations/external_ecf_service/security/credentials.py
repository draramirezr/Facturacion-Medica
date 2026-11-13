"""Hash de contraseñas para credenciales de integración."""

from werkzeug.security import check_password_hash, generate_password_hash


def hash_integration_password(plain: str) -> str:
    return generate_password_hash(plain)


def verify_integration_password(plain: str, password_hash: str) -> bool:
    if not plain or not password_hash:
        return False
    return check_password_hash(password_hash, plain)
