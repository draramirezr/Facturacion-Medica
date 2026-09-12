"""Agrega la preferencia individual del corrector ortográfico."""

from app import app
from core.database import execute_query, execute_update


def migrate():
    with app.app_context():
        columnas = execute_query("SHOW COLUMNS FROM usuarios", fetch="all") or []
        if "idioma_correccion" not in {
            columna["Field"] for columna in columnas
        }:
            execute_update(
                "ALTER TABLE usuarios "
                "ADD COLUMN idioma_correccion VARCHAR(10) "
                "NOT NULL DEFAULT 'es' AFTER fuente_ui"
            )
            print("[OK] Agregada usuarios.idioma_correccion")
        else:
            print("[OK] usuarios.idioma_correccion ya existe")


if __name__ == "__main__":
    migrate()
