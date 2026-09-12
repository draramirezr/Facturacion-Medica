"""Agrega los campos del responsable para pacientes menores de edad."""

from app import app
from core.database import execute_query, execute_update


def agregar_campos_pariente():
    with app.app_context():
        columnas = execute_query("SHOW COLUMNS FROM pacientes", fetch="all") or []
        existentes = {columna["Field"] for columna in columnas}

        if "nombre_pariente" not in existentes:
            execute_update(
                "ALTER TABLE pacientes "
                "ADD COLUMN nombre_pariente VARCHAR(200) NULL AFTER sexo"
            )
            print("[OK] Columna nombre_pariente agregada")

        if "parentesco" not in existentes:
            execute_update(
                "ALTER TABLE pacientes "
                "ADD COLUMN parentesco VARCHAR(50) NULL AFTER nombre_pariente"
            )
            print("[OK] Columna parentesco agregada")

        if "cedula_pariente" not in existentes:
            execute_update(
                "ALTER TABLE pacientes "
                "ADD COLUMN cedula_pariente VARCHAR(11) NULL AFTER nombre_pariente"
            )
            print("[OK] Columna cedula_pariente agregada")

        if "telefono_pariente" not in existentes:
            execute_update(
                "ALTER TABLE pacientes "
                "ADD COLUMN telefono_pariente VARCHAR(10) NULL AFTER cedula_pariente"
            )
            print("[OK] Columna telefono_pariente agregada")

        if {"nombre_pariente", "cedula_pariente", "telefono_pariente", "parentesco"}.issubset(existentes):
            print("[OK] Las columnas ya existían")


if __name__ == "__main__":
    agregar_campos_pariente()
