#!/usr/bin/env python3
"""Agregar la preferencia de tipografía a los usuarios."""

import sys

import pymysql
from dotenv import load_dotenv

from crear_base_facturacion_electronica import get_database_config


load_dotenv()


def migrate():
    config = get_database_config()
    database = config["database"]
    connection = pymysql.connect(
        **config,
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=False,
    )
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT COUNT(*) AS total
                FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=%s
                  AND TABLE_NAME='usuarios'
                  AND COLUMN_NAME='fuente_ui'
                """,
                (database,),
            )
            if cursor.fetchone()["total"] == 0:
                cursor.execute(
                    """
                    ALTER TABLE usuarios
                    ADD COLUMN fuente_ui VARCHAR(30)
                    NOT NULL DEFAULT 'arsflow'
                    AFTER tema_color
                    """
                )
                print("Agregada usuarios.fuente_ui")
            else:
                print("usuarios.fuente_ui ya existe")

            cursor.execute(
                """
                UPDATE usuarios
                SET fuente_ui='arsflow'
                WHERE fuente_ui IS NULL OR TRIM(fuente_ui)=''
                """
            )
        connection.commit()
        print("Preferencia de tipografía preparada correctamente")
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


if __name__ == "__main__":
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    try:
        migrate()
    except Exception as error:
        print(f"Error agregando fuente_ui: {error}")
        raise SystemExit(1)
