#!/usr/bin/env python3
"""Permitir identificar tipos e-CF personalizados en sus secuencias."""

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
                  AND TABLE_NAME='ecf_secuencias'
                  AND COLUMN_NAME='descripcion_tipo'
                """,
                (database,),
            )
            if cursor.fetchone()["total"] == 0:
                cursor.execute(
                    """
                    ALTER TABLE ecf_secuencias
                    ADD COLUMN descripcion_tipo VARCHAR(150)
                    NULL AFTER tipo_ecf
                    """
                )
                print("Agregada ecf_secuencias.descripcion_tipo")
            else:
                print("ecf_secuencias.descripcion_tipo ya existe")

        connection.commit()
        print("Catálogo personalizado e-CF preparado correctamente")
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
        print(f"Error preparando tipos e-CF personalizados: {error}")
        raise SystemExit(1)
