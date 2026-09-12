#!/usr/bin/env python3
"""Permitir códigos ARS asociados a centros de salud."""

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
                  AND TABLE_NAME='codigo_ars'
                  AND COLUMN_NAME='centro_medico_id'
                """,
                (database,),
            )
            if cursor.fetchone()["total"] == 0:
                cursor.execute(
                    """
                    ALTER TABLE codigo_ars
                    ADD COLUMN centro_medico_id INT NULL AFTER medico_id
                    """
                )
                print("Agregada codigo_ars.centro_medico_id")
            else:
                print("codigo_ars.centro_medico_id ya existe")

            cursor.execute(
                """
                SELECT COUNT(*) AS total
                FROM information_schema.STATISTICS
                WHERE TABLE_SCHEMA=%s
                  AND TABLE_NAME='codigo_ars'
                  AND INDEX_NAME='idx_codigo_ars_centro'
                """,
                (database,),
            )
            if cursor.fetchone()["total"] == 0:
                cursor.execute(
                    """
                    ALTER TABLE codigo_ars
                    ADD INDEX idx_codigo_ars_centro (centro_medico_id)
                    """
                )
                print("Agregado índice de centro médico")

            cursor.execute(
                """
                SELECT COUNT(*) AS total
                FROM information_schema.TABLE_CONSTRAINTS
                WHERE CONSTRAINT_SCHEMA=%s
                  AND TABLE_NAME='codigo_ars'
                  AND CONSTRAINT_NAME='fk_codigo_ars_centro'
                """,
                (database,),
            )
            if cursor.fetchone()["total"] == 0:
                cursor.execute(
                    """
                    ALTER TABLE codigo_ars
                    ADD CONSTRAINT fk_codigo_ars_centro
                    FOREIGN KEY (centro_medico_id)
                    REFERENCES centros_medicos(id)
                    ON DELETE RESTRICT
                    """
                )
                print("Agregada relación con centros médicos")

        connection.commit()
        print("Relación centro de salud–ARS preparada correctamente")
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
        print(f"Error preparando codigo_ars: {error}")
        raise SystemExit(1)
