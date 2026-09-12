#!/usr/bin/env python3
"""Permitir catálogo ampliable de tipos NCF tradicionales."""

import sys

import pymysql
from dotenv import load_dotenv

from crear_base_facturacion_electronica import get_database_config


load_dotenv()

NCF_DESCRIPTIONS = {
    "B01": "Factura de Crédito Fiscal",
    "B02": "Factura de Consumo",
    "B03": "Nota de Débito",
    "B04": "Nota de Crédito",
    "B11": "Comprobante de Compras",
    "B12": "Registro Único de Ingresos",
    "B13": "Comprobante para Gastos Menores",
    "B14": "Comprobante para Regímenes Especiales",
    "B15": "Comprobante Gubernamental",
    "B16": "Comprobante para Exportaciones",
    "B17": "Comprobante para Pagos al Exterior",
}


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
                SELECT DATA_TYPE
                FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=%s AND TABLE_NAME='ncf'
                  AND COLUMN_NAME='tipo'
                """,
                (database,),
            )
            tipo_column = cursor.fetchone()
            if not tipo_column:
                raise RuntimeError("La tabla ncf no contiene la columna tipo")
            if tipo_column["DATA_TYPE"].lower() != "varchar":
                cursor.execute(
                    "ALTER TABLE ncf MODIFY COLUMN tipo VARCHAR(10) NOT NULL"
                )
                print("ncf.tipo convertido a catálogo ampliable")
            else:
                print("ncf.tipo ya permite nuevos valores")

            cursor.execute(
                """
                SELECT COUNT(*) AS total
                FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=%s AND TABLE_NAME='ncf'
                  AND COLUMN_NAME='descripcion'
                """,
                (database,),
            )
            if cursor.fetchone()["total"] == 0:
                cursor.execute(
                    "ALTER TABLE ncf ADD COLUMN descripcion VARCHAR(150) "
                    "NULL AFTER tipo"
                )
                print("Agregada ncf.descripcion")
            else:
                print("ncf.descripcion ya existe")

            for code, description in NCF_DESCRIPTIONS.items():
                cursor.execute(
                    """
                    UPDATE ncf
                    SET descripcion=%s
                    WHERE tipo=%s
                      AND (descripcion IS NULL OR TRIM(descripcion)='')
                    """,
                    (description, code),
                )

        connection.commit()
        print("Catálogo NCF actualizado correctamente")
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
        print(f"Error actualizando catálogo NCF: {error}")
        raise SystemExit(1)
