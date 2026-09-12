#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Migración idempotente para habilitar multiempresa en la tabla ``ars``."""

import os
import re
import sys

import pymysql
from dotenv import load_dotenv


if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

load_dotenv()


def parse_mysql_url(url):
    """Convertir MYSQL_URL al formato esperado por PyMySQL."""
    if not url:
        return None

    match = re.match(r"mysql://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)", url)
    if not match:
        return None

    return {
        "user": match.group(1),
        "password": match.group(2),
        "host": match.group(3),
        "port": int(match.group(4)),
        "database": match.group(5),
        "charset": "utf8mb4",
    }


def get_database_config():
    """Obtener la misma configuración de base de datos utilizada por la app."""
    mysql_url = os.getenv("MYSQL_URL", "")
    if mysql_url:
        config = parse_mysql_url(mysql_url)
        if not config:
            raise ValueError("MYSQL_URL tiene un formato inválido")
        return config

    return {
        "host": os.getenv("MYSQL_HOST", "localhost"),
        "user": os.getenv("MYSQL_USER", "root"),
        "password": os.getenv("MYSQL_PASSWORD", ""),
        "database": os.getenv("MYSQL_DATABASE", "facturacion_medica"),
        "port": int(os.getenv("MYSQL_PORT", "3306")),
        "charset": "utf8mb4",
    }


def column_exists(cursor, database, table, column):
    cursor.execute(
        """
        SELECT COUNT(*) AS total
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = %s
          AND TABLE_NAME = %s
          AND COLUMN_NAME = %s
        """,
        (database, table, column),
    )
    return cursor.fetchone()["total"] > 0


def index_exists(cursor, database, table, index_name):
    cursor.execute(
        """
        SELECT COUNT(*) AS total
        FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA = %s
          AND TABLE_NAME = %s
          AND INDEX_NAME = %s
        """,
        (database, table, index_name),
    )
    return cursor.fetchone()["total"] > 0


def resolve_default_tenant(cursor):
    """Determinar de forma segura a qué empresa pertenecen los registros antiguos."""
    configured_tenant = os.getenv("DEFAULT_TENANT_ID")
    if configured_tenant:
        cursor.execute("SELECT id FROM empresas WHERE id = %s", (configured_tenant,))
        if not cursor.fetchone():
            raise RuntimeError(
                f"DEFAULT_TENANT_ID={configured_tenant} no existe en empresas"
            )
        return int(configured_tenant)

    cursor.execute("SELECT id FROM empresas ORDER BY id")
    empresas = cursor.fetchall()
    if len(empresas) != 1:
        raise RuntimeError(
            "No se puede asignar automáticamente las ARS antiguas: "
            "configure DEFAULT_TENANT_ID porque existe más de una empresa"
        )
    return empresas[0]["id"]


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
            if not column_exists(cursor, database, "ars", "tenant_id"):
                print("Agregando ars.tenant_id...")
                cursor.execute(
                    """
                    ALTER TABLE ars
                    ADD COLUMN tenant_id INT NULL AFTER id,
                    ADD INDEX idx_ars_tenant (tenant_id)
                    """
                )
            else:
                print("ars.tenant_id ya existe")

            cursor.execute("SELECT COUNT(*) AS total FROM ars WHERE tenant_id IS NULL")
            pendientes = cursor.fetchone()["total"]
            if pendientes:
                tenant_id = resolve_default_tenant(cursor)
                cursor.execute(
                    "UPDATE ars SET tenant_id = %s WHERE tenant_id IS NULL",
                    (tenant_id,),
                )
                print(f"{pendientes} ARS asignadas a la empresa {tenant_id}")

            cursor.execute(
                """
                SELECT IS_NULLABLE
                FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA = %s
                  AND TABLE_NAME = 'ars'
                  AND COLUMN_NAME = 'tenant_id'
                """,
                (database,),
            )
            if cursor.fetchone()["IS_NULLABLE"] == "YES":
                cursor.execute(
                    "ALTER TABLE ars MODIFY COLUMN tenant_id INT NOT NULL AFTER id"
                )

            # El código de una ARS debe ser único dentro de cada empresa, no globalmente.
            if index_exists(cursor, database, "ars", "codigo"):
                cursor.execute("ALTER TABLE ars DROP INDEX codigo")

            if not index_exists(cursor, database, "ars", "unique_ars_tenant_codigo"):
                cursor.execute(
                    """
                    ALTER TABLE ars
                    ADD UNIQUE INDEX unique_ars_tenant_codigo (tenant_id, codigo)
                    """
                )

        connection.commit()
        print("Migración completada correctamente")
        return True
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


if __name__ == "__main__":
    try:
        migrate()
    except Exception as error:
        print(f"Error en la migración: {error}")
        raise SystemExit(1)
