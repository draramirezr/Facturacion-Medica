#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fase 2: crear de forma idempotente la base de datos para e-CF.

Esta migración no genera e-NCF ni conecta con la DGII.
"""

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
        WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s AND COLUMN_NAME=%s
        """,
        (database, table, column),
    )
    return cursor.fetchone()["total"] > 0


def index_exists(cursor, database, table, index_name):
    cursor.execute(
        """
        SELECT COUNT(*) AS total
        FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s AND INDEX_NAME=%s
        """,
        (database, table, index_name),
    )
    return cursor.fetchone()["total"] > 0


def ensure_column(cursor, database, table, column, definition):
    if column_exists(cursor, database, table, column):
        print(f"{table}.{column} ya existe")
        return
    cursor.execute(f"ALTER TABLE `{table}` ADD COLUMN `{column}` {definition}")
    print(f"Agregada {table}.{column}")


def ensure_index(cursor, database, table, name, columns, unique=False):
    if index_exists(cursor, database, table, name):
        print(f"Índice {name} ya existe")
        return
    keyword = "UNIQUE INDEX" if unique else "INDEX"
    cursor.execute(
        f"ALTER TABLE `{table}` ADD {keyword} `{name}` ({columns})"
    )
    print(f"Creado índice {name}")


TABLES = [
    """
    CREATE TABLE IF NOT EXISTS ecf_configuraciones (
        id INT AUTO_INCREMENT PRIMARY KEY,
        tenant_id INT NOT NULL,
        habilitado TINYINT(1) NOT NULL DEFAULT 0,
        ambiente VARCHAR(20) NOT NULL DEFAULT 'PRUEBAS',
        certificado_referencia VARCHAR(500) NULL,
        secreto_referencia VARCHAR(500) NULL,
        certificado_huella VARCHAR(128) NULL,
        certificado_vence DATE NULL,
        certificado_validado_en DATETIME NULL,
        produccion_confirmada TINYINT(1) NOT NULL DEFAULT 0,
        creado_por INT NULL,
        actualizado_por INT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY uq_ecf_config_tenant (tenant_id),
        INDEX idx_ecf_config_habilitado (habilitado)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    """
    CREATE TABLE IF NOT EXISTS ecf_secuencias (
        id INT AUTO_INCREMENT PRIMARY KEY,
        tenant_id INT NOT NULL,
        tipo_ecf VARCHAR(2) NOT NULL,
        serie CHAR(1) NOT NULL DEFAULT 'E',
        secuencia_inicial BIGINT UNSIGNED NOT NULL,
        secuencia_final BIGINT UNSIGNED NOT NULL,
        ultimo_numero BIGINT UNSIGNED NOT NULL DEFAULT 0,
        fecha_autorizacion DATE NULL,
        fecha_vencimiento DATE NOT NULL,
        activo TINYINT(1) NOT NULL DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY uq_ecf_secuencia_rango (tenant_id, tipo_ecf, secuencia_inicial),
        INDEX idx_ecf_secuencia_activa (tenant_id, activo)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    """
    CREATE TABLE IF NOT EXISTS facturas_ecf (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        tenant_id INT NOT NULL,
        factura_id INT NOT NULL,
        tipo_ecf VARCHAR(2) NOT NULL,
        e_ncf VARCHAR(13) NULL,
        estado VARCHAR(30) NOT NULL DEFAULT 'PENDIENTE_ENVIO',
        xml_generado LONGTEXT NULL,
        xml_firmado LONGTEXT NULL,
        hash_xml_generado CHAR(64) NULL,
        hash_xml_firmado CHAR(64) NULL,
        fecha_generacion DATETIME(6) NULL,
        fecha_firma DATETIME(6) NULL,
        fecha_envio DATETIME(6) NULL,
        fecha_respuesta DATETIME(6) NULL,
        track_id VARCHAR(150) NULL,
        codigo_respuesta VARCHAR(50) NULL,
        mensaje_respuesta TEXT NULL,
        respuesta_dgii LONGTEXT NULL,
        intentos INT UNSIGNED NOT NULL DEFAULT 0,
        ultimo_error TEXT NULL,
        idempotency_key CHAR(36) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY uq_facturas_ecf_factura (factura_id),
        UNIQUE KEY uq_facturas_ecf_tenant_encf (tenant_id, e_ncf),
        UNIQUE KEY uq_facturas_ecf_idempotency (idempotency_key),
        INDEX idx_facturas_ecf_estado (tenant_id, estado),
        INDEX idx_facturas_ecf_track (track_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    """
    CREATE TABLE IF NOT EXISTS ecf_eventos (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        tenant_id INT NOT NULL,
        factura_ecf_id BIGINT NOT NULL,
        estado_anterior VARCHAR(30) NULL,
        estado_nuevo VARCHAR(30) NOT NULL,
        evento VARCHAR(80) NOT NULL,
        detalle LONGTEXT NULL,
        usuario_id INT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_ecf_eventos_documento (factura_ecf_id, created_at),
        INDEX idx_ecf_eventos_tenant (tenant_id, created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    """
    CREATE TABLE IF NOT EXISTS ecf_outbox (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        tenant_id INT NOT NULL,
        factura_ecf_id BIGINT NOT NULL,
        clave_evento VARCHAR(100) NOT NULL,
        tipo_evento VARCHAR(50) NOT NULL,
        estado VARCHAR(20) NOT NULL DEFAULT 'PENDIENTE',
        payload LONGTEXT NULL,
        intentos INT UNSIGNED NOT NULL DEFAULT 0,
        proximo_intento DATETIME NULL,
        bloqueado_en DATETIME NULL,
        bloqueado_por VARCHAR(100) NULL,
        ultimo_error TEXT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY uq_ecf_outbox_clave (clave_evento),
        INDEX idx_ecf_outbox_pendiente (estado, proximo_intento),
        INDEX idx_ecf_outbox_documento (factura_ecf_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
]


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
            ensure_column(
                cursor,
                database,
                "facturas",
                "tipo_factura",
                "VARCHAR(20) NOT NULL DEFAULT 'TRADICIONAL' AFTER numero_factura",
            )
            ensure_index(
                cursor,
                database,
                "facturas",
                "idx_facturas_tenant_tipo",
                "`tenant_id`, `tipo_factura`",
            )
            ensure_column(
                cursor,
                database,
                "factura_detalles",
                "tenant_id",
                "INT NULL AFTER id",
            )
            ensure_index(
                cursor,
                database,
                "factura_detalles",
                "idx_factura_detalles_tenant",
                "`tenant_id`",
            )

            for statement in TABLES:
                cursor.execute(statement)

            ensure_column(
                cursor,
                database,
                "ecf_configuraciones",
                "secreto_referencia",
                "VARCHAR(500) NULL AFTER certificado_referencia",
            )
            ensure_column(
                cursor,
                database,
                "ecf_configuraciones",
                "certificado_validado_en",
                "DATETIME NULL AFTER certificado_vence",
            )

            # Permitir futuros rangos del mismo tipo sin mezclar sus consecutivos.
            if index_exists(
                cursor,
                database,
                "ecf_secuencias",
                "uq_ecf_secuencia_tenant_tipo",
            ):
                cursor.execute(
                    "ALTER TABLE ecf_secuencias "
                    "DROP INDEX uq_ecf_secuencia_tenant_tipo"
                )
                print("Retirado índice antiguo de secuencia por tipo")
            ensure_index(
                cursor,
                database,
                "ecf_secuencias",
                "uq_ecf_secuencia_rango",
                "`tenant_id`, `tipo_ecf`, `secuencia_inicial`",
                unique=True,
            )

        connection.commit()
        print("Base de facturación electrónica actualizada correctamente")
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
        print(f"Error en la migración e-CF: {error}")
        raise SystemExit(1)
