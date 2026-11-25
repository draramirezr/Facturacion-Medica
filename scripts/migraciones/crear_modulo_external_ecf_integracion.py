#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Crea tablas del servicio e-CF externo (idempotente).

No ejecutar en producción sin revisión explícita.
"""

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))  # raíz del proyecto

import os
import re
import sys

import pymysql
from dotenv import load_dotenv

if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

load_dotenv()


def parse_mysql_url(url):
    if not url:
        return None
    match = re.match(r'mysql://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)', url)
    if not match:
        return None
    return {
        'user': match.group(1),
        'password': match.group(2),
        'host': match.group(3),
        'port': int(match.group(4)),
        'database': match.group(5),
        'charset': 'utf8mb4',
    }


def get_database_config():
    mysql_url = os.getenv('MYSQL_URL', '')
    if mysql_url:
        config = parse_mysql_url(mysql_url)
        if not config:
            raise ValueError('MYSQL_URL tiene un formato inválido')
        return config
    return {
        'host': os.getenv('MYSQL_HOST', 'localhost'),
        'user': os.getenv('MYSQL_USER', 'root'),
        'password': os.getenv('MYSQL_PASSWORD', ''),
        'database': os.getenv('MYSQL_DATABASE', 'facturacion_medica'),
        'port': int(os.getenv('MYSQL_PORT', '3306')),
        'charset': 'utf8mb4',
    }


def table_exists(cursor, database, table):
    cursor.execute(
        '''
        SELECT COUNT(*) AS total
        FROM information_schema.TABLES
        WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s
        ''',
        (database, table),
    )
    return cursor.fetchone()['total'] > 0


def main():
    config = get_database_config()
    database = config['database']
    config['cursorclass'] = pymysql.cursors.DictCursor
    conn = pymysql.connect(**config)
    try:
        with conn.cursor() as cursor:
            statements = [
                '''
                CREATE TABLE IF NOT EXISTS ext_integration_clients (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    nombre VARCHAR(150) NOT NULL,
                    codigo VARCHAR(50) NOT NULL,
                    estado ENUM('activo', 'inactivo', 'suspendido')
                        NOT NULL DEFAULT 'activo',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY uq_ext_clients_codigo (codigo),
                    INDEX idx_ext_clients_estado (estado)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                    COLLATE=utf8mb4_unicode_ci
                ''',
                '''
                CREATE TABLE IF NOT EXISTS ext_integration_emitters (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    client_id INT NOT NULL,
                    tenant_id INT NOT NULL,
                    rnc VARCHAR(20) NOT NULL,
                    razon_social VARCHAR(255) NOT NULL,
                    ambiente ENUM('PRUEBAS', 'CERTIFICACION', 'PRODUCCION')
                        NOT NULL DEFAULT 'PRUEBAS',
                    estado ENUM('activo', 'inactivo', 'suspendido')
                        NOT NULL DEFAULT 'activo',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        ON UPDATE CURRENT_TIMESTAMP,
                    FOREIGN KEY (client_id) REFERENCES ext_integration_clients(id)
                        ON DELETE RESTRICT,
                    FOREIGN KEY (tenant_id) REFERENCES empresas(id)
                        ON DELETE RESTRICT,
                    UNIQUE KEY uq_ext_emitter_client_rnc (client_id, rnc),
                    INDEX idx_ext_emitter_tenant (tenant_id),
                    INDEX idx_ext_emitter_estado (estado)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                    COLLATE=utf8mb4_unicode_ci
                ''',
                '''
                CREATE TABLE IF NOT EXISTS ext_integration_credentials (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    client_id INT NOT NULL,
                    emitter_id INT NULL,
                    usuario VARCHAR(100) NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    estado ENUM('activa', 'inactiva', 'suspendida')
                        NOT NULL DEFAULT 'activa',
                    fecha_expiracion DATETIME NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        ON UPDATE CURRENT_TIMESTAMP,
                    FOREIGN KEY (client_id) REFERENCES ext_integration_clients(id)
                        ON DELETE RESTRICT,
                    FOREIGN KEY (emitter_id) REFERENCES ext_integration_emitters(id)
                        ON DELETE RESTRICT,
                    UNIQUE KEY uq_ext_credentials_usuario (usuario),
                    INDEX idx_ext_credentials_client (client_id),
                    INDEX idx_ext_credentials_estado (estado)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                    COLLATE=utf8mb4_unicode_ci
                ''',
                '''
                CREATE TABLE IF NOT EXISTS ext_ecf_documents (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    client_id INT NOT NULL,
                    emitter_id INT NOT NULL,
                    tenant_id INT NOT NULL,
                    external_document_id VARCHAR(100) NULL,
                    tipo_ecf VARCHAR(10) NULL,
                    encf VARCHAR(20) NULL,
                    rnc_emisor VARCHAR(20) NOT NULL,
                    rnc_comprador VARCHAR(20) NULL,
                    fecha_documento DATE NULL,
                    moneda VARCHAR(10) NULL,
                    total DECIMAL(18, 4) NOT NULL DEFAULT 0,
                    payload_original JSON NOT NULL,
                    payload_hash CHAR(64) NOT NULL,
                    canonical_document JSON NOT NULL,
                    estado ENUM(
                        'recibido', 'rechazado', 'pendiente_emision', 'duplicado'
                    ) NOT NULL DEFAULT 'recibido',
                    error_codigo INT NULL,
                    error_mensaje VARCHAR(500) NULL,
                    response_snapshot JSON NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        ON UPDATE CURRENT_TIMESTAMP,
                    FOREIGN KEY (client_id) REFERENCES ext_integration_clients(id)
                        ON DELETE RESTRICT,
                    FOREIGN KEY (emitter_id) REFERENCES ext_integration_emitters(id)
                        ON DELETE RESTRICT,
                    FOREIGN KEY (tenant_id) REFERENCES empresas(id)
                        ON DELETE RESTRICT,
                    UNIQUE KEY uq_ext_doc_emitter_hash (emitter_id, payload_hash),
                    UNIQUE KEY uq_ext_doc_emitter_encf (emitter_id, encf),
                    INDEX idx_ext_doc_client (client_id),
                    INDEX idx_ext_doc_tenant (tenant_id),
                    INDEX idx_ext_doc_estado (estado),
                    INDEX idx_ext_doc_created (created_at),
                    INDEX idx_ext_doc_tipo (tipo_ecf)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                    COLLATE=utf8mb4_unicode_ci
                ''',
                '''
                CREATE TABLE IF NOT EXISTS ext_integration_audit (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    client_id INT NULL,
                    emitter_id INT NULL,
                    evento VARCHAR(80) NOT NULL,
                    resultado VARCHAR(40) NOT NULL,
                    ip_origen VARCHAR(45) NULL,
                    fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_ext_audit_client (client_id, fecha),
                    INDEX idx_ext_audit_evento (evento, fecha)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                    COLLATE=utf8mb4_unicode_ci
                ''',
            ]
            for stmt in statements:
                cursor.execute(stmt)
        conn.commit()
        print('Tablas external_ecf_service listas en', database)
    finally:
        conn.close()


if __name__ == '__main__':
    main()
