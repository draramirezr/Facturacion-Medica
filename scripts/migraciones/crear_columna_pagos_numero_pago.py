#!/usr/bin/env python3
"""Añade numero_pago a pagos si falta (idempotente). Ejecutar en Railway/producción."""

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
        if config:
            return config
    return {
        'host': os.getenv('MYSQL_HOST', 'localhost'),
        'user': os.getenv('MYSQL_USER', 'root'),
        'password': os.getenv('MYSQL_PASSWORD', ''),
        'database': os.getenv('MYSQL_DATABASE', 'facturacion_medica'),
        'port': int(os.getenv('MYSQL_PORT', '3306')),
        'charset': 'utf8mb4',
    }


def columna_existe(cursor, tabla, columna):
    cursor.execute(
        '''
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = %s AND COLUMN_NAME = %s
        LIMIT 1
        ''',
        (tabla, columna),
    )
    return cursor.fetchone() is not None


def main():
    config = get_database_config()
    config['cursorclass'] = pymysql.cursors.DictCursor
    conn = pymysql.connect(**config)
    try:
        with conn.cursor() as cursor:
            if not columna_existe(cursor, 'pagos', 'numero_pago'):
                cursor.execute(
                    '''
                    ALTER TABLE pagos
                    ADD COLUMN numero_pago VARCHAR(50) NULL
                    AFTER tenant_id
                    '''
                )
                print('Columna pagos.numero_pago creada.')
            else:
                print('pagos.numero_pago ya existe.')
            if not columna_existe(cursor, 'pagos', 'monto_total'):
                cursor.execute(
                    '''
                    ALTER TABLE pagos
                    ADD COLUMN monto_total DECIMAL(10, 2) NOT NULL DEFAULT 0.00
                    AFTER numero_pago
                    '''
                )
                print('Columna pagos.monto_total creada.')
            else:
                print('pagos.monto_total ya existe.')
        conn.commit()
    finally:
        conn.close()


if __name__ == '__main__':
    main()