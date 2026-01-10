#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script para agregar columna tipo_empresa a la tabla empresas
Ejecutar: python agregar_tipo_empresa.py
"""

import os
import sys
from dotenv import load_dotenv
import pymysql

load_dotenv()

def parse_mysql_url(url):
    """Parsear URL de MySQL"""
    if url.startswith('mysql://'):
        url = url[8:]
        parts = url.split('@')
        if len(parts) == 2:
            auth, host_db = parts
            user, password = auth.split(':')
            host_port, database = host_db.split('/')
            if ':' in host_port:
                host, port = host_port.split(':')
            else:
                host = host_port
                port = 3306
            return {
                'host': host,
                'user': user,
                'password': password,
                'database': database,
                'port': int(port),
                'charset': 'utf8mb4'
            }
    return None

mysql_url = os.getenv('MYSQL_URL', '')
if mysql_url:
    parsed_config = parse_mysql_url(mysql_url)
    if parsed_config:
        DATABASE_CONFIG = parsed_config
    else:
        raise Exception("MYSQL_URL inválida")
else:
    DATABASE_CONFIG = {
        'host': os.getenv('MYSQL_HOST', 'localhost'),
        'user': os.getenv('MYSQL_USER', 'root'),
        'password': os.getenv('MYSQL_PASSWORD', ''),
        'database': os.getenv('MYSQL_DATABASE', 'facturacion_medica'),
        'port': int(os.getenv('MYSQL_PORT', '3306')),
        'charset': 'utf8mb4'
    }

def agregar_columna_tipo_empresa():
    """Agregar columna tipo_empresa a la tabla empresas"""
    conn = None
    cursor = None
    try:
        conn = pymysql.connect(**DATABASE_CONFIG)
        cursor = conn.cursor()
        
        # Verificar si la columna ya existe
        cursor.execute("""
            SELECT COUNT(*) as count 
            FROM information_schema.COLUMNS 
            WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME = 'empresas' 
            AND COLUMN_NAME = 'tipo_empresa'
        """)
        result = cursor.fetchone()
        
        if result and result[0] > 0:
            print("✅ La columna 'tipo_empresa' ya existe en la tabla 'empresas'")
            return
        
        # Agregar la columna
        cursor.execute("""
            ALTER TABLE empresas 
            ADD COLUMN tipo_empresa ENUM('medico', 'centro_salud') NULL 
            AFTER estado
        """)
        
        conn.commit()
        print("✅ Columna 'tipo_empresa' agregada exitosamente a la tabla 'empresas'")
        print("   Tipo: ENUM('medico', 'centro_salud')")
        print("   Posición: Después de 'estado'")
        
    except Exception as e:
        if conn:
            conn.rollback()
        print(f"❌ Error al agregar columna: {e}")
        sys.exit(1)
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

if __name__ == '__main__':
    print("=" * 60)
    print("  AGREGAR COLUMNA tipo_empresa A TABLA empresas")
    print("=" * 60)
    print()
    print(f"Base de datos: {DATABASE_CONFIG['database']}")
    print(f"Host: {DATABASE_CONFIG['host']}")
    print()
    
    # Ejecutar automáticamente sin confirmación
    agregar_columna_tipo_empresa()
    print()
    print("=" * 60)
    print("  PROCESO COMPLETADO")
    print("=" * 60)

