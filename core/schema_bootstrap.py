"""Instala el esquema multiempresa en la base configurada."""

import logging
from pathlib import Path

import pymysql

from core.config import DATABASE_CONFIG, REQUIRED_TENANT_TABLES

logger = logging.getLogger(__name__)

SCHEMA_PATH = Path(__file__).resolve().parent.parent / 'database_schema.sql'


def extraer_sentencias_esquema(script):
    """Separar CREATE TABLE del script, sin CREATE DATABASE ni USE."""
    sentencias = []
    acumulado = []
    for linea in script.splitlines():
        recorte = linea.strip()
        if not recorte or recorte.startswith('--'):
            continue
        acumulado.append(linea)
        if not recorte.endswith(';'):
            continue
        sentencia = '\n'.join(acumulado).strip().rstrip(';').strip()
        acumulado = []
        if not sentencia:
            continue
        cabecera = sentencia.split(None, 2)
        verbo = cabecera[0].upper() if cabecera else ''
        objeto = cabecera[1].upper() if len(cabecera) > 1 else ''
        if verbo == 'USE' or (verbo == 'CREATE' and objeto == 'DATABASE'):
            continue
        sentencias.append(sentencia)
    return sentencias


def _tablas_con_tenant(cursor, database):
    placeholders = ', '.join(['%s'] * len(REQUIRED_TENANT_TABLES))
    cursor.execute(
        f'''
        SELECT TABLE_NAME
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = %s
          AND COLUMN_NAME = 'tenant_id'
          AND TABLE_NAME IN ({placeholders})
        ''',
        (database, *REQUIRED_TENANT_TABLES),
    )
    return {fila['TABLE_NAME'] for fila in cursor.fetchall()}


def _existe_tabla(cursor, database, tabla):
    cursor.execute(
        '''
        SELECT 1
        FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s
        ''',
        (database, tabla),
    )
    return cursor.fetchone() is not None


def _sembrar_permisos(cursor, database):
    if not _existe_tabla(cursor, database, 'permisos'):
        return
    from rbac_catalog import PERMISOS

    for permiso in PERMISOS:
        cursor.execute(
            '''
            INSERT INTO permisos (codigo, grupo, nombre, descripcion, activo)
            VALUES (%s, %s, %s, %s, 1)
            ON DUPLICATE KEY UPDATE
                grupo = VALUES(grupo),
                nombre = VALUES(nombre),
                descripcion = VALUES(descripcion),
                activo = 1
            ''',
            (
                permiso['codigo'],
                permiso['grupo'],
                permiso['nombre'],
                permiso['descripcion'],
            ),
        )


def _asegurar_columnas_activacion(cursor, database):
    columnas = {
        'email_verificado': 'TINYINT(1) NOT NULL DEFAULT 1',
        'activacion_token': 'VARCHAR(255) NULL',
        'activacion_token_expiracion': 'DATETIME NULL',
    }
    for nombre, definicion in columnas.items():
        cursor.execute(
            '''
            SELECT 1
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = %s
              AND TABLE_NAME = 'usuarios'
              AND COLUMN_NAME = %s
            ''',
            (database, nombre),
        )
        if cursor.fetchone():
            continue
        cursor.execute(
            f'ALTER TABLE usuarios ADD COLUMN `{nombre}` {definicion}'
        )


def _asegurar_columnas_smtp_empresa(cursor, database):
    columnas = {
        'smtp_host': 'VARCHAR(255) NULL',
        'smtp_port': 'INT NULL',
        'smtp_usuario': 'VARCHAR(255) NULL',
        'smtp_password_cifrado': 'TEXT NULL',
        'smtp_remitente': 'VARCHAR(255) NULL',
        'smtp_nombre_remitente': 'VARCHAR(150) NULL',
        'smtp_usar_tls': 'TINYINT(1) NOT NULL DEFAULT 1',
    }
    for nombre, definicion in columnas.items():
        cursor.execute(
            '''
            SELECT 1
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = %s
              AND TABLE_NAME = 'empresas'
              AND COLUMN_NAME = %s
            ''',
            (database, nombre),
        )
        if cursor.fetchone():
            continue
        cursor.execute(
            f'ALTER TABLE empresas ADD COLUMN `{nombre}` {definicion}'
        )


def _asegurar_columnas_confirmacion_cita(cursor, database):
    columnas = {
        'confirmacion_token_hash': 'VARCHAR(64) NULL',
        'confirmacion_token_expiracion': 'DATETIME NULL',
        'recordatorio_enviado': 'TINYINT(1) NOT NULL DEFAULT 0',
    }
    for nombre, definicion in columnas.items():
        cursor.execute(
            '''
            SELECT 1
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = %s
              AND TABLE_NAME = 'citas_medicas'
              AND COLUMN_NAME = %s
            ''',
            (database, nombre),
        )
        if cursor.fetchone():
            continue
        cursor.execute(
            f'ALTER TABLE citas_medicas ADD COLUMN `{nombre}` {definicion}'
        )


def _asegurar_columnas_presencia_chat(cursor, database):
    cursor.execute(
        '''
        SELECT 1
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = %s
          AND TABLE_NAME = 'usuarios'
          AND COLUMN_NAME = 'last_seen_at'
        ''',
        (database,),
    )
    if cursor.fetchone():
        return
    cursor.execute(
        'ALTER TABLE usuarios ADD COLUMN `last_seen_at` DATETIME NULL'
    )


def bootstrap_required_schema(connection_factory=None):
    """Crear tablas faltantes en la base actual y sembrar permisos."""
    factory = connection_factory or pymysql.connect
    config = DATABASE_CONFIG.copy()
    config['cursorclass'] = pymysql.cursors.DictCursor
    database = config['database']
    connection = factory(**config)
    aplicadas = False
    try:
        with connection.cursor() as cursor:
            faltantes = set(REQUIRED_TENANT_TABLES) - _tablas_con_tenant(
                cursor, database
            )
            if faltantes:
                logger.warning(
                    'Esquema incompleto en %s. Instalando tablas: %s',
                    database,
                    ', '.join(sorted(faltantes)),
                )
                script = SCHEMA_PATH.read_text(encoding='utf-8')
                for sentencia in extraer_sentencias_esquema(script):
                    cursor.execute(sentencia)
                aplicadas = True
            _sembrar_permisos(cursor, database)
            _asegurar_columnas_activacion(cursor, database)
            _asegurar_columnas_smtp_empresa(cursor, database)
            _asegurar_columnas_confirmacion_cita(cursor, database)
            _asegurar_columnas_presencia_chat(cursor, database)
        connection.commit()
    except Exception:
        try:
            connection.rollback()
        except Exception:
            pass
        raise
    finally:
        connection.close()
    return aplicadas
