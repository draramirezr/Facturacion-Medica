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
