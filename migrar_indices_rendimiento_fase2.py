#!/usr/bin/env python
"""Crear índices compuestos de Fase 2 de forma idempotente."""

import pymysql

from core.config import DATABASE_CONFIG


INDEX_SPECS = (
    ('pacientes', 'idx_pacientes_tenant_nombre', ('tenant_id', 'nombre')),
    ('pacientes', 'idx_pacientes_tenant_nss_ars', ('tenant_id', 'nss', 'ars_id')),
    ('pacientes', 'idx_pacientes_tenant_cedula', ('tenant_id', 'cedula')),
    ('pacientes', 'idx_pacientes_tenant_telefono', ('tenant_id', 'telefono')),
    (
        'pacientes_pendientes',
        'idx_pendientes_tenant_estado_fecha',
        ('tenant_id', 'estado', 'fecha_servicio', 'id'),
    ),
    (
        'pacientes_pendientes',
        'idx_pendientes_tenant_medico_estado',
        ('tenant_id', 'medico_id', 'estado'),
    ),
    (
        'pacientes_pendientes',
        'idx_pendientes_tenant_ars_estado',
        ('tenant_id', 'ars_id', 'estado'),
    ),
    (
        'facturas',
        'idx_facturas_tenant_fecha',
        ('tenant_id', 'fecha_emision', 'id'),
    ),
    (
        'facturas',
        'idx_facturas_tenant_ars_fecha',
        ('tenant_id', 'ars_id', 'fecha_emision'),
    ),
    ('facturas', 'idx_facturas_tenant_ncf', ('tenant_id', 'ncf')),
    ('pagos', 'idx_pagos_tenant_fecha', ('tenant_id', 'fecha_pago', 'id')),
    (
        'reclamaciones',
        'idx_reclamaciones_tenant_fecha',
        ('tenant_id', 'fecha_reclamacion', 'id'),
    ),
    ('pago_facturas', 'idx_pago_facturas_factura', ('factura_id', 'pago_id')),
    ('medicos', 'idx_medicos_tenant_activo_nombre', ('tenant_id', 'activo', 'nombre')),
    ('ars', 'idx_ars_tenant_activo_nombre', ('tenant_id', 'activo', 'nombre')),
)


def existing_index_columns(cursor, table):
    cursor.execute(
        '''
        SELECT INDEX_NAME, COLUMN_NAME, SEQ_IN_INDEX
        FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s
        ORDER BY INDEX_NAME, SEQ_IN_INDEX
        ''',
        (DATABASE_CONFIG['database'], table),
    )
    indexes = {}
    for row in cursor.fetchall():
        indexes.setdefault(row['INDEX_NAME'], []).append(row['COLUMN_NAME'])
    return {name: tuple(columns) for name, columns in indexes.items()}


def table_columns(cursor, table):
    cursor.execute(
        '''
        SELECT COLUMN_NAME
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s
        ''',
        (DATABASE_CONFIG['database'], table),
    )
    return {row['COLUMN_NAME'] for row in cursor.fetchall()}


def migrate():
    config = DATABASE_CONFIG.copy()
    config['cursorclass'] = pymysql.cursors.DictCursor
    connection = pymysql.connect(**config)
    created = 0
    skipped = 0
    try:
        with connection.cursor() as cursor:
            for table, index_name, columns in INDEX_SPECS:
                available = table_columns(cursor, table)
                if not available or not set(columns).issubset(available):
                    print(
                        f'OMITIDO {table}.{index_name}: tabla o columnas ausentes'
                    )
                    skipped += 1
                    continue

                indexes = existing_index_columns(cursor, table)
                if (
                    index_name in indexes
                    or any(existing[:len(columns)] == columns for existing in indexes.values())
                ):
                    print(f'OK {table}.{index_name}: ya cubierto')
                    skipped += 1
                    continue

                quoted_columns = ', '.join(f'`{column}`' for column in columns)
                cursor.execute(
                    f'ALTER TABLE `{table}` '
                    f'ADD INDEX `{index_name}` ({quoted_columns})'
                )
                print(f'CREADO {table}.{index_name}')
                created += 1
        connection.commit()
    finally:
        connection.close()

    print(f'Índices creados: {created}; omitidos/cubiertos: {skipped}')


if __name__ == '__main__':
    migrate()
