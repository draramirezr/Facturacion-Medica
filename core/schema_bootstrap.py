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


# El orden importa: almacen_movimientos tiene FK hacia almacen_articulos.
TABLAS_MODULOS_OPCIONALES = (
    'constancias_medicas',
    'almacen_articulos',
    'almacen_movimientos',
)

# Permisos nuevos que heredan los roles (de sistema o personalizados) que ya
# tenían el permiso equivalente. Solo se aplica la primera vez que el permiso
# aparece en la base, para no revertir cambios del administrador.
PERMISOS_HEREDADOS = {
    'constancias.ver': 'licencias.ver',
    'constancias.crear': 'licencias.crear',
    'constancias.editar': 'licencias.editar',
    'constancias.anular': 'licencias.anular',
    'constancias.imprimir': 'licencias.imprimir',
    # Quien registra emergencias consume del almacén; quien edita catálogos
    # administra los artículos.
    'almacen.ver': 'emergencia.crear',
    'almacen.movimientos': 'emergencia.crear',
    'almacen.gestionar': 'catalogos.editar',
}


def _asegurar_tablas_modulos(cursor):
    """Crear tablas de módulos agregados después de instalar la base."""
    script = SCHEMA_PATH.read_text(encoding='utf-8')
    for sentencia in extraer_sentencias_esquema(script):
        for tabla in TABLAS_MODULOS_OPCIONALES:
            if sentencia.startswith(f'CREATE TABLE IF NOT EXISTS {tabla} '):
                cursor.execute(sentencia)


def _permisos_existentes(cursor, database, codigos):
    if not codigos or not _existe_tabla(cursor, database, 'permisos'):
        return set()
    placeholders = ', '.join(['%s'] * len(codigos))
    cursor.execute(
        f'SELECT codigo FROM permisos WHERE codigo IN ({placeholders})',
        tuple(codigos),
    )
    return {fila['codigo'] for fila in cursor.fetchall()}


def _heredar_permisos_nuevos(cursor, database, ya_existian):
    """Dar los permisos recién sembrados a los roles con el permiso base."""
    if not _existe_tabla(cursor, database, 'rol_permisos'):
        return
    for nuevo, base in PERMISOS_HEREDADOS.items():
        if nuevo in ya_existian:
            continue
        cursor.execute(
            '''
            INSERT IGNORE INTO rol_permisos (tenant_id, rol_id, permiso_id)
            SELECT rp.tenant_id, rp.rol_id, pn.id
            FROM rol_permisos rp
            JOIN permisos pb ON pb.id = rp.permiso_id AND pb.codigo = %s
            JOIN permisos pn ON pn.codigo = %s
            ''',
            (base, nuevo),
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


def _asegurar_columnas_ecf_emisor(cursor, database):
    if not _existe_tabla(cursor, database, 'ecf_configuraciones'):
        return
    columnas = {
        'rnc_emisor': 'VARCHAR(20) NULL',
        'razon_social_emisor': 'VARCHAR(200) NULL',
        'direccion_emisor': 'VARCHAR(255) NULL',
        'fecha_vencimiento_secuencia': 'VARCHAR(20) NULL',
        'last_test_at': 'DATETIME NULL',
        'last_test_json': 'LONGTEXT NULL',
    }
    for nombre, definicion in columnas.items():
        cursor.execute(
            '''
            SELECT 1
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = %s
              AND TABLE_NAME = 'ecf_configuraciones'
              AND COLUMN_NAME = %s
            ''',
            (database, nombre),
        )
        if cursor.fetchone():
            continue
        cursor.execute(
            f'ALTER TABLE ecf_configuraciones ADD COLUMN `{nombre}` {definicion}'
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


def _asegurar_columnas_ars(cursor, database):
    if not _existe_tabla(cursor, database, 'ars'):
        return
    cursor.execute(
        '''
        SELECT 1
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = %s
          AND TABLE_NAME = 'ars'
          AND COLUMN_NAME = 'tipo_ncf'
        ''',
        (database,),
    )
    if cursor.fetchone():
        return
    cursor.execute(
        'ALTER TABLE ars ADD COLUMN `tipo_ncf` VARCHAR(10) NULL '
        'AFTER `rnc`'
    )


def _asegurar_columna(cursor, database, tabla, columna, definicion):
    if not _existe_tabla(cursor, database, tabla):
        return
    cursor.execute(
        '''
        SELECT 1
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = %s
          AND TABLE_NAME = %s
          AND COLUMN_NAME = %s
        ''',
        (database, tabla, columna),
    )
    if cursor.fetchone():
        return
    cursor.execute(
        f'ALTER TABLE `{tabla}` ADD COLUMN `{columna}` {definicion}'
    )


def _asegurar_columnas_centro_contexto(cursor, database):
    """Centro de captura/atención para médicos multi-centro."""
    _asegurar_columna(
        cursor, database, 'pacientes', 'centro_medico_id',
        'INT NULL AFTER ars_id',
    )
    _asegurar_columna(
        cursor, database, 'consultas_clinicas', 'centro_medico_id',
        'INT NULL AFTER medico_id',
    )
    _asegurar_columna(
        cursor, database, 'citas_medicas', 'centro_medico_id',
        'INT NULL AFTER medico_id',
    )


def _asegurar_columnas_cambio_password(cursor, database):
    for columna, definicion in (
        ('password_pendiente_hash', 'VARCHAR(255) NULL'),
        ('password_cambio_token', 'VARCHAR(255) NULL'),
        ('password_cambio_expira', 'DATETIME NULL'),
        ('password_pendiente_temporal', 'TINYINT(1) NULL'),
    ):
        _asegurar_columna(cursor, database, 'usuarios', columna, definicion)


def _asegurar_columnas_cambio_correo_empresa(cursor, database):
    for columna, definicion in (
        ('email_pendiente', 'VARCHAR(255) NULL'),
        ('email_cambio_token', 'VARCHAR(255) NULL'),
        ('email_cambio_expira', 'DATETIME NULL'),
    ):
        _asegurar_columna(cursor, database, 'empresas', columna, definicion)


def _asegurar_columnas_factura_edicion(cursor, database):
    """Vínculo detalle↔pendiente y auditoría de anulación."""
    _asegurar_columna(
        cursor, database, 'factura_detalles', 'paciente_pendiente_id',
        'INT NULL AFTER factura_id',
    )
    _asegurar_columna(
        cursor, database, 'facturas', 'motivo_anulacion',
        'TEXT NULL',
    )
    _asegurar_columna(
        cursor, database, 'facturas', 'anulado_por',
        'INT NULL',
    )
    _asegurar_columna(
        cursor, database, 'facturas', 'fecha_anulacion',
        'DATETIME NULL',
    )


def _asegurar_columnas_catalogos(cursor, database):
    """Columnas que el código usa y que bases antiguas pueden no tener."""
    for tabla, columna, definicion in (
        ('ncf', 'descripcion', 'VARCHAR(150) NULL'),
        ('ncf', 'prefijo', "VARCHAR(10) NOT NULL DEFAULT 'B01'"),
        ('ncf', 'ultimo_numero', 'INT NOT NULL DEFAULT 0'),
        ('ncf', 'proximo_numero', 'INT NOT NULL DEFAULT 1'),
        ('ncf', 'tamano_secuencia', 'INT NOT NULL DEFAULT 8'),
        ('ncf', 'fecha_fin', 'DATE NULL'),
        ('medicos', 'factura', 'TINYINT(1) NOT NULL DEFAULT 0'),
        ('centros_medicos', 'rnc', 'VARCHAR(20) NULL'),
        ('medico_centro', 'es_defecto', 'TINYINT(1) NOT NULL DEFAULT 0'),
        ('servicios', 'precio_base', 'DECIMAL(10, 2) NOT NULL DEFAULT 0.00'),
        ('codigo_ars', 'medico_id', 'INT NULL'),
        ('codigo_ars', 'centro_medico_id', 'INT NULL'),
        ('facturas', 'tipo_factura', "VARCHAR(20) NOT NULL DEFAULT 'TRADICIONAL'"),
        # Factura al paciente (cobro directo) vs. factura consolidada a la ARS.
        ('facturas', 'destinatario', "VARCHAR(10) NOT NULL DEFAULT 'ARS'"),
        ('facturas', 'rnc_comprador', 'VARCHAR(11) NULL'),
        ('facturas', 'razon_social_comprador', 'VARCHAR(200) NULL'),
        ('facturas', 'metodo_pago', 'VARCHAR(20) NULL'),
        ('facturas', 'referencia_pago', 'VARCHAR(100) NULL'),
        ('facturas', 'monto_recibido', 'DECIMAL(10, 2) NULL'),
        ('hojas_enfermeria', 'medico_id', 'INT NULL'),
        ('hojas_enfermeria', 'nombre_medico', 'VARCHAR(200) NULL'),
        ('pacientes', 'created_by', 'INT NULL'),
    ):
        _asegurar_columna(cursor, database, tabla, columna, definicion)


def _existe_indice(cursor, database, tabla, indice):
    cursor.execute(
        '''
        SELECT 1 FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s AND INDEX_NAME = %s
        LIMIT 1
        ''',
        (database, tabla, indice),
    )
    return cursor.fetchone() is not None


def _asegurar_ncf_unico_por_empresa(cursor, database):
    """Un mismo NCF no puede aparecer en dos facturas de la misma empresa.

    Si ya existen duplicados no se crea el índice (fallaría el arranque);
    se registran para que se corrijan a mano y se reintenta en el próximo inicio.
    """
    if not _existe_tabla(cursor, database, 'facturas'):
        return
    if _existe_indice(cursor, database, 'facturas', 'uq_facturas_tenant_ncf'):
        return
    cursor.execute(
        '''
        SELECT tenant_id, ncf, COUNT(*) AS veces
        FROM facturas
        WHERE ncf IS NOT NULL
        GROUP BY tenant_id, ncf
        HAVING COUNT(*) > 1
        LIMIT 50
        '''
    )
    duplicados = cursor.fetchall()
    if duplicados:
        logger.error(
            'No se creó uq_facturas_tenant_ncf: hay NCF repetidos en facturas: %s',
            ', '.join(
                f"tenant {d['tenant_id']} NCF {d['ncf']} x{d['veces']}"
                for d in duplicados
            ),
        )
        return
    cursor.execute(
        'ALTER TABLE facturas ADD UNIQUE KEY uq_facturas_tenant_ncf (tenant_id, ncf)'
    )
    logger.info('Creado índice único uq_facturas_tenant_ncf')


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
            _asegurar_tablas_modulos(cursor)
            permisos_previos = _permisos_existentes(
                cursor, database, tuple(PERMISOS_HEREDADOS)
            )
            _sembrar_permisos(cursor, database)
            _heredar_permisos_nuevos(cursor, database, permisos_previos)
            _asegurar_columnas_activacion(cursor, database)
            _asegurar_columnas_smtp_empresa(cursor, database)
            _asegurar_columnas_confirmacion_cita(cursor, database)
            _asegurar_columnas_presencia_chat(cursor, database)
            _asegurar_columnas_ecf_emisor(cursor, database)
            _asegurar_columnas_ars(cursor, database)
            _asegurar_columnas_centro_contexto(cursor, database)
            _asegurar_columnas_factura_edicion(cursor, database)
            _asegurar_columnas_cambio_correo_empresa(cursor, database)
            _asegurar_columnas_cambio_password(cursor, database)
            _asegurar_columnas_catalogos(cursor, database)
            _asegurar_ncf_unico_por_empresa(cursor, database)
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
