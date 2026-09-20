"""Configuración de entorno y validaciones de arranque."""

import os
import secrets
from datetime import timedelta
from urllib.parse import unquote, urlparse

import pymysql
from dotenv import load_dotenv

from ecf import ECFConfig

load_dotenv()

ENVIRONMENT = os.getenv('FLASK_ENV', 'development').strip().lower()
IS_PRODUCTION = ENVIRONMENT == 'production'


def parse_mysql_url(url):
    """Parsear una URL MySQL en la configuración aceptada por PyMySQL."""
    if not url:
        return None
    parsed = urlparse(url)
    if parsed.scheme not in ('mysql', 'mysql+pymysql'):
        return None
    database = unquote((parsed.path or '').lstrip('/').split('?')[0])
    if not parsed.hostname or not database:
        return None
    return {
        'user': unquote(parsed.username or ''),
        'password': unquote(parsed.password or ''),
        'host': parsed.hostname,
        'port': int(parsed.port or 3306),
        'database': database,
        'charset': 'utf8mb4',
    }


def _primer_env(*nombres, default=''):
    for nombre in nombres:
        valor = os.getenv(nombre, '').strip()
        if valor:
            return valor
    return default


def _es_host_interno_railway(host):
    return str(host or '').endswith('.railway.internal')


def _nombre_base_datos(url_config=None, en_railway=False):
    """El nombre explícito gana sobre el path de MYSQL_URL."""
    explicita = _primer_env('MYSQL_DATABASE', 'MYSQLDATABASE')
    if explicita:
        return explicita
    if url_config and url_config.get('database'):
        return url_config['database']
    return 'railway' if en_railway else 'facturacion_medica'


def _con_base_datos(config, en_railway=False):
    ajustada = dict(config)
    ajustada['database'] = _nombre_base_datos(config, en_railway=en_railway)
    return ajustada


def construir_database_config():
    """Resolver MySQL para local y Railway (MYSQLHOST / MYSQL_URL)."""
    url_privada = parse_mysql_url(
        _primer_env('MYSQL_URL', 'DATABASE_URL')
    )
    url_publica = parse_mysql_url(os.getenv('MYSQL_PUBLIC_URL', '').strip())
    host_railway = os.getenv('MYSQLHOST', '').strip()
    en_railway = bool(os.getenv('RAILWAY_ENVIRONMENT') or host_railway)

    # La red privada de Railway a veces no resuelve mysql.railway.internal.
    if en_railway and url_publica and (
        not url_privada or _es_host_interno_railway(url_privada.get('host'))
    ):
        return _con_base_datos(url_publica, en_railway=True)
    if url_privada:
        return _con_base_datos(url_privada, en_railway=en_railway)
    if url_publica:
        return _con_base_datos(url_publica, en_railway=en_railway)

    host = _primer_env('MYSQL_HOST', 'MYSQLHOST', default='localhost')
    if host in {'localhost', '127.0.0.1'} and host_railway:
        host = host_railway
    if en_railway and url_publica and _es_host_interno_railway(host):
        return _con_base_datos(url_publica, en_railway=True)

    if en_railway:
        return {
            'host': host,
            'user': _primer_env('MYSQLUSER', 'MYSQL_USER', default='root'),
            'password': _primer_env('MYSQLPASSWORD', 'MYSQL_PASSWORD'),
            'database': _nombre_base_datos(en_railway=True),
            'port': int(_primer_env('MYSQLPORT', 'MYSQL_PORT', default='3306')),
            'charset': 'utf8mb4',
        }

    return {
        'host': host,
        'user': _primer_env('MYSQL_USER', 'MYSQLUSER', default='root'),
        'password': _primer_env('MYSQL_PASSWORD', 'MYSQLPASSWORD'),
        'database': _nombre_base_datos(),
        'port': int(_primer_env('MYSQL_PORT', 'MYSQLPORT', default='3306')),
        'charset': 'utf8mb4',
    }


DATABASE_CONFIG = construir_database_config()


REQUIRED_TENANT_TABLES = (
    'ars', 'auditoria_historia_clinica', 'auditoria_licencias_medicas',
    'centros_medicos', 'citas_medicas', 'codigo_ars', 'consultas_clinicas',
    'conversaciones_internas', 'ecf_configuraciones', 'ecf_eventos',
    'ecf_outbox', 'ecf_secuencias', 'evoluciones_clinicas',
    'factura_detalles', 'facturas', 'facturas_ecf', 'historias_emergencia',
    'hojas_enfermeria', 'licencias_medicas', 'medico_centro', 'medicos',
    'mensajes_internos', 'ncf', 'pacientes', 'pacientes_pendientes',
    'pago_facturas', 'pagos', 'receta_medicamentos', 'recetas_medicas',
    'reclamaciones', 'roles', 'rol_permisos', 'secuencias_turnos',
    'servicios', 'pantallas_turnos', 'tipos_licencia_medica',
    'turnos_atencion', 'turnos_eventos', 'usuario_medico', 'usuario_roles',
    'usuarios',
)


def configure_app(app):
    """Aplicar la configuración Flask sin registrar rutas."""
    configured_secret_key = os.getenv('SECRET_KEY', '').strip()
    if IS_PRODUCTION and (
        len(configured_secret_key) < 32
        or configured_secret_key == 'cambia_esto_por_una_clave_secreta'
    ):
        raise RuntimeError(
            'SECRET_KEY debe configurarse con al menos 32 caracteres '
            'en producción.'
        )

    app.secret_key = configured_secret_key or secrets.token_hex(32)
    app.config.update(
        SESSION_COOKIE_SECURE=IS_PRODUCTION,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        SESSION_COOKIE_NAME='facturacion_session',
        TEMPLATES_AUTO_RELOAD=not IS_PRODUCTION,
        WTF_CSRF_TIME_LIMIT=8 * 60 * 60,
        MAX_CONTENT_LENGTH=int(
            os.getenv('MAX_UPLOAD_BYTES', str(10 * 1024 * 1024))
        ),
        ECF_CONFIG=ECFConfig.from_env(),
    )


def validate_required_tenant_schema(connection_factory=None):
    """Fallar de forma segura si el esquema multiempresa está incompleto."""
    factory = connection_factory or pymysql.connect
    config = DATABASE_CONFIG.copy()
    config['cursorclass'] = pymysql.cursors.DictCursor
    connection = factory(**config)
    try:
        with connection.cursor() as cursor:
            placeholders = ', '.join(['%s'] * len(REQUIRED_TENANT_TABLES))
            cursor.execute(
                f'''
                SELECT TABLE_NAME
                FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA = %s
                  AND COLUMN_NAME = 'tenant_id'
                  AND TABLE_NAME IN ({placeholders})
                ''',
                (DATABASE_CONFIG['database'], *REQUIRED_TENANT_TABLES),
            )
            present = {row['TABLE_NAME'] for row in cursor.fetchall()}
    finally:
        connection.close()

    missing = sorted(set(REQUIRED_TENANT_TABLES) - present)
    if missing:
        raise RuntimeError(
            'Esquema multiempresa incompleto. Falta tenant_id en: '
            + ', '.join(missing)
        )


def url_publica_base():
    """URL HTTPS pública: APP_BASE_URL o el dominio que Railway publica."""
    configurada = os.getenv('APP_BASE_URL', '').strip()
    if configurada:
        return configurada
    dominio_railway = os.getenv('RAILWAY_PUBLIC_DOMAIN', '').strip()
    if dominio_railway:
        return f'https://{dominio_railway}'
    return ''


def validate_production_startup():
    """Validar controles que no pueden degradarse silenciosamente."""
    public_base_url = url_publica_base()
    parsed_url = urlparse(public_base_url)
    if parsed_url.scheme != 'https' or not parsed_url.netloc:
        raise RuntimeError(
            'APP_BASE_URL debe ser una URL HTTPS completa en producción.'
        )
    if (
        os.getenv('RAILWAY_ENVIRONMENT')
        and DATABASE_CONFIG.get('host') in {'localhost', '127.0.0.1'}
    ):
        raise RuntimeError(
            'MySQL apunta a localhost. En Railway vincula el servicio MySQL '
            'y no definas MYSQL_HOST=localhost. Usa MYSQL_URL o MYSQLHOST.'
        )
    from core.schema_bootstrap import bootstrap_required_schema

    bootstrap_required_schema()
    validate_required_tenant_schema()
