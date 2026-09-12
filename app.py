# ARSFLOW Gestion de Factras Medicas

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, make_response, send_file, session, g
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
import os
import calendar as calendar_module
from datetime import datetime, timedelta
import json
import functools
from dotenv import load_dotenv
import secrets
import re
from markupsafe import escape
from io import BytesIO
import threading
import time
import zipfile
from collections import defaultdict
from contextlib import contextmanager
from decimal import Decimal, InvalidOperation
from threading import Lock
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler
from urllib.parse import urljoin, urlparse

import pymysql
from ecf import (
    DGIIClient,
    DGIIClientError,
    ECFBuildError,
    ECFBuilder,
    ECFCertificateResolutionError,
    ECFConfig,
    ECFPrintableError,
    ECFSchemaError,
    ECFSequenceError,
    ECF_TYPE_CATALOG,
    ECFSigningError,
    ECFValidationError,
    ECFValidator,
    TenantCertificateProvider,
    build_encf,
    build_stamp,
    classify_dgii_status,
    generate_e31_pdf,
    generate_qr,
    reserve_encf,
)

pymysql.install_as_MySQLdb()

try:
    from sendgrid import SendGridAPIClient
    from sendgrid.helpers.mail import Mail
    import base64
    SENDGRID_AVAILABLE = True
except ImportError:
    SENDGRID_AVAILABLE = False
    print("AVISO: SendGrid no disponible")

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    print("AVISO: ReportLab no disponible")

try:
    from openpyxl import Workbook
    from openpyxl.styles import Font, Alignment, PatternFill, Protection
    from openpyxl.worksheet.datavalidation import DataValidation
    from openpyxl.utils import get_column_letter
    OPENPYXL_AVAILABLE = True
except ImportError:
    OPENPYXL_AVAILABLE = False
    print("AVISO: OpenPyXL no disponible")

load_dotenv()

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler('app.log', maxBytes=10485760, backupCount=5),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

ENVIRONMENT = os.getenv('FLASK_ENV', 'development').strip().lower()
IS_PRODUCTION = ENVIRONMENT == 'production'
configured_secret_key = os.getenv('SECRET_KEY', '').strip()
if IS_PRODUCTION and (
    len(configured_secret_key) < 32
    or configured_secret_key == 'cambia_esto_por_una_clave_secreta'
):
    raise RuntimeError(
        'SECRET_KEY debe configurarse con al menos 32 caracteres en producción.'
    )

app.secret_key = configured_secret_key or secrets.token_hex(32)

app.config['SESSION_COOKIE_SECURE'] = IS_PRODUCTION
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
app.config['SESSION_COOKIE_NAME'] = 'facturacion_session'
app.config['TEMPLATES_AUTO_RELOAD'] = not IS_PRODUCTION
app.config['WTF_CSRF_TIME_LIMIT'] = 8 * 60 * 60
app.config['MAX_CONTENT_LENGTH'] = int(
    os.getenv('MAX_UPLOAD_BYTES', str(10 * 1024 * 1024))
)
app.config['ECF_CONFIG'] = ECFConfig.from_env()
csrf = CSRFProtect(app)


@app.before_request
def generate_csp_nonce():
    """Crear un nonce distinto para cada respuesta HTML."""
    g.csp_nonce = secrets.token_urlsafe(18)


@app.context_processor
def inject_csp_nonce():
    """Permitir que las plantillas autoricen scripts durante la migración CSP."""
    return {'csp_nonce': g.get('csp_nonce', '')}


@app.errorhandler(CSRFError)
def handle_csrf_error(error):
    """Responder sin filtrar detalles cuando falta o vence el token CSRF."""
    logger.warning(
        'Solicitud CSRF rechazada: endpoint=%s method=%s',
        request.endpoint,
        request.method,
    )
    if request.path.startswith('/api/') or request.is_json:
        return jsonify({
            'error': True,
            'mensaje': 'La sesión de seguridad venció. Recarga la página.',
        }), 400
    flash('La sesión de seguridad venció. Recarga la página e inténtalo de nuevo.', 'error')
    destination = 'facturacion_menu' if current_user.is_authenticated else 'login'
    return redirect(url_for(destination))

@app.after_request
def set_security_headers(response):
    """Agregar headers de seguridad a todas las respuestas"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    nonce = g.get('csp_nonce', '')
    csp = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://www.googletagmanager.com; "
        f"script-src-elem 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://www.googletagmanager.com; "
        "script-src-attr 'none'; "
        f"style-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        f"style-src-elem 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "style-src-attr 'none'; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://www.googletagmanager.com; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'self';"
    )
    response.headers['Content-Security-Policy'] = csp

    report_only_csp = (
        "default-src 'self'; "
        f"script-src-elem 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://www.googletagmanager.com; "
        "script-src-attr 'none'; "
        f"style-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        f"style-src-elem 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "style-src-attr 'none'; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://www.googletagmanager.com; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'self'; "
        "report-uri /api/csp-report;"
    )
    response.headers['Content-Security-Policy-Report-Only'] = report_only_csp
    
    if request.path.startswith('/static/'):
        response.headers['Cache-Control'] = 'public, max-age=31536000'
    else:
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    
    return response

import gzip

@app.after_request
def compress_response(response):
    """Comprimir respuestas para reducir tamaño de transferencia"""
    if response.status_code < 200 or response.status_code >= 300:
        return response
    
    accept_encoding = request.headers.get('Accept-Encoding', '')
    
    if 'gzip' not in accept_encoding.lower():
        return response
    
    if response.direct_passthrough:
        return response
    
    # Comprimir solo si es mayor a 1KB
    if len(response.get_data()) < 1024:
        return response
    
    response.set_data(gzip.compress(response.get_data()))
    response.headers['Content-Encoding'] = 'gzip'
    response.headers['Content-Length'] = len(response.get_data())
    response.headers['Vary'] = 'Accept-Encoding'
    
    return response

def parse_mysql_url(url):
    """Parsear URL de MySQL"""
    if not url:
        return None
    pattern = r'mysql://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)'
    match = re.match(pattern, url)
    if match:
        return {
            'user': match.group(1),
            'password': match.group(2),
            'host': match.group(3),
            'port': int(match.group(4)),
            'database': match.group(5),
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

print(f"[OK] Configurado para MySQL: {DATABASE_CONFIG['database']}")

REQUIRED_TENANT_TABLES = (
    'ars',
    'auditoria_historia_clinica',
    'auditoria_licencias_medicas',
    'centros_medicos',
    'citas_medicas',
    'codigo_ars',
    'consultas_clinicas',
    'ecf_configuraciones',
    'ecf_eventos',
    'ecf_outbox',
    'ecf_secuencias',
    'evoluciones_clinicas',
    'factura_detalles',
    'facturas',
    'facturas_ecf',
    'historias_emergencia',
    'hojas_enfermeria',
    'licencias_medicas',
    'medico_centro',
    'medicos',
    'ncf',
    'pacientes',
    'pacientes_pendientes',
    'pago_facturas',
    'pagos',
    'receta_medicamentos',
    'recetas_medicas',
    'reclamaciones',
    'servicios',
    'tipos_licencia_medica',
    'usuarios',
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


def validate_production_startup():
    """Validar controles que no pueden degradarse silenciosamente."""
    public_base_url = os.getenv('APP_BASE_URL', '').strip()
    parsed_url = urlparse(public_base_url)
    if parsed_url.scheme != 'https' or not parsed_url.netloc:
        raise RuntimeError(
            'APP_BASE_URL debe ser una URL HTTPS completa en producción.'
        )
    validate_required_tenant_schema()

# Cache de conexiones para mejor rendimiento (pymysql no tiene pool nativo)
# Usaremos conexiones reutilizables con contexto de aplicación Flask
from flask import g

def get_db_connection():
    """
    Obtener conexión a la base de datos
    Reutiliza conexión en el contexto de la request si existe
    """
    if 'db_conn' not in g:
        config = DATABASE_CONFIG.copy()
        config['cursorclass'] = pymysql.cursors.DictCursor
        # Lecturas y escrituras simples no mantienen transacciones abiertas.
        # Los flujos atómicos usan database_transaction().
        config['autocommit'] = True
        g.db_conn = pymysql.connect(**config)
        logger.debug("Nueva conexión a BD creada")
    
    return g.db_conn

@app.teardown_appcontext
def close_db(error):
    """Cerrar conexión al finalizar request"""
    db_conn = g.pop('db_conn', None)
    if db_conn is not None:
        try:
            db_conn.close()
            logger.debug("Conexión a BD cerrada")
        except Exception as e:
            logger.error(f"Error al cerrar conexión: {e}")

def execute_query(query, params=None, fetch='one'):
    """
    Ejecutar query y retornar resultados
    Con manejo mejorado de errores, logging y reutilización de conexiones
    """
    cursor = None
    try:
        # Validar que la query no esté vacía
        if not query or not query.strip():
            logger.error("Intento de ejecutar query vacía")
            return None
        
        # Validar que params sea tupla o lista si se proporciona
        if params is not None and not isinstance(params, (tuple, list)):
            logger.warning(f"Params debe ser tupla o lista, recibido: {type(params)}")
            params = (params,)
        
        # Validar que no haya SQL injection básico (solo advertencia)
        if params and any(isinstance(p, str) and (';' in p or '--' in p or '/*' in p) for p in params):
            logger.warning("Posible intento de SQL injection detectado en params")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(query, params or ())
        
        if fetch == 'one':
            result = cursor.fetchone()
        elif fetch == 'all':
            result = cursor.fetchall()
        else:
            result = None
        
        return result
    except pymysql.Error as e:
        conn = get_db_connection()
        try:
            conn.rollback()
        except:
            pass
        logger.error(f"Error SQL en execute_query: {e} - Query: {query[:100]}...")
        # No exponer detalles del error al usuario en producción
        if g.get('db_transaction_active', False) or ENVIRONMENT == 'development':
            raise
        return None
    except Exception as e:
        conn = get_db_connection()
        try:
            conn.rollback()
        except:
            pass
        logger.error(f"Error inesperado en execute_query: {e}", exc_info=True)
        if g.get('db_transaction_active', False) or ENVIRONMENT == 'development':
            raise
        return None
    finally:
        if cursor:
            cursor.close()
        # No cerramos la conexión aquí, se cierra al finalizar la request

def execute_update(query, params=None):
    """
    Ejecutar UPDATE/INSERT/DELETE
    Con manejo mejorado de errores, logging y reutilización de conexiones
    """
    cursor = None
    try:
        # Validar que la query no esté vacía
        if not query or not query.strip():
            logger.error("Intento de ejecutar update con query vacía")
            return None
        
        # Validar que params sea tupla o lista si se proporciona
        if params is not None and not isinstance(params, (tuple, list)):
            logger.warning(f"Params debe ser tupla o lista, recibido: {type(params)}")
            params = (params,)
        
        # Validar que no haya SQL injection básico (solo advertencia)
        if params and any(isinstance(p, str) and (';' in p or '--' in p or '/*' in p) for p in params):
            logger.warning("Posible intento de SQL injection detectado en params")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(query, params or ())
        return cursor.lastrowid
    except pymysql.Error as e:
        conn = get_db_connection()
        try:
            conn.rollback()
        except:
            pass
        logger.error(f"Error SQL en execute_update: {e} - Query: {query[:100]}...")
        # No exponer detalles del error al usuario en producción
        if g.get('db_transaction_active', False) or ENVIRONMENT == 'development':
            raise
        return None
    except Exception as e:
        conn = get_db_connection()
        try:
            conn.rollback()
        except:
            pass
        logger.error(f"Error inesperado en execute_update: {e}", exc_info=True)
        if g.get('db_transaction_active', False) or ENVIRONMENT == 'development':
            raise
        return None
    finally:
        if cursor:
            cursor.close()
        # No cerramos la conexión aquí, se cierra al finalizar la request


@contextmanager
def database_transaction():
    """Agrupar helpers existentes en una única transacción atómica."""
    conn = get_db_connection()
    if g.get('db_transaction_active', False):
        yield conn
        return

    g.db_transaction_active = True
    conn.begin()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        g.pop('db_transaction_active', None)


def transactional_methods(*methods):
    """Aplicar una transacción a métodos HTTP que realizan varias escrituras."""
    protected_methods = {method.upper() for method in methods}

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if request.method not in protected_methods:
                return func(*args, **kwargs)
            with database_transaction():
                return func(*args, **kwargs)

        wrapper.transactional_methods = frozenset(protected_methods)
        return wrapper

    return decorator


def ecf_habilitado_para_tenant(tenant_id, solo_consulta=False):
    """Aplicar interruptor global y autorización e-CF específica por cuenta."""
    config = app.config['ECF_CONFIG']
    if not config.enabled:
        return False

    tenant_config = execute_query('''
        SELECT habilitado, ambiente, produccion_confirmada
        FROM ecf_configuraciones
        WHERE tenant_id=%s
        LIMIT 1
    ''', (tenant_id,))

    # En pruebas se conserva la habilitación global para facilitar el proceso
    # de certificación. Producción siempre exige un registro por cuenta.
    if not tenant_config:
        return config.environment != 'PRODUCCION'
    if not solo_consulta and not bool(tenant_config.get('habilitado')):
        return False
    if str(tenant_config.get('ambiente') or '').upper() != config.environment:
        return False
    if config.environment == 'PRODUCCION':
        return bool(tenant_config.get('produccion_confirmada'))
    return True


def obtener_configuracion_ecf_tenant(tenant_id):
    return execute_query('''
        SELECT *
        FROM ecf_configuraciones
        WHERE tenant_id=%s
        LIMIT 1
    ''', (tenant_id,)) or {}


def obtener_firmante_ecf_tenant(tenant_id):
    """Resolver el firmante aislado correspondiente a una sola cuenta."""
    provider = TenantCertificateProvider(app.config['ECF_CONFIG'])
    resolved = provider.resolve(
        tenant_id,
        obtener_configuracion_ecf_tenant(tenant_id),
    )
    return resolved.signer()


def procesar_envio_ecf_dgii(factura_ecf_id, tenant_id, usuario_id):
    """Procesar una sola entrega pendiente sin reintentos automáticos."""
    if not ecf_habilitado_para_tenant(tenant_id):
        return False, 'La cuenta no está habilitada para enviar e-CF'
    try:
        tenant_signer = obtener_firmante_ecf_tenant(tenant_id)
    except ECFCertificateResolutionError as error:
        return False, str(error)
    conn = get_db_connection()
    cursor = None
    outbox_key = f'ENVIAR_ECF:{factura_ecf_id}'
    try:
        conn.begin()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE ecf_outbox
            SET estado='PROCESANDO', intentos=intentos+1,
                bloqueado_en=NOW(), bloqueado_por=%s,
                ultimo_error=NULL
            WHERE clave_evento=%s AND tenant_id=%s
              AND estado='PENDIENTE'
        ''', (f'web:{os.getpid()}', outbox_key, tenant_id))
        if cursor.rowcount != 1:
            conn.rollback()
            return False, 'El envío no está pendiente o ya fue procesado'

        cursor.execute('''
            SELECT fe.id, fe.e_ncf, fe.xml_firmado, fe.estado,
                   e.rnc AS rnc_emisor
            FROM facturas_ecf fe
            INNER JOIN empresas e ON e.id=fe.tenant_id
            WHERE fe.id=%s AND fe.tenant_id=%s
            LIMIT 1
            FOR UPDATE
        ''', (factura_ecf_id, tenant_id))
        document = cursor.fetchone()
        if (
            not document
            or document.get('estado') != 'FIRMADO'
            or not document.get('xml_firmado')
        ):
            cursor.execute('''
                UPDATE ecf_outbox
                SET estado='ERROR', ultimo_error=%s,
                    bloqueado_en=NULL, bloqueado_por=NULL
                WHERE clave_evento=%s AND tenant_id=%s
            ''', (
                'El documento no está firmado y listo para envío',
                outbox_key,
                tenant_id
            ))
            conn.commit()
            return False, 'El documento no está firmado y listo para envío'

        cursor.execute('''
            INSERT INTO ecf_eventos
            (tenant_id, factura_ecf_id, estado_anterior, estado_nuevo,
             evento, detalle, usuario_id)
            VALUES (%s, %s, 'FIRMADO', 'FIRMADO',
                    'ENVIO_DGII_INICIADO', %s, %s)
        ''', (
            tenant_id,
            factura_ecf_id,
            'Autenticación y envío al ambiente DGII no productivo iniciados',
            usuario_id
        ))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        if cursor:
            cursor.close()

    try:
        reception = DGIIClient(
            app.config['ECF_CONFIG'],
            signer=tenant_signer,
        ).submit_e31(
            document['xml_firmado'],
            document['rnc_emisor'],
            document['e_ncf']
        )
    except DGIIClientError as error:
        outbox_status = (
            'REQUIERE_CONSULTA'
            if error.delivery_uncertain
            else 'ERROR'
        )
        error_message = str(error)
        response_text = error.response_text
        cursor = None
        try:
            conn.begin()
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE facturas_ecf
                SET estado='ERROR_ENVIO', intentos=intentos+1,
                    ultimo_error=%s, codigo_respuesta=%s,
                    mensaje_respuesta=%s,
                    respuesta_dgii=COALESCE(%s, respuesta_dgii)
                WHERE id=%s AND tenant_id=%s
            ''', (
                error_message,
                f'HTTP_{error.http_status}' if error.http_status else None,
                error_message,
                response_text,
                factura_ecf_id,
                tenant_id
            ))
            cursor.execute('''
                UPDATE ecf_outbox
                SET estado=%s, ultimo_error=%s,
                    bloqueado_en=NULL, bloqueado_por=NULL
                WHERE clave_evento=%s AND tenant_id=%s
            ''', (
                outbox_status,
                error_message,
                outbox_key,
                tenant_id
            ))
            cursor.execute('''
                INSERT INTO ecf_eventos
                (tenant_id, factura_ecf_id,
                 estado_anterior, estado_nuevo,
                 evento, detalle, usuario_id)
                VALUES (%s, %s, 'FIRMADO', 'ERROR_ENVIO',
                        %s, %s, %s)
            ''', (
                tenant_id,
                factura_ecf_id,
                (
                    'ENVIO_INCIERTO_REQUIERE_CONSULTA'
                    if error.delivery_uncertain
                    else 'ERROR_ENVIO_DGII'
                ),
                error_message,
                usuario_id
            ))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            if cursor:
                cursor.close()
        logger.warning(
            'Falló el envío e-CF %s a DGII: %s',
            factura_ecf_id,
            error_message
        )
        return False, error_message

    cursor = None
    try:
        conn.begin()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE facturas_ecf
            SET estado='ENVIADO', track_id=%s, fecha_envio=NOW(6),
                respuesta_dgii=%s, intentos=intentos+1,
                codigo_respuesta=%s, mensaje_respuesta=%s,
                ultimo_error=NULL
            WHERE id=%s AND tenant_id=%s AND estado='FIRMADO'
        ''', (
            reception.track_id,
            reception.raw_response,
            f'HTTP_{reception.http_status}',
            reception.message or reception.error or 'Recibido por DGII',
            factura_ecf_id,
            tenant_id
        ))
        if cursor.rowcount != 1:
            raise RuntimeError('El estado del e-CF cambió durante el envío')
        cursor.execute('''
            UPDATE ecf_outbox
            SET estado='COMPLETADO', ultimo_error=NULL,
                bloqueado_en=NULL, bloqueado_por=NULL
            WHERE clave_evento=%s AND tenant_id=%s
        ''', (outbox_key, tenant_id))
        cursor.execute('''
            INSERT INTO ecf_eventos
            (tenant_id, factura_ecf_id, estado_anterior, estado_nuevo,
             evento, detalle, usuario_id)
            VALUES (%s, %s, 'FIRMADO', 'ENVIADO',
                    'ECF_RECIBIDO_DGII', %s, %s)
        ''', (
            tenant_id,
            factura_ecf_id,
            f'TrackID recibido: {reception.track_id}',
            usuario_id
        ))
        conn.commit()
        return True, reception.track_id
    except Exception:
        conn.rollback()
        raise
    finally:
        if cursor:
            cursor.close()


def consultar_resultado_ecf_dgii(factura_ecf_id, tenant_id, usuario_id):
    """Consultar una vez el resultado; nunca reenvía el comprobante."""
    document = execute_query('''
        SELECT fe.id, fe.e_ncf, fe.track_id, fe.estado,
               e.rnc AS rnc_emisor
        FROM facturas_ecf fe
        INNER JOIN empresas e ON e.id=fe.tenant_id
        WHERE fe.id=%s AND fe.tenant_id=%s
        LIMIT 1
    ''', (factura_ecf_id, tenant_id))
    if not document:
        return False, None, 'Documento e-CF no encontrado'
    if document.get('estado') not in {
        'ENVIADO', 'ERROR_ENVIO', 'ACEPTADO', 'RECHAZADO'
    }:
        return (
            False,
            document.get('estado'),
            'El documento todavía no está listo para consultar en DGII'
        )

    try:
        client = DGIIClient(
            app.config['ECF_CONFIG'],
            signer=obtener_firmante_ecf_tenant(tenant_id),
        )
        token = client.authenticate(document['rnc_emisor'])
        track_id = str(document.get('track_id') or '').strip()
        recovered_track = False
        if not track_id:
            tracks = client.find_track_ids(
                document['rnc_emisor'],
                document['e_ncf'],
                token=token
            )
            if len(tracks) == 0:
                message = (
                    'DGII todavía no reporta un TrackID para este e-NCF; '
                    'no se realizará un reenvío automático'
                )
                _registrar_error_consulta_ecf(
                    factura_ecf_id,
                    tenant_id,
                    document['estado'],
                    message,
                    usuario_id
                )
                return False, document['estado'], message
            if len(tracks) > 1:
                message = (
                    'DGII reportó varios TrackID para el mismo e-NCF; '
                    'se requiere revisión manual'
                )
                _registrar_error_consulta_ecf(
                    factura_ecf_id,
                    tenant_id,
                    document['estado'],
                    message,
                    usuario_id
                )
                return False, document['estado'], message
            track_id = tracks[0].track_id
            recovered_track = True

        result = client.query_result(
            track_id,
            document['rnc_emisor'],
            token=token
        )
        expected_rnc = re.sub(r'\D', '', document['rnc_emisor'] or '')
        returned_rnc = re.sub(r'\D', '', result.rnc or '')
        if returned_rnc and returned_rnc != expected_rnc:
            raise DGIIClientError(
                'La respuesta DGII pertenece a otro RNC emisor'
            )
        if result.encf and result.encf.upper() != document['e_ncf'].upper():
            raise DGIIClientError(
                'La respuesta DGII pertenece a otro e-NCF'
            )

        local_status = classify_dgii_status(result.code, result.status)
        detail_message = ' | '.join(result.messages)
        if not detail_message:
            detail_message = result.status or 'Respuesta recibida de DGII'
        if result.sequence_used is not None:
            detail_message += (
                ' | Secuencia marcada como utilizada: '
                f'{"Sí" if result.sequence_used else "No"}'
            )

        conn = get_db_connection()
        cursor = None
        try:
            conn.begin()
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE facturas_ecf
                SET estado=%s, track_id=%s, fecha_respuesta=NOW(6),
                    codigo_respuesta=%s, mensaje_respuesta=%s,
                    respuesta_dgii=%s, ultimo_error=NULL
                WHERE id=%s AND tenant_id=%s
            ''', (
                local_status,
                track_id,
                result.code or f'HTTP_{result.http_status}',
                detail_message,
                result.raw_response,
                factura_ecf_id,
                tenant_id
            ))
            if recovered_track:
                cursor.execute('''
                    UPDATE ecf_outbox
                    SET estado='COMPLETADO', ultimo_error=NULL,
                        bloqueado_en=NULL, bloqueado_por=NULL
                    WHERE factura_ecf_id=%s AND tenant_id=%s
                      AND tipo_evento='ENVIAR_ECF'
                ''', (factura_ecf_id, tenant_id))
            cursor.execute('''
                INSERT INTO ecf_eventos
                (tenant_id, factura_ecf_id,
                 estado_anterior, estado_nuevo,
                 evento, detalle, usuario_id)
                VALUES (%s, %s, %s, %s,
                        'RESULTADO_DGII_CONSULTADO', %s, %s)
            ''', (
                tenant_id,
                factura_ecf_id,
                document['estado'],
                local_status,
                (
                    f'Estado DGII: {result.status or result.code}; '
                    f'TrackID: {track_id}; {detail_message}'
                ),
                usuario_id
            ))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            if cursor:
                cursor.close()
        return True, local_status, detail_message
    except (DGIIClientError, ECFCertificateResolutionError) as error:
        message = str(error)
        _registrar_error_consulta_ecf(
            factura_ecf_id,
            tenant_id,
            document['estado'],
            message,
            usuario_id
        )
        return False, document['estado'], message


def _registrar_error_consulta_ecf(
    factura_ecf_id,
    tenant_id,
    current_status,
    message,
    usuario_id
):
    """Registrar fallo de consulta sin alterar el estado fiscal conocido."""
    conn = get_db_connection()
    cursor = None
    try:
        conn.begin()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE facturas_ecf
            SET ultimo_error=%s
            WHERE id=%s AND tenant_id=%s
        ''', (message, factura_ecf_id, tenant_id))
        cursor.execute('''
            INSERT INTO ecf_eventos
            (tenant_id, factura_ecf_id,
             estado_anterior, estado_nuevo,
             evento, detalle, usuario_id)
            VALUES (%s, %s, %s, %s,
                    'ERROR_CONSULTA_DGII', %s, %s)
        ''', (
            tenant_id,
            factura_ecf_id,
            current_status,
            current_status,
            message,
            usuario_id
        ))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        if cursor:
            cursor.close()


def sanitize_input(text, max_length=500, allow_html=False):
    """
    Sanitizar entrada de texto para prevenir XSS y otros ataques
    
    Args:
        text: Texto a sanitizar
        max_length: Longitud máxima permitida
        allow_html: Si True, permite HTML (usar con escape en templates)
    
    Returns: Texto sanitizado
    """
    if not text:
        return ""
    
    text = str(text).strip()
    
    # Remover HTML/scripts a menos que se permita explícitamente
    if not allow_html:
        text = re.sub(r'<[^>]*>', '', text)
        # Remover caracteres peligrosos
        text = text.replace('javascript:', '').replace('onerror=', '')
        text = text.replace('onclick=', '').replace('onload=', '')
    
    # Limitar longitud
    if max_length and len(text) > max_length:
        text = text[:max_length]
        logger.warning(f"Texto truncado por exceder longitud máxima: {max_length}")
    
    return text

def validate_int(value, min_value=None, max_value=None, default=None):
    """Validar y convertir a entero de forma segura"""
    try:
        int_value = int(value)
        if min_value is not None and int_value < min_value:
            return default
        if max_value is not None and int_value > max_value:
            return default
        return int_value
    except (ValueError, TypeError):
        return default

def validate_float(value, min_value=None, max_value=None, default=None):
    """Validar y convertir a float de forma segura"""
    try:
        float_value = float(value)
        if min_value is not None and float_value < min_value:
            return default
        if max_value is not None and float_value > max_value:
            return default
        return float_value
    except (ValueError, TypeError):
        return default

def validate_email(email):
    """Validar formato de email"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_digits(value, length):
    """Validar que el valor contenga exactamente la cantidad indicada de dígitos."""
    return bool(re.fullmatch(rf'\d{{{length}}}', value or ''))

ESPECIALIDADES_MEDICAS = (
    'Medicina Interna',
    'Pediatría',
    'Ginecología y Obstetricia',
    'Cardiología',
    'Dermatología',
    'Medicina Familiar',
    'Ortopedia y Traumatología',
    'Oftalmología',
    'Otorrinolaringología',
    'Urología',
    'Gastroenterología',
    'Endocrinología',
    'Neurología',
    'Psiquiatría',
    'Neumología',
    'Cirugía General',
    'Nefrología',
    'Oncología',
    'Infectología',
    'Radiología',
)

def get_especialidad_form(form):
    """Obtener una especialidad del catálogo o una ingresada manualmente."""
    especialidad = sanitize_input(form.get('especialidad', ''), 100)
    if especialidad == '__otra__':
        return sanitize_input(form.get('especialidad_otra', ''), 100)
    return especialidad

def validar_password_segura(password):
    """Validar contraseña segura"""
    errores = []
    if len(password) < 8:
        errores.append("Mínimo 8 caracteres")
    if not re.search(r'[A-Z]', password):
        errores.append("Al menos una mayúscula")
    if not re.search(r'[a-z]', password):
        errores.append("Al menos una minúscula")
    if not re.search(r'\d', password):
        errores.append("Al menos un número")
    return errores

@app.template_filter('formato_moneda')
def formato_moneda(valor):
    """Formatear números como moneda"""
    try:
        return "{:,.2f}".format(float(valor))
    except (ValueError, TypeError):
        return "0.00"


@app.template_filter('hora_input')
def hora_input(valor):
    """Formatear TIME de MySQL para controles y etiquetas HH:MM."""
    if valor is None:
        return ''
    if isinstance(valor, timedelta):
        segundos = int(valor.total_seconds())
        return f'{(segundos // 3600) % 24:02d}:{(segundos % 3600) // 60:02d}'
    if hasattr(valor, 'strftime'):
        return valor.strftime('%H:%M')
    partes = str(valor).split(':')
    if len(partes) >= 2:
        return f'{partes[0].zfill(2)}:{partes[1].zfill(2)}'
    return str(valor)


FUENTES_UI = {
    'arsflow': {
        'nombre': 'ARSFlow',
        'descripcion': 'Montserrat + Be Vietnam Pro',
        'muestra': 'Claridad clínica y moderna',
    },
    'inter': {
        'nombre': 'Inter',
        'descripcion': 'Precisa y muy legible',
        'muestra': 'Información médica ordenada',
    },
    'manrope': {
        'nombre': 'Manrope',
        'descripcion': 'Amable y contemporánea',
        'muestra': 'Gestión sencilla y cercana',
    },
    'jakarta': {
        'nombre': 'Plus Jakarta Sans',
        'descripcion': 'Elegante y profesional',
        'muestra': 'Una experiencia más refinada',
    },
}


# Context processor para temas de color y tipografía
@app.context_processor
def inject_theme():
    """Inyectar preferencias visuales en todos los templates."""
    TEMAS = {
        'cyan': {
            'primary': '#06B6D4',
            'primary_dark': '#0891B2',
            'primary_light': '#22D3EE',
            'background': '#F0FDFA',
            'gradient_start': '#06B6D4',
            'gradient_end': '#0891B2',
            'nombre': 'Verde Azulado',
            'categoria': 'Fresco'
        },
        'ocean': {
            'primary': '#0EA5E9',
            'primary_dark': '#0284C7',
            'primary_light': '#38BDF8',
            'background': '#F0F9FF',
            'gradient_start': '#0EA5E9',
            'gradient_end': '#0284C7',
            'nombre': 'Azul Océano',
            'categoria': 'Fresco'
        },
        'emerald': {
            'primary': '#10B981',
            'primary_dark': '#059669',
            'primary_light': '#34D399',
            'background': '#F0FDF4',
            'gradient_start': '#10B981',
            'gradient_end': '#059669',
            'nombre': 'Verde Esmeralda',
            'categoria': 'Fresco'
        },
        'teal': {
            'primary': '#14B8A6',
            'primary_dark': '#0D9488',
            'primary_light': '#2DD4BF',
            'background': '#F0FDFA',
            'gradient_start': '#14B8A6',
            'gradient_end': '#0D9488',
            'nombre': 'Verde Azulado Oscuro',
            'categoria': 'Fresco'
        },
        'aqua': {
            'primary': '#22B8CF',
            'primary_dark': '#1098AD',
            'primary_light': '#66D9E8',
            'background': '#F0FCFF',
            'gradient_start': '#22B8CF',
            'gradient_end': '#1098AD',
            'nombre': 'Brisa Aqua',
            'categoria': 'Fresco'
        },
        'mint': {
            'primary': '#2CB67D',
            'primary_dark': '#218C61',
            'primary_light': '#65D6A5',
            'background': '#F1FCF7',
            'gradient_start': '#2CB67D',
            'gradient_end': '#218C61',
            'nombre': 'Menta Clínica',
            'categoria': 'Fresco'
        },
        'lagoon': {
            'primary': '#0F9D8A',
            'primary_dark': '#0B7568',
            'primary_light': '#4EC7B5',
            'background': '#F0FBF9',
            'gradient_start': '#0F9D8A',
            'gradient_end': '#0B7568',
            'nombre': 'Laguna Serena',
            'categoria': 'Fresco'
        },
        'sky': {
            'primary': '#3B9AE1',
            'primary_dark': '#2778B8',
            'primary_light': '#73BDF0',
            'background': '#F2F9FE',
            'gradient_start': '#3B9AE1',
            'gradient_end': '#2778B8',
            'nombre': 'Azul Cielo',
            'categoria': 'Fresco'
        },
        'sage': {
            'primary': '#56A68B',
            'primary_dark': '#3E7E68',
            'primary_light': '#86C7B1',
            'background': '#F4FAF7',
            'gradient_start': '#56A68B',
            'gradient_end': '#3E7E68',
            'nombre': 'Verde Salvia',
            'categoria': 'Fresco'
        }
    }
    
    tema_actual = 'cyan'  # Default
    if current_user.is_authenticated:
        tema_actual = current_user.tema_color or 'cyan'
    if tema_actual not in TEMAS:
        tema_actual = 'cyan'

    fuente_actual = 'arsflow'
    if current_user.is_authenticated:
        fuente_actual = getattr(current_user, 'fuente_ui', 'arsflow')
    if fuente_actual not in FUENTES_UI:
        fuente_actual = 'arsflow'
    
    # Información de empresa para multi-tenant
    empresa_info = {}
    if current_user.is_authenticated and hasattr(current_user, 'tenant_id'):
        empresa_info = {
            'tenant_id': current_user.tenant_id,
            'empresa_nombre': current_user.empresa_nombre or 'Sin empresa'
        }
    
    return {
        'tema': TEMAS.get(tema_actual, TEMAS['cyan']),
        'tema_nombre': tema_actual,
        'temas_disponibles': TEMAS,
        'fuente_nombre': fuente_actual,
        'fuente': FUENTES_UI[fuente_actual],
        'fuentes_disponibles': FUENTES_UI,
        'empresa': empresa_info
    }

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = None

class User(UserMixin):
    def __init__(
        self, id, nombre, email, perfil, tema_color='cyan',
        fuente_ui='arsflow', tenant_id=1, empresa_nombre=''
    ):
        self.id = id
        self.nombre = nombre
        self.email = email
        self.perfil = perfil
        self.tema_color = tema_color or 'cyan'
        self.fuente_ui = (
            fuente_ui if fuente_ui in FUENTES_UI else 'arsflow'
        )
        self.tenant_id = tenant_id
        self.empresa_nombre = empresa_nombre

@login_manager.user_loader
def load_user(user_id):
    """Cargar usuario desde la base de datos con información de empresa"""
    user_data = execute_query('''
        SELECT u.*, e.nombre as empresa_nombre 
        FROM usuarios u
        LEFT JOIN empresas e ON u.tenant_id = e.id
        WHERE u.id = %s AND u.activo = 1
    ''', (user_id,))
    
    if user_data:
        return User(
            id=user_data['id'],
            nombre=user_data['nombre'],
            email=user_data['email'],
            perfil=user_data['perfil'],
            tema_color=user_data.get('tema_color', 'cyan'),
            fuente_ui=user_data.get('fuente_ui', 'arsflow'),
            tenant_id=user_data.get('tenant_id', 1),
            empresa_nombre=user_data.get('empresa_nombre', '')
        )
    return None

def validate_id(value, field_name="ID"):
    """
    Validar que un valor sea un ID válido (entero positivo).
    Previene inyección SQL y errores de tipo.
    """
    try:
        id_val = int(value)
        if id_val <= 0:
            raise ValueError(f"{field_name} debe ser positivo")
        return id_val
    except (ValueError, TypeError):
        raise ValueError(f"{field_name} inválido")

def validate_date(date_string, field_name="Fecha"):
    """Validar formato de fecha"""
    try:
        return datetime.strptime(date_string, '%Y-%m-%d').date()
    except ValueError:
        raise ValueError(f"{field_name} inválida. Formato esperado: YYYY-MM-DD")

def validate_numeric(value, field_name="Valor", min_val=None, max_val=None):
    """Validar valores numéricos con rangos opcionales"""
    try:
        num = float(value)
        if min_val is not None and num < min_val:
            raise ValueError(f"{field_name} debe ser mayor o igual a {min_val}")
        if max_val is not None and num > max_val:
            raise ValueError(f"{field_name} debe ser menor o igual a {max_val}")
        return num
    except (ValueError, TypeError):
        raise ValueError(f"{field_name} debe ser un número válido")


def execute_paginated_query(
    base_query,
    params,
    order_by,
    default_per_page=25,
):
    """Ejecutar un listado y su conteo conservando filtros de la URL."""
    page = validate_int(
        request.args.get('page', 1),
        min_value=1,
        default=1,
    )
    per_page = validate_int(
        request.args.get('per_page', default_per_page),
        min_value=10,
        max_value=100,
        default=default_per_page,
    )
    params = tuple(params or ())
    total_row = execute_query(
        f'SELECT COUNT(*) AS total FROM ({base_query}) AS filtered_rows',
        params,
    ) or {'total': 0}
    total = int(total_row.get('total', 0) or 0)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, total_pages)
    offset = (page - 1) * per_page
    rows = execute_query(
        f'{base_query} ORDER BY {order_by} LIMIT %s OFFSET %s',
        params + (per_page, offset),
        fetch='all',
    ) or []

    def page_url(target):
        query_args = request.args.to_dict(flat=True)
        query_args['page'] = target
        query_args['per_page'] = per_page
        return url_for(request.endpoint, **query_args)

    return rows, {
        'page': page,
        'per_page': per_page,
        'total': total,
        'total_pages': total_pages,
        'first_item': offset + 1 if total else 0,
        'last_item': min(offset + per_page, total),
        'previous_url': page_url(page - 1) if page > 1 else None,
        'next_url': page_url(page + 1) if page < total_pages else None,
    }


@app.errorhandler(404)
def not_found(error):
    """Página no encontrada"""
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """Error interno del servidor"""
    return render_template('errors/500.html'), 500

@app.errorhandler(403)
def forbidden(error):
    """Acceso prohibido"""
    flash('No tienes permisos para acceder a este recurso', 'error')
    return redirect(url_for('facturacion_menu')), 403


@app.errorhandler(413)
def request_entity_too_large(error):
    """Rechazar cargas que superen el límite global."""
    if request.path.startswith('/api/') or request.path == '/facturacion/procesar-excel':
        return jsonify({
            'error': True,
            'mensaje': 'El archivo supera el tamaño máximo permitido.',
        }), 413
    flash('El archivo supera el tamaño máximo permitido.', 'error')
    return redirect(url_for('facturacion_menu'))


def get_current_tenant_id():
    """
    Obtener el TenantID del usuario actual de forma segura.
    El TenantID NUNCA viene del cliente, siempre de la sesión.
    """
    if current_user.is_authenticated:
        return current_user.tenant_id
    return None


@app.context_processor
def inject_notifications():
    """Mostrar pendientes de facturación y citas vencidas del tenant."""
    if not current_user.is_authenticated:
        return {'notificaciones': [], 'total_notificaciones': 0}

    tenant_id = get_current_tenant_id()
    notificaciones = []
    try:
        consultas_sin_factura = execute_query('''
            SELECT id, nombre_paciente, fecha_servicio
            FROM pacientes_pendientes
            WHERE tenant_id=%s AND estado='Pendiente'
            ORDER BY fecha_servicio DESC, id DESC
            LIMIT 6
        ''', (tenant_id,), fetch='all') or []
        for consulta in consultas_sin_factura:
            notificaciones.append({
                'tipo': 'facturacion',
                'titulo': 'Consulta pendiente de facturar',
                'detalle': consulta.get('nombre_paciente') or 'Paciente sin nombre',
                'fecha': consulta.get('fecha_servicio'),
                'url': url_for('facturacion_pacientes_pendientes')
            })
    except Exception as error:
        logger.warning(f'No se pudieron cargar consultas pendientes: {error}')

    if current_user.perfil == 'Registro de Facturas':
        return {
            'notificaciones': notificaciones,
            'total_notificaciones': len(notificaciones),
        }

    try:
        citas_vencidas = execute_query('''
            SELECT c.id, c.fecha, p.id AS paciente_id,
                   p.nombre AS paciente_nombre
            FROM citas_medicas c
            JOIN pacientes p
              ON p.id=c.paciente_id AND p.tenant_id=c.tenant_id
            WHERE c.tenant_id=%s
              AND (c.estado='Vencida' OR (
                    c.estado IN ('Programada','Confirmada')
                    AND c.fecha<CURDATE()
              ))
            ORDER BY c.fecha DESC, c.id DESC
            LIMIT 6
        ''', (tenant_id,), fetch='all') or []
        for cita in citas_vencidas:
            notificaciones.append({
                'tipo': 'cita',
                'titulo': 'Paciente con cita vencida',
                'detalle': cita['paciente_nombre'],
                'fecha': cita['fecha'],
                'url': url_for('facturacion_cita_editar', cita_id=cita['id'])
            })
    except Exception as error:
        logger.warning(f'No se pudieron cargar citas vencidas: {error}')

    return {
        'notificaciones': notificaciones,
        'total_notificaciones': len(notificaciones)
    }


def require_tenant(func):
    """
    Decorador que asegura que el usuario tenga un TenantID válido.
    Uso: @require_tenant antes de @login_required
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        
        if not hasattr(current_user, 'tenant_id') or not current_user.tenant_id:
            flash('Error: Usuario sin empresa asignada', 'error')
            return redirect(url_for('logout'))
        
        return func(*args, **kwargs)
    return wrapper


def roles_required(*allowed_profiles):
    """Restringir una ruta a perfiles explícitamente autorizados."""
    allowed = frozenset(allowed_profiles)

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            if current_user.perfil not in allowed:
                logger.warning(
                    'Acceso denegado por perfil: user_id=%s endpoint=%s',
                    current_user.get_id(),
                    request.endpoint,
                )
                flash('No tienes permisos para acceder a esta función', 'error')
                return redirect(url_for('facturacion_menu'))
            return func(*args, **kwargs)

        return wrapper

    return decorator


# Whitelist de tablas permitidas para prevenir SQL injection
_ALLOWED_TABLES = {
    'ars', 'auditoria_historia_clinica', 'auditoria_licencias_medicas',
    'centros_medicos', 'citas_medicas', 'codigo_ars',
    'consultas_clinicas', 'ecf_configuraciones', 'ecf_eventos',
    'ecf_outbox', 'ecf_secuencias', 'evoluciones_clinicas',
    'factura_detalles', 'facturas', 'facturas_ecf',
    'historias_emergencia', 'hojas_enfermeria', 'licencias_medicas',
    'medico_centro', 'medicos', 'ncf', 'pacientes',
    'pacientes_pendientes', 'pago_facturas', 'pagos',
    'receta_medicamentos', 'recetas_medicas', 'reclamaciones',
    'servicios', 'tipos_licencia_medica', 'usuarios',
}

_ALLOWED_ID_COLUMNS = {'id', 'paciente_id', 'medico_id', 'ars_id', 'factura_id'}

def validate_tenant_access(table, record_id, id_column='id'):
    """
    Validar que un registro pertenece al Tenant del usuario actual.
    Previene acceso a datos de otras empresas.
    
    Args:
        table: Nombre de la tabla (debe estar en whitelist)
        record_id: ID del registro a validar
        id_column: Nombre de la columna ID (debe estar en whitelist)
    
    Returns: True si el usuario tiene acceso, False si no.
    """
    # Validación de seguridad: whitelist de tablas y columnas
    if table not in _ALLOWED_TABLES:
        logger.warning(f"Intento de acceso a tabla no permitida: {table}")
        return False
    
    if id_column not in _ALLOWED_ID_COLUMNS:
        logger.warning(f"Intento de acceso con columna ID no permitida: {id_column}")
        return False
    
    # Validar que record_id sea un entero
    try:
        record_id = int(record_id)
    except (ValueError, TypeError):
        logger.warning(f"record_id inválido: {record_id}")
        return False
    
    tenant_id = get_current_tenant_id()
    if not tenant_id:
        return False
    
    # Query segura usando parámetros
    result = execute_query(
        "SELECT COUNT(*) as count FROM {} WHERE {} = %s AND tenant_id = %s".format(
            table, id_column
        ),
        (record_id, tenant_id)
    )
    
    return result and result.get('count', 0) > 0

def check_license_available(tenant_id):
    """
    Verificar si una empresa tiene licencias disponibles.
    Returns: (disponible: bool, licencias_restantes: int, mensaje: str)
    """
    empresa = execute_query('''
        SELECT licencias_totales, licencias_usadas, 
               (licencias_totales - licencias_usadas) as disponibles
        FROM empresas 
        WHERE id = %s AND estado = 'activo'
    ''', (tenant_id,))
    
    if not empresa:
        return (False, 0, "Empresa no encontrada o inactiva")
    
    disponibles = empresa['disponibles']
    
    if disponibles <= 0:
        return (False, 0, f"No hay licencias disponibles ({empresa['licencias_usadas']}/{empresa['licencias_totales']} en uso)")
    
    return (True, disponibles, f"{disponibles} licencias disponibles")

def get_empresa_info(tenant_id=None):
    """
    Obtener información de la empresa actual.
    """
    if tenant_id is None:
        tenant_id = get_current_tenant_id()
    
    if not tenant_id:
        return None
    
    return execute_query('SELECT * FROM empresas WHERE id = %s', (tenant_id,))

def verificar_suscripciones_vencidas():
    """
    Verificar y suspender automáticamente empresas con suscripción vencida.
    Esta función es un backup del evento MySQL.
    Se ejecuta en momentos clave (login, dashboard admin, etc.)
    """
    try:
        from datetime import date
        
        # Suspender empresas cuya fecha_fin ya pasó
        result = execute_update('''
            UPDATE empresas
            SET estado = 'suspendido'
            WHERE fecha_fin < CURDATE()
              AND estado = 'activo'
        ''')
        
        # Retornar número de empresas suspendidas
        return result if result else 0
    except Exception as e:
        print(f"Error verificando suscripciones: {e}")
        return 0

def get_dias_restantes_suscripcion(tenant_id=None):
    """
    Obtener días restantes de suscripción de una empresa.
    Returns: (dias_restantes: int, estado: str, mensaje: str)
    """
    empresa = get_empresa_info(tenant_id)
    
    if not empresa:
        return (0, 'error', 'Empresa no encontrada')
    
    if not empresa.get('fecha_fin'):
        return (9999, 'sin_fecha', 'Sin fecha de vencimiento')
    
    from datetime import date
    fecha_fin = empresa['fecha_fin']
    if isinstance(fecha_fin, str):
        fecha_fin = datetime.strptime(fecha_fin, '%Y-%m-%d').date()
    
    dias = (fecha_fin - date.today()).days
    
    if dias < 0:
        return (dias, 'vencida', f'Suscripción vencida hace {abs(dias)} días')
    elif dias <= 7:
        return (dias, 'urgente', f'Vence en {dias} días - URGENTE')
    elif dias <= 30:
        return (dias, 'proximo', f'Vence en {dias} días')
    else:
        return (dias, 'vigente', f'{dias} días restantes')

request_counts = defaultdict(list)
rate_limit_lock = Lock()

def rate_limit(
    max_requests=10,
    window=60,
    methods=('POST', 'PUT', 'PATCH', 'DELETE'),
):
    """Limitar operaciones mutables por cliente y endpoint."""
    limited_methods = frozenset(method.upper() for method in methods)

    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            if request.method.upper() not in limited_methods:
                return f(*args, **kwargs)

            client_ip = request.remote_addr or 'unknown'
            request_key = f'{client_ip}:{request.endpoint or f.__name__}'
            current_time = time.time()
            
            with rate_limit_lock:
                request_counts[request_key] = [
                    req_time for req_time in request_counts[request_key]
                    if current_time - req_time < window
                ]
                
                if len(request_counts[request_key]) >= max_requests:
                    return jsonify({'error': 'Rate limit exceeded'}), 429
                
                request_counts[request_key].append(current_time)
            
            return f(*args, **kwargs)
        return wrapper
    return decorator


@app.route('/api/csp-report', methods=['POST'])
@csrf.exempt
@rate_limit(max_requests=120, window=60)
def receive_csp_report():
    """Registrar únicamente los datos necesarios de una violación CSP."""
    payload = request.get_json(silent=True) or {}
    report = payload.get('csp-report', payload)
    if isinstance(report, dict):
        logger.warning(
            'CSP report: directive=%s blocked=%s document=%s',
            report.get('effective-directive') or report.get('violated-directive'),
            report.get('blocked-uri'),
            report.get('document-uri'),
        )
    return '', 204


@app.route('/')
def index():
    """Página pública de presentación de ARSFlow."""
    return render_template('inicio.html', current_year=datetime.now().year)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Inicio de sesión"""
    if current_user.is_authenticated:
        return redirect(url_for('facturacion_menu'))
    
    if request.method == 'POST':
        # Verificar suscripciones vencidas antes del login
        verificar_suscripciones_vencidas()
        # Rate limit manual
        client_ip = request.remote_addr
        current_time = time.time()
        
        with rate_limit_lock:
            request_counts[f'{client_ip}_login'] = [
                req_time for req_time in request_counts.get(f'{client_ip}_login', [])
                if current_time - req_time < 300
            ]
            
            if len(request_counts.get(f'{client_ip}_login', [])) >= 5:
                flash('Demasiados intentos. Espera 5 minutos.', 'error')
                return redirect(url_for('login'))
            
            if f'{client_ip}_login' not in request_counts:
                request_counts[f'{client_ip}_login'] = []
            request_counts[f'{client_ip}_login'].append(current_time)
        
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        
        if not email or not password:
            flash('Por favor ingresa email y contraseña', 'error')
            return redirect(url_for('login'))
        
        # Obtener usuario con información de empresa
        user_data = execute_query('''
            SELECT u.*, 
                   e.nombre as empresa_nombre, 
                   e.estado as empresa_estado,
                   e.fecha_fin as empresa_fecha_fin
            FROM usuarios u
            LEFT JOIN empresas e ON u.tenant_id = e.id
            WHERE u.email = %s
        ''', (email,))
        
        if user_data and user_data['activo']:
            # Validar que la empresa esté activa
            if user_data.get('empresa_estado') != 'activo':
                if user_data.get('empresa_estado') == 'suspendido':
                    flash('Suscripción vencida o suspendida. Contacta al administrador del sistema.', 'error')
                else:
                    flash('La empresa asociada a este usuario está inactiva', 'error')
                return redirect(url_for('login'))
            
            # Validar fecha de fin de suscripción
            if user_data.get('empresa_fecha_fin'):
                from datetime import date
                fecha_fin = user_data['empresa_fecha_fin']
                if isinstance(fecha_fin, str):
                    fecha_fin = datetime.strptime(fecha_fin, '%Y-%m-%d').date()
                
                if fecha_fin < date.today():
                    # Suscripción vencida - suspender empresa automáticamente
                    execute_update('''
                        UPDATE empresas 
                        SET estado = 'suspendido' 
                        WHERE id = %s AND estado = 'activo'
                    ''', (user_data.get('tenant_id'),))
                    
                    flash('La suscripción de tu empresa ha vencido. Contacta al administrador.', 'error')
                    return redirect(url_for('login'))
            
            if check_password_hash(user_data['password_hash'], password):
                if user_data['password_temporal']:
                    session['cambio_password_usuario_id'] = user_data['id']
                    session['cambio_password_email'] = user_data['email']
                    session['cambio_password_tenant_id'] = user_data.get('tenant_id')
                    flash('Debes cambiar tu contraseña temporal', 'warning')
                    return redirect(url_for('cambiar_password_obligatorio'))
                
                user = User(
                    id=user_data['id'],
                    nombre=user_data['nombre'],
                    email=user_data['email'],
                    perfil=user_data['perfil'],
                    tema_color=user_data.get('tema_color', 'cyan'),
                    fuente_ui=user_data.get('fuente_ui', 'arsflow'),
                    tenant_id=user_data.get('tenant_id', 1),
                    empresa_nombre=user_data.get('empresa_nombre', '')
                )
                
                session.permanent = True
                session['tenant_id'] = user.tenant_id  # Guardar tenant_id en sesión
                session['empresa_nombre'] = user.empresa_nombre
                login_user(user, remember=True)
                
                execute_update(
                    '''
                    UPDATE usuarios SET last_login = %s
                    WHERE id = %s AND tenant_id <=> %s
                    ''',
                    (datetime.now(), user_data['id'], user_data.get('tenant_id')),
                )
                
                return redirect(url_for('facturacion_menu'))
            else:
                flash('Contraseña incorrecta', 'error')
        else:
            flash('Usuario no encontrado o inactivo', 'error')
        
        return redirect(url_for('login'))
    
    allow_dev_prefill = (
        ENVIRONMENT == 'development'
        and os.getenv('ALLOW_DEV_LOGIN_PREFILL', '').lower() == 'true'
    )
    return render_template(
        'login.html',
        dev_login_email=(
            os.getenv('DEV_LOGIN_EMAIL', '').strip() if allow_dev_prefill else ''
        ),
        dev_login_password=(
            os.getenv('DEV_LOGIN_PASSWORD', '') if allow_dev_prefill else ''
        ),
        development_prefill_enabled=allow_dev_prefill,
    )

@app.route('/registro', methods=['GET', 'POST'])
@rate_limit(max_requests=5, window=300)
def registro():
    """Registro público gratuito de empresa + usuario administrador"""
    if current_user.is_authenticated:
        return redirect(url_for('facturacion_menu'))

    if request.method == 'POST':
        nombre_empresa = sanitize_input(request.form.get('nombre_empresa', ''), 255)
        tipo_empresa = request.form.get('tipo_empresa', '').strip()
        nombre = sanitize_input(request.form.get('nombre', ''), 255)
        email = request.form.get('email', '').strip().lower()
        telefono = sanitize_input(request.form.get('telefono', ''), 20)
        password = request.form.get('password', '')
        password_confirm = request.form.get('password_confirm', '')

        if not nombre_empresa or not nombre or not email or not telefono or not password:
            flash('Completa todos los campos obligatorios', 'error')
            return render_template('registro.html')

        if tipo_empresa not in ('medico', 'centro_salud'):
            flash('Selecciona un tipo de empresa válido', 'error')
            return render_template('registro.html')

        if not validate_email(email):
            flash('Ingresa un correo electrónico válido', 'error')
            return render_template('registro.html')

        if not validate_digits(telefono, 10):
            flash('El teléfono debe contener exactamente 10 números', 'error')
            return render_template('registro.html')

        if password != password_confirm:
            flash('Las contraseñas no coinciden', 'error')
            return render_template('registro.html')

        password_errors = validar_password_segura(password)
        if password_errors:
            flash(f'Contraseña no válida: {", ".join(password_errors)}', 'error')
            return render_template('registro.html')

        email_existe = execute_query('SELECT id FROM usuarios WHERE email = %s', (email,))
        if email_existe:
            flash('Ya existe una cuenta con ese correo. Inicia sesión o recupera tu contraseña.', 'error')
            return render_template('registro.html')

        empresa_existe = execute_query('SELECT id FROM empresas WHERE nombre = %s', (nombre_empresa,))
        if empresa_existe:
            flash('Ya existe una empresa con ese nombre. Usa otro nombre o inicia sesión.', 'error')
            return render_template('registro.html')

        from datetime import date, timedelta
        fecha_inicio = date.today()
        fecha_fin = fecha_inicio + timedelta(days=30)

        try:
            with database_transaction():
                empresa_id = execute_update('''
                    INSERT INTO empresas (
                        nombre, razon_social, telefono, email, fecha_inicio, fecha_fin,
                        licencias_totales, licencias_usadas, plan, estado, tipo_empresa
                    ) VALUES (%s, %s, %s, %s, %s, %s, 5, 1, 'basico', 'activo', %s)
                ''', (
                    nombre_empresa, nombre_empresa, telefono, email,
                    fecha_inicio, fecha_fin, tipo_empresa,
                ))
                if not empresa_id:
                    raise RuntimeError('No se pudo crear la empresa')

                password_hash = generate_password_hash(password)
                user_id = execute_update('''
                    INSERT INTO usuarios (
                        tenant_id, nombre, email, password_hash, perfil, activo, password_temporal
                    ) VALUES (%s, %s, %s, %s, 'Administrador', 1, 0)
                ''', (empresa_id, nombre, email, password_hash))
                if not user_id:
                    raise RuntimeError('No se pudo crear el usuario administrador')

            flash('Cuenta creada exitosamente. Ya puedes iniciar sesión.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            logger.error(f'Error en registro público: {e}', exc_info=True)
            flash('Ocurrió un error al crear la cuenta. Intenta de nuevo.', 'error')
            return render_template('registro.html')

    return render_template('registro.html')

@app.route('/logout')
@login_required
def logout():
    """Cerrar sesión"""
    logout_user()
    flash('Sesión cerrada correctamente', 'success')
    return redirect(url_for('index'))

@app.route('/cambiar-password-obligatorio', methods=['GET', 'POST'])
def cambiar_password_obligatorio():
    """Cambio de contraseña obligatorio"""
    if 'cambio_password_usuario_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        password = request.form.get('password', '')
        password_confirm = request.form.get('password_confirm', '')
        
        if not password or not password_confirm:
            flash('Debes completar todos los campos', 'error')
            return redirect(url_for('cambiar_password_obligatorio'))
        
        if password != password_confirm:
            flash('Las contraseñas no coinciden', 'error')
            return redirect(url_for('cambiar_password_obligatorio'))
        
        password_errors = validar_password_segura(password)
        if password_errors:
            flash(f'Contraseña no válida: {", ".join(password_errors)}', 'error')
            return redirect(url_for('cambiar_password_obligatorio'))
        
        user_id = session['cambio_password_usuario_id']
        tenant_id = session.get('cambio_password_tenant_id')
        password_hash = generate_password_hash(password)
        
        execute_update('''
            UPDATE usuarios 
            SET password_hash = %s, password_temporal = 0
            WHERE id = %s AND tenant_id <=> %s
        ''', (password_hash, user_id, tenant_id))
        
        user_data = execute_query(
            'SELECT * FROM usuarios WHERE id = %s AND tenant_id <=> %s',
            (user_id, tenant_id),
        )
        
        # Limpiar sesión temporal
        session.pop('cambio_password_usuario_id', None)
        session.pop('cambio_password_email', None)
        session.pop('cambio_password_tenant_id', None)
        
        # Login automático
        user = User(
            id=user_data['id'],
            nombre=user_data['nombre'],
            email=user_data['email'],
            perfil=user_data['perfil'],
            tema_color=user_data.get('tema_color', 'cyan'),
            fuente_ui=user_data.get('fuente_ui', 'arsflow'),
            tenant_id=user_data.get('tenant_id', 1),
            empresa_nombre=user_data.get('empresa_nombre', '')
        )
        login_user(user, remember=True)
        
        flash('Contraseña cambiada exitosamente', 'success')
        return redirect(url_for('facturacion_menu'))
    
    return render_template('cambiar_password_obligatorio.html')

@app.route('/solicitar-recuperacion', methods=['GET', 'POST'])
@rate_limit(max_requests=3, window=300)
def solicitar_recuperacion():
    """Solicitar recuperación de contraseña"""
    if current_user.is_authenticated:
        return redirect(url_for('facturacion_menu'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        
        if not email or not validate_email(email):
            flash('Por favor ingresa un email válido', 'error')
            return redirect(url_for('solicitar_recuperacion'))
        
        usuario = execute_query(
            'SELECT * FROM usuarios WHERE email = %s AND activo = 1',
            (email,)
        )
        
        if usuario:
            # Generar token de recuperación
            token = secrets.token_urlsafe(32)
            expiracion = datetime.now() + timedelta(hours=1)
            
            execute_update('''
                UPDATE usuarios 
                SET reset_token = %s, reset_token_expiracion = %s
                WHERE id = %s AND tenant_id <=> %s
            ''', (token, expiracion, usuario['id'], usuario.get('tenant_id')))
            
            # Enviar email si SendGrid está disponible
            if SENDGRID_AVAILABLE:
                try:
                    public_base_url = os.getenv('APP_BASE_URL', '').strip()
                    if public_base_url:
                        reset_url = urljoin(
                            public_base_url.rstrip('/') + '/',
                            url_for('recuperar_password', token=token).lstrip('/'),
                        )
                    elif not IS_PRODUCTION:
                        reset_url = url_for(
                            'recuperar_password', token=token, _external=True
                        )
                    else:
                        raise RuntimeError(
                            'APP_BASE_URL no está configurada para recuperación.'
                        )
                    
                    message = Mail(
                        from_email=os.getenv('SENDGRID_FROM_EMAIL', 'noreply@facturacion.com'),
                        to_emails=email,
                        subject='Recuperación de Contraseña - ARSFLOW Gestion de Factras Medicas',
                        html_content=f'''
                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                            <h2 style="color: #CEB0B7;">Recuperación de Contraseña</h2>
                            <p>Hola {usuario['nombre']},</p>
                            <p>Has solicitado recuperar tu contraseña. Haz clic en el siguiente enlace para crear una nueva contraseña:</p>
                            <p style="margin: 30px 0;">
                                <a href="{reset_url}" 
                                   style="background: #CEB0B7; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
                                    Recuperar Contraseña
                                </a>
                            </p>
                            <p style="color: #666; font-size: 14px;">Este enlace expirará en 1 hora.</p>
                            <p style="color: #666; font-size: 14px;">Si no solicitaste este cambio, ignora este email.</p>
                            <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
                            <p style="color: #999; font-size: 12px;">ARSFLOW Gestion de Factras Medicas</p>
                        </div>
                        '''
                    )
                    
                    sg = SendGridAPIClient(os.getenv('SENDGRID_API_KEY'))
                    sg.send(message)
                    
                    flash('Se ha enviado un email con instrucciones para recuperar tu contraseña', 'success')
                except Exception as e:
                    print(f"Error enviando email: {e}")
                    flash('Error al enviar el email. Contacta al administrador.', 'error')
            elif (
                ENVIRONMENT == 'development'
                and os.getenv('ALLOW_INSECURE_DEV_RESET_TOKEN', '').lower() == 'true'
            ):
                # Opt-in explícito para un entorno local aislado.
                flash(f'Token de recuperación (solo desarrollo): {token}', 'info')
                flash('Usa este enlace para recuperar tu contraseña', 'info')
            else:
                logger.error(
                    'Recuperación solicitada sin un proveedor de correo disponible.'
                )
                flash(
                    'No fue posible enviar el correo. Contacta al administrador.',
                    'error',
                )
        else:
            # Por seguridad, mostramos el mismo mensaje aunque el usuario no exista
            flash('Si el email existe, recibirás instrucciones para recuperar tu contraseña', 'info')
        
        return redirect(url_for('login'))
    
    return render_template('solicitar_recuperacion.html')

@app.route('/recuperar-password/<token>', methods=['GET', 'POST'])
def recuperar_password(token):
    """Recuperar contraseña con token"""
    if current_user.is_authenticated:
        return redirect(url_for('facturacion_menu'))
    
    usuario = execute_query('''
        SELECT * FROM usuarios 
        WHERE reset_token = %s 
        AND reset_token_expiracion > %s
        AND activo = 1
    ''', (token, datetime.now()))
    
    if not usuario:
        flash('El enlace de recuperación es inválido o ha expirado', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        password = request.form.get('password', '')
        password_confirm = request.form.get('password_confirm', '')
        
        if not password or not password_confirm:
            flash('Debes completar todos los campos', 'error')
            return redirect(url_for('recuperar_password', token=token))
        
        if password != password_confirm:
            flash('Las contraseñas no coinciden', 'error')
            return redirect(url_for('recuperar_password', token=token))
        
        password_errors = validar_password_segura(password)
        if password_errors:
            flash(f'Contraseña no válida: {", ".join(password_errors)}', 'error')
            return redirect(url_for('recuperar_password', token=token))
        
        password_hash = generate_password_hash(password)
        
        execute_update('''
            UPDATE usuarios 
            SET password_hash = %s, 
                password_temporal = 0,
                reset_token = NULL,
                reset_token_expiracion = NULL
            WHERE id = %s AND tenant_id <=> %s
        ''', (password_hash, usuario['id'], usuario.get('tenant_id')))
        
        flash('Contraseña actualizada exitosamente. Ahora puedes iniciar sesión.', 'success')
        return redirect(url_for('login'))
    
    return render_template('recuperar_password.html', token=token)

@app.route('/admin/empresas')
@login_required
def admin_empresas():
    """Listar empresas - Super Admin ve todas, Administrador ve solo la suya"""
    if current_user.perfil != 'Administrador':
        flash('No tienes permisos para gestionar empresas', 'error')
        return redirect(url_for('facturacion_menu'))
    
    tenant_id = get_current_tenant_id()
    
    # Si es Super Admin (sin tenant_id), ver todas las empresas
    if tenant_id is None:
        # Super Admin puede ver todas las empresas
        empresas = execute_query('''
            SELECT e.*, 
                   COUNT(u.id) as total_usuarios
            FROM empresas e
            LEFT JOIN usuarios u ON e.id = u.tenant_id AND u.activo = 1
            GROUP BY e.id
            ORDER BY e.fecha_creacion DESC
        ''', fetch='all')
    else:
        # Administrador de empresa solo ve su propia empresa
        empresas = execute_query('''
            SELECT e.*, 
                   COUNT(u.id) as total_usuarios
            FROM empresas e
            LEFT JOIN usuarios u ON e.id = u.tenant_id AND u.activo = 1
            WHERE e.id = %s
            GROUP BY e.id
            ORDER BY e.fecha_creacion DESC
        ''', (tenant_id,), fetch='all') or []
    
    # Verificar y suspender empresas vencidas
    empresas_suspendidas = verificar_suscripciones_vencidas()
    if empresas_suspendidas > 0:
        flash(f'{empresas_suspendidas} empresa(s) suspendida(s) por vencimiento de suscripción', 'warning')
    
    # Calcular días restantes y estado de suscripción para cada empresa
    from datetime import date
    for empresa in empresas:
        if empresa.get('fecha_fin'):
            try:
                fecha_fin = empresa['fecha_fin']
                if isinstance(fecha_fin, str):
                    fecha_fin = datetime.strptime(fecha_fin, '%Y-%m-%d').date()
                
                dias_restantes = (fecha_fin - date.today()).days
                empresa['dias_restantes'] = dias_restantes
                
                # Determinar estado y clase CSS
                if dias_restantes < 0:
                    empresa['estado_suscripcion'] = 'vencida'
                    empresa['estado_texto'] = 'VENCIDA'
                    empresa['estado_clase'] = 'danger'
                    empresa['estado_icono'] = 'exclamation-circle'
                elif dias_restantes <= 7:
                    empresa['estado_suscripcion'] = 'urgente'
                    empresa['estado_texto'] = f'{dias_restantes}d - URGENTE'
                    empresa['estado_clase'] = 'danger'
                    empresa['estado_icono'] = 'exclamation-triangle'
                elif dias_restantes <= 30:
                    empresa['estado_suscripcion'] = 'proximo'
                    empresa['estado_texto'] = f'{dias_restantes} días'
                    empresa['estado_clase'] = 'warning'
                    empresa['estado_icono'] = 'clock'
                else:
                    empresa['estado_suscripcion'] = 'vigente'
                    empresa['estado_texto'] = f'{dias_restantes} días'
                    empresa['estado_clase'] = 'success'
                    empresa['estado_icono'] = 'check-circle'
            except:
                empresa['dias_restantes'] = None
                empresa['estado_suscripcion'] = 'error'
                empresa['estado_texto'] = 'Error'
                empresa['estado_clase'] = 'secondary'
                empresa['estado_icono'] = 'question'
        else:
            empresa['dias_restantes'] = None
            empresa['estado_suscripcion'] = 'sin_fecha'
            empresa['estado_texto'] = 'Sin fecha'
            empresa['estado_clase'] = 'secondary'
            empresa['estado_icono'] = 'calendar'
    
    return render_template('admin/empresas/lista.html', empresas=empresas)

@app.route('/admin/empresas/nueva', methods=['GET', 'POST'])
@login_required
def admin_empresas_nueva():
    """Crear nueva empresa - Solo Super Admin (sin tenant_id)"""
    # Solo usuarios sin tenant_id (Super Admin) pueden crear empresas
    # Los administradores de una empresa solo gestionan usuarios dentro de su empresa
    tenant_id = get_current_tenant_id()
    if tenant_id is not None:
        flash('No tienes permisos para crear empresas. Solo Super Administradores pueden crear nuevas empresas.', 'error')
        return redirect(url_for('admin_empresas'))
    
    if current_user.perfil != 'Administrador':
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_menu'))
    
    if request.method == 'POST':
        nombre = sanitize_input(request.form.get('nombre', ''), 255)
        razon_social = sanitize_input(request.form.get('razon_social', ''), 255)
        rnc = sanitize_input(request.form.get('rnc', ''), 20)
        telefono = sanitize_input(request.form.get('telefono', ''), 20)
        email = request.form.get('email', '').strip().lower()
        direccion = sanitize_input(request.form.get('direccion', ''), 500)
        fecha_inicio = request.form.get('fecha_inicio')
        fecha_fin = request.form.get('fecha_fin')
        licencias_raw = request.form.get('licencias_totales', '').strip()
        licencias_totales = validate_int(licencias_raw, min_value=1, max_value=1000, default=None)
        plan = request.form.get('plan', '').strip()
        tipo_empresa = request.form.get('tipo_empresa', '').strip()
        
        # Validar tipo_empresa
        if tipo_empresa not in ['medico', 'centro_salud']:
            flash('Debe seleccionar un tipo de empresa válido', 'error')
            return redirect(url_for('admin_empresas_nueva'))
        
        if (not nombre or not razon_social or not rnc or not telefono or not email or
                not direccion or not fecha_inicio or not fecha_fin or
                licencias_totales is None or not plan or not tipo_empresa):
            flash('Todos los campos son obligatorios', 'error')
            return redirect(url_for('admin_empresas_nueva'))

        documento_nombre = 'cédula' if tipo_empresa == 'medico' else 'RNC'
        documento_longitud = 11 if tipo_empresa == 'medico' else 9
        if not validate_digits(rnc, documento_longitud):
            flash(f'La {documento_nombre} debe contener exactamente {documento_longitud} números', 'error')
            return redirect(url_for('admin_empresas_nueva'))

        if not validate_digits(telefono, 10):
            flash('El teléfono debe contener exactamente 10 números', 'error')
            return redirect(url_for('admin_empresas_nueva'))

        if not validate_email(email):
            flash('Debe introducir un email válido', 'error')
            return redirect(url_for('admin_empresas_nueva'))

        if plan not in ['basico', 'profesional', 'empresarial']:
            flash('Debe seleccionar un plan válido', 'error')
            return redirect(url_for('admin_empresas_nueva'))
        
        # Validar fechas
        try:
            fecha_inicio_obj = datetime.strptime(fecha_inicio, '%Y-%m-%d').date()
            fecha_fin_obj = datetime.strptime(fecha_fin, '%Y-%m-%d').date()
            
            if fecha_fin_obj <= fecha_inicio_obj:
                flash('La fecha de fin debe ser posterior a la fecha de inicio', 'error')
                return redirect(url_for('admin_empresas_nueva'))
        except ValueError:
            flash('Fechas inválidas', 'error')
            return redirect(url_for('admin_empresas_nueva'))
        
        # Verificar que no exista
        existe = execute_query('SELECT id FROM empresas WHERE nombre = %s', (nombre,))
        if existe:
            flash('Ya existe una empresa con ese nombre', 'error')
            return redirect(url_for('admin_empresas_nueva'))
        
        # Crear empresa - Verificar si existe columna tipo_empresa
        try:
            # Intentar insertar con tipo_empresa
            execute_update('''
                INSERT INTO empresas (
                    nombre, razon_social, rnc, telefono, email, direccion,
                    fecha_inicio, fecha_fin,
                    licencias_totales, licencias_usadas, plan, estado, tipo_empresa,
                    creado_por
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 0, %s, 'activo', %s, %s)
            ''', (nombre, razon_social, rnc, telefono, email, direccion, 
                  fecha_inicio, fecha_fin, licencias_totales, plan, tipo_empresa, current_user.id))
        except Exception as e:
            error_msg = str(e).lower()
            if 'unknown column' in error_msg and 'tipo_empresa' in error_msg:
                # Si no existe la columna, crear sin tipo_empresa y mostrar advertencia
                logger.warning("Columna tipo_empresa no existe en tabla empresas. Ejecute el script de migración.")
                execute_update('''
                    INSERT INTO empresas (
                        nombre, razon_social, rnc, telefono, email, direccion,
                        fecha_inicio, fecha_fin,
                        licencias_totales, licencias_usadas, plan, estado,
                        creado_por
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 0, %s, 'activo', %s)
                ''', (nombre, razon_social, rnc, telefono, email, direccion, 
                      fecha_inicio, fecha_fin, licencias_totales, plan, current_user.id))
                flash(f'Empresa {nombre} creada exitosamente. NOTA: Ejecute el script de migración para agregar el campo tipo_empresa.', 'warning')
            else:
                raise
        
        flash(f'Empresa "{nombre}" creada exitosamente', 'success')
        return redirect(url_for('admin_empresas'))
    
    return render_template('admin/empresas/form.html', empresa=None)

@app.route('/admin/empresas/editar/<int:empresa_id>', methods=['GET', 'POST'])
@login_required
def admin_empresas_editar(empresa_id):
    """Editar empresa - Super Admin puede editar cualquier empresa, Administrador solo la suya"""
    if current_user.perfil != 'Administrador':
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_menu'))
    
    tenant_id = get_current_tenant_id()
    
    empresa = execute_query('SELECT * FROM empresas WHERE id = %s', (empresa_id,))
    
    if not empresa:
        flash('Empresa no encontrada', 'error')
        return redirect(url_for('admin_empresas'))
    
    # Si el usuario tiene tenant_id (no es Super Admin), solo puede editar su propia empresa
    if tenant_id is not None and empresa['id'] != tenant_id:
        flash('No tienes permisos para editar esta empresa. Solo puedes editar tu propia empresa.', 'error')
        return redirect(url_for('admin_empresas'))
    
    if request.method == 'POST':
        nombre = sanitize_input(request.form.get('nombre', ''), 255)
        razon_social = sanitize_input(request.form.get('razon_social', ''), 255)
        rnc = sanitize_input(request.form.get('rnc', ''), 20)
        telefono = sanitize_input(request.form.get('telefono', ''), 20)
        email = request.form.get('email', '').strip().lower()
        direccion = sanitize_input(request.form.get('direccion', ''), 500)
        fecha_inicio = request.form.get('fecha_inicio')
        fecha_fin = request.form.get('fecha_fin')
        licencias_raw = request.form.get('licencias_totales', '').strip()
        licencias_totales = validate_int(licencias_raw, min_value=1, max_value=1000, default=None)
        plan = request.form.get('plan', '').strip()
        estado = request.form.get('estado', '').strip()
        tipo_empresa = request.form.get('tipo_empresa', '').strip()
        
        # Validar tipo_empresa - debe ser obligatorio
        if not tipo_empresa:
            flash('El tipo de empresa es obligatorio', 'error')
            return redirect(url_for('admin_empresas_editar', empresa_id=empresa_id))
        
        # Validar que sea un valor válido
        if tipo_empresa not in ['medico', 'centro_salud']:
            flash('Tipo de empresa inválido', 'error')
            return redirect(url_for('admin_empresas_editar', empresa_id=empresa_id))

        if (not nombre or not razon_social or not rnc or not telefono or not email or
                not direccion or not fecha_inicio or not fecha_fin or
                licencias_totales is None or not plan or not estado):
            flash('Todos los campos son obligatorios', 'error')
            return redirect(url_for('admin_empresas_editar', empresa_id=empresa_id))

        documento_nombre = 'cédula' if tipo_empresa == 'medico' else 'RNC'
        documento_longitud = 11 if tipo_empresa == 'medico' else 9
        if not validate_digits(rnc, documento_longitud):
            flash(f'La {documento_nombre} debe contener exactamente {documento_longitud} números', 'error')
            return redirect(url_for('admin_empresas_editar', empresa_id=empresa_id))

        if not validate_digits(telefono, 10):
            flash('El teléfono debe contener exactamente 10 números', 'error')
            return redirect(url_for('admin_empresas_editar', empresa_id=empresa_id))

        if not validate_email(email):
            flash('Debe introducir un email válido', 'error')
            return redirect(url_for('admin_empresas_editar', empresa_id=empresa_id))

        if plan not in ['basico', 'profesional', 'empresarial']:
            flash('Debe seleccionar un plan válido', 'error')
            return redirect(url_for('admin_empresas_editar', empresa_id=empresa_id))

        if estado not in ['activo', 'suspendido', 'inactivo']:
            flash('Debe seleccionar un estado válido', 'error')
            return redirect(url_for('admin_empresas_editar', empresa_id=empresa_id))
        
        # Validar fechas
        try:
            fecha_inicio_obj = datetime.strptime(fecha_inicio, '%Y-%m-%d').date()
            fecha_fin_obj = datetime.strptime(fecha_fin, '%Y-%m-%d').date()
            
            if fecha_fin_obj <= fecha_inicio_obj:
                flash('La fecha de fin debe ser posterior a la fecha de inicio', 'error')
                return redirect(url_for('admin_empresas_editar', empresa_id=empresa_id))
            
            # Si la fecha ya venció y está activo, cambiar a suspendido
            from datetime import date
            if fecha_fin_obj < date.today() and estado == 'activo':
                estado = 'suspendido'
                flash('La fecha de fin ya venció. El estado se cambió a "suspendido" automáticamente.', 'warning')
        except ValueError:
            flash('Fechas inválidas', 'error')
            return redirect(url_for('admin_empresas_editar', empresa_id=empresa_id))
        
        # Actualizar empresa - Verificar si existe columna tipo_empresa
        try:
            # Intentar actualizar con tipo_empresa (siempre incluir el campo, incluso si está vacío)
            execute_update('''
                UPDATE empresas SET
                    nombre = %s, razon_social = %s, rnc = %s,
                    telefono = %s, email = %s, direccion = %s,
                    fecha_inicio = %s, fecha_fin = %s,
                    licencias_totales = %s, plan = %s, estado = %s, tipo_empresa = %s
                WHERE id = %s
            ''', (nombre, razon_social, rnc, telefono, email, direccion,
                  fecha_inicio, fecha_fin, licencias_totales, plan, estado, tipo_empresa or None, empresa_id))
        except Exception as e:
            error_msg = str(e).lower()
            if 'unknown column' in error_msg and 'tipo_empresa' in error_msg:
                # Si no existe la columna, actualizar sin tipo_empresa
                logger.warning("Columna tipo_empresa no existe en tabla empresas. Ejecute el script de migración.")
                execute_update('''
                    UPDATE empresas SET
                        nombre = %s, razon_social = %s, rnc = %s,
                        telefono = %s, email = %s, direccion = %s,
                        fecha_inicio = %s, fecha_fin = %s,
                        licencias_totales = %s, plan = %s, estado = %s
                    WHERE id = %s
                ''', (nombre, razon_social, rnc, telefono, email, direccion,
                      fecha_inicio, fecha_fin, licencias_totales, plan, estado, empresa_id))
                flash(f'Empresa {nombre} actualizada exitosamente. NOTA: Ejecute el script de migración para agregar el campo tipo_empresa.', 'warning')
            else:
                logger.error(f"Error al actualizar empresa: {e}")
                raise
        
        flash(f'Empresa "{nombre}" actualizada exitosamente', 'success')
        return redirect(url_for('admin_empresas'))
    
    return render_template('admin/empresas/form.html', empresa=empresa)

@app.route('/admin/verificar-multitenant')
@login_required
def verificar_multitenant():
    """Verificar que el sistema multi-tenant está configurado correctamente"""
    if current_user.perfil != 'Administrador':
        return jsonify({'error': 'No tienes permisos'}), 403
    
    verificacion = {
        'titulo': 'VERIFICACIÓN SISTEMA MULTI-TENANT',
        'fecha': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'estado_general': 'OK',
        'errores': [],
        'advertencias': [],
        'detalles': {}
    }
    
    try:
        # 1. Verificar tabla empresas existe
        try:
            empresas = execute_query('SELECT COUNT(*) as total FROM empresas', fetch='one')
            verificacion['detalles']['tabla_empresas'] = {
                'existe': True,
                'total_empresas': empresas['total']
            }
        except Exception as e:
            verificacion['errores'].append(f'Tabla empresas no existe: {str(e)}')
            verificacion['estado_general'] = 'ERROR'
            return jsonify(verificacion)
        
        # 2. Verificar empresa por defecto
        empresa_default = execute_query('SELECT * FROM empresas WHERE id = 1', fetch='one')
        if empresa_default:
            verificacion['detalles']['empresa_default'] = {
                'existe': True,
                'nombre': empresa_default['nombre'],
                'licencias_totales': empresa_default['licencias_totales'],
                'licencias_usadas': empresa_default['licencias_usadas'],
                'licencias_disponibles': empresa_default['licencias_totales'] - empresa_default['licencias_usadas'],
                'plan': empresa_default['plan'],
                'estado': empresa_default['estado']
            }
        else:
            verificacion['advertencias'].append('No existe empresa con ID=1 (empresa por defecto)')
        
        # 3. Verificar columnas tenant_id en tablas
        tablas_verificar = REQUIRED_TENANT_TABLES
        
        columnas_ok = []
        columnas_faltantes = []
        
        for tabla in tablas_verificar:
            try:



                
                result = execute_query(f"SHOW COLUMNS FROM {tabla} LIKE 'tenant_id'", fetch='one')
                if result:
                    columnas_ok.append(tabla)
                else:
                    columnas_faltantes.append(tabla)
                    verificacion['errores'].append(f'Tabla {tabla} NO tiene columna tenant_id')
            except Exception as e:
                columnas_faltantes.append(tabla)
                verificacion['errores'].append(f'Error verificando tabla {tabla}: {str(e)}')
        
        verificacion['detalles']['columnas_tenant_id'] = {
            'total_tablas': len(tablas_verificar),
            'tablas_ok': len(columnas_ok),
            'tablas_faltantes': len(columnas_faltantes),
            'lista_ok': columnas_ok,
            'lista_faltantes': columnas_faltantes
        }
        
        # 4. Verificar usuarios con tenant_id
        usuarios_sin_tenant = execute_query('''
            SELECT COUNT(*) as total FROM usuarios 
            WHERE tenant_id IS NULL OR tenant_id = 0
        ''', fetch='one')
        
        if usuarios_sin_tenant and usuarios_sin_tenant['total'] > 0:
            verificacion['advertencias'].append(f'{usuarios_sin_tenant["total"]} usuarios sin tenant_id asignado')
        
        usuarios_por_tenant = execute_query('''
            SELECT tenant_id, COUNT(*) as total
            FROM usuarios
            WHERE activo = 1
            GROUP BY tenant_id
        ''', fetch='all')
        
        verificacion['detalles']['usuarios_por_tenant'] = [
            {'tenant_id': u['tenant_id'], 'total': u['total']}
            for u in (usuarios_por_tenant or [])
        ]
        
        # 5. Verificar triggers
        triggers = execute_query('''
            SHOW TRIGGERS WHERE `Trigger` LIKE 'trg_usuarios_%'
        ''', fetch='all')
        
        verificacion['detalles']['triggers'] = {
            'total': len(triggers) if triggers else 0,
            'esperados': 3,
            'ok': len(triggers) == 3 if triggers else False,
            'lista': [t['Trigger'] for t in (triggers or [])]
        }
        
        if not triggers or len(triggers) < 3:
            verificacion['advertencias'].append(f'Solo {len(triggers) if triggers else 0}/3 triggers encontrados')
        
        # 6. Verificar índices
        indices_tenant = execute_query('''
            SELECT TABLE_NAME, INDEX_NAME
            FROM information_schema.STATISTICS
            WHERE TABLE_SCHEMA = DATABASE()
            AND INDEX_NAME LIKE '%tenant%'
        ''', fetch='all')
        
        verificacion['detalles']['indices'] = {
            'total': len(indices_tenant) if indices_tenant else 0,
            'lista': [{'tabla': i['TABLE_NAME'], 'indice': i['INDEX_NAME']} for i in (indices_tenant or [])]
        }
        
        # 7. Estado del usuario actual
        verificacion['detalles']['usuario_actual'] = {
            'nombre': current_user.nombre,
            'email': current_user.email,
            'tenant_id': current_user.tenant_id if hasattr(current_user, 'tenant_id') else 'NO DISPONIBLE',
            'empresa_nombre': current_user.empresa_nombre if hasattr(current_user, 'empresa_nombre') else 'NO DISPONIBLE'
        }
        
        # Determinar estado general
        if verificacion['errores']:
            verificacion['estado_general'] = 'ERROR'
        elif verificacion['advertencias']:
            verificacion['estado_general'] = 'ADVERTENCIAS'
        else:
            verificacion['estado_general'] = 'PERFECTO ✅'
        
    except Exception as e:
        verificacion['estado_general'] = 'ERROR CRÍTICO'
        verificacion['errores'].append(f'Error durante verificación: {str(e)}')
    
    return jsonify(verificacion)

@app.route('/admin/verificar-multitenant-visual')
@login_required
def verificar_multitenant_visual():
    """Página visual de verificación multi-tenant"""
    if current_user.perfil != 'Administrador':
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_menu'))
    
    return render_template('admin/empresas/verificar.html')

@app.route('/admin')
@login_required
def admin():
    """Panel admin - redirige al menú de facturación"""
    return redirect(url_for('facturacion_menu'))

@app.route('/facturacion')
@login_required
def facturacion_menu():
    """Menú principal de facturación"""
    return render_template('facturacion/menu.html')

@app.route('/facturacion/ars')
@login_required
def facturacion_ars():
    """Lista de ARS - Filtrado por tenant"""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos para acceder a esta sección', 'error')
        return redirect(url_for('facturacion_menu'))
    
    tenant_id = get_current_tenant_id()
    ars_list = execute_query(
        'SELECT * FROM ars WHERE tenant_id = %s ORDER BY nombre', 
        (tenant_id,), fetch='all'
    ) or []
    return render_template('facturacion/ars.html', ars_list=ars_list)

@app.route('/facturacion/ars/nuevo', methods=['GET', 'POST'])
@login_required
def facturacion_ars_nuevo():
    """Crear nueva ARS"""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_menu'))
    
    if request.method == 'POST':
        nombre_ars = sanitize_input(request.form.get('nombre_ars', ''), 50)
        rnc = sanitize_input(request.form.get('rnc', ''), 50)
        activo = 1 if request.form.get('activo') == '1' else 0
        
        if not nombre_ars or not rnc:
            flash('El nombre y el RNC son obligatorios', 'error')
            return redirect(url_for('facturacion_ars_nuevo'))

        if not validate_digits(rnc, 9):
            flash('El RNC debe contener exactamente 9 números', 'error')
            return redirect(url_for('facturacion_ars_nuevo'))
        
        tenant_id = get_current_tenant_id()
        
        # Generar código automáticamente basado en el nombre (primeras letras + timestamp)
        import time
        codigo = ''.join(filter(str.isalnum, nombre_ars[:6].upper())) + str(int(time.time()))[-4:]
        
        # Asegurar que el código sea único
        contador = 1
        codigo_original = codigo
        while execute_query('SELECT id FROM ars WHERE codigo = %s AND tenant_id = %s', (codigo, tenant_id)):
            codigo = f"{codigo_original}{contador}"
            contador += 1
        
        execute_update('''
            INSERT INTO ars (tenant_id, codigo, nombre, rnc, activo)
            VALUES (%s, %s, %s, %s, %s)
        ''', (tenant_id, codigo, nombre_ars, rnc, activo))
        
        flash(f'ARS {nombre_ars} creada exitosamente', 'success')
        return redirect(url_for('facturacion_ars'))
    
    return render_template('facturacion/ars_form.html', ars=None)

@app.route('/facturacion/ars/<int:ars_id>/editar', methods=['GET', 'POST'])
@login_required
def facturacion_ars_editar(ars_id):
    """Editar ARS"""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_menu'))
    
    tenant_id = get_current_tenant_id()
    ars = execute_query('SELECT * FROM ars WHERE id = %s AND tenant_id = %s', (ars_id, tenant_id))
    if not ars:
        flash('ARS no encontrada', 'error')
        return redirect(url_for('facturacion_ars'))
    
    if request.method == 'POST':
        nombre_ars = sanitize_input(request.form.get('nombre_ars', ''), 50)
        rnc = sanitize_input(request.form.get('rnc', ''), 50)
        activo = 1 if request.form.get('activo') == '1' else 0
        
        if not nombre_ars or not rnc:
            flash('El nombre y el RNC son obligatorios', 'error')
            return redirect(url_for('facturacion_ars_editar', ars_id=ars_id))

        if not validate_digits(rnc, 9):
            flash('El RNC debe contener exactamente 9 números', 'error')
            return redirect(url_for('facturacion_ars_editar', ars_id=ars_id))
        
        # Mantener el código existente (no se modifica en edición)
        
        execute_update('''
            UPDATE ars 
            SET nombre = %s, rnc = %s, activo = %s
            WHERE id = %s AND tenant_id = %s
        ''', (nombre_ars, rnc, activo, ars_id, tenant_id))
        
        flash(f'ARS {nombre_ars} actualizada exitosamente', 'success')
        return redirect(url_for('facturacion_ars'))
    
    return render_template('facturacion/ars_form.html', ars=ars)

@app.route('/facturacion/ars/<int:ars_id>/eliminar', methods=['POST'])
@login_required
def facturacion_ars_eliminar(ars_id):
    """Eliminar ARS"""
    if current_user.perfil != 'Administrador':
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_ars'))
    
    tenant_id = get_current_tenant_id()
    # Validar que pertenece al tenant antes de eliminar
    if not validate_tenant_access('ars', ars_id):
        flash('No tienes acceso a esta ARS', 'error')
        return redirect(url_for('facturacion_ars'))
    
    execute_update('DELETE FROM ars WHERE id = %s AND tenant_id = %s', (ars_id, tenant_id))
    flash('ARS eliminada exitosamente', 'success')
    return redirect(url_for('facturacion_ars'))

@app.route('/facturacion/medicos')
@login_required  
def facturacion_medicos():
    """Lista de médicos - Filtrado por tenant"""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos para acceder a esta sección', 'error')
        return redirect(url_for('facturacion_menu'))
    
    tenant_id = get_current_tenant_id()
    search = sanitize_input(request.args.get('search', ''), 100)

    if search:
        search_term = f'%{search}%'
        medicos_list = execute_query('''
            SELECT * FROM medicos
            WHERE tenant_id = %s
              AND (nombre LIKE %s OR especialidad LIKE %s OR telefono LIKE %s)
            ORDER BY nombre
        ''', (tenant_id, search_term, search_term, search_term), fetch='all') or []
    else:
        medicos_list = execute_query(
            'SELECT * FROM medicos WHERE tenant_id = %s ORDER BY nombre',
            (tenant_id,), fetch='all'
        ) or []

    return render_template(
        'facturacion/medicos.html',
        medicos_list=medicos_list,
        search=search
    )

@app.route('/facturacion/medicos/nuevo', methods=['GET', 'POST'])
@login_required
def facturacion_medicos_nuevo():
    """Crear nuevo médico"""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_menu'))
    
    if request.method == 'POST':
        nombre = sanitize_input(request.form.get('nombre', ''), 200)
        exequatur = sanitize_input(request.form.get('exequatur', ''), 50)
        especialidad = get_especialidad_form(request.form)
        telefono = sanitize_input(request.form.get('telefono', ''), 20)
        email = request.form.get('email', '').strip()
        cedula = sanitize_input(request.form.get('cedula', ''), 20)
        factura = 1 if request.form.get('factura') == '1' else 0
        
        if not all([nombre, exequatur, especialidad, telefono, email, cedula]):
            flash('Todos los campos del médico son obligatorios', 'error')
            return redirect(url_for('facturacion_medicos_nuevo'))

        if not validate_digits(cedula, 11):
            flash('La cédula debe contener exactamente 11 números', 'error')
            return redirect(url_for('facturacion_medicos_nuevo'))

        if not validate_digits(telefono, 10):
            flash('El teléfono debe contener exactamente 10 números', 'error')
            return redirect(url_for('facturacion_medicos_nuevo'))

        if not validate_email(email):
            flash('Ingresa un correo electrónico válido', 'error')
            return redirect(url_for('facturacion_medicos_nuevo'))
        
        tenant_id = get_current_tenant_id()
        execute_update('''
            INSERT INTO medicos (tenant_id, nombre, exequatur, especialidad, telefono, email, cedula, activo, factura)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 1, %s)
        ''', (tenant_id, nombre, exequatur, especialidad, telefono, email, cedula, factura))
        
        flash(f'Médico {nombre} creado exitosamente', 'success')
        return redirect(url_for('facturacion_medicos'))
    
    return render_template(
        'facturacion/medicos_form.html',
        medico=None,
        especialidades=ESPECIALIDADES_MEDICAS
    )

@app.route('/facturacion/medicos/<int:medico_id>/editar', methods=['GET', 'POST'])
@login_required
def facturacion_medicos_editar(medico_id):
    """Editar médico"""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_menu'))
    
    tenant_id = get_current_tenant_id()
    medico = execute_query('SELECT * FROM medicos WHERE id = %s AND tenant_id = %s', (medico_id, tenant_id))
    if not medico:
        flash('Médico no encontrado', 'error')
        return redirect(url_for('facturacion_medicos'))
    
    if request.method == 'POST':
        nombre = sanitize_input(request.form.get('nombre', ''), 200)
        exequatur = sanitize_input(request.form.get('exequatur', ''), 50)
        especialidad = get_especialidad_form(request.form)
        telefono = sanitize_input(request.form.get('telefono', ''), 20)
        email = request.form.get('email', '').strip()
        cedula = sanitize_input(request.form.get('cedula', ''), 20)
        activo = 1 if request.form.get('activo') == '1' else 0
        factura = 1 if request.form.get('factura') == '1' else 0
        
        if not all([nombre, exequatur, especialidad, telefono, email, cedula]):
            flash('Todos los campos del médico son obligatorios', 'error')
            return redirect(url_for('facturacion_medicos_editar', medico_id=medico_id))

        if not validate_digits(cedula, 11):
            flash('La cédula debe contener exactamente 11 números', 'error')
            return redirect(url_for('facturacion_medicos_editar', medico_id=medico_id))

        if not validate_digits(telefono, 10):
            flash('El teléfono debe contener exactamente 10 números', 'error')
            return redirect(url_for('facturacion_medicos_editar', medico_id=medico_id))

        if not validate_email(email):
            flash('Ingresa un correo electrónico válido', 'error')
            return redirect(url_for('facturacion_medicos_editar', medico_id=medico_id))
        
        tenant_id = get_current_tenant_id()
        execute_update('''
            UPDATE medicos 
            SET nombre = %s, exequatur = %s, especialidad = %s, telefono = %s, email = %s, cedula = %s, activo = %s, factura = %s
            WHERE id = %s AND tenant_id = %s
        ''', (nombre, exequatur, especialidad, telefono, email, cedula, activo, factura, medico_id, tenant_id))
        
        flash(f'Médico {nombre} actualizado exitosamente', 'success')
        return redirect(url_for('facturacion_medicos'))
    
    return render_template(
        'facturacion/medicos_form.html',
        medico=medico,
        especialidades=ESPECIALIDADES_MEDICAS
    )

@app.route('/facturacion/medicos/<int:medico_id>/eliminar', methods=['POST'])
@login_required
def facturacion_medicos_eliminar(medico_id):
    """Eliminar médico"""
    if current_user.perfil != 'Administrador':
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_medicos'))
    
    tenant_id = get_current_tenant_id()
    if not validate_tenant_access('medicos', medico_id):
        flash('No tienes acceso a este médico', 'error')
        return redirect(url_for('facturacion_medicos'))
    
    execute_update('DELETE FROM medicos WHERE id = %s AND tenant_id = %s', (medico_id, tenant_id))
    flash('Médico eliminado exitosamente', 'success')
    return redirect(url_for('facturacion_medicos'))

@app.route('/facturacion/centros-medicos')
@login_required
def facturacion_centros_medicos():
    """Lista de centros médicos - Filtrado por tenant"""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos para acceder a esta sección', 'error')
        return redirect(url_for('facturacion_menu'))
    
    tenant_id = get_current_tenant_id()
    search = request.args.get('search', '').strip()
    
    if search:
        centros_list = execute_query(
            '''SELECT * FROM centros_medicos 
               WHERE tenant_id = %s AND (nombre LIKE %s OR rnc LIKE %s OR direccion LIKE %s)
               ORDER BY nombre''', 
            (tenant_id, f'%{search}%', f'%{search}%', f'%{search}%'), fetch='all'
        ) or []
    else:
        centros_list = execute_query(
            'SELECT * FROM centros_medicos WHERE tenant_id = %s ORDER BY nombre', 
            (tenant_id,), fetch='all'
        ) or []
    
    return render_template('facturacion/centros_medicos.html', centros_list=centros_list, search=search)

@app.route('/facturacion/centros-medicos/nuevo', methods=['GET', 'POST'])
@login_required
def facturacion_centros_medicos_nuevo():
    """Crear nuevo centro médico"""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_menu'))
    
    if request.method == 'POST':
        nombre = sanitize_input(request.form.get('nombre', ''), 200)
        codigo = sanitize_input(request.form.get('codigo', ''), 50)
        direccion = sanitize_input(request.form.get('direccion', ''), 500)
        rnc = sanitize_input(request.form.get('rnc', ''), 20)
        telefono = sanitize_input(request.form.get('telefono', ''), 20)
        
        if not nombre or not telefono or not rnc:
            flash('El nombre, el teléfono y el RNC son obligatorios', 'error')
            return redirect(url_for('facturacion_centros_medicos_nuevo'))

        if not validate_digits(telefono, 10):
            flash('El teléfono debe contener exactamente 10 números', 'error')
            return redirect(url_for('facturacion_centros_medicos_nuevo'))

        if not validate_digits(rnc, 9):
            flash('El RNC debe contener exactamente 9 números', 'error')
            return redirect(url_for('facturacion_centros_medicos_nuevo'))
        
        tenant_id = get_current_tenant_id()
        execute_update('''
            INSERT INTO centros_medicos (tenant_id, nombre, codigo, direccion, rnc, telefono, activo)
            VALUES (%s, %s, %s, %s, %s, %s, 1)
        ''', (tenant_id, nombre, codigo, direccion, rnc, telefono))
        
        flash(f'Centro médico {nombre} creado exitosamente', 'success')
        return redirect(url_for('facturacion_centros_medicos'))
    
    return render_template('facturacion/centro_medico_form.html', centro=None)

@app.route('/facturacion/centros-medicos/<int:centro_id>/editar', methods=['GET', 'POST'])
@login_required
def facturacion_centros_medicos_editar(centro_id):
    """Editar centro médico"""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_menu'))
    
    tenant_id = get_current_tenant_id()
    centro = execute_query('SELECT * FROM centros_medicos WHERE id = %s AND tenant_id = %s', (centro_id, tenant_id))
    if not centro:
        flash('Centro médico no encontrado', 'error')
        return redirect(url_for('facturacion_centros_medicos'))
    
    if request.method == 'POST':
        nombre = sanitize_input(request.form.get('nombre', ''), 200)
        codigo = sanitize_input(request.form.get('codigo', ''), 50)
        direccion = sanitize_input(request.form.get('direccion', ''), 500)
        rnc = sanitize_input(request.form.get('rnc', ''), 20)
        telefono = sanitize_input(request.form.get('telefono', ''), 20)
        activo = 1 if request.form.get('activo') == '1' else 0
        
        if not nombre or not telefono or not rnc:
            flash('El nombre, el teléfono y el RNC son obligatorios', 'error')
            return redirect(url_for('facturacion_centros_medicos_editar', centro_id=centro_id))

        if not validate_digits(telefono, 10):
            flash('El teléfono debe contener exactamente 10 números', 'error')
            return redirect(url_for('facturacion_centros_medicos_editar', centro_id=centro_id))

        if not validate_digits(rnc, 9):
            flash('El RNC debe contener exactamente 9 números', 'error')
            return redirect(url_for('facturacion_centros_medicos_editar', centro_id=centro_id))
        
        tenant_id = get_current_tenant_id()
        execute_update('''
            UPDATE centros_medicos 
            SET nombre = %s, codigo = %s, direccion = %s, rnc = %s, telefono = %s, activo = %s
            WHERE id = %s AND tenant_id = %s
        ''', (nombre, codigo, direccion, rnc, telefono, activo, centro_id, tenant_id))
        
        flash(f'Centro médico {nombre} actualizado exitosamente', 'success')
        return redirect(url_for('facturacion_centros_medicos'))
    
    return render_template('facturacion/centro_medico_form.html', centro=centro)

@app.route('/facturacion/centros-medicos/<int:centro_id>/eliminar', methods=['POST'])
@login_required
def facturacion_centros_medicos_eliminar(centro_id):
    """Eliminar centro médico"""
    if current_user.perfil != 'Administrador':
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_centros_medicos'))
    
    tenant_id = get_current_tenant_id()
    if not validate_tenant_access('centros_medicos', centro_id):
        flash('No tienes acceso a este centro médico', 'error')
        return redirect(url_for('facturacion_centros_medicos'))
    
    execute_update('DELETE FROM centros_medicos WHERE id = %s AND tenant_id = %s', (centro_id, tenant_id))
    flash('Centro médico eliminado exitosamente', 'success')
    return redirect(url_for('facturacion_centros_medicos'))

@app.route('/facturacion/servicios')
@login_required
def facturacion_servicios():
    """Lista de servicios - Filtrado por tenant"""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos para acceder a esta sección', 'error')
        return redirect(url_for('facturacion_menu'))
    
    tenant_id = get_current_tenant_id()
    servicios_list = execute_query(
        'SELECT * FROM servicios WHERE tenant_id = %s ORDER BY descripcion', 
        (tenant_id,), fetch='all'
    ) or []
    return render_template('facturacion/servicios.html', servicios_list=servicios_list)

@app.route('/facturacion/servicios/nuevo', methods=['GET', 'POST'])
@login_required
def facturacion_servicios_nuevo():
    """Crear nuevo servicio"""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_menu'))
    
    if request.method == 'POST':
        descripcion = sanitize_input(request.form.get('descripcion', ''), 15)
        precio_base = request.form.get('precio_base', '0')
        
        if not descripcion:
            flash('La descripción es obligatoria', 'error')
            return redirect(url_for('facturacion_servicios_nuevo'))
        
        try:
            precio_base = float(precio_base)
        except:
            precio_base = 0.0
        
        tenant_id = get_current_tenant_id()
        execute_update('''
            INSERT INTO servicios (tenant_id, nombre, descripcion, precio_base, activo)
            VALUES (%s, %s, %s, %s, 1)
        ''', (tenant_id, descripcion, descripcion, precio_base))
        
        flash(f'Servicio {descripcion} creado exitosamente', 'success')
        return redirect(url_for('facturacion_servicios'))
    
    return render_template('facturacion/servicios_form.html', servicio=None)

@app.route('/facturacion/servicios/<int:servicio_id>/editar', methods=['GET', 'POST'])
@login_required
def facturacion_servicios_editar(servicio_id):
    """Editar servicio"""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_menu'))
    
    tenant_id = get_current_tenant_id()
    servicio = execute_query('SELECT * FROM servicios WHERE id = %s AND tenant_id = %s', (servicio_id, tenant_id))
    if not servicio:
        flash('Servicio no encontrado', 'error')
        return redirect(url_for('facturacion_servicios'))
    
    if request.method == 'POST':
        descripcion = sanitize_input(request.form.get('descripcion', ''), 15)
        precio_base = request.form.get('precio_base', '0')
        activo = 1 if request.form.get('activo') == '1' else 0
        
        if not descripcion:
            flash('La descripción es obligatoria', 'error')
            return redirect(url_for('facturacion_servicios_editar', servicio_id=servicio_id))
        
        try:
            precio_base = float(precio_base)
        except:
            precio_base = 0.0
        
        tenant_id = get_current_tenant_id()
        execute_update('''
            UPDATE servicios 
            SET nombre = %s, descripcion = %s, precio_base = %s, activo = %s
            WHERE id = %s AND tenant_id = %s
        ''', (descripcion, descripcion, precio_base, activo, servicio_id, tenant_id))
        
        flash(f'Servicio {descripcion} actualizado exitosamente', 'success')
        return redirect(url_for('facturacion_servicios'))
    
    return render_template('facturacion/servicios_form.html', servicio=servicio)

@app.route('/facturacion/servicios/<int:servicio_id>/eliminar', methods=['POST'])
@login_required
def facturacion_servicios_eliminar(servicio_id):
    """Eliminar servicio"""
    if current_user.perfil != 'Administrador':
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_servicios'))
    
    tenant_id = get_current_tenant_id()
    if not validate_tenant_access('servicios', servicio_id):
        flash('No tienes acceso a este servicio', 'error')
        return redirect(url_for('facturacion_servicios'))
    
    execute_update('DELETE FROM servicios WHERE id = %s AND tenant_id = %s', (servicio_id, tenant_id))
    flash('Servicio eliminado exitosamente', 'success')
    return redirect(url_for('facturacion_servicios'))

def obtener_relacion_codigo_ars(tenant_id):
    """Configurar la entidad que se relaciona con ARS según la empresa."""
    empresa = get_empresa_info(tenant_id) or {}
    es_centro_salud = empresa.get('tipo_empresa') == 'centro_salud'
    if es_centro_salud:
        entidades = execute_query('''
            SELECT id, nombre
            FROM centros_medicos
            WHERE activo=1 AND tenant_id=%s
            ORDER BY nombre
        ''', (tenant_id,), fetch='all') or []
        return {
            'tipo_empresa': 'centro_salud',
            'es_centro_salud': True,
            'entidades': entidades,
            'campo': 'centro_medico_id',
            'etiqueta': 'Centro de salud',
            'etiqueta_plural': 'centros de salud',
        }

    entidades = execute_query('''
        SELECT id, nombre, especialidad
        FROM medicos
        WHERE activo=1 AND tenant_id=%s
        ORDER BY nombre
    ''', (tenant_id,), fetch='all') or []
    return {
        'tipo_empresa': 'medico',
        'es_centro_salud': False,
        'entidades': entidades,
        'campo': 'medico_id',
        'etiqueta': 'Médico',
        'etiqueta_plural': 'médicos',
    }


@app.route('/facturacion/codigo-ars')
@login_required
def facturacion_codigo_ars():
    """Lista de códigos ARS - Filtrado por tenant"""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos para acceder a esta sección', 'error')
        return redirect(url_for('facturacion_menu'))
    
    tenant_id = get_current_tenant_id()
    relacion = obtener_relacion_codigo_ars(tenant_id)
    search = request.args.get('search', '').strip()
    query = '''
        SELECT ca.*, a.nombre,
               m.nombre AS nombre_medico,
               c.nombre AS nombre_centro
        FROM codigo_ars ca
        JOIN ars a
          ON ca.ars_id = a.id AND a.tenant_id = ca.tenant_id
        LEFT JOIN medicos m
          ON ca.medico_id = m.id AND m.tenant_id = ca.tenant_id
        LEFT JOIN centros_medicos c
          ON ca.centro_medico_id = c.id AND c.tenant_id = ca.tenant_id
        WHERE ca.tenant_id = %s
    '''
    params = [tenant_id]
    if search:
        pattern = f'%{search}%'
        query += '''
            AND (
                a.nombre LIKE %s OR ca.codigo LIKE %s
                OR m.nombre LIKE %s OR c.nombre LIKE %s
            )
        '''
        params.extend([pattern, pattern, pattern, pattern])
    query += '''
        ORDER BY COALESCE(c.nombre, m.nombre), a.nombre, ca.codigo
    '''
    codigos_list = execute_query(
        query, tuple(params), fetch='all'
    ) or []
    return render_template(
        'facturacion/codigo_ars.html',
        codigos_list=codigos_list,
        relacion=relacion,
        search=search,
    )

@app.route('/facturacion/codigo-ars/nuevo', methods=['GET', 'POST'])
@login_required
def facturacion_codigo_ars_nuevo():
    """Crear nuevo código ARS"""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_menu'))
    
    tenant_id = get_current_tenant_id()
    relacion = obtener_relacion_codigo_ars(tenant_id)

    if request.method == 'POST':
        entidad_id = request.form.get('entidad_id')
        ars_id = request.form.get('ars_id')
        codigo = sanitize_input(request.form.get('codigo_ars', ''), 50)
        descripcion = sanitize_input(request.form.get('descripcion', ''), 500)
        precio = request.form.get('precio', '0')
        activo = 1 if request.form.get('activo') == '1' else 0
        
        if not entidad_id or not ars_id or not codigo:
            flash(
                f"{relacion['etiqueta']}, ARS y código son obligatorios",
                'error'
            )
            return redirect(url_for('facturacion_codigo_ars_nuevo'))
        
        entidad = execute_query(
            f"SELECT id FROM {'centros_medicos' if relacion['es_centro_salud'] else 'medicos'} "
            "WHERE id=%s AND tenant_id=%s AND activo=1",
            (entidad_id, tenant_id)
        )
        ars = execute_query(
            'SELECT id FROM ars WHERE id=%s AND tenant_id=%s AND activo=1',
            (ars_id, tenant_id)
        )
        if not entidad or not ars:
            flash('La relación seleccionada no es válida', 'error')
            return redirect(url_for('facturacion_codigo_ars_nuevo'))

        try:
            precio = float(precio) if precio else 0.0
        except (TypeError, ValueError):
            precio = 0.0
        
        existe = execute_query(
            f'SELECT id FROM codigo_ars WHERE {relacion["campo"]}=%s '
            'AND ars_id=%s AND tenant_id=%s',
            (entidad_id, ars_id, tenant_id)
        )
        if existe:
            flash(
                f"Ya existe un código para este "
                f"{relacion['etiqueta'].lower()} y ARS",
                'error'
            )
            return redirect(url_for('facturacion_codigo_ars_nuevo'))
        
        medico_id = None if relacion['es_centro_salud'] else entidad_id
        centro_medico_id = entidad_id if relacion['es_centro_salud'] else None
        execute_update('''
            INSERT INTO codigo_ars
                (tenant_id, medico_id, centro_medico_id, ars_id, codigo,
                 descripcion, precio, activo)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ''', (
            tenant_id, medico_id, centro_medico_id, ars_id, codigo,
            descripcion or '', precio, activo
        ))
        
        flash(f'Código ARS {codigo} creado exitosamente', 'success')
        return redirect(url_for('facturacion_codigo_ars'))
    
    ars_list = execute_query('SELECT * FROM ars WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    return render_template(
        'facturacion/codigo_ars_form.html',
        codigo=None,
        ars_list=ars_list,
        relacion=relacion,
    )

@app.route('/facturacion/codigo-ars/<int:codigo_id>/editar', methods=['GET', 'POST'])
@login_required
def facturacion_codigo_ars_editar(codigo_id):
    """Editar código ARS"""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_menu'))
    
    tenant_id = get_current_tenant_id()
    codigo = execute_query('SELECT * FROM codigo_ars WHERE id = %s AND tenant_id = %s', (codigo_id, tenant_id))
    if not codigo:
        flash('Código ARS no encontrado', 'error')
        return redirect(url_for('facturacion_codigo_ars'))
    
    relacion = obtener_relacion_codigo_ars(tenant_id)

    if request.method == 'POST':
        entidad_id = request.form.get('entidad_id')
        ars_id = request.form.get('ars_id')
        codigo_texto = sanitize_input(request.form.get('codigo_ars', ''), 50)
        descripcion = sanitize_input(request.form.get('descripcion', ''), 500)
        precio = request.form.get('precio', '0')
        activo = 1 if request.form.get('activo') == '1' else 0
        
        if not entidad_id or not ars_id or not codigo_texto:
            flash(
                f"{relacion['etiqueta']}, ARS y código son obligatorios",
                'error'
            )
            return redirect(url_for('facturacion_codigo_ars_editar', codigo_id=codigo_id))
        
        entidad = execute_query(
            f"SELECT id FROM {'centros_medicos' if relacion['es_centro_salud'] else 'medicos'} "
            "WHERE id=%s AND tenant_id=%s AND activo=1",
            (entidad_id, tenant_id)
        )
        ars = execute_query(
            'SELECT id FROM ars WHERE id=%s AND tenant_id=%s AND activo=1',
            (ars_id, tenant_id)
        )
        if not entidad or not ars:
            flash('La relación seleccionada no es válida', 'error')
            return redirect(url_for(
                'facturacion_codigo_ars_editar', codigo_id=codigo_id
            ))

        try:
            precio = float(precio) if precio else 0.0
        except (TypeError, ValueError):
            precio = 0.0
        
        existe = execute_query(
            f'SELECT id FROM codigo_ars WHERE {relacion["campo"]}=%s '
            'AND ars_id=%s AND id!=%s AND tenant_id=%s',
            (entidad_id, ars_id, codigo_id, tenant_id)
        )
        if existe:
            flash(
                f"Ya existe un código para este "
                f"{relacion['etiqueta'].lower()} y ARS",
                'error'
            )
            return redirect(url_for('facturacion_codigo_ars_editar', codigo_id=codigo_id))
        
        medico_id = None if relacion['es_centro_salud'] else entidad_id
        centro_medico_id = entidad_id if relacion['es_centro_salud'] else None
        execute_update('''
            UPDATE codigo_ars 
            SET medico_id=%s, centro_medico_id=%s, ars_id=%s, codigo=%s,
                descripcion=%s, precio=%s, activo=%s
            WHERE id = %s AND tenant_id = %s
        ''', (
            medico_id, centro_medico_id, ars_id, codigo_texto,
            descripcion or '', precio, activo, codigo_id, tenant_id
        ))
        
        flash(f'Código ARS actualizado exitosamente', 'success')
        return redirect(url_for('facturacion_codigo_ars'))
    
    ars_list = execute_query('SELECT * FROM ars WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    return render_template(
        'facturacion/codigo_ars_form.html',
        codigo=codigo,
        ars_list=ars_list,
        relacion=relacion,
    )

@app.route('/facturacion/codigo-ars/<int:codigo_id>/eliminar', methods=['POST'])
@login_required
def facturacion_codigo_ars_eliminar(codigo_id):
    """Eliminar código ARS"""
    if current_user.perfil != 'Administrador':
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_codigo_ars'))
    
    tenant_id = get_current_tenant_id()
    if not validate_tenant_access('codigo_ars', codigo_id):
        flash('No tienes acceso a este código ARS', 'error')
        return redirect(url_for('facturacion_codigo_ars'))
    
    execute_update('DELETE FROM codigo_ars WHERE id = %s AND tenant_id = %s', (codigo_id, tenant_id))
    flash('Código ARS eliminado exitosamente', 'success')
    return redirect(url_for('facturacion_codigo_ars'))

@app.route('/facturacion/medico-centro')
@login_required
def facturacion_medico_centro():
    """Relación médico-centro - Filtrado por tenant"""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos para acceder a esta sección', 'error')
        return redirect(url_for('facturacion_menu'))
    
    tenant_id = get_current_tenant_id()
    relaciones_list = execute_query('''
        SELECT mc.*, m.nombre as medico_nombre, m.especialidad, c.nombre as centro_nombre
        FROM medico_centro mc
        JOIN medicos m
          ON mc.medico_id = m.id AND m.tenant_id = mc.tenant_id
        JOIN centros_medicos c
          ON mc.centro_medico_id = c.id AND c.tenant_id = mc.tenant_id
        WHERE mc.tenant_id = %s
        ORDER BY m.nombre, c.nombre
    ''', (tenant_id,), fetch='all') or []
    return render_template('facturacion/medico_centro.html', relaciones_list=relaciones_list)

@app.route('/facturacion/medico-centro/nuevo', methods=['GET', 'POST'])
@login_required
@transactional_methods('POST')
def facturacion_medico_centro_nuevo():
    """Crear nueva relación médico-centro"""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_menu'))
    
    if request.method == 'POST':
        medico_id = request.form.get('medico_id')
        centro_medico_id = request.form.get('centro_medico_id')
        es_defecto = 1 if request.form.get('es_defecto') == '1' else 0
        
        if not medico_id or not centro_medico_id:
            flash('Médico y centro médico son obligatorios', 'error')
            return redirect(url_for('facturacion_medico_centro_nuevo'))
        
        tenant_id = get_current_tenant_id()
        medico = execute_query(
            '''
            SELECT id FROM medicos
            WHERE id = %s AND tenant_id = %s AND activo = 1
            ''',
            (medico_id, tenant_id),
        )
        centro = execute_query(
            '''
            SELECT id FROM centros_medicos
            WHERE id = %s AND tenant_id = %s AND activo = 1
            ''',
            (centro_medico_id, tenant_id),
        )
        if not medico or not centro:
            flash('El médico o centro seleccionado no pertenece a tu empresa', 'error')
            return redirect(url_for('facturacion_medico_centro_nuevo'))

        existe = execute_query('SELECT id FROM medico_centro WHERE medico_id = %s AND centro_medico_id = %s AND tenant_id = %s', 
                              (medico_id, centro_medico_id, tenant_id))
        if existe:
            flash('Esta relación ya existe', 'error')
            return redirect(url_for('facturacion_medico_centro_nuevo'))
        
        # Si se marca como por defecto, desmarcar otros centros por defecto de este médico
        if es_defecto:
            execute_update('''
                UPDATE medico_centro 
                SET es_defecto = 0 
                WHERE medico_id = %s AND tenant_id = %s
            ''', (medico_id, tenant_id))
        
        execute_update('''
            INSERT INTO medico_centro (tenant_id, medico_id, centro_medico_id, es_defecto)
            VALUES (%s, %s, %s, %s)
        ''', (tenant_id, medico_id, centro_medico_id, es_defecto))
        
        flash('Relación médico-centro creada exitosamente', 'success')
        return redirect(url_for('facturacion_medico_centro'))
    
    tenant_id = get_current_tenant_id()
    
    # Cargar médicos y centros ACTIVOS del tenant
    medicos = execute_query('SELECT * FROM medicos WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    centros = execute_query('SELECT * FROM centros_medicos WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    
    # Si no hay médicos, verificar si hay inactivos
    if not medicos:
        medicos_inactivos = execute_query('SELECT nombre FROM medicos WHERE activo = 0 AND tenant_id = %s', (tenant_id,), fetch='all') or []
        if medicos_inactivos:
            nombres = ', '.join([m['nombre'] for m in medicos_inactivos])
            flash(f'No hay médicos ACTIVOS. Tienes médicos INACTIVOS: {nombres}. Ve a la lista de médicos para activarlos.', 'warning')
        else:
            flash('No hay médicos registrados. Por favor, crea un médico primero.', 'warning')
    
    if not centros:
        centros_inactivos = execute_query('SELECT nombre FROM centros_medicos WHERE activo = 0 AND tenant_id = %s', (tenant_id,), fetch='all') or []
        if centros_inactivos:
            nombres = ', '.join([c['nombre'] for c in centros_inactivos])
            flash(f'No hay centros médicos ACTIVOS. Tienes centros INACTIVOS: {nombres}. Ve a la lista de centros para activarlos.', 'warning')
        else:
            flash('No hay centros médicos registrados. Por favor, crea un centro médico primero.', 'warning')
    
    return render_template('facturacion/medico_centro_form.html', relacion=None, medicos=medicos, centros=centros)

@app.route('/facturacion/medico-centro/<int:relacion_id>/editar', methods=['GET', 'POST'])
@login_required
@transactional_methods('POST')
def facturacion_medico_centro_editar(relacion_id):
    """Editar relación médico-centro"""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_menu'))
    
    tenant_id = get_current_tenant_id()
    
    # Obtener la relación actual
    relacion = execute_query('SELECT * FROM medico_centro WHERE id = %s AND tenant_id = %s', (relacion_id, tenant_id))
    if not relacion:
        flash('Relación no encontrada', 'error')
        return redirect(url_for('facturacion_medico_centro'))
    
    if request.method == 'POST':
        medico_id = request.form.get('medico_id')
        centro_medico_id = request.form.get('centro_medico_id')
        es_defecto = 1 if request.form.get('es_defecto') == '1' else 0
        
        if not medico_id or not centro_medico_id:
            flash('Médico y centro médico son obligatorios', 'error')
            return redirect(url_for('facturacion_medico_centro_editar', relacion_id=relacion_id))

        medico = execute_query(
            '''
            SELECT id FROM medicos
            WHERE id = %s AND tenant_id = %s AND activo = 1
            ''',
            (medico_id, tenant_id),
        )
        centro = execute_query(
            '''
            SELECT id FROM centros_medicos
            WHERE id = %s AND tenant_id = %s AND activo = 1
            ''',
            (centro_medico_id, tenant_id),
        )
        if not medico or not centro:
            flash('El médico o centro seleccionado no pertenece a tu empresa', 'error')
            return redirect(url_for(
                'facturacion_medico_centro_editar',
                relacion_id=relacion_id,
            ))

        # Verificar si ya existe otra relación con estos valores (excluyendo la actual)
        existe = execute_query('''
            SELECT id FROM medico_centro 
            WHERE medico_id = %s AND centro_medico_id = %s AND tenant_id = %s AND id != %s
        ''', (medico_id, centro_medico_id, tenant_id, relacion_id))
        
        if existe:
            flash('Ya existe otra relación con este médico y centro médico', 'error')
            return redirect(url_for('facturacion_medico_centro_editar', relacion_id=relacion_id))
        
        # Si se marca como por defecto, desmarcar otros centros por defecto de este médico
        if es_defecto:
            execute_update('''
                UPDATE medico_centro 
                SET es_defecto = 0 
                WHERE medico_id = %s AND tenant_id = %s AND id != %s
            ''', (medico_id, tenant_id, relacion_id))
        
        # Actualizar la relación
        execute_update('''
            UPDATE medico_centro 
            SET medico_id = %s, centro_medico_id = %s, es_defecto = %s
            WHERE id = %s AND tenant_id = %s
        ''', (medico_id, centro_medico_id, es_defecto, relacion_id, tenant_id))
        
        flash('Relación actualizada exitosamente', 'success')
        return redirect(url_for('facturacion_medico_centro'))
    
    # Cargar médicos y centros ACTIVOS del tenant
    medicos = execute_query('SELECT * FROM medicos WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    centros = execute_query('SELECT * FROM centros_medicos WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    
    return render_template('facturacion/medico_centro_form.html', relacion=relacion, medicos=medicos, centros=centros)

@app.route('/facturacion/medico-centro/<int:relacion_id>/eliminar', methods=['POST'])
@login_required
def facturacion_medico_centro_eliminar(relacion_id):
    """Eliminar relación médico-centro"""
    if current_user.perfil != 'Administrador':
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_medico_centro'))
    
    tenant_id = get_current_tenant_id()
    if not validate_tenant_access('medico_centro', relacion_id):
        flash('No tienes acceso a esta relación', 'error')
        return redirect(url_for('facturacion_medico_centro'))
    
    execute_update('DELETE FROM medico_centro WHERE id = %s AND tenant_id = %s', (relacion_id, tenant_id))
    flash('Relación eliminada exitosamente', 'success')
    return redirect(url_for('facturacion_medico_centro'))

NCF_TIPOS_TRADICIONALES = {
    'B01': 'Factura de Crédito Fiscal',
    'B02': 'Factura de Consumo',
    'B03': 'Nota de Débito',
    'B04': 'Nota de Crédito',
    'B11': 'Comprobante de Compras',
    'B12': 'Registro Único de Ingresos',
    'B13': 'Comprobante para Gastos Menores',
    'B14': 'Comprobante para Regímenes Especiales',
    'B15': 'Comprobante Gubernamental',
    'B16': 'Comprobante para Exportaciones',
    'B17': 'Comprobante para Pagos al Exterior',
}


def obtener_tipo_ncf_formulario():
    selector = request.form.get('tipo', '').strip().upper()
    if selector == 'OTRO':
        tipo = request.form.get('tipo_personalizado', '').strip().upper()
        descripcion = sanitize_input(
            request.form.get('descripcion_personalizada', ''), 150
        )
    else:
        tipo = selector
        descripcion = NCF_TIPOS_TRADICIONALES.get(tipo, '')
        if not descripcion and re.fullmatch(r'B\d{2}', tipo):
            existente = execute_query('''
                SELECT descripcion
                FROM ncf
                WHERE tenant_id=%s AND tipo=%s
                ORDER BY id DESC
                LIMIT 1
            ''', (get_current_tenant_id(), tipo))
            descripcion = (existente or {}).get('descripcion', '')

    if not re.fullmatch(r'B\d{2}', tipo):
        return None, None, 'El código debe tener formato B seguido de dos números'
    if not descripcion:
        return None, None, 'La descripción del tipo de NCF es obligatoria'
    return tipo, descripcion, None


def obtener_catalogo_ncf_tenant(tenant_id):
    catalogo = dict(NCF_TIPOS_TRADICIONALES)
    tipos_propios = execute_query('''
        SELECT tipo, MAX(descripcion) AS descripcion
        FROM ncf
        WHERE tenant_id=%s
        GROUP BY tipo
        ORDER BY tipo
    ''', (tenant_id,), fetch='all') or []
    for item in tipos_propios:
        tipo = str(item.get('tipo') or '').upper()
        descripcion = str(item.get('descripcion') or '').strip()
        if re.fullmatch(r'B\d{2}', tipo) and descripcion:
            catalogo[tipo] = descripcion
    return dict(sorted(catalogo.items()))


def obtener_catalogo_ecf_tenant(tenant_id):
    """Combinar tipos oficiales con tipos registrados por la empresa."""
    catalogo = dict(ECF_TYPE_CATALOG)
    personalizados = execute_query('''
        SELECT tipo_ecf, MAX(descripcion_tipo) AS descripcion
        FROM ecf_secuencias
        WHERE tenant_id=%s
          AND descripcion_tipo IS NOT NULL
          AND TRIM(descripcion_tipo)<>''
        GROUP BY tipo_ecf
        ORDER BY tipo_ecf
    ''', (tenant_id,), fetch='all') or []
    for item in personalizados:
        codigo = str(item.get('tipo_ecf') or '').strip()
        descripcion = str(item.get('descripcion') or '').strip()
        if re.fullmatch(r'\d{2}', codigo) and codigo != '00' and descripcion:
            catalogo[codigo] = descripcion
    return dict(sorted(catalogo.items()))


def obtener_tipo_ecf_formulario(catalogo):
    selector = request.form.get('tipo_ecf', '').strip()
    if selector == 'OTRO':
        codigo = request.form.get('tipo_ecf_personalizado', '').strip()
        descripcion = sanitize_input(
            request.form.get('descripcion_tipo_ecf', ''), 150
        )
        if codigo in catalogo:
            return None, None, (
                f'El tipo E{codigo} ya existe; selecciónalo en la lista'
            )
    else:
        codigo = selector
        descripcion = catalogo.get(codigo, '')

    if not re.fullmatch(r'\d{2}', codigo or '') or codigo == '00':
        return None, None, 'El tipo e-CF debe contener dos dígitos distintos de 00'
    if not descripcion:
        return None, None, 'La descripción del tipo e-CF es obligatoria'
    return codigo, descripcion, None


def build_ncf_number(tipo, numero, tamano):
    """Construir el NCF completo usando el tipo y el tamaño de secuencia."""
    return f"{tipo}{numero:0{tamano}d}"

def invoice_has_ncf(tenant_id, tipo, numero, tamano):
    """Comprobar si una factura de la empresa ya utiliza ese número NCF."""
    ncf_completo = build_ncf_number(tipo, numero, tamano)
    factura = execute_query(
        'SELECT id FROM facturas WHERE tenant_id = %s AND ncf = %s LIMIT 1',
        (tenant_id, ncf_completo)
    )
    return bool(factura), ncf_completo

@app.route('/facturacion/ncf/verificar-numero')
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_ncf_verificar_numero():
    """Validar en tiempo real si un número NCF ya figura en facturas."""
    tipo = request.args.get('tipo', '')
    try:
        numero = int(request.args.get('numero', ''))
        tamano = int(request.args.get('tamano', '8'))
    except (TypeError, ValueError):
        return jsonify({'exists': False, 'valid': False}), 400

    if not re.fullmatch(r'B\d{2}', tipo) or numero < 0 or not 1 <= tamano <= 20:
        return jsonify({'exists': False, 'valid': False}), 400

    exists, ncf_completo = invoice_has_ncf(
        get_current_tenant_id(), tipo, numero, tamano
    )
    return jsonify({
        'exists': exists,
        'valid': True,
        'ncf': ncf_completo
    })

@app.route('/facturacion/ncf')
@login_required
def facturacion_ncf():
    """Lista de NCF - Filtrado por tenant"""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos para acceder a esta sección', 'error')
        return redirect(url_for('facturacion_menu'))
    
    tenant_id = get_current_tenant_id()
    ncf_list = execute_query(
        'SELECT * FROM ncf WHERE tenant_id = %s ORDER BY tipo, id DESC',
        (tenant_id,),
        fetch='all',
    ) or []
    ecf_secuencias = execute_query('''
        SELECT *,
               GREATEST(ultimo_numero, secuencia_inicial - 1) + 1 AS proximo_numero
        FROM ecf_secuencias
        WHERE tenant_id = %s
        ORDER BY tipo_ecf, activo DESC, fecha_vencimiento DESC, id DESC
    ''', (tenant_id,), fetch='all') or []
    ecf_types = obtener_catalogo_ecf_tenant(tenant_id)
    return render_template(
        'facturacion/ncf.html',
        ncf_list=ncf_list,
        ecf_secuencias=ecf_secuencias,
        ecf_types=ecf_types,
    )


@app.route('/facturacion/ncf/electronico/nuevo', methods=['GET', 'POST'])
@login_required
def facturacion_ecf_secuencia_nueva():
    """Registrar un rango e-NCF autorizado por la DGII."""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_menu'))

    tenant_id = get_current_tenant_id()
    ecf_types = obtener_catalogo_ecf_tenant(tenant_id)
    if request.method == 'POST':
        tipo_ecf, descripcion_tipo, tipo_error = (
            obtener_tipo_ecf_formulario(ecf_types)
        )
        fecha_autorizacion = request.form.get('fecha_autorizacion') or None
        fecha_vencimiento = request.form.get('fecha_vencimiento', '').strip()
        activo = 1 if request.form.get('activo') == '1' else 0
        try:
            if tipo_error:
                raise ValueError(tipo_error)
            secuencia_inicial = int(request.form.get('secuencia_inicial', ''))
            secuencia_final = int(request.form.get('secuencia_final', ''))
            ultimo_numero = int(
                request.form.get('ultimo_numero', str(secuencia_inicial - 1))
            )
            if not 1 <= secuencia_inicial <= 9999999999:
                raise ValueError('La secuencia inicial no es válida')
            if not secuencia_inicial <= secuencia_final <= 9999999999:
                raise ValueError('La secuencia final no es válida')
            if not secuencia_inicial - 1 <= ultimo_numero <= secuencia_final:
                raise ValueError('El último número utilizado está fuera del rango')
            if not fecha_vencimiento:
                raise ValueError('La fecha de vencimiento es obligatoria')
            fecha_fin = datetime.strptime(fecha_vencimiento, '%Y-%m-%d').date()
            fecha_inicio = (
                datetime.strptime(fecha_autorizacion, '%Y-%m-%d').date()
                if fecha_autorizacion else None
            )
            if fecha_inicio and fecha_fin < fecha_inicio:
                raise ValueError(
                    'La fecha de vencimiento no puede ser anterior a la autorización'
                )
        except (TypeError, ValueError) as error:
            flash(str(error) or 'Los datos de la secuencia no son válidos', 'error')
            return render_template(
                'facturacion/ncf_electronico_form.html',
                form=request.form,
                ecf_types=ecf_types,
            )

        overlapping = execute_query('''
            SELECT id
            FROM ecf_secuencias
            WHERE tenant_id=%s AND tipo_ecf=%s
              AND NOT (secuencia_final < %s OR secuencia_inicial > %s)
            LIMIT 1
        ''', (
            tenant_id,
            tipo_ecf,
            secuencia_inicial,
            secuencia_final
        ))
        if overlapping:
            flash('El rango indicado se solapa con otra secuencia e-NCF', 'error')
            return render_template(
                'facturacion/ncf_electronico_form.html',
                form=request.form,
                ecf_types=ecf_types,
            )

        execute_update('''
            INSERT INTO ecf_secuencias
            (tenant_id, tipo_ecf, descripcion_tipo, serie, secuencia_inicial,
             secuencia_final, ultimo_numero, fecha_autorizacion,
             fecha_vencimiento, activo)
            VALUES (%s, %s, %s, 'E', %s, %s, %s, %s, %s, %s)
        ''', (
            tenant_id,
            tipo_ecf,
            descripcion_tipo,
            secuencia_inicial,
            secuencia_final,
            ultimo_numero,
            fecha_autorizacion,
            fecha_vencimiento,
            activo
        ))
        flash(f'Secuencia E{tipo_ecf} registrada correctamente', 'success')
        return redirect(url_for('facturacion_ncf'))

    return render_template(
        'facturacion/ncf_electronico_form.html',
        form={},
        ecf_types=ecf_types,
    )


@app.route(
    '/facturacion/ncf/electronico/<int:secuencia_id>/estado',
    methods=['POST']
)
@login_required
def facturacion_ecf_secuencia_estado(secuencia_id):
    """Activar o desactivar un rango e-NCF sin eliminar su historial."""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_menu'))

    tenant_id = get_current_tenant_id()
    secuencia = execute_query(
        'SELECT * FROM ecf_secuencias WHERE id=%s AND tenant_id=%s',
        (secuencia_id, tenant_id)
    )
    if not secuencia:
        flash('Secuencia electrónica no encontrada', 'error')
        return redirect(url_for('facturacion_ncf'))

    nuevo_estado = 0 if secuencia.get('activo') else 1
    if nuevo_estado:
        if secuencia['fecha_vencimiento'] < datetime.now().date():
            flash('No se puede activar una secuencia vencida', 'error')
            return redirect(url_for('facturacion_ncf'))
        if int(secuencia['ultimo_numero']) >= int(secuencia['secuencia_final']):
            flash('No se puede activar una secuencia agotada', 'error')
            return redirect(url_for('facturacion_ncf'))

    execute_update(
        'UPDATE ecf_secuencias SET activo=%s WHERE id=%s AND tenant_id=%s',
        (nuevo_estado, secuencia_id, tenant_id)
    )
    flash(
        f"Secuencia E31 {'activada' if nuevo_estado else 'desactivada'}",
        'success'
    )
    return redirect(url_for('facturacion_ncf'))

@app.route('/facturacion/ncf/nuevo', methods=['GET', 'POST'])
@login_required
def facturacion_ncf_nuevo():
    """Crear nuevo NCF"""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_menu'))
    
    if request.method == 'POST':
        tipo, descripcion, tipo_error = obtener_tipo_ncf_formulario()
        if tipo_error:
            flash(tipo_error, 'error')
            return redirect(url_for('facturacion_ncf_nuevo'))
        prefijo = tipo or ''
        tamano_secuencia = request.form.get('tamano_secuencia', '8')
        ultimo_numero = request.form.get('ultimo_numero', '0')
        fecha_fin = request.form.get('fecha_fin')
        
        if not all([tipo, prefijo, tamano_secuencia]):
            flash('Tipo, Prefijo y Tamaño son obligatorios', 'error')
            return redirect(url_for('facturacion_ncf_nuevo'))
        
        try:
            ultimo_numero_int = int(ultimo_numero or 0)
            tamano_secuencia_int = int(tamano_secuencia)
            if ultimo_numero_int < 0 or not 1 <= tamano_secuencia_int <= 20:
                raise ValueError
        except (TypeError, ValueError):
            flash('El último número y el tamaño de secuencia no son válidos', 'error')
            return redirect(url_for('facturacion_ncf_nuevo'))

        tenant_id = get_current_tenant_id()
        exists, ncf_completo = invoice_has_ncf(
            tenant_id, tipo, ultimo_numero_int, tamano_secuencia_int
        )
        if exists:
            flash(
                f'No se puede usar el último número: la factura {ncf_completo} ya existe',
                'error'
            )
            return redirect(url_for('facturacion_ncf_nuevo'))

        proximo_numero = ultimo_numero_int + 1
        execute_update('''
            INSERT INTO ncf
                (tenant_id, tipo, descripcion, prefijo, ultimo_numero,
                 proximo_numero, tamano_secuencia, fecha_fin, activo)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 1)
        ''', (
            tenant_id, tipo, descripcion, prefijo, ultimo_numero_int,
            proximo_numero, tamano_secuencia_int, fecha_fin
        ))
        
        flash(f'NCF {tipo} creado exitosamente', 'success')
        return redirect(url_for('facturacion_ncf'))
    
    return render_template(
        'facturacion/ncf_form.html',
        ncf=None,
        ncf_tipos=obtener_catalogo_ncf_tenant(get_current_tenant_id()),
    )

@app.route('/facturacion/ncf/<int:ncf_id>/editar', methods=['GET', 'POST'])
@login_required
def facturacion_ncf_editar(ncf_id):
    """Editar NCF"""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_menu'))
    
    tenant_id = get_current_tenant_id()
    ncf = execute_query(
        'SELECT * FROM ncf WHERE id = %s AND tenant_id = %s',
        (ncf_id, tenant_id),
    )
    if not ncf:
        flash('NCF no encontrado', 'error')
        return redirect(url_for('facturacion_ncf'))
    
    if request.method == 'POST':
        tipo, descripcion, tipo_error = obtener_tipo_ncf_formulario()
        if tipo_error:
            flash(tipo_error, 'error')
            return redirect(url_for('facturacion_ncf_editar', ncf_id=ncf_id))
        prefijo = tipo or ''
        tamano_secuencia = request.form.get('tamano_secuencia', '8')
        ultimo_numero = request.form.get('ultimo_numero', '0')
        fecha_fin = request.form.get('fecha_fin')
        activo = 1 if request.form.get('activo') == '1' else 0
        
        if not all([tipo, prefijo, tamano_secuencia]):
            flash('Tipo, Prefijo y Tamaño son obligatorios', 'error')
            return redirect(url_for('facturacion_ncf_editar', ncf_id=ncf_id))
        
        try:
            ultimo_numero_int = int(ultimo_numero or 0)
            tamano_secuencia_int = int(tamano_secuencia)
            if ultimo_numero_int < 0 or not 1 <= tamano_secuencia_int <= 20:
                raise ValueError
        except (TypeError, ValueError):
            flash('El último número y el tamaño de secuencia no son válidos', 'error')
            return redirect(url_for('facturacion_ncf_editar', ncf_id=ncf_id))

        tenant_id = get_current_tenant_id()
        sequence_changed = (
            tipo != ncf['tipo']
            or ultimo_numero_int != ncf['ultimo_numero']
            or tamano_secuencia_int != ncf['tamano_secuencia']
        )
        if sequence_changed:
            exists, ncf_completo = invoice_has_ncf(
                tenant_id, tipo, ultimo_numero_int, tamano_secuencia_int
            )
            if exists:
                flash(
                    f'No se puede usar el último número: la factura {ncf_completo} ya existe',
                    'error'
                )
                return redirect(url_for('facturacion_ncf_editar', ncf_id=ncf_id))

        proximo_numero = ultimo_numero_int + 1
        execute_update('''
            UPDATE ncf 
            SET tipo = %s, descripcion = %s, prefijo = %s,
                ultimo_numero = %s, proximo_numero = %s,
                tamano_secuencia = %s, fecha_fin = %s, activo = %s
            WHERE id = %s AND tenant_id = %s
        ''', (
            tipo, descripcion, prefijo, ultimo_numero_int, proximo_numero,
            tamano_secuencia_int, fecha_fin, activo, ncf_id, tenant_id
        ))
        
        flash(f'NCF actualizado exitosamente', 'success')
        return redirect(url_for('facturacion_ncf'))
    
    return render_template(
        'facturacion/ncf_form.html',
        ncf=ncf,
        ncf_tipos=obtener_catalogo_ncf_tenant(tenant_id),
    )

@app.route('/facturacion/ncf/<int:ncf_id>/eliminar', methods=['POST'])
@login_required
def facturacion_ncf_eliminar(ncf_id):
    """Eliminar NCF"""
    if current_user.perfil != 'Administrador':
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_ncf'))
    
    tenant_id = get_current_tenant_id()
    if not validate_tenant_access('ncf', ncf_id):
        flash('No tienes acceso a este NCF', 'error')
        return redirect(url_for('facturacion_ncf'))
    
    execute_update('DELETE FROM ncf WHERE id = %s AND tenant_id = %s', (ncf_id, tenant_id))
    flash('NCF eliminado exitosamente', 'success')
    return redirect(url_for('facturacion_ncf'))

@app.route('/facturacion/pacientes')
@login_required
def facturacion_pacientes():
    """Lista de pacientes - Filtrado por tenant"""
    tenant_id = get_current_tenant_id()
    search = request.args.get('search', '').strip()
    
    query = '''
        SELECT p.*, a.nombre as ars_nombre 
        FROM pacientes p
        LEFT JOIN ars a
          ON p.ars_id = a.id AND a.tenant_id = p.tenant_id
        WHERE p.tenant_id = %s
    '''
    params = [tenant_id]
    
    if search:
        query += (' AND (p.nombre LIKE %s OR p.nss LIKE %s OR p.cedula LIKE %s '
                  'OR p.telefono LIKE %s OR p.telefono_pariente LIKE %s)')
        search_pattern = f'%{search}%'
        phone_digits = re.sub(r'\D', '', search)
        phone_pattern = f'%{phone_digits}%' if phone_digits else search_pattern
        params.extend([
            search_pattern, search_pattern, search_pattern,
            phone_pattern, phone_pattern
        ])
    
    pacientes_list, pagination = execute_paginated_query(
        query,
        params,
        'p.nombre, p.id',
    )
    return render_template(
        'facturacion/pacientes.html',
        pacientes_list=pacientes_list,
        search=search,
        pagination=pagination,
    )


@app.route('/facturacion/pacientes/nuevo', methods=['GET', 'POST'])
@login_required
def facturacion_pacientes_nuevo():
    """Crear un paciente manualmente."""
    tenant_id = get_current_tenant_id()

    if request.method == 'POST':
        nombre = sanitize_input(request.form.get('nombre', ''), 200)
        cedula = sanitize_input(request.form.get('cedula', ''), 20)
        nss = sanitize_input(request.form.get('nss', ''), 50)
        telefono = sanitize_input(request.form.get('telefono', ''), 20)
        email = request.form.get('email', '').strip().lower()
        direccion = sanitize_input(request.form.get('direccion', ''), 500)
        fecha_nacimiento = request.form.get('fecha_nacimiento') or None
        sexo = request.form.get('sexo') or None
        ars_id = request.form.get('ars_id') or None
        es_asegurado = request.form.get('es_asegurado') == '1'
        nombre_pariente = sanitize_input(request.form.get('nombre_pariente', ''), 200)
        cedula_pariente = sanitize_input(request.form.get('cedula_pariente', ''), 20)
        telefono_pariente = sanitize_input(request.form.get('telefono_pariente', ''), 20)
        parentesco = sanitize_input(request.form.get('parentesco', ''), 50)

        if (not nombre or not telefono or not email or not direccion or
                not fecha_nacimiento or not sexo):
            flash('Todos los campos del paciente son obligatorios', 'error')
            return redirect(url_for('facturacion_pacientes_nuevo'))

        if cedula and not validate_digits(cedula, 11):
            flash('La cédula debe contener exactamente 11 números', 'error')
            return redirect(url_for('facturacion_pacientes_nuevo'))
        if not validate_digits(telefono, 10):
            flash('El teléfono debe contener exactamente 10 números', 'error')
            return redirect(url_for('facturacion_pacientes_nuevo'))
        if not validate_email(email):
            flash('Debe introducir un correo electrónico válido', 'error')
            return redirect(url_for('facturacion_pacientes_nuevo'))
        if sexo not in ['M', 'F', 'Otro']:
            flash('Debe seleccionar el sexo del paciente', 'error')
            return redirect(url_for('facturacion_pacientes_nuevo'))

        try:
            nacimiento = datetime.strptime(fecha_nacimiento, '%Y-%m-%d').date()
            hoy = datetime.now().date()
            if nacimiento > hoy:
                flash('La fecha de nacimiento no puede ser futura', 'error')
                return redirect(url_for('facturacion_pacientes_nuevo'))
            edad = hoy.year - nacimiento.year - (
                (hoy.month, hoy.day) < (nacimiento.month, nacimiento.day)
            )
        except ValueError:
            flash('La fecha de nacimiento no es válida', 'error')
            return redirect(url_for('facturacion_pacientes_nuevo'))

        if edad < 18:
            if not nombre_pariente or not cedula_pariente or not telefono_pariente or not parentesco:
                flash('El nombre, la cédula, el teléfono y el parentesco son obligatorios para menores de 18 años', 'error')
                return redirect(url_for('facturacion_pacientes_nuevo'))
            if not validate_digits(cedula_pariente, 11):
                flash('La cédula del pariente debe contener exactamente 11 números', 'error')
                return redirect(url_for('facturacion_pacientes_nuevo'))
            if not validate_digits(telefono_pariente, 10):
                flash('El teléfono del pariente debe contener exactamente 10 números', 'error')
                return redirect(url_for('facturacion_pacientes_nuevo'))
        else:
            if not cedula:
                flash('La cédula del paciente es obligatoria para mayores de edad', 'error')
                return redirect(url_for('facturacion_pacientes_nuevo'))
            nombre_pariente = ''
            cedula_pariente = ''
            telefono_pariente = ''
            parentesco = ''

        if es_asegurado:
            if not nss or not ars_id:
                flash('Para un paciente asegurado, el NSS y la ARS son obligatorios', 'error')
                return redirect(url_for('facturacion_pacientes_nuevo'))
            try:
                ars_id = int(ars_id)
            except (TypeError, ValueError):
                flash('Debe seleccionar una ARS válida', 'error')
                return redirect(url_for('facturacion_pacientes_nuevo'))
            ars_valida = execute_query(
                'SELECT id FROM ars WHERE id = %s AND tenant_id = %s AND activo = 1',
                (ars_id, tenant_id)
            )
            if not ars_valida:
                flash('La ARS seleccionada no es válida', 'error')
                return redirect(url_for('facturacion_pacientes_nuevo'))
        else:
            nss = ''
            ars_id = None

        cedula_existente = execute_query(
            'SELECT id FROM pacientes WHERE cedula = %s AND tenant_id = %s',
            (cedula, tenant_id)
        ) if cedula else None
        if cedula_existente:
            flash('Ya existe un paciente con esta cédula', 'error')
            return redirect(url_for('facturacion_pacientes_nuevo'))

        paciente_id = execute_update('''
            INSERT INTO pacientes (
                tenant_id, nombre, cedula, nss, telefono, email, direccion,
                fecha_nacimiento, sexo, nombre_pariente, cedula_pariente,
                telefono_pariente, parentesco, ars_id
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (
            tenant_id, nombre, cedula or None, nss or None, telefono, email, direccion,
            fecha_nacimiento, sexo, nombre_pariente or None, cedula_pariente or None,
            telefono_pariente or None, parentesco or None, ars_id
        ))
        flash('Paciente creado exitosamente', 'success')
        return redirect(url_for('facturacion_paciente_acciones', paciente_id=paciente_id))

    ars_list = execute_query(
        'SELECT * FROM ars WHERE activo = 1 AND tenant_id = %s ORDER BY nombre',
        (tenant_id,), fetch='all'
    ) or []
    return render_template('facturacion/paciente_form.html', paciente=None, ars_list=ars_list)


def paciente_adulto_sin_cedula(paciente):
    """Indicar si un paciente ya cumplió 18 años y requiere cédula propia."""
    if not paciente or paciente.get('cedula') or not paciente.get('fecha_nacimiento'):
        return False
    try:
        nacimiento = paciente['fecha_nacimiento']
        if isinstance(nacimiento, str):
            nacimiento = datetime.strptime(nacimiento, '%Y-%m-%d').date()
        hoy = datetime.now().date()
        edad = hoy.year - nacimiento.year - (
            (hoy.month, hoy.day) < (nacimiento.month, nacimiento.day)
        )
        return edad >= 18
    except (ValueError, TypeError):
        return False


@app.route('/facturacion/pacientes/<int:paciente_id>/acciones')
@login_required
def facturacion_paciente_acciones(paciente_id):
    """Mostrar los siguientes pasos después de crear un paciente."""
    tenant_id = get_current_tenant_id()
    paciente = execute_query(
        'SELECT id, nombre, cedula, fecha_nacimiento FROM pacientes WHERE id=%s AND tenant_id=%s',
        (paciente_id, tenant_id)
    )
    if not paciente:
        flash('Paciente no encontrado', 'error')
        return redirect(url_for('facturacion_pacientes'))
    return render_template(
        'facturacion/paciente_acciones.html',
        paciente=paciente,
        requiere_cedula=paciente_adulto_sin_cedula(paciente)
    )


@app.route('/facturacion/pacientes/<int:paciente_id>/actualizar-cedula', methods=['POST'])
@login_required
def facturacion_paciente_actualizar_cedula(paciente_id):
    """Solicitar la cédula propia cuando un paciente alcanza la mayoría de edad."""
    tenant_id = get_current_tenant_id()
    paciente = execute_query(
        'SELECT id, cedula, fecha_nacimiento FROM pacientes WHERE id=%s AND tenant_id=%s',
        (paciente_id, tenant_id)
    )
    if not paciente:
        flash('Paciente no encontrado', 'error')
        return redirect(url_for('facturacion_pacientes'))
    if not paciente_adulto_sin_cedula(paciente):
        return redirect(url_for('facturacion_paciente_acciones', paciente_id=paciente_id))

    cedula = sanitize_input(request.form.get('cedula', ''), 20)
    if not validate_digits(cedula, 11):
        flash('La cédula del paciente debe contener exactamente 11 números', 'error')
        return redirect(url_for('facturacion_paciente_acciones', paciente_id=paciente_id))
    existente = execute_query(
        'SELECT id FROM pacientes WHERE cedula=%s AND tenant_id=%s AND id<>%s',
        (cedula, tenant_id, paciente_id)
    )
    if existente:
        flash('Esta cédula ya está registrada con otro paciente', 'error')
        return redirect(url_for('facturacion_paciente_acciones', paciente_id=paciente_id))

    execute_update(
        'UPDATE pacientes SET cedula=%s WHERE id=%s AND tenant_id=%s',
        (cedula, paciente_id, tenant_id)
    )
    flash('Cédula propia del paciente actualizada correctamente', 'success')
    return redirect(url_for('facturacion_paciente_acciones', paciente_id=paciente_id))


@app.route('/facturacion/pacientes/<int:paciente_id>/editar', methods=['GET', 'POST'])
@login_required
def facturacion_pacientes_editar(paciente_id):
    """Editar paciente"""
    tenant_id = get_current_tenant_id()
    paciente = execute_query('''
        SELECT p.*, a.nombre as ars_nombre 
        FROM pacientes p
        LEFT JOIN ars a
          ON p.ars_id = a.id AND a.tenant_id = p.tenant_id
        WHERE p.id = %s AND p.tenant_id = %s
    ''', (paciente_id, tenant_id))
    
    if not paciente:
        flash('Paciente no encontrado', 'error')
        return redirect(url_for('facturacion_pacientes'))
    
    if request.method == 'POST':
        nombre = sanitize_input(request.form.get('nombre', ''), 200)
        cedula = sanitize_input(request.form.get('cedula', ''), 20)
        nss = sanitize_input(request.form.get('nss', ''), 50)
        telefono = sanitize_input(request.form.get('telefono', ''), 20)
        email = request.form.get('email', '').strip().lower()
        direccion = request.form.get('direccion', '').strip()
        fecha_nacimiento = request.form.get('fecha_nacimiento') or None
        sexo = request.form.get('sexo') or None
        ars_id = request.form.get('ars_id') or None
        tipo_afiliacion = request.form.get('tipo_afiliacion') or None
        es_asegurado = request.form.get('es_asegurado') == '1'
        nombre_pariente = sanitize_input(request.form.get('nombre_pariente', ''), 200)
        cedula_pariente = sanitize_input(request.form.get('cedula_pariente', ''), 20)
        telefono_pariente = sanitize_input(request.form.get('telefono_pariente', ''), 20)
        parentesco = sanitize_input(request.form.get('parentesco', ''), 50)
        
        if (not nombre or not telefono or not email or not direccion or
                not fecha_nacimiento or not sexo):
            flash('Todos los campos del paciente son obligatorios', 'error')
            return redirect(url_for('facturacion_pacientes_editar', paciente_id=paciente_id))
        
        if cedula and not validate_digits(cedula, 11):
            flash('La cédula debe contener exactamente 11 números', 'error')
            return redirect(url_for('facturacion_pacientes_editar', paciente_id=paciente_id))

        if not validate_digits(telefono, 10):
            flash('El teléfono debe contener exactamente 10 números', 'error')
            return redirect(url_for('facturacion_pacientes_editar', paciente_id=paciente_id))

        if not validate_email(email):
            flash('Debe introducir un correo electrónico válido', 'error')
            return redirect(url_for('facturacion_pacientes_editar', paciente_id=paciente_id))

        if sexo not in ['M', 'F', 'Otro']:
            flash('Debe seleccionar el sexo del paciente', 'error')
            return redirect(url_for('facturacion_pacientes_editar', paciente_id=paciente_id))

        try:
            nacimiento = datetime.strptime(fecha_nacimiento, '%Y-%m-%d').date()
            hoy = datetime.now().date()
            if nacimiento > hoy:
                flash('La fecha de nacimiento no puede ser futura', 'error')
                return redirect(url_for('facturacion_pacientes_editar', paciente_id=paciente_id))
            edad = hoy.year - nacimiento.year - (
                (hoy.month, hoy.day) < (nacimiento.month, nacimiento.day)
            )
        except ValueError:
            flash('La fecha de nacimiento no es válida', 'error')
            return redirect(url_for('facturacion_pacientes_editar', paciente_id=paciente_id))

        if edad < 18:
            if not nombre_pariente or not cedula_pariente or not telefono_pariente or not parentesco:
                flash('El nombre, la cédula, el teléfono y el parentesco son obligatorios para menores de 18 años', 'error')
                return redirect(url_for('facturacion_pacientes_editar', paciente_id=paciente_id))
            if not validate_digits(cedula_pariente, 11):
                flash('La cédula del pariente debe contener exactamente 11 números', 'error')
                return redirect(url_for('facturacion_pacientes_editar', paciente_id=paciente_id))
            if not validate_digits(telefono_pariente, 10):
                flash('El teléfono del pariente debe contener exactamente 10 números', 'error')
                return redirect(url_for('facturacion_pacientes_editar', paciente_id=paciente_id))
        else:
            if not cedula:
                flash('La cédula del paciente es obligatoria para mayores de edad', 'error')
                return redirect(url_for('facturacion_pacientes_editar', paciente_id=paciente_id))
            nombre_pariente = ''
            cedula_pariente = ''
            telefono_pariente = ''
            parentesco = ''

        if es_asegurado:
            if not nss or not ars_id:
                flash('Para un paciente asegurado, el NSS y la ARS son obligatorios', 'error')
                return redirect(url_for('facturacion_pacientes_editar', paciente_id=paciente_id))
            try:
                ars_id = int(ars_id)
            except (TypeError, ValueError):
                flash('Debe seleccionar una ARS válida', 'error')
                return redirect(url_for('facturacion_pacientes_editar', paciente_id=paciente_id))

            ars_valida = execute_query(
                'SELECT id FROM ars WHERE id = %s AND tenant_id = %s AND activo = 1',
                (ars_id, tenant_id)
            )
            if not ars_valida:
                flash('La ARS seleccionada no es válida', 'error')
                return redirect(url_for('facturacion_pacientes_editar', paciente_id=paciente_id))
        else:
            nss = ''
            ars_id = None
        
        execute_update('''
            UPDATE pacientes 
            SET nombre = %s, cedula = %s, nss = %s, telefono = %s, email = %s, 
                direccion = %s, fecha_nacimiento = %s, sexo = %s,
                nombre_pariente = %s, cedula_pariente = %s, telefono_pariente = %s,
                parentesco = %s, ars_id = %s, tipo_afiliacion = %s
            WHERE id = %s AND tenant_id = %s
        ''', (nombre, cedula or None, nss or None, telefono or None, email or None, 
              direccion or None, fecha_nacimiento, sexo, nombre_pariente or None,
              cedula_pariente or None, telefono_pariente or None, parentesco or None,
              ars_id, tipo_afiliacion, paciente_id, tenant_id))
        
        flash('Paciente actualizado exitosamente', 'success')
        return redirect(url_for('facturacion_pacientes'))
    
    # Obtener lista de ARS para el dropdown
    ars_list = execute_query('SELECT * FROM ars WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    
    return render_template('facturacion/paciente_form.html', paciente=paciente, ars_list=ars_list)

@app.route('/facturacion/pacientes/<int:paciente_id>/eliminar', methods=['POST'])
@login_required
@roles_required('Administrador')
def facturacion_pacientes_eliminar(paciente_id):
    """Eliminar paciente"""
    tenant_id = get_current_tenant_id()
    
    # Verificar que el paciente existe y pertenece al tenant
    paciente = execute_query('SELECT id FROM pacientes WHERE id = %s AND tenant_id = %s', (paciente_id, tenant_id))
    if not paciente:
        flash('Paciente no encontrado', 'error')
        return redirect(url_for('facturacion_pacientes'))
    
    # Eliminar el paciente
    execute_update('DELETE FROM pacientes WHERE id = %s AND tenant_id = %s', (paciente_id, tenant_id))
    
    flash('Paciente eliminado exitosamente', 'success')
    return redirect(url_for('facturacion_pacientes'))

@app.route('/facturacion/pacientes-pendientes/<int:paciente_id>/eliminar', methods=['POST'])
@login_required
def facturacion_pacientes_pendientes_eliminar(paciente_id):
    """Eliminar paciente pendiente"""
    tenant_id = get_current_tenant_id()

    paciente = execute_query(
        'SELECT id FROM pacientes_pendientes WHERE id = %s AND tenant_id = %s',
        (paciente_id, tenant_id),
    )
    if not paciente:
        flash('Registro no encontrado', 'error')
        return redirect(url_for('facturacion_pacientes_pendientes'))

    execute_update(
        'DELETE FROM pacientes_pendientes WHERE id = %s AND tenant_id = %s',
        (paciente_id, tenant_id),
    )
    
    flash('Registro eliminado exitosamente', 'success')
    return redirect(url_for('facturacion_pacientes_pendientes'))

@app.route('/api/facturacion/pacientes-pendientes/<int:paciente_id>', methods=['GET'])
@login_required
def api_facturacion_pacientes_pendientes_get(paciente_id):
    """Obtener datos de un paciente pendiente para editar"""
    tenant_id = get_current_tenant_id()

    paciente = execute_query('''
        SELECT pp.*, a.nombre as ars_nombre, m.nombre as medico_nombre
        FROM pacientes_pendientes pp
        LEFT JOIN ars a
          ON pp.ars_id = a.id AND a.tenant_id = pp.tenant_id
        LEFT JOIN medicos m
          ON pp.medico_id = m.id AND m.tenant_id = pp.tenant_id
        WHERE pp.id = %s AND pp.tenant_id = %s
    ''', (paciente_id, tenant_id))
    
    if not paciente:
        return jsonify({'error': 'Registro no encontrado'}), 404
    
    # Extraer solo el servicio sin la autorización
    servicio_completo = paciente.get('servicios_realizados', '') or ''
    servicio = servicio_completo.split(' - Autorización:')[0].strip() if ' - Autorización:' in servicio_completo else servicio_completo.strip()
    autorizacion = ''
    if ' - Autorización:' in servicio_completo:
        partes = servicio_completo.split(' - Autorización:')
        if len(partes) > 1:
            autorizacion = partes[1].strip()
    
    # Formatear fecha para input type="date" (YYYY-MM-DD)
    fecha_servicio = paciente.get('fecha_servicio', '')
    if fecha_servicio:
        if isinstance(fecha_servicio, str):
            # Si es string, verificar formato y convertir si es necesario
            if '/' in fecha_servicio:
                # Formato MM/DD/YYYY o DD/MM/YYYY
                partes = fecha_servicio.split('/')
                if len(partes) == 3:
                    fecha_servicio = f"{partes[2]}-{partes[0].zfill(2)}-{partes[1].zfill(2)}"
            elif fecha_servicio.count('-') == 2 and len(fecha_servicio.split('-')[0]) == 2:
                # Formato DD-MM-YYYY
                partes = fecha_servicio.split('-')
                fecha_servicio = f"{partes[2]}-{partes[1]}-{partes[0]}"
        else:
            # Si es objeto date/datetime, convertir a string YYYY-MM-DD
            from datetime import date, datetime
            if isinstance(fecha_servicio, (date, datetime)):
                fecha_servicio = fecha_servicio.strftime('%Y-%m-%d')
    
    return jsonify({
        'id': paciente['id'],
        'nombre_paciente': paciente.get('nombre_paciente', ''),
        'nss': paciente.get('nss', ''),
        'fecha_servicio': fecha_servicio,
        'servicio': servicio,
        'autorizacion': autorizacion,
        'monto_estimado': float(paciente.get('monto_estimado', 0)),
        'ars_id': paciente.get('ars_id'),
        'ars_nombre': paciente.get('ars_nombre', ''),
        'medico_id': paciente.get('medico_id'),
        'medico_nombre': paciente.get('medico_nombre', ''),
        'centro_medico_id': paciente.get('centro_medico_id'),
        'observaciones': paciente.get('observaciones', '')
    })

@app.route('/api/facturacion/pacientes-pendientes/<int:paciente_id>', methods=['PUT'])
@login_required
def api_facturacion_pacientes_pendientes_update(paciente_id):
    """Actualizar un paciente pendiente"""
    try:
        tenant_id = get_current_tenant_id()
        
        if not request.is_json:
            return jsonify({'error': 'Content-Type debe ser application/json'}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No se recibieron datos'}), 400
        
        # Validar datos
        nombre_paciente = sanitize_input(data.get('nombre_paciente', ''), 200)
        nss = sanitize_input(data.get('nss', ''), 50)
        fecha_servicio = data.get('fecha_servicio', '')
        servicio_completo = sanitize_input(data.get('servicio', ''), 500)  # Ya viene con autorización si existe
        
        try:
            monto_estimado = float(data.get('monto_estimado', 0))
        except (ValueError, TypeError):
            monto_estimado = 0.0
        
        ars_id = data.get('ars_id') or None
        medico_id = data.get('medico_id') or None
        centro_medico_id = data.get('centro_medico_id') or None
        
        # Manejar observaciones de forma segura
        observaciones = data.get('observaciones')
        if observaciones:
            observaciones = str(observaciones).strip()
            if not observaciones:
                observaciones = None
        else:
            observaciones = None
        
        if not nombre_paciente:
            return jsonify({'error': 'El nombre del paciente es obligatorio'}), 400
        
        if not fecha_servicio:
            return jsonify({'error': 'La fecha de servicio es obligatoria'}), 400

        paciente = execute_query(
            '''
            SELECT id
            FROM pacientes_pendientes
            WHERE id = %s AND tenant_id = %s
            ''',
            (paciente_id, tenant_id),
        )
        if not paciente:
            return jsonify({'error': 'Registro no encontrado'}), 404
        
        # El servicio ya viene completo con autorización desde el frontend
        servicios_realizados = servicio_completo
        
        # Convertir IDs a enteros si existen
        try:
            if ars_id:
                ars_id = int(ars_id)
        except (ValueError, TypeError):
            ars_id = None
            
        try:
            if medico_id:
                medico_id = int(medico_id)
        except (ValueError, TypeError):
            medico_id = None
            
        try:
            if centro_medico_id:
                centro_medico_id = int(centro_medico_id)
        except (ValueError, TypeError):
            centro_medico_id = None
        
        updated_id = execute_update('''
            UPDATE pacientes_pendientes
            SET nombre_paciente = %s, nss = %s, fecha_servicio = %s,
                servicios_realizados = %s, monto_estimado = %s,
                ars_id = %s, medico_id = %s, centro_medico_id = %s,
                observaciones = %s
            WHERE id = %s AND tenant_id = %s
        ''', (
            nombre_paciente, nss or None, fecha_servicio,
            servicios_realizados, monto_estimado, ars_id, medico_id,
            centro_medico_id, observaciones, paciente_id, tenant_id,
        ))
        if updated_id is None:
            return jsonify({'error': 'No se pudo actualizar el registro'}), 500
        
        return jsonify({'success': True, 'message': 'Registro actualizado exitosamente'})
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"Error al actualizar paciente pendiente: {error_trace}")
        return jsonify({'error': f'Error al actualizar: {str(e)}'}), 500
    
    return jsonify({'success': True, 'message': 'Registro actualizado exitosamente'})

def calcular_edad_clinica(fecha_nacimiento, fecha_referencia=None):
    if not fecha_nacimiento:
        return None
    if isinstance(fecha_nacimiento, str):
        fecha_nacimiento = datetime.strptime(fecha_nacimiento, '%Y-%m-%d').date()
    fecha_referencia = fecha_referencia or datetime.now().date()
    return fecha_referencia.year - fecha_nacimiento.year - (
        (fecha_referencia.month, fecha_referencia.day)
        < (fecha_nacimiento.month, fecha_nacimiento.day)
    )


@app.route('/api/busqueda-global')
@login_required
def api_busqueda_global():
    """Buscar entidades del tenant desde la barra superior."""
    termino = request.args.get('q', '').strip()
    if len(termino) < 2:
        return jsonify({'resultados': []})

    tenant_id = get_current_tenant_id()
    patron = f'%{termino}%'
    digitos = re.sub(r'\D', '', termino)
    patron_telefono = f'%{digitos}%' if len(digitos) >= 3 else patron
    resultados = []

    pacientes = execute_query('''
        SELECT id, nombre, cedula, nss, telefono
        FROM pacientes
        WHERE tenant_id = %s
          AND (nombre LIKE %s OR cedula LIKE %s OR nss LIKE %s
               OR telefono LIKE %s OR telefono_pariente LIKE %s OR email LIKE %s)
        ORDER BY nombre
        LIMIT 6
    ''', (tenant_id, patron, patron, patron, patron_telefono, patron_telefono, patron), fetch='all') or []
    paciente_endpoint = (
        'facturacion_paciente_acciones'
        if current_user.perfil == 'Registro de Facturas'
        else 'facturacion_historia_clinica_expediente'
    )
    for paciente in pacientes:
        referencias = [
            valor for valor in [
                f"Cédula: {paciente.get('cedula')}" if paciente.get('cedula') else None,
                f"NSS: {paciente.get('nss')}" if paciente.get('nss') else None,
                paciente.get('telefono')
            ] if valor
        ]
        resultados.append({
            'tipo': 'Paciente',
            'titulo': paciente['nombre'],
            'detalle': ' · '.join(referencias) or 'Expediente del paciente',
            'icono': 'fas fa-user-injured',
            'url': url_for(paciente_endpoint, paciente_id=paciente['id'])
        })

    facturas = execute_query('''
        SELECT id, numero_factura, ncf, nombre_paciente, cedula_paciente,
               nss_paciente, nombre_ars, estado
        FROM facturas
        WHERE tenant_id = %s
          AND (numero_factura LIKE %s OR ncf LIKE %s OR nombre_paciente LIKE %s
               OR cedula_paciente LIKE %s OR nss_paciente LIKE %s
               OR nombre_ars LIKE %s)
        ORDER BY fecha_emision DESC, id DESC
        LIMIT 6
    ''', (tenant_id, patron, patron, patron, patron, patron, patron), fetch='all') or []
    for factura in facturas:
        resultados.append({
            'tipo': 'Factura',
            'titulo': factura.get('numero_factura') or f"Factura {factura['id']}",
            'detalle': f"NCF: {factura.get('ncf') or 'N/D'} · {factura.get('nombre_paciente') or 'Sin paciente'} · {factura.get('estado') or ''}",
            'icono': 'fas fa-file-invoice-dollar',
            'url': url_for('facturacion_ver_factura', factura_id=factura['id'])
        })

    # El perfil de facturación puede localizar pacientes y facturas, pero no
    # diagnósticos, consultas, recetas, licencias ni otros datos clínicos.
    if current_user.perfil == 'Registro de Facturas':
        return jsonify({'resultados': resultados[:30]})

    consultas = execute_query('''
        SELECT c.id, c.fecha, c.motivo_consulta, c.diagnostico_principal,
               c.codigo_cie10, p.nombre AS paciente_nombre
        FROM consultas_clinicas c
        JOIN pacientes p ON p.id = c.paciente_id AND p.tenant_id = c.tenant_id
        WHERE c.tenant_id = %s
          AND (p.nombre LIKE %s OR p.cedula LIKE %s OR p.nss LIKE %s
               OR c.motivo_consulta LIKE %s OR c.diagnostico_principal LIKE %s
               OR c.codigo_cie10 LIKE %s)
        ORDER BY c.fecha DESC, c.id DESC
        LIMIT 6
    ''', (tenant_id, patron, patron, patron, patron, patron, patron), fetch='all') or []
    for consulta in consultas:
        resultados.append({
            'tipo': 'Consulta clínica',
            'titulo': consulta['paciente_nombre'],
            'detalle': f"{consulta['fecha']} · {consulta.get('codigo_cie10') or consulta.get('diagnostico_principal') or consulta.get('motivo_consulta')}",
            'icono': 'fas fa-notes-medical',
            'url': url_for('facturacion_historia_clinica_ver', consulta_id=consulta['id'])
        })

    licencias = execute_query('''
        SELECT l.id, l.codigo, l.diagnostico, l.codigo_cie10, l.estado,
               p.nombre AS paciente_nombre, p.cedula
        FROM licencias_medicas l
        JOIN pacientes p ON p.id=l.paciente_id AND p.tenant_id=l.tenant_id
        WHERE l.tenant_id=%s
          AND (l.codigo LIKE %s OR p.nombre LIKE %s OR p.cedula LIKE %s
               OR l.diagnostico LIKE %s OR l.codigo_cie10 LIKE %s)
        ORDER BY l.fecha_emision DESC, l.id DESC LIMIT 6
    ''', (tenant_id, patron, patron, patron, patron, patron), fetch='all') or []
    for licencia in licencias:
        resultados.append({
            'tipo': 'Licencia médica',
            'titulo': licencia['codigo'],
            'detalle': f"{licencia['paciente_nombre']} · {licencia.get('codigo_cie10') or licencia['diagnostico']} · {licencia['estado']}",
            'icono': 'fas fa-file-medical',
            'url': url_for('facturacion_licencia_medica_ver', licencia_id=licencia['id'])
        })

    citas = execute_query('''
        SELECT c.id, c.fecha, c.hora, c.motivo, c.estado,
               p.nombre AS paciente_nombre, m.nombre AS medico_nombre
        FROM citas_medicas c
        JOIN pacientes p ON p.id=c.paciente_id AND p.tenant_id=c.tenant_id
        JOIN medicos m ON m.id=c.medico_id AND m.tenant_id=c.tenant_id
        WHERE c.tenant_id=%s
          AND (p.nombre LIKE %s OR p.cedula LIKE %s
               OR m.nombre LIKE %s OR c.motivo LIKE %s)
        ORDER BY c.fecha DESC, c.hora DESC LIMIT 6
    ''', (tenant_id, patron, patron, patron, patron), fetch='all') or []
    for cita in citas:
        resultados.append({
            'tipo': 'Cita médica',
            'titulo': cita['paciente_nombre'],
            'detalle': f"{cita['fecha']} {hora_input(cita['hora'])} · {cita['medico_nombre']} · {cita['estado']}",
            'icono': 'fas fa-calendar-days',
            'url': url_for('facturacion_cita_editar', cita_id=cita['id'])
        })

    recetas = execute_query('''
        SELECT DISTINCT r.id, r.codigo, r.fecha, r.estado,
               p.nombre AS paciente_nombre
        FROM recetas_medicas r
        JOIN pacientes p ON p.id=r.paciente_id AND p.tenant_id=r.tenant_id
        LEFT JOIN receta_medicamentos rm
          ON rm.receta_id=r.id AND rm.tenant_id=r.tenant_id
        WHERE r.tenant_id=%s
          AND (r.codigo LIKE %s OR p.nombre LIKE %s OR p.cedula LIKE %s
               OR r.diagnostico LIKE %s OR rm.medicamento LIKE %s)
        ORDER BY r.fecha DESC, r.id DESC LIMIT 6
    ''', (tenant_id, patron, patron, patron, patron, patron), fetch='all') or []
    for receta in recetas:
        resultados.append({
            'tipo': 'Receta médica',
            'titulo': receta['paciente_nombre'],
            'detalle': f"{receta['codigo']} · {receta['fecha']} · {receta['estado']}",
            'icono': 'fas fa-prescription',
            'url': url_for(
                'facturacion_receta_medica_ver', receta_id=receta['id']
            )
        })

    if current_user.perfil in ['Administrador', 'Nivel 2']:
        medicos = execute_query('''
            SELECT id, nombre, cedula, exequatur, especialidad, telefono
            FROM medicos
            WHERE tenant_id = %s
              AND (nombre LIKE %s OR cedula LIKE %s OR exequatur LIKE %s
                   OR especialidad LIKE %s OR telefono LIKE %s)
            ORDER BY nombre LIMIT 5
        ''', (tenant_id, patron, patron, patron, patron, patron_telefono), fetch='all') or []
        for medico in medicos:
            resultados.append({
                'tipo': 'Médico',
                'titulo': medico['nombre'],
                'detalle': f"{medico.get('especialidad') or 'Sin especialidad'} · Exequátur: {medico.get('exequatur') or 'N/D'}",
                'icono': 'fas fa-user-doctor',
                'url': url_for('facturacion_medicos_editar', medico_id=medico['id'])
            })

        ars_list = execute_query('''
            SELECT id, nombre, codigo, rnc, telefono
            FROM ars
            WHERE tenant_id = %s
              AND (nombre LIKE %s OR codigo LIKE %s OR rnc LIKE %s OR telefono LIKE %s)
            ORDER BY nombre LIMIT 5
        ''', (tenant_id, patron, patron, patron, patron_telefono), fetch='all') or []
        for ars in ars_list:
            resultados.append({
                'tipo': 'ARS',
                'titulo': ars['nombre'],
                'detalle': f"Código: {ars.get('codigo') or 'N/D'} · RNC: {ars.get('rnc') or 'N/D'} · {ars.get('telefono') or 'Sin teléfono'}",
                'icono': 'fas fa-shield-heart',
                'url': url_for('facturacion_ars_editar', ars_id=ars['id'])
            })

        centros = execute_query('''
            SELECT id, nombre, codigo, rnc, telefono
            FROM centros_medicos
            WHERE tenant_id = %s
              AND (nombre LIKE %s OR codigo LIKE %s OR rnc LIKE %s OR telefono LIKE %s)
            ORDER BY nombre LIMIT 5
        ''', (tenant_id, patron, patron, patron, patron_telefono), fetch='all') or []
        for centro in centros:
            resultados.append({
                'tipo': 'Centro médico',
                'titulo': centro['nombre'],
                'detalle': f"Código: {centro.get('codigo') or 'N/D'} · RNC: {centro.get('rnc') or 'N/D'}",
                'icono': 'fas fa-hospital',
                'url': url_for('facturacion_centros_medicos_editar', centro_id=centro['id'])
            })

        servicios = execute_query('''
            SELECT id, codigo, nombre, categoria
            FROM servicios
            WHERE tenant_id = %s
              AND (codigo LIKE %s OR nombre LIKE %s OR descripcion LIKE %s
                   OR categoria LIKE %s)
            ORDER BY nombre LIMIT 5
        ''', (tenant_id, patron, patron, patron, patron), fetch='all') or []
        for servicio in servicios:
            resultados.append({
                'tipo': 'Servicio',
                'titulo': servicio['nombre'],
                'detalle': f"Código: {servicio.get('codigo') or 'N/D'} · {servicio.get('categoria') or 'Sin categoría'}",
                'icono': 'fas fa-list-check',
                'url': url_for('facturacion_servicios_editar', servicio_id=servicio['id'])
            })

        comprobantes = execute_query('''
            SELECT id, tipo, prefijo, ultimo_numero, activo
            FROM ncf
            WHERE tenant_id = %s
              AND (tipo LIKE %s OR prefijo LIKE %s
                   OR CONCAT(prefijo, LPAD(ultimo_numero, 8, '0')) LIKE %s)
            ORDER BY tipo LIMIT 5
        ''', (tenant_id, patron, patron, patron), fetch='all') or []
        for comprobante in comprobantes:
            resultados.append({
                'tipo': 'Secuencia NCF',
                'titulo': f"{comprobante['tipo']} · {comprobante['prefijo']}",
                'detalle': f"Último número: {comprobante.get('ultimo_numero') or 0}",
                'icono': 'fas fa-receipt',
                'url': url_for('facturacion_ncf_editar', ncf_id=comprobante['id'])
            })

    return jsonify({'resultados': resultados[:30]})


@app.route('/api/verificar-telefono')
@login_required
def api_verificar_telefono():
    """Localizar un teléfono repetido en los mantenimientos del tenant."""
    telefono = re.sub(r'\D', '', request.args.get('telefono', ''))
    if len(telefono) != 10:
        return jsonify({'coincidencias': []})

    tenant_id = get_current_tenant_id()
    coincidencias = []

    pacientes = execute_query(
        'SELECT id, nombre, telefono, telefono_pariente FROM pacientes '
        'WHERE tenant_id=%s AND (telefono=%s OR telefono_pariente=%s) LIMIT 10',
        (tenant_id, telefono, telefono), fetch='all'
    ) or []
    for registro in pacientes:
        coincidencias.append({
            'tipo': (
                'paciente'
                if registro.get('telefono') == telefono
                else 'pariente del paciente'
            ),
            'nombre': registro['nombre'],
            'url': url_for('facturacion_pacientes_editar', paciente_id=registro['id'])
        })

    if current_user.perfil == 'Registro de Facturas':
        return jsonify({'coincidencias': coincidencias})

    medicos = execute_query(
        'SELECT id, nombre FROM medicos WHERE tenant_id=%s AND telefono=%s LIMIT 10',
        (tenant_id, telefono), fetch='all'
    ) or []
    for registro in medicos:
        coincidencias.append({
            'tipo': 'médico',
            'nombre': registro['nombre'],
            'url': url_for('facturacion_medicos_editar', medico_id=registro['id'])
        })

    ars_list = execute_query(
        'SELECT id, nombre FROM ars WHERE tenant_id=%s AND telefono=%s LIMIT 10',
        (tenant_id, telefono), fetch='all'
    ) or []
    for registro in ars_list:
        coincidencias.append({
            'tipo': 'ARS',
            'nombre': registro['nombre'],
            'url': url_for('facturacion_ars_editar', ars_id=registro['id'])
        })

    centros = execute_query(
        'SELECT id, nombre FROM centros_medicos WHERE tenant_id=%s AND telefono=%s LIMIT 10',
        (tenant_id, telefono), fetch='all'
    ) or []
    for registro in centros:
        coincidencias.append({
            'tipo': 'centro médico',
            'nombre': registro['nombre'],
            'url': url_for('facturacion_centros_medicos_editar', centro_id=registro['id'])
        })

    if tenant_id is not None:
        empresa = execute_query(
            'SELECT id, nombre FROM empresas WHERE id=%s AND telefono=%s',
            (tenant_id, telefono)
        )
        if empresa:
            coincidencias.append({
                'tipo': 'empresa',
                'nombre': empresa['nombre'],
                'url': url_for('admin_empresas_editar', empresa_id=empresa['id'])
            })

    return jsonify({'coincidencias': coincidencias})


def cargar_json_clinico(valor):
    try:
        return json.loads(valor or '{}')
    except (TypeError, ValueError):
        return {}


def obtener_consulta_clinica_formulario():
    fecha = request.form.get('fecha', '').strip()
    hora = request.form.get('hora', '').strip()
    medico_id = request.form.get('medico_id', '').strip()
    motivo = sanitize_input(request.form.get('motivo_consulta', ''), 5000)
    diagnostico_principal = sanitize_input(request.form.get('diagnostico_principal', ''), 5000)

    if not all([fecha, hora, medico_id, motivo, diagnostico_principal]):
        return None, 'Fecha, hora, médico, motivo y diagnóstico principal son obligatorios'
    try:
        fecha_consulta = datetime.strptime(fecha, '%Y-%m-%d').date()
        datetime.strptime(hora, '%H:%M')
        medico_id = int(medico_id)
    except (ValueError, TypeError):
        return None, 'La fecha, hora o médico no es válido'
    if fecha_consulta > datetime.now().date():
        return None, 'La fecha de la consulta no puede ser futura'

    def texto(nombre, limite=5000):
        return sanitize_input(request.form.get(nombre, ''), limite)

    def numero_decimal(nombre, minimo, maximo):
        valor = request.form.get(nombre, '').strip()
        if not valor:
            return None
        try:
            numero = float(valor)
            return numero if minimo <= numero <= maximo else 'invalido'
        except ValueError:
            return 'invalido'

    def numero_entero(nombre, minimo, maximo):
        valor = request.form.get(nombre, '').strip()
        if not valor:
            return None
        numero = validate_int(valor, min_value=minimo, max_value=maximo, default=None)
        return numero if numero is not None else 'invalido'

    peso = numero_decimal('peso', 0.1, 500)
    talla = numero_decimal('talla', 0.3, 2.5)
    temperatura = numero_decimal('temperatura', 25, 45)
    saturacion = numero_decimal('saturacion_oxigeno', 0, 100)
    frecuencia_cardiaca = numero_entero('frecuencia_cardiaca', 1, 300)
    frecuencia_respiratoria = numero_entero('frecuencia_respiratoria', 1, 100)
    if 'invalido' in [peso, talla, temperatura, saturacion,
                      frecuencia_cardiaca, frecuencia_respiratoria]:
        return None, 'Revise los valores numéricos de los signos vitales'

    imc = round(peso / (talla * talla), 2) if peso and talla else None
    datos = {
        'fecha': fecha,
        'hora': hora,
        'medico_id': medico_id,
        'motivo_consulta': motivo,
        'enfermedad_actual': {
            'inicio_sintomas': texto('inicio_sintomas', 1000),
            'evolucion': texto('evolucion', 3000),
            'intensidad': texto('intensidad', 100),
            'factores_agravan': texto('factores_agravan', 2000),
            'factores_alivian': texto('factores_alivian', 2000),
            'sintomas_asociados': texto('sintomas_asociados', 3000),
            'tratamientos_previos': texto('tratamientos_previos', 3000)
        },
        'antecedentes_personales': {
            'enfermedades_previas': texto('enfermedades_previas', 3000),
            'cirugias': texto('cirugias', 2000),
            'hospitalizaciones': texto('hospitalizaciones', 2000),
            'alergias': texto('alergias', 2000),
            'medicamentos_actuales': texto('medicamentos_actuales', 3000),
            'habitos': texto('habitos', 2000),
            'otros': texto('otros_antecedentes', 3000)
        },
        'antecedentes_familiares': {
            'diabetes': request.form.get('familiar_diabetes') == '1',
            'hipertension': request.form.get('familiar_hipertension') == '1',
            'cardiacas': request.form.get('familiar_cardiacas') == '1',
            'cancer': request.form.get('familiar_cancer') == '1',
            'hereditarias': texto('familiar_hereditarias', 2000),
            'otros': texto('otros_antecedentes_familiares', 2000)
        },
        'signos_vitales': {
            'presion_arterial': texto('presion_arterial', 30),
            'frecuencia_cardiaca': frecuencia_cardiaca,
            'frecuencia_respiratoria': frecuencia_respiratoria,
            'temperatura': temperatura,
            'saturacion_oxigeno': saturacion,
            'peso': peso,
            'talla': talla,
            'imc': imc
        },
        'examen_fisico': {
            'estado_general': texto('estado_general', 2000),
            'cabeza_cuello': texto('cabeza_cuello', 2000),
            'cardiovascular': texto('cardiovascular', 2000),
            'respiratorio': texto('respiratorio', 2000),
            'abdomen': texto('abdomen', 2000),
            'extremidades': texto('extremidades', 2000),
            'neurologico': texto('neurologico', 2000),
            'otros': texto('otros_hallazgos', 3000)
        },
        'diagnostico_principal': diagnostico_principal,
        'diagnosticos_secundarios': texto('diagnosticos_secundarios', 4000),
        'diagnostico_presuntivo': texto('diagnostico_presuntivo', 3000),
        'diagnostico_diferencial': texto('diagnostico_diferencial', 3000),
        'codigo_cie10': texto('codigo_cie10', 30).upper(),
        'plan_tratamiento': {
            'medicamentos': texto('plan_medicamentos', 4000),
            'dosis': texto('plan_dosis', 1000),
            'frecuencia': texto('plan_frecuencia', 1000),
            'duracion': texto('plan_duracion', 1000),
            'laboratorios': texto('estudios_laboratorio', 3000),
            'imagenes': texto('estudios_imagenes', 3000),
            'procedimientos': texto('procedimientos', 3000),
            'recomendaciones': texto('recomendaciones', 4000)
        },
        'nota_evolucion_inicial': texto('nota_evolucion_inicial', 5000),
        'proxima_cita': request.form.get('proxima_cita') or None,
        'proxima_hora': request.form.get('proxima_hora') or None,
        'proxima_especialidad': texto('proxima_especialidad', 150),
        'proxima_motivo': texto('proxima_motivo', 2000),
        'indicaciones_seguimiento': texto('indicaciones_seguimiento', 3000),
        'ocupacion': texto('ocupacion', 150)
    }
    if datos['proxima_cita']:
        try:
            proxima_cita = datetime.strptime(datos['proxima_cita'], '%Y-%m-%d').date()
        except ValueError:
            return None, 'La fecha de próxima cita no es válida'
        if proxima_cita < fecha_consulta:
            return None, 'La próxima cita no puede ser anterior a la consulta'
        if not datos['proxima_hora']:
            return None, 'Indique la hora de la próxima cita'
        try:
            datetime.strptime(datos['proxima_hora'], '%H:%M')
        except ValueError:
            return None, 'La hora de próxima cita no es válida'
    return datos, None


def obtener_consulta_clinica(consulta_id, tenant_id):
    consulta = execute_query('''
        SELECT c.*, p.nombre AS paciente_nombre, p.fecha_nacimiento, p.cedula,
               p.telefono, p.email, p.direccion, p.ocupacion, p.sexo,
               m.nombre AS medico_nombre
        FROM consultas_clinicas c
        JOIN pacientes p ON c.paciente_id = p.id AND p.tenant_id = c.tenant_id
        JOIN medicos m ON c.medico_id = m.id AND m.tenant_id = c.tenant_id
        WHERE c.id = %s AND c.tenant_id = %s
    ''', (consulta_id, tenant_id))
    if consulta:
        for campo in ['enfermedad_actual', 'antecedentes_personales',
                      'antecedentes_familiares', 'signos_vitales',
                      'examen_fisico', 'plan_tratamiento']:
            consulta[campo] = cargar_json_clinico(consulta.get(campo))
    return consulta


def sincronizar_cita_desde_historia(consulta_id, tenant_id):
    """Crear o actualizar en agenda la próxima cita registrada en la historia."""
    consulta = execute_query('''
        SELECT c.id, c.paciente_id, c.medico_id, c.proxima_cita,
               c.proxima_hora, c.proxima_especialidad, c.proxima_motivo,
               c.indicaciones_seguimiento
        FROM consultas_clinicas c
        WHERE c.id=%s AND c.tenant_id=%s
    ''', (consulta_id, tenant_id))
    if not consulta:
        return 'No se encontró la consulta para programar la cita'
    existente = execute_query(
        'SELECT id, estado FROM citas_medicas '
        'WHERE tenant_id=%s AND consulta_origen_id=%s',
        (tenant_id, consulta_id)
    )
    if not consulta.get('proxima_cita'):
        if existente and existente['estado'] not in ['Completada', 'Cancelada']:
            execute_update('''
                UPDATE citas_medicas
                SET estado='Cancelada', motivo_cancelacion=%s,
                    fecha_cancelacion=NOW(), cancelada_por=%s, updated_by=%s
                WHERE id=%s AND tenant_id=%s
            ''', (
                'Próxima cita retirada de la Historia Clínica',
                current_user.id, current_user.id, existente['id'], tenant_id
            ))
        return None
    hora = consulta.get('proxima_hora') or '09:00:00'
    parametros = [
        tenant_id, consulta['medico_id'], consulta['paciente_id'],
        consulta['proxima_cita'],
        hora, hora
    ]
    query = '''
        SELECT c.id, c.hora, c.medico_id, c.paciente_id,
               p.nombre AS paciente_nombre
        FROM citas_medicas c
        JOIN pacientes p
          ON p.id=c.paciente_id AND p.tenant_id=c.tenant_id
        WHERE c.tenant_id=%s
          AND (c.medico_id=%s OR c.paciente_id=%s) AND c.fecha=%s
          AND c.estado NOT IN ('Cancelada','Vencida','No asistió')
          AND c.hora<ADDTIME(%s, '00:30:00')
          AND ADDTIME(c.hora, SEC_TO_TIME(c.duracion_minutos * 60))>%s
    '''
    if existente:
        query += ' AND c.id<>%s'
        parametros.append(existente['id'])
    query += ' LIMIT 1'
    conflicto = execute_query(query, tuple(parametros))
    if conflicto:
        recurso = (
            'el médico' if conflicto['medico_id'] == consulta['medico_id']
            else 'el paciente'
        )
        return (
            f"No se agregó a la agenda: {recurso} ya tiene una cita a las "
            f"{hora_input(conflicto['hora'])} con {conflicto['paciente_nombre']}"
        )
    motivo = consulta.get('proxima_motivo') or 'Seguimiento médico'
    if existente:
        execute_update('''
            UPDATE citas_medicas SET
                paciente_id=%s, medico_id=%s, fecha=%s, hora=%s,
                especialidad=%s, motivo=%s, notas=%s,
                estado=CASE WHEN estado IN ('Cancelada','Vencida')
                            THEN 'Programada' ELSE estado END,
                updated_by=%s
            WHERE id=%s AND tenant_id=%s
        ''', (
            consulta['paciente_id'], consulta['medico_id'],
            consulta['proxima_cita'], hora,
            consulta.get('proxima_especialidad'), motivo,
            consulta.get('indicaciones_seguimiento'), current_user.id,
            existente['id'], tenant_id
        ))
    else:
        execute_update('''
            INSERT INTO citas_medicas (
                tenant_id, paciente_id, medico_id, consulta_origen_id,
                fecha, hora, duracion_minutos, especialidad, motivo,
                notas, estado, origen, created_by, updated_by
            ) VALUES (
                %s,%s,%s,%s,%s,%s,30,%s,%s,%s,
                'Programada','Historia clinica',%s,%s
            )
        ''', (
            tenant_id, consulta['paciente_id'], consulta['medico_id'],
            consulta_id, consulta['proxima_cita'], hora,
            consulta.get('proxima_especialidad'), motivo,
            consulta.get('indicaciones_seguimiento'),
            current_user.id, current_user.id
        ))
    return None


@app.route('/facturacion/historia-clinica')
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_historia_clinica():
    tenant_id = get_current_tenant_id()
    search = request.args.get('search', '').strip()
    query = '''
        SELECT p.id, p.nombre, p.cedula, p.telefono, p.fecha_nacimiento,
               MAX(c.fecha) AS ultima_consulta, COUNT(c.id) AS total_consultas
        FROM pacientes p
        LEFT JOIN consultas_clinicas c
          ON c.paciente_id = p.id AND c.tenant_id = p.tenant_id
        WHERE p.tenant_id = %s
    '''
    params = [tenant_id]
    if search:
        query += ' AND (p.nombre LIKE %s OR p.cedula LIKE %s OR p.nss LIKE %s)'
        patron = f'%{search}%'
        params.extend([patron, patron, patron])
    query += ' GROUP BY p.id'
    pacientes, pagination = execute_paginated_query(
        query,
        params,
        'p.nombre, p.id',
    )
    return render_template(
        'facturacion/historia_clinica.html',
        pacientes=pacientes,
        search=search,
        pagination=pagination,
    )


@app.route('/facturacion/reportes/pacientes-360')
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_reporte_pacientes_360():
    """Listado de pacientes para acceder a su vista clínica integral."""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos para acceder a esta sección', 'error')
        return redirect(url_for('facturacion_menu'))

    tenant_id = get_current_tenant_id()
    search = request.args.get('search', '').strip()
    query = '''
        SELECT p.id, p.nombre, p.cedula, p.telefono, p.fecha_nacimiento,
               p.sexo, MAX(c.fecha) AS ultima_consulta,
               COUNT(DISTINCT c.id) AS total_consultas
        FROM pacientes p
        LEFT JOIN consultas_clinicas c
          ON c.paciente_id=p.id AND c.tenant_id=p.tenant_id
        WHERE p.tenant_id=%s
    '''
    params = [tenant_id]
    if search:
        query += '''
            AND (
                p.nombre LIKE %s OR p.cedula LIKE %s OR p.telefono LIKE %s
            )
        '''
        pattern = f'%{search}%'
        params.extend([pattern, pattern, pattern])
    query += '''
        GROUP BY p.id, p.nombre, p.cedula, p.telefono,
                 p.fecha_nacimiento, p.sexo
        ORDER BY p.nombre
        LIMIT 200
    '''
    pacientes = execute_query(query, tuple(params), fetch='all') or []
    for paciente in pacientes:
        paciente['edad'] = calcular_edad_clinica(
            paciente.get('fecha_nacimiento')
        )

    return render_template(
        'facturacion/reporte_pacientes_360.html',
        pacientes=pacientes,
        search=search,
    )


@app.route('/facturacion/historia-clinica/paciente/<int:paciente_id>')
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_historia_clinica_expediente(paciente_id):
    tenant_id = get_current_tenant_id()
    paciente = execute_query('''
        SELECT p.*, a.nombre AS ars_nombre
        FROM pacientes p
        LEFT JOIN ars a
          ON p.ars_id = a.id AND a.tenant_id = p.tenant_id
        WHERE p.id = %s AND p.tenant_id = %s
    ''', (paciente_id, tenant_id))
    if not paciente:
        flash('Paciente no encontrado', 'error')
        return redirect(url_for('facturacion_historia_clinica'))
    paciente['edad'] = calcular_edad_clinica(paciente.get('fecha_nacimiento'))
    consultas = execute_query('''
        SELECT c.id, c.fecha, c.hora, c.motivo_consulta,
               c.diagnostico_principal, c.plan_tratamiento,
               c.nota_evolucion_inicial, c.proxima_cita, c.version,
               m.nombre AS medico_nombre,
               COUNT(e.id) AS total_evoluciones
        FROM consultas_clinicas c
        JOIN medicos m
          ON c.medico_id = m.id AND m.tenant_id = c.tenant_id
        LEFT JOIN evoluciones_clinicas e
          ON e.consulta_id = c.id AND e.tenant_id = c.tenant_id
        WHERE c.paciente_id = %s AND c.tenant_id = %s
        GROUP BY c.id
        ORDER BY c.fecha DESC, c.hora DESC, c.id DESC
    ''', (paciente_id, tenant_id), fetch='all') or []
    for consulta in consultas:
        consulta['plan'] = cargar_json_clinico(consulta.get('plan_tratamiento'))
    actualizar_licencias_vencidas(tenant_id)
    licencias = execute_query('''
        SELECT l.id, l.codigo, l.fecha_emision, l.fecha_inicio, l.fecha_termino,
               l.cantidad_dias, l.diagnostico, l.estado,
               m.nombre AS medico_nombre
        FROM licencias_medicas l
        JOIN medicos m
          ON m.id=l.medico_id AND m.tenant_id=l.tenant_id
        WHERE l.paciente_id=%s AND l.tenant_id=%s
        ORDER BY l.fecha_emision DESC, l.id DESC
    ''', (paciente_id, tenant_id), fetch='all') or []
    emergencias = execute_query('''
        SELECT id, fecha, hora_servicio, motivo_emergencia,
               diagnostico_impresion, estatus_paciente, medico_nombre
        FROM historias_emergencia
        WHERE paciente_id=%s AND tenant_id=%s
        ORDER BY fecha DESC, hora_servicio DESC, id DESC
    ''', (paciente_id, tenant_id), fetch='all') or []
    consultas_registradas = execute_query('''
        SELECT id, fecha_servicio, monto_estimado, estado,
               servicios_realizados, medico_id
        FROM pacientes_pendientes
        WHERE paciente_id=%s AND tenant_id=%s
        ORDER BY fecha_servicio DESC, id DESC
    ''', (paciente_id, tenant_id), fetch='all') or []
    facturas = execute_query('''
        SELECT id, numero_factura, ncf, fecha_emision, total, estado
        FROM facturas
        WHERE paciente_id=%s AND tenant_id=%s
        ORDER BY fecha_emision DESC, id DESC
    ''', (paciente_id, tenant_id), fetch='all') or []
    actualizar_citas_vencidas(tenant_id)
    citas = execute_query('''
        SELECT c.id, c.fecha, c.hora, c.motivo, c.estado,
               c.especialidad, m.nombre AS medico_nombre
        FROM citas_medicas c
        JOIN medicos m ON m.id=c.medico_id AND m.tenant_id=c.tenant_id
        WHERE c.paciente_id=%s AND c.tenant_id=%s
        ORDER BY c.fecha DESC, c.hora DESC, c.id DESC
    ''', (paciente_id, tenant_id), fetch='all') or []
    recetas = execute_query('''
        SELECT r.id, r.codigo, r.fecha, r.diagnostico, r.estado,
               m.nombre AS medico_nombre, COUNT(rm.id) AS medicamentos
        FROM recetas_medicas r
        JOIN medicos m ON m.id=r.medico_id AND m.tenant_id=r.tenant_id
        LEFT JOIN receta_medicamentos rm
          ON rm.receta_id=r.id AND rm.tenant_id=r.tenant_id
        WHERE r.paciente_id=%s AND r.tenant_id=%s
        GROUP BY r.id ORDER BY r.fecha DESC, r.id DESC
    ''', (paciente_id, tenant_id), fetch='all') or []
    resumen = {
        'consultas_clinicas': len(consultas),
        'emergencias': len(emergencias),
        'citas': len(citas),
        'recetas': len(recetas),
        'licencias': len(licencias),
        'consultas_registradas': len(consultas_registradas),
        'facturas': len(facturas),
        'pendientes_facturar': sum(
            1 for registro in consultas_registradas
            if str(registro.get('estado', '')).lower() == 'pendiente'
        )
    }
    return render_template(
        'facturacion/paciente_360.html',
        paciente=paciente,
        consultas=consultas,
        citas=citas,
        recetas=recetas,
        licencias=licencias,
        emergencias=emergencias,
        consultas_registradas=consultas_registradas,
        facturas=facturas,
        resumen=resumen
    )


@app.route('/facturacion/historia-clinica/paciente/<int:paciente_id>/nueva', methods=['GET', 'POST'])
@login_required
@roles_required('Administrador', 'Nivel 2')
@transactional_methods('POST')
def facturacion_historia_clinica_nueva(paciente_id):
    tenant_id = get_current_tenant_id()
    paciente = execute_query(
        'SELECT * FROM pacientes WHERE id = %s AND tenant_id = %s',
        (paciente_id, tenant_id)
    )
    if not paciente:
        flash('Paciente no encontrado', 'error')
        return redirect(url_for('facturacion_historia_clinica'))
    if paciente_adulto_sin_cedula(paciente):
        flash('Debe actualizar la cédula propia del paciente antes de registrar la consulta', 'warning')
        return redirect(url_for('facturacion_paciente_acciones', paciente_id=paciente_id))
    if request.method == 'POST':
        datos, error = obtener_consulta_clinica_formulario()
        if error:
            flash(error, 'error')
            return redirect(url_for('facturacion_historia_clinica_nueva', paciente_id=paciente_id))
        medico = execute_query(
            'SELECT id FROM medicos WHERE id = %s AND tenant_id = %s AND activo = 1',
            (datos['medico_id'], tenant_id)
        )
        if not medico:
            flash('El médico seleccionado no es válido', 'error')
            return redirect(url_for('facturacion_historia_clinica_nueva', paciente_id=paciente_id))
        consulta_id = execute_update('''
            INSERT INTO consultas_clinicas (
                tenant_id, paciente_id, medico_id, fecha, hora, motivo_consulta,
                enfermedad_actual, antecedentes_personales, antecedentes_familiares,
                signos_vitales, examen_fisico, diagnostico_principal,
                diagnosticos_secundarios, diagnostico_presuntivo,
                diagnostico_diferencial, codigo_cie10, plan_tratamiento,
                nota_evolucion_inicial, proxima_cita, proxima_hora, proxima_especialidad,
                proxima_motivo, indicaciones_seguimiento, created_by, updated_by
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
        ''', (
            tenant_id, paciente_id, datos['medico_id'], datos['fecha'], datos['hora'],
            datos['motivo_consulta'], json.dumps(datos['enfermedad_actual'], ensure_ascii=False),
            json.dumps(datos['antecedentes_personales'], ensure_ascii=False),
            json.dumps(datos['antecedentes_familiares'], ensure_ascii=False),
            json.dumps(datos['signos_vitales'], ensure_ascii=False),
            json.dumps(datos['examen_fisico'], ensure_ascii=False),
            datos['diagnostico_principal'], datos['diagnosticos_secundarios'],
            datos['diagnostico_presuntivo'], datos['diagnostico_diferencial'],
            datos['codigo_cie10'] or None,
            json.dumps(datos['plan_tratamiento'], ensure_ascii=False),
            datos['nota_evolucion_inicial'] or None, datos['proxima_cita'],
            datos['proxima_hora'],
            datos['proxima_especialidad'] or None, datos['proxima_motivo'] or None,
            datos['indicaciones_seguimiento'] or None, current_user.id, current_user.id
        ))
        execute_update(
            'UPDATE pacientes SET ocupacion = %s WHERE id = %s AND tenant_id = %s',
            (datos['ocupacion'] or None, paciente_id, tenant_id)
        )
        error_agenda = sincronizar_cita_desde_historia(consulta_id, tenant_id)
        if error_agenda:
            flash(error_agenda, 'warning')
        else:
            flash('Consulta clínica registrada y seguimiento agregado a la agenda', 'success')
        return redirect(url_for('facturacion_historia_clinica_ver', consulta_id=consulta_id))
    medicos = execute_query(
        'SELECT id, nombre, especialidad FROM medicos WHERE tenant_id = %s AND activo = 1 ORDER BY nombre',
        (tenant_id,), fetch='all'
    ) or []
    return render_template(
        'facturacion/historia_clinica_form.html',
        paciente=paciente, medicos=medicos, consulta=None,
        fecha_actual=datetime.now().strftime('%Y-%m-%d'),
        hora_actual=datetime.now().strftime('%H:%M')
    )


@app.route('/facturacion/historia-clinica/consulta/<int:consulta_id>')
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_historia_clinica_ver(consulta_id):
    tenant_id = get_current_tenant_id()
    consulta = obtener_consulta_clinica(consulta_id, tenant_id)
    if not consulta:
        flash('Consulta clínica no encontrada', 'error')
        return redirect(url_for('facturacion_historia_clinica'))
    consulta['edad'] = calcular_edad_clinica(consulta.get('fecha_nacimiento'), consulta['fecha'])
    evoluciones = execute_query('''
        SELECT e.*, m.nombre AS medico_nombre
        FROM evoluciones_clinicas e
        JOIN medicos m
          ON e.medico_id = m.id AND m.tenant_id = e.tenant_id
        WHERE e.consulta_id = %s AND e.tenant_id = %s
        ORDER BY e.fecha ASC, e.hora ASC, e.id ASC
    ''', (consulta_id, tenant_id), fetch='all') or []
    auditoria = execute_query('''
        SELECT a.version_anterior, a.created_at, u.nombre AS usuario_nombre
        FROM auditoria_historia_clinica a
        LEFT JOIN usuarios u
          ON a.usuario_id = u.id AND u.tenant_id = a.tenant_id
        WHERE a.consulta_id = %s AND a.tenant_id = %s
        ORDER BY a.created_at DESC
    ''', (consulta_id, tenant_id), fetch='all') or []
    medicos = execute_query(
        'SELECT id, nombre FROM medicos WHERE tenant_id = %s AND activo = 1 ORDER BY nombre',
        (tenant_id,), fetch='all'
    ) or []
    cita_agenda = execute_query(
        'SELECT id, estado FROM citas_medicas '
        'WHERE consulta_origen_id=%s AND tenant_id=%s',
        (consulta_id, tenant_id)
    )
    recetas = execute_query('''
        SELECT r.id, r.codigo, r.fecha, r.estado, COUNT(rm.id) AS medicamentos
        FROM recetas_medicas r
        LEFT JOIN receta_medicamentos rm
          ON rm.receta_id=r.id AND rm.tenant_id=r.tenant_id
        WHERE r.consulta_id=%s AND r.tenant_id=%s
        GROUP BY r.id ORDER BY r.fecha DESC, r.id DESC
    ''', (consulta_id, tenant_id), fetch='all') or []
    return render_template(
        'facturacion/historia_clinica_ver.html',
        consulta=consulta, evoluciones=evoluciones,
        auditoria=auditoria, medicos=medicos, cita_agenda=cita_agenda,
        recetas=recetas,
        fecha_actual=datetime.now().strftime('%Y-%m-%d'),
        hora_actual=datetime.now().strftime('%H:%M')
    )


@app.route('/facturacion/historia-clinica/consulta/<int:consulta_id>/editar', methods=['GET', 'POST'])
@login_required
@roles_required('Administrador', 'Nivel 2')
@transactional_methods('POST')
def facturacion_historia_clinica_editar(consulta_id):
    tenant_id = get_current_tenant_id()
    consulta = obtener_consulta_clinica(consulta_id, tenant_id)
    if not consulta:
        flash('Consulta clínica no encontrada', 'error')
        return redirect(url_for('facturacion_historia_clinica'))
    if request.method == 'POST':
        datos, error = obtener_consulta_clinica_formulario()
        if error:
            flash(error, 'error')
            return redirect(url_for('facturacion_historia_clinica_editar', consulta_id=consulta_id))
        medico = execute_query(
            'SELECT id FROM medicos WHERE id = %s AND tenant_id = %s AND activo = 1',
            (datos['medico_id'], tenant_id)
        )
        if not medico:
            flash('El médico seleccionado no es válido', 'error')
            return redirect(url_for('facturacion_historia_clinica_editar', consulta_id=consulta_id))
        datos_anteriores = json.dumps(consulta, default=str, ensure_ascii=False)
        version_anterior = consulta['version']
        execute_update('''
            UPDATE consultas_clinicas SET
                medico_id=%s, fecha=%s, hora=%s, motivo_consulta=%s,
                enfermedad_actual=%s, antecedentes_personales=%s,
                antecedentes_familiares=%s, signos_vitales=%s, examen_fisico=%s,
                diagnostico_principal=%s, diagnosticos_secundarios=%s,
                diagnostico_presuntivo=%s, diagnostico_diferencial=%s,
                codigo_cie10=%s, plan_tratamiento=%s, nota_evolucion_inicial=%s,
                proxima_cita=%s, proxima_hora=%s, proxima_especialidad=%s, proxima_motivo=%s,
                indicaciones_seguimiento=%s, version=version+1, updated_by=%s
            WHERE id=%s AND tenant_id=%s
        ''', (
            datos['medico_id'], datos['fecha'], datos['hora'], datos['motivo_consulta'],
            json.dumps(datos['enfermedad_actual'], ensure_ascii=False),
            json.dumps(datos['antecedentes_personales'], ensure_ascii=False),
            json.dumps(datos['antecedentes_familiares'], ensure_ascii=False),
            json.dumps(datos['signos_vitales'], ensure_ascii=False),
            json.dumps(datos['examen_fisico'], ensure_ascii=False),
            datos['diagnostico_principal'], datos['diagnosticos_secundarios'],
            datos['diagnostico_presuntivo'], datos['diagnostico_diferencial'],
            datos['codigo_cie10'] or None,
            json.dumps(datos['plan_tratamiento'], ensure_ascii=False),
            datos['nota_evolucion_inicial'] or None, datos['proxima_cita'],
            datos['proxima_hora'],
            datos['proxima_especialidad'] or None, datos['proxima_motivo'] or None,
            datos['indicaciones_seguimiento'] or None, current_user.id,
            consulta_id, tenant_id
        ))
        execute_update(
            'UPDATE pacientes SET ocupacion=%s WHERE id=%s AND tenant_id=%s',
            (datos['ocupacion'] or None, consulta['paciente_id'], tenant_id)
        )
        consulta_nueva = execute_query(
            'SELECT * FROM consultas_clinicas WHERE id=%s AND tenant_id=%s',
            (consulta_id, tenant_id)
        )
        execute_update('''
            INSERT INTO auditoria_historia_clinica (
                tenant_id, consulta_id, usuario_id, version_anterior,
                datos_anteriores, datos_nuevos, ip, user_agent
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ''', (
            tenant_id, consulta_id, current_user.id, version_anterior,
            datos_anteriores, json.dumps(consulta_nueva, default=str, ensure_ascii=False),
            request.remote_addr, (request.user_agent.string or '')[:500]
        ))
        error_agenda = sincronizar_cita_desde_historia(consulta_id, tenant_id)
        if error_agenda:
            flash(error_agenda, 'warning')
        else:
            flash('Consulta actualizada y próxima cita sincronizada con la agenda', 'success')
        return redirect(url_for('facturacion_historia_clinica_ver', consulta_id=consulta_id))
    medicos = execute_query(
        'SELECT id, nombre, especialidad FROM medicos WHERE tenant_id=%s AND activo=1 ORDER BY nombre',
        (tenant_id,), fetch='all'
    ) or []
    return render_template(
        'facturacion/historia_clinica_form.html',
        paciente=consulta, medicos=medicos, consulta=consulta,
        fecha_actual=consulta['fecha'], hora_actual=str(consulta['hora'])[:5]
    )


@app.route('/facturacion/historia-clinica/consulta/<int:consulta_id>/evolucion', methods=['POST'])
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_historia_clinica_evolucion(consulta_id):
    tenant_id = get_current_tenant_id()
    consulta = execute_query(
        'SELECT id, paciente_id, fecha FROM consultas_clinicas WHERE id=%s AND tenant_id=%s',
        (consulta_id, tenant_id)
    )
    nota = sanitize_input(request.form.get('nota_evolucion', ''), 5000)
    fecha = request.form.get('fecha_evolucion', '').strip()
    hora = request.form.get('hora_evolucion', '').strip()
    medico_id = request.form.get('medico_evolucion', '').strip()
    if not consulta or not all([nota, fecha, hora, medico_id]):
        flash('Complete todos los datos de la evolución', 'error')
        return redirect(url_for('facturacion_historia_clinica_ver', consulta_id=consulta_id))
    try:
        fecha_evolucion = datetime.strptime(fecha, '%Y-%m-%d').date()
        datetime.strptime(hora, '%H:%M')
        medico_id = int(medico_id)
    except (ValueError, TypeError):
        flash('Los datos de la evolución no son válidos', 'error')
        return redirect(url_for('facturacion_historia_clinica_ver', consulta_id=consulta_id))
    if fecha_evolucion < consulta['fecha'] or fecha_evolucion > datetime.now().date():
        flash('La fecha de evolución debe estar entre la consulta y hoy', 'error')
        return redirect(url_for('facturacion_historia_clinica_ver', consulta_id=consulta_id))
    medico = execute_query(
        'SELECT id FROM medicos WHERE id=%s AND tenant_id=%s AND activo=1',
        (medico_id, tenant_id)
    )
    if not medico:
        flash('El médico seleccionado no es válido', 'error')
        return redirect(url_for('facturacion_historia_clinica_ver', consulta_id=consulta_id))
    execute_update('''
        INSERT INTO evoluciones_clinicas (
            tenant_id, consulta_id, paciente_id, medico_id, fecha, hora,
            nota_evolucion, diagnostico, tratamiento, created_by
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ''', (
        tenant_id, consulta_id, consulta['paciente_id'], medico_id, fecha, hora,
        nota, sanitize_input(request.form.get('diagnostico_evolucion', ''), 3000) or None,
        sanitize_input(request.form.get('tratamiento_evolucion', ''), 3000) or None,
        current_user.id
    ))
    flash('Nueva nota de evolución agregada al historial', 'success')
    return redirect(url_for('facturacion_historia_clinica_ver', consulta_id=consulta_id))


def actualizar_citas_vencidas(tenant_id):
    execute_update('''
        UPDATE citas_medicas
        SET estado='Vencida'
        WHERE tenant_id=%s
          AND estado IN ('Programada', 'Confirmada')
          AND (
              fecha<CURDATE()
              OR (
                  fecha=CURDATE()
                  AND ADDTIME(hora, SEC_TO_TIME(duracion_minutos * 60))<CURTIME()
              )
          )
    ''', (tenant_id,))


def contexto_formulario_cita(tenant_id):
    return {
        'pacientes': execute_query(
            'SELECT id, nombre, cedula, telefono FROM pacientes '
            'WHERE tenant_id=%s ORDER BY nombre',
            (tenant_id,), fetch='all'
        ) or [],
        'medicos': execute_query(
            'SELECT id, nombre, especialidad FROM medicos '
            'WHERE tenant_id=%s AND activo=1 ORDER BY nombre',
            (tenant_id,), fetch='all'
        ) or []
    }


def validar_formulario_cita(tenant_id, cita_id=None):
    paciente_id = validate_int(request.form.get('paciente_id'), min_value=1, default=None)
    medico_id = validate_int(request.form.get('medico_id'), min_value=1, default=None)
    fecha = request.form.get('fecha', '').strip()
    hora = request.form.get('hora', '').strip()
    duracion = validate_int(
        request.form.get('duracion_minutos'), min_value=10,
        max_value=480, default=None
    )
    especialidad = sanitize_input(request.form.get('especialidad', ''), 150)
    motivo = sanitize_input(request.form.get('motivo', ''), 2000)
    notas = sanitize_input(request.form.get('notas', ''), 3000)
    estado = request.form.get('estado', 'Programada').strip()
    estados_validos = [
        'Programada', 'Confirmada', 'Completada',
        'Cancelada', 'No asistió', 'Vencida'
    ]
    if not all([paciente_id, medico_id, fecha, hora, duracion, motivo]):
        return None, 'Complete todos los campos obligatorios'
    if estado not in estados_validos:
        return None, 'El estado de la cita no es válido'
    try:
        fecha_obj = datetime.strptime(fecha, '%Y-%m-%d').date()
        hora_obj = datetime.strptime(hora, '%H:%M').time()
    except ValueError:
        return None, 'La fecha u hora no es válida'
    paciente = execute_query(
        'SELECT id FROM pacientes WHERE id=%s AND tenant_id=%s',
        (paciente_id, tenant_id)
    )
    medico = execute_query(
        'SELECT id, especialidad FROM medicos '
        'WHERE id=%s AND tenant_id=%s AND activo=1',
        (medico_id, tenant_id)
    )
    if not paciente or not medico:
        return None, 'El paciente o médico seleccionado no es válido'
    if estado in ['Programada', 'Confirmada']:
        inicio = datetime.combine(fecha_obj, hora_obj)
        if inicio < datetime.now():
            return None, 'No puede programar una cita en una fecha u hora pasada'
    parametros = [
        tenant_id, medico_id, paciente_id, fecha_obj, hora_obj, duracion,
        hora_obj
    ]
    conflicto_sql = '''
        SELECT c.id, c.hora, c.medico_id, c.paciente_id,
               c.duracion_minutos, p.nombre AS paciente_nombre
        FROM citas_medicas c
        JOIN pacientes p
          ON p.id=c.paciente_id AND p.tenant_id=c.tenant_id
        WHERE c.tenant_id=%s AND (c.medico_id=%s OR c.paciente_id=%s)
          AND c.fecha=%s
          AND c.estado NOT IN ('Cancelada', 'Vencida', 'No asistió')
          AND c.hora<ADDTIME(%s, SEC_TO_TIME(%s * 60))
          AND ADDTIME(c.hora, SEC_TO_TIME(c.duracion_minutos * 60))>%s
    '''
    if cita_id:
        conflicto_sql += ' AND c.id<>%s'
        parametros.append(cita_id)
    conflicto_sql += ' LIMIT 1'
    conflicto = None
    if estado in ['Programada', 'Confirmada']:
        conflicto = execute_query(conflicto_sql, tuple(parametros))
    if conflicto:
        recurso = 'El médico' if conflicto['medico_id'] == medico_id else 'El paciente'
        return None, (
            f"{recurso} ya tiene una cita a las {hora_input(conflicto['hora'])} "
            f"con {conflicto['paciente_nombre']}"
        )
    return {
        'paciente_id': paciente_id,
        'medico_id': medico_id,
        'fecha': fecha_obj,
        'hora': hora_obj,
        'duracion': duracion,
        'especialidad': especialidad or medico.get('especialidad'),
        'motivo': motivo,
        'notas': notas or None,
        'estado': estado
    }, None


@app.route('/facturacion/citas')
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_citas():
    tenant_id = get_current_tenant_id()
    actualizar_citas_vencidas(tenant_id)
    vista = request.args.get('vista', 'mes')
    if vista not in ['mes', 'hoy', 'proximas', 'todas']:
        vista = 'mes'
    mes_texto = request.args.get('mes', datetime.now().strftime('%Y-%m'))
    try:
        primer_dia = datetime.strptime(mes_texto, '%Y-%m').date().replace(day=1)
    except ValueError:
        primer_dia = datetime.now().date().replace(day=1)
        mes_texto = primer_dia.strftime('%Y-%m')
    ultimo_dia_numero = calendar_module.monthrange(
        primer_dia.year, primer_dia.month
    )[1]
    ultimo_dia = primer_dia.replace(day=ultimo_dia_numero)
    mes_anterior = (primer_dia - timedelta(days=1)).replace(day=1)
    mes_siguiente = (ultimo_dia + timedelta(days=1)).replace(day=1)
    paciente_id = validate_int(
        request.args.get('paciente_id'), min_value=1, default=None
    )
    medico_id = validate_int(
        request.args.get('medico_id'), min_value=1, default=None
    )
    estado = request.args.get('estado', '').strip()
    buscar = request.args.get('buscar', '').strip()
    query = '''
        SELECT c.*, p.nombre AS paciente_nombre, p.telefono,
               m.nombre AS medico_nombre, m.especialidad AS medico_especialidad
        FROM citas_medicas c
        JOIN pacientes p ON p.id=c.paciente_id AND p.tenant_id=c.tenant_id
        JOIN medicos m ON m.id=c.medico_id AND m.tenant_id=c.tenant_id
        WHERE c.tenant_id=%s
    '''
    params = [tenant_id]
    hoy = datetime.now().date()
    if vista == 'mes':
        query += ' AND c.fecha BETWEEN %s AND %s'
        params.extend([primer_dia, ultimo_dia])
    elif vista == 'hoy':
        query += ' AND c.fecha=%s'
        params.append(hoy)
    elif vista == 'proximas':
        query += " AND c.fecha>=%s AND c.estado NOT IN ('Cancelada','Completada','Vencida','No asistió')"
        params.append(hoy)
    if paciente_id:
        query += ' AND c.paciente_id=%s'
        params.append(paciente_id)
    if medico_id:
        query += ' AND c.medico_id=%s'
        params.append(medico_id)
    if estado in [
        'Programada', 'Confirmada', 'Completada',
        'Cancelada', 'No asistió', 'Vencida'
    ]:
        query += ' AND c.estado=%s'
        params.append(estado)
    if buscar:
        patron = f'%{buscar}%'
        query += ' AND (p.nombre LIKE %s OR m.nombre LIKE %s OR c.motivo LIKE %s)'
        params.extend([patron, patron, patron])
    query += ' ORDER BY c.fecha ASC, c.hora ASC'
    citas = execute_query(query, tuple(params), fetch='all') or []
    citas_por_fecha = defaultdict(list)
    for cita in citas:
        citas_por_fecha[cita['fecha'].isoformat()].append(cita)
    calendario = calendar_module.Calendar(firstweekday=0)
    semanas = calendario.monthdatescalendar(primer_dia.year, primer_dia.month)
    contexto = contexto_formulario_cita(tenant_id)
    return render_template(
        'facturacion/citas.html',
        citas=citas, citas_por_fecha=dict(citas_por_fecha),
        semanas=semanas, vista=vista, mes=mes_texto,
        mes_numero=primer_dia.month, anio=primer_dia.year,
        mes_anterior=mes_anterior.strftime('%Y-%m'),
        mes_siguiente=mes_siguiente.strftime('%Y-%m'),
        hoy=hoy, filtros=request.args, **contexto
    )


@app.route('/facturacion/citas/nueva', methods=['GET', 'POST'])
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_citas_nueva():
    tenant_id = get_current_tenant_id()
    contexto = contexto_formulario_cita(tenant_id)
    consulta_id = validate_int(
        request.args.get('consulta_id') or request.form.get('consulta_origen_id'),
        min_value=1, default=None
    )
    consulta_origen = None
    if consulta_id:
        consulta_origen = execute_query('''
            SELECT c.id, c.paciente_id, c.medico_id, c.proxima_cita,
                   c.proxima_hora, c.proxima_especialidad, c.proxima_motivo,
                   c.indicaciones_seguimiento
            FROM consultas_clinicas c
            WHERE c.id=%s AND c.tenant_id=%s
        ''', (consulta_id, tenant_id))
    if request.method == 'POST':
        datos, error = validar_formulario_cita(tenant_id)
        if error:
            flash(error, 'error')
            return render_template(
                'facturacion/cita_form.html', cita=None,
                consulta_origen=consulta_origen, form_data=request.form,
                **contexto
            )
        if consulta_id:
            existente = execute_query(
                'SELECT id FROM citas_medicas '
                'WHERE tenant_id=%s AND consulta_origen_id=%s',
                (tenant_id, consulta_id)
            )
            if existente:
                flash('Esta consulta ya tiene una próxima cita en la agenda', 'warning')
                return redirect(url_for(
                    'facturacion_cita_editar', cita_id=existente['id']
                ))
        cita_id = execute_update('''
            INSERT INTO citas_medicas (
                tenant_id, paciente_id, medico_id, consulta_origen_id,
                fecha, hora, duracion_minutos, especialidad, motivo,
                notas, estado, origen, created_by, updated_by
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
        ''', (
            tenant_id, datos['paciente_id'], datos['medico_id'], consulta_id,
            datos['fecha'], datos['hora'], datos['duracion'],
            datos['especialidad'], datos['motivo'], datos['notas'],
            datos['estado'], 'Historia clinica' if consulta_id else 'Manual',
            current_user.id, current_user.id
        ))
        flash('Cita programada exitosamente', 'success')
        return redirect(url_for(
            'facturacion_citas', vista='mes',
            mes=datos['fecha'].strftime('%Y-%m')
        ))
    return render_template(
        'facturacion/cita_form.html', cita=None,
        consulta_origen=consulta_origen, form_data={},
        fecha_actual=request.args.get('fecha', ''),
        paciente_preseleccionado=request.args.get('paciente_id', ''),
        medico_preseleccionado=request.args.get('medico_id', ''),
        **contexto
    )


@app.route('/facturacion/citas/<int:cita_id>/editar', methods=['GET', 'POST'])
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_cita_editar(cita_id):
    tenant_id = get_current_tenant_id()
    cita = execute_query(
        'SELECT * FROM citas_medicas WHERE id=%s AND tenant_id=%s',
        (cita_id, tenant_id)
    )
    if not cita:
        flash('Cita no encontrada', 'error')
        return redirect(url_for('facturacion_citas'))
    contexto = contexto_formulario_cita(tenant_id)
    if request.method == 'POST':
        datos, error = validar_formulario_cita(tenant_id, cita_id)
        if error:
            flash(error, 'error')
            return render_template(
                'facturacion/cita_form.html', cita=cita,
                consulta_origen=None, form_data=request.form, **contexto
            )
        execute_update('''
            UPDATE citas_medicas SET
                paciente_id=%s, medico_id=%s, fecha=%s, hora=%s,
                duracion_minutos=%s, especialidad=%s, motivo=%s,
                notas=%s, estado=%s, updated_by=%s
            WHERE id=%s AND tenant_id=%s
        ''', (
            datos['paciente_id'], datos['medico_id'], datos['fecha'],
            datos['hora'], datos['duracion'], datos['especialidad'],
            datos['motivo'], datos['notas'], datos['estado'],
            current_user.id, cita_id, tenant_id
        ))
        flash('Cita actualizada correctamente', 'success')
        return redirect(url_for(
            'facturacion_citas', vista='mes',
            mes=datos['fecha'].strftime('%Y-%m')
        ))
    return render_template(
        'facturacion/cita_form.html', cita=cita,
        consulta_origen=None, form_data=cita, **contexto
    )


@app.route('/facturacion/citas/<int:cita_id>/estado', methods=['POST'])
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_cita_estado(cita_id):
    tenant_id = get_current_tenant_id()
    estado = request.form.get('estado', '').strip()
    if estado not in [
        'Programada', 'Confirmada', 'Completada',
        'Cancelada', 'No asistió'
    ]:
        flash('Estado de cita no válido', 'error')
        return redirect(url_for('facturacion_citas'))
    cita = execute_query(
        'SELECT id FROM citas_medicas WHERE id=%s AND tenant_id=%s',
        (cita_id, tenant_id)
    )
    if not cita:
        flash('Cita no encontrada', 'error')
        return redirect(url_for('facturacion_citas'))
    motivo_cancelacion = sanitize_input(
        request.form.get('motivo_cancelacion', ''), 1000
    )
    if estado == 'Cancelada' and not motivo_cancelacion:
        flash('Indique el motivo de cancelación', 'error')
        return redirect(request.referrer or url_for('facturacion_citas'))
    execute_update('''
        UPDATE citas_medicas SET estado=%s, updated_by=%s,
            cancelada_por=%s, fecha_cancelacion=%s, motivo_cancelacion=%s
        WHERE id=%s AND tenant_id=%s
    ''', (
        estado, current_user.id,
        current_user.id if estado == 'Cancelada' else None,
        datetime.now() if estado == 'Cancelada' else None,
        motivo_cancelacion if estado == 'Cancelada' else None,
        cita_id, tenant_id
    ))
    flash('Estado de la cita actualizado', 'success')
    return redirect(request.referrer or url_for('facturacion_citas'))


def actualizar_licencias_vencidas(tenant_id):
    execute_update(
        """
        UPDATE licencias_medicas
        SET estado='Vencida'
        WHERE tenant_id=%s AND estado='Emitida' AND fecha_termino < CURDATE()
        """,
        (tenant_id,)
    )


def obtener_licencia_medica(licencia_id, tenant_id):
    return execute_query(
        """
        SELECT l.*, p.nombre AS paciente_nombre, p.cedula, p.fecha_nacimiento,
               p.telefono, p.direccion, m.nombre AS medico_nombre,
               m.especialidad, m.exequatur, t.nombre AS tipo_licencia,
               c.fecha AS consulta_fecha, c.motivo_consulta AS consulta_motivo,
               uc.nombre AS creado_por_nombre, um.nombre AS modificado_por_nombre,
               ua.nombre AS anulado_por_nombre
        FROM licencias_medicas l
        JOIN pacientes p ON p.id=l.paciente_id AND p.tenant_id=l.tenant_id
        JOIN medicos m ON m.id=l.medico_id AND m.tenant_id=l.tenant_id
        JOIN tipos_licencia_medica t ON t.id=l.tipo_licencia_id AND t.tenant_id=l.tenant_id
        LEFT JOIN consultas_clinicas c ON c.id=l.consulta_id AND c.tenant_id=l.tenant_id
        LEFT JOIN usuarios uc
          ON uc.id=l.created_by AND uc.tenant_id=l.tenant_id
        LEFT JOIN usuarios um
          ON um.id=l.updated_by AND um.tenant_id=l.tenant_id
        LEFT JOIN usuarios ua
          ON ua.id=l.anulado_por AND ua.tenant_id=l.tenant_id
        WHERE l.id=%s AND l.tenant_id=%s
        """,
        (licencia_id, tenant_id)
    )


def contexto_formulario_licencia(tenant_id, paciente_preseleccionado=None):
    pacientes = execute_query(
        "SELECT id, nombre, cedula, fecha_nacimiento FROM pacientes "
        "WHERE tenant_id=%s ORDER BY nombre",
        (tenant_id,), fetch='all'
    ) or []
    medicos = execute_query(
        "SELECT id, nombre, especialidad FROM medicos "
        "WHERE tenant_id=%s AND activo=1 ORDER BY nombre",
        (tenant_id,), fetch='all'
    ) or []
    consultas = execute_query(
        """
        SELECT c.id, c.paciente_id, c.fecha, c.diagnostico_principal,
               c.codigo_cie10, m.nombre AS medico_nombre
        FROM consultas_clinicas c
        JOIN medicos m
          ON m.id=c.medico_id AND m.tenant_id=c.tenant_id
        WHERE c.tenant_id=%s
        ORDER BY c.fecha DESC, c.id DESC
        """,
        (tenant_id,), fetch='all'
    ) or []
    tipos = execute_query(
        "SELECT id, nombre FROM tipos_licencia_medica "
        "WHERE tenant_id=%s AND activo=1 ORDER BY nombre",
        (tenant_id,), fetch='all'
    ) or []
    return {
        'pacientes': pacientes,
        'medicos': medicos,
        'consultas': consultas,
        'tipos_licencia': tipos,
        'paciente_preseleccionado': paciente_preseleccionado
    }


def validar_datos_licencia(tenant_id):
    paciente_id = validate_int(request.form.get('paciente_id'), min_value=1, default=None)
    medico_id = validate_int(request.form.get('medico_id'), min_value=1, default=None)
    consulta_id = validate_int(request.form.get('consulta_id'), min_value=1, default=None)
    tipo_id = validate_int(request.form.get('tipo_licencia_id'), min_value=1, default=None)
    diagnostico = sanitize_input(request.form.get('diagnostico', ''), 5000)
    cie10 = sanitize_input(request.form.get('codigo_cie10', ''), 30).upper()
    motivo = sanitize_input(request.form.get('motivo_condicion', ''), 5000)
    observaciones = sanitize_input(request.form.get('observaciones', ''), 5000)
    fecha_emision = request.form.get('fecha_emision', '').strip()
    fecha_inicio = request.form.get('fecha_inicio', '').strip()
    fecha_termino = request.form.get('fecha_termino', '').strip()
    estado = request.form.get('estado', 'Borrador').strip()

    if not all([paciente_id, medico_id, tipo_id, diagnostico, motivo,
                fecha_emision, fecha_inicio, fecha_termino]):
        return None, 'Complete todos los campos obligatorios'
    if estado not in ['Borrador', 'Emitida']:
        return None, 'El estado seleccionado no es válido'
    try:
        emision = datetime.strptime(fecha_emision, '%Y-%m-%d').date()
        inicio = datetime.strptime(fecha_inicio, '%Y-%m-%d').date()
        termino = datetime.strptime(fecha_termino, '%Y-%m-%d').date()
    except ValueError:
        return None, 'Las fechas de la licencia no son válidas'
    if termino < inicio:
        return None, 'La fecha de término no puede ser menor que la fecha de inicio'
    cantidad_dias = (termino - inicio).days + 1

    paciente = execute_query(
        "SELECT id, cedula, fecha_nacimiento FROM pacientes "
        "WHERE id=%s AND tenant_id=%s",
        (paciente_id, tenant_id)
    )
    medico = execute_query(
        "SELECT id FROM medicos WHERE id=%s AND tenant_id=%s AND activo=1",
        (medico_id, tenant_id)
    )
    tipo = execute_query(
        "SELECT id FROM tipos_licencia_medica "
        "WHERE id=%s AND tenant_id=%s AND activo=1",
        (tipo_id, tenant_id)
    )
    if not paciente or not medico or not tipo:
        return None, 'El paciente, médico o tipo de licencia no es válido'
    if paciente_adulto_sin_cedula(paciente):
        return None, 'Debe actualizar la cédula propia del paciente antes de emitir la licencia'

    if consulta_id:
        consulta = execute_query(
            "SELECT id, paciente_id FROM consultas_clinicas "
            "WHERE id=%s AND tenant_id=%s",
            (consulta_id, tenant_id)
        )
        if not consulta or consulta['paciente_id'] != paciente_id:
            return None, 'La consulta seleccionada no pertenece al paciente'

    return {
        'paciente_id': paciente_id, 'medico_id': medico_id,
        'consulta_id': consulta_id, 'tipo_id': tipo_id,
        'diagnostico': diagnostico, 'cie10': cie10 or None,
        'motivo': motivo, 'observaciones': observaciones or None,
        'fecha_emision': emision, 'fecha_inicio': inicio,
        'fecha_termino': termino, 'cantidad_dias': cantidad_dias,
        'estado': estado
    }, None


@app.route('/facturacion/licencias-medicas')
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_licencias_medicas():
    tenant_id = get_current_tenant_id()
    actualizar_licencias_vencidas(tenant_id)
    buscar = request.args.get('buscar', '').strip()
    fecha = request.args.get('fecha', '').strip()
    medico_id = validate_int(request.args.get('medico_id'), min_value=1, default=None)
    estado = request.args.get('estado', '').strip()
    orden = request.args.get('orden', 'recientes').strip()
    query = """
        SELECT l.*, p.nombre AS paciente_nombre, m.nombre AS medico_nombre,
               t.nombre AS tipo_licencia
        FROM licencias_medicas l
        JOIN pacientes p
          ON p.id=l.paciente_id AND p.tenant_id=l.tenant_id
        JOIN medicos m
          ON m.id=l.medico_id AND m.tenant_id=l.tenant_id
        JOIN tipos_licencia_medica t
          ON t.id=l.tipo_licencia_id AND t.tenant_id=l.tenant_id
        WHERE l.tenant_id=%s
    """
    params = [tenant_id]
    if buscar:
        patron = f'%{buscar}%'
        query += " AND (l.codigo LIKE %s OR p.nombre LIKE %s OR p.cedula LIKE %s OR l.diagnostico LIKE %s OR l.codigo_cie10 LIKE %s)"
        params.extend([patron] * 5)
    if fecha:
        query += " AND (l.fecha_emision=%s OR l.fecha_inicio=%s OR l.fecha_termino=%s)"
        params.extend([fecha, fecha, fecha])
    if medico_id:
        query += " AND l.medico_id=%s"
        params.append(medico_id)
    if estado in ['Borrador', 'Emitida', 'Anulada', 'Vencida']:
        query += " AND l.estado=%s"
        params.append(estado)
    ordenes = {
        'recientes': 'l.fecha_emision DESC, l.id DESC',
        'antiguas': 'l.fecha_emision ASC, l.id ASC',
        'paciente': 'p.nombre ASC, l.fecha_emision DESC',
        'medico': 'm.nombre ASC, l.fecha_emision DESC',
        'estado': 'l.estado ASC, l.fecha_emision DESC'
    }
    licencias, pagination = execute_paginated_query(
        query,
        params,
        ordenes.get(orden, ordenes['recientes']),
    )
    medicos = execute_query(
        "SELECT id, nombre FROM medicos WHERE tenant_id=%s AND activo=1 ORDER BY nombre",
        (tenant_id,), fetch='all'
    ) or []
    return render_template(
        'facturacion/licencias_medicas.html', licencias=licencias,
        medicos=medicos, filtros=request.args, pagination=pagination
    )


@app.route('/facturacion/licencias-medicas/nueva', methods=['GET', 'POST'])
@login_required
@roles_required('Administrador', 'Nivel 2')
@transactional_methods('POST')
def facturacion_licencias_medicas_nueva():
    tenant_id = get_current_tenant_id()
    paciente_preseleccionado = validate_int(
        request.args.get('paciente_id') or request.form.get('paciente_id'),
        min_value=1, default=None
    )
    contexto = contexto_formulario_licencia(tenant_id, paciente_preseleccionado)
    if request.method == 'POST':
        datos, error = validar_datos_licencia(tenant_id)
        if error:
            flash(error, 'error')
            return render_template(
                'facturacion/licencia_medica_form.html',
                licencia=None, form_data=request.form, **contexto
            )
        duplicada = execute_query(
            """
            SELECT id FROM licencias_medicas
            WHERE tenant_id=%s AND paciente_id=%s AND medico_id=%s
              AND fecha_inicio=%s AND fecha_termino=%s
              AND diagnostico=%s AND estado<>'Anulada'
            """,
            (tenant_id, datos['paciente_id'], datos['medico_id'],
             datos['fecha_inicio'], datos['fecha_termino'], datos['diagnostico'])
        )
        if duplicada:
            flash('Ya existe una licencia igual; se evitó crear un duplicado', 'error')
            return render_template(
                'facturacion/licencia_medica_form.html',
                licencia=None, form_data=request.form, **contexto
            )
        solapada = execute_query(
            """
            SELECT codigo, fecha_inicio, fecha_termino
            FROM licencias_medicas
            WHERE tenant_id=%s AND paciente_id=%s AND estado<>'Anulada'
              AND fecha_inicio<=%s AND fecha_termino>=%s
            LIMIT 1
            """,
            (tenant_id, datos['paciente_id'],
             datos['fecha_termino'], datos['fecha_inicio'])
        )
        if solapada and request.form.get('confirmar_solapamiento') != '1':
            flash(
                f"El período se solapa con {solapada['codigo']} "
                f"({solapada['fecha_inicio']} a {solapada['fecha_termino']}). "
                "Marque la confirmación para continuar.",
                'warning'
            )
            return render_template(
                'facturacion/licencia_medica_form.html',
                licencia=None, form_data=request.form,
                advertencia_solapamiento=True, **contexto
            )

        codigo = None
        while not codigo:
            candidato = f"LM-{datetime.now().strftime('%Y%m%d')}-{secrets.token_hex(3).upper()}"
            if not execute_query(
                "SELECT id FROM licencias_medicas WHERE tenant_id=%s AND codigo=%s",
                (tenant_id, candidato)
            ):
                codigo = candidato
        licencia_id = execute_update(
            """
            INSERT INTO licencias_medicas (
                tenant_id, codigo, paciente_id, medico_id, consulta_id,
                tipo_licencia_id, diagnostico, codigo_cie10, motivo_condicion,
                observaciones, fecha_emision, fecha_inicio, fecha_termino,
                cantidad_dias, estado, created_by, updated_by
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s
            )
            """,
            (
                tenant_id, codigo, datos['paciente_id'], datos['medico_id'],
                datos['consulta_id'], datos['tipo_id'], datos['diagnostico'],
                datos['cie10'], datos['motivo'], datos['observaciones'],
                datos['fecha_emision'], datos['fecha_inicio'],
                datos['fecha_termino'], datos['cantidad_dias'],
                datos['estado'], current_user.id, current_user.id
            )
        )
        execute_update(
            """
            INSERT INTO auditoria_licencias_medicas (
                tenant_id, licencia_id, usuario_id, accion, datos_nuevos,
                ip, user_agent
            ) VALUES (%s, %s, %s, 'Creación', %s, %s, %s)
            """,
            (
                tenant_id, licencia_id, current_user.id,
                json.dumps(datos, default=str, ensure_ascii=False),
                request.remote_addr, (request.user_agent.string or '')[:500]
            )
        )
        flash('Licencia médica registrada exitosamente', 'success')
        return redirect(url_for(
            'facturacion_licencia_medica_ver', licencia_id=licencia_id
        ))

    return render_template(
        'facturacion/licencia_medica_form.html', licencia=None,
        form_data={}, fecha_actual=datetime.now().strftime('%Y-%m-%d'),
        **contexto
    )


@app.route('/facturacion/licencias-medicas/<int:licencia_id>')
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_licencia_medica_ver(licencia_id):
    tenant_id = get_current_tenant_id()
    actualizar_licencias_vencidas(tenant_id)
    licencia = obtener_licencia_medica(licencia_id, tenant_id)
    if not licencia:
        flash('Licencia médica no encontrada', 'error')
        return redirect(url_for('facturacion_licencias_medicas'))
    licencia['edad'] = calcular_edad_clinica(
        licencia.get('fecha_nacimiento'), licencia['fecha_emision']
    )
    auditoria = execute_query(
        """
        SELECT a.*, u.nombre AS usuario_nombre
        FROM auditoria_licencias_medicas a
        LEFT JOIN usuarios u
          ON u.id=a.usuario_id AND u.tenant_id=a.tenant_id
        WHERE a.licencia_id=%s AND a.tenant_id=%s
        ORDER BY a.created_at DESC
        """,
        (licencia_id, tenant_id), fetch='all'
    ) or []
    return render_template(
        'facturacion/licencia_medica_ver.html',
        licencia=licencia, auditoria=auditoria, imprimir=False
    )


@app.route('/facturacion/licencias-medicas/<int:licencia_id>/editar', methods=['GET', 'POST'])
@login_required
@roles_required('Administrador', 'Nivel 2')
@transactional_methods('POST')
def facturacion_licencia_medica_editar(licencia_id):
    tenant_id = get_current_tenant_id()
    licencia = obtener_licencia_medica(licencia_id, tenant_id)
    if not licencia:
        flash('Licencia médica no encontrada', 'error')
        return redirect(url_for('facturacion_licencias_medicas'))
    if licencia['estado'] != 'Borrador':
        flash('Solo las licencias en borrador pueden editarse', 'warning')
        return redirect(url_for('facturacion_licencia_medica_ver', licencia_id=licencia_id))
    contexto = contexto_formulario_licencia(tenant_id, licencia['paciente_id'])
    if request.method == 'POST':
        datos, error = validar_datos_licencia(tenant_id)
        if error:
            flash(error, 'error')
            return render_template(
                'facturacion/licencia_medica_form.html',
                licencia=licencia, form_data=request.form, **contexto
            )
        solapada = execute_query(
            """
            SELECT codigo, fecha_inicio, fecha_termino
            FROM licencias_medicas
            WHERE tenant_id=%s AND paciente_id=%s AND id<>%s
              AND estado<>'Anulada' AND fecha_inicio<=%s AND fecha_termino>=%s
            LIMIT 1
            """,
            (tenant_id, datos['paciente_id'], licencia_id,
             datos['fecha_termino'], datos['fecha_inicio'])
        )
        if solapada and request.form.get('confirmar_solapamiento') != '1':
            flash('Existe otra licencia que se solapa con este período', 'warning')
            return render_template(
                'facturacion/licencia_medica_form.html',
                licencia=licencia, form_data=request.form,
                advertencia_solapamiento=True, **contexto
            )
        anterior = json.dumps(licencia, default=str, ensure_ascii=False)
        version = licencia['version']
        execute_update(
            """
            UPDATE licencias_medicas SET
                paciente_id=%s, medico_id=%s, consulta_id=%s,
                tipo_licencia_id=%s, diagnostico=%s, codigo_cie10=%s,
                motivo_condicion=%s, observaciones=%s, fecha_emision=%s,
                fecha_inicio=%s, fecha_termino=%s, cantidad_dias=%s,
                estado=%s, version=version+1, updated_by=%s
            WHERE id=%s AND tenant_id=%s AND estado='Borrador'
            """,
            (
                datos['paciente_id'], datos['medico_id'], datos['consulta_id'],
                datos['tipo_id'], datos['diagnostico'], datos['cie10'],
                datos['motivo'], datos['observaciones'], datos['fecha_emision'],
                datos['fecha_inicio'], datos['fecha_termino'],
                datos['cantidad_dias'], datos['estado'], current_user.id,
                licencia_id, tenant_id
            )
        )
        nueva = execute_query(
            "SELECT * FROM licencias_medicas WHERE id=%s AND tenant_id=%s",
            (licencia_id, tenant_id)
        )
        execute_update(
            """
            INSERT INTO auditoria_licencias_medicas (
                tenant_id, licencia_id, usuario_id, accion, version_anterior,
                datos_anteriores, datos_nuevos, ip, user_agent
            ) VALUES (%s, %s, %s, 'Modificación', %s, %s, %s, %s, %s)
            """,
            (
                tenant_id, licencia_id, current_user.id, version, anterior,
                json.dumps(nueva, default=str, ensure_ascii=False),
                request.remote_addr, (request.user_agent.string or '')[:500]
            )
        )
        flash('Licencia médica actualizada con trazabilidad', 'success')
        return redirect(url_for(
            'facturacion_licencia_medica_ver', licencia_id=licencia_id
        ))
    return render_template(
        'facturacion/licencia_medica_form.html', licencia=licencia,
        form_data=licencia, **contexto
    )


@app.route('/facturacion/licencias-medicas/<int:licencia_id>/anular', methods=['POST'])
@login_required
@roles_required('Administrador', 'Nivel 2')
@transactional_methods('POST')
def facturacion_licencia_medica_anular(licencia_id):
    tenant_id = get_current_tenant_id()
    licencia = obtener_licencia_medica(licencia_id, tenant_id)
    motivo = sanitize_input(request.form.get('motivo_anulacion', ''), 2000)
    if not licencia:
        flash('Licencia médica no encontrada', 'error')
        return redirect(url_for('facturacion_licencias_medicas'))
    if licencia['estado'] == 'Anulada':
        flash('La licencia ya está anulada', 'warning')
        return redirect(url_for('facturacion_licencia_medica_ver', licencia_id=licencia_id))
    if not motivo:
        flash('Debe indicar el motivo de la anulación', 'error')
        return redirect(url_for('facturacion_licencia_medica_ver', licencia_id=licencia_id))
    execute_update(
        """
        UPDATE licencias_medicas
        SET estado='Anulada', anulado_por=%s, fecha_anulacion=NOW(),
            motivo_anulacion=%s, updated_by=%s, version=version+1
        WHERE id=%s AND tenant_id=%s
        """,
        (current_user.id, motivo, current_user.id, licencia_id, tenant_id)
    )
    execute_update(
        """
        INSERT INTO auditoria_licencias_medicas (
            tenant_id, licencia_id, usuario_id, accion, version_anterior,
            datos_anteriores, motivo, ip, user_agent
        ) VALUES (%s, %s, %s, 'Anulación', %s, %s, %s, %s, %s)
        """,
        (
            tenant_id, licencia_id, current_user.id, licencia['version'],
            json.dumps(licencia, default=str, ensure_ascii=False), motivo,
            request.remote_addr, (request.user_agent.string or '')[:500]
        )
    )
    flash('Licencia anulada; el documento permanece en el historial', 'success')
    return redirect(url_for('facturacion_licencia_medica_ver', licencia_id=licencia_id))


@app.route('/facturacion/licencias-medicas/<int:licencia_id>/imprimir')
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_licencia_medica_imprimir(licencia_id):
    licencia = obtener_licencia_medica(licencia_id, get_current_tenant_id())
    if not licencia:
        flash('Licencia médica no encontrada', 'error')
        return redirect(url_for('facturacion_licencias_medicas'))
    licencia['edad'] = calcular_edad_clinica(
        licencia.get('fecha_nacimiento'), licencia['fecha_emision']
    )
    return render_template(
        'facturacion/licencia_medica_ver.html',
        licencia=licencia, auditoria=[], imprimir=True
    )


@app.route('/facturacion/tipos-licencia-medica', methods=['GET', 'POST'])
@login_required
@roles_required('Administrador')
def facturacion_tipos_licencia_medica():
    if current_user.perfil != 'Administrador':
        flash('Solo los administradores pueden configurar tipos de licencia', 'error')
        return redirect(url_for('facturacion_licencias_medicas'))
    tenant_id = get_current_tenant_id()
    if request.method == 'POST':
        nombre = sanitize_input(request.form.get('nombre', ''), 120)
        if not nombre:
            flash('El nombre del tipo es obligatorio', 'error')
        elif execute_query(
            "SELECT id FROM tipos_licencia_medica WHERE tenant_id=%s AND nombre=%s",
            (tenant_id, nombre)
        ):
            flash('Ya existe un tipo de licencia con ese nombre', 'error')
        else:
            execute_update(
                "INSERT INTO tipos_licencia_medica "
                "(tenant_id, nombre, created_by, updated_by) VALUES (%s,%s,%s,%s)",
                (tenant_id, nombre, current_user.id, current_user.id)
            )
            flash('Tipo de licencia agregado', 'success')
        return redirect(url_for('facturacion_tipos_licencia_medica'))
    tipos = execute_query(
        "SELECT * FROM tipos_licencia_medica WHERE tenant_id=%s ORDER BY nombre",
        (tenant_id,), fetch='all'
    ) or []
    return render_template('facturacion/tipos_licencia_medica.html', tipos=tipos)


@app.route('/facturacion/tipos-licencia-medica/<int:tipo_id>/actualizar', methods=['POST'])
@login_required
@roles_required('Administrador')
def facturacion_tipo_licencia_medica_actualizar(tipo_id):
    if current_user.perfil != 'Administrador':
        flash('No tiene permisos para esta acción', 'error')
        return redirect(url_for('facturacion_licencias_medicas'))
    tenant_id = get_current_tenant_id()
    tipo = execute_query(
        "SELECT id FROM tipos_licencia_medica WHERE id=%s AND tenant_id=%s",
        (tipo_id, tenant_id)
    )
    if not tipo:
        flash('Tipo de licencia no encontrado', 'error')
        return redirect(url_for('facturacion_tipos_licencia_medica'))
    nombre = sanitize_input(request.form.get('nombre', ''), 120)
    activo = 1 if request.form.get('activo') == '1' else 0
    if not nombre:
        flash('El nombre es obligatorio', 'error')
    else:
        duplicado = execute_query(
            "SELECT id FROM tipos_licencia_medica "
            "WHERE tenant_id=%s AND nombre=%s AND id<>%s",
            (tenant_id, nombre, tipo_id)
        )
        if duplicado:
            flash('Ya existe otro tipo con ese nombre', 'error')
        else:
            execute_update(
                "UPDATE tipos_licencia_medica SET nombre=%s, activo=%s, "
                "updated_by=%s WHERE id=%s AND tenant_id=%s",
                (nombre, activo, current_user.id, tipo_id, tenant_id)
            )
            flash('Tipo de licencia actualizado', 'success')
    return redirect(url_for('facturacion_tipos_licencia_medica'))


def obtener_receta_medica(receta_id, tenant_id):
    receta = execute_query('''
        SELECT r.*, p.nombre AS paciente_nombre, p.cedula,
               p.fecha_nacimiento, p.telefono, p.direccion,
               m.nombre AS medico_nombre, m.especialidad, m.exequatur,
               c.fecha AS consulta_fecha
        FROM recetas_medicas r
        JOIN pacientes p ON p.id=r.paciente_id AND p.tenant_id=r.tenant_id
        JOIN medicos m ON m.id=r.medico_id AND m.tenant_id=r.tenant_id
        LEFT JOIN consultas_clinicas c
          ON c.id=r.consulta_id AND c.tenant_id=r.tenant_id
        WHERE r.id=%s AND r.tenant_id=%s
    ''', (receta_id, tenant_id))
    if receta:
        receta['medicamentos'] = execute_query('''
            SELECT * FROM receta_medicamentos
            WHERE receta_id=%s AND tenant_id=%s
            ORDER BY orden, id
        ''', (receta_id, tenant_id), fetch='all') or []
    return receta


@app.route('/facturacion/recetas-medicas')
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_recetas_medicas():
    tenant_id = get_current_tenant_id()
    buscar = request.args.get('buscar', '').strip()
    paciente_id = validate_int(
        request.args.get('paciente_id'), min_value=1, default=None
    )
    medico_id = validate_int(
        request.args.get('medico_id'), min_value=1, default=None
    )
    estado = request.args.get('estado', '').strip()
    query = '''
        SELECT r.id, r.codigo, r.fecha, r.diagnostico, r.estado,
               p.nombre AS paciente_nombre, m.nombre AS medico_nombre,
               COUNT(rm.id) AS total_medicamentos
        FROM recetas_medicas r
        JOIN pacientes p ON p.id=r.paciente_id AND p.tenant_id=r.tenant_id
        JOIN medicos m ON m.id=r.medico_id AND m.tenant_id=r.tenant_id
        LEFT JOIN receta_medicamentos rm
          ON rm.receta_id=r.id AND rm.tenant_id=r.tenant_id
        WHERE r.tenant_id=%s
    '''
    params = [tenant_id]
    if buscar:
        patron = f'%{buscar}%'
        query += (
            ' AND (r.codigo LIKE %s OR p.nombre LIKE %s OR p.cedula LIKE %s '
            'OR m.nombre LIKE %s OR r.diagnostico LIKE %s '
            'OR EXISTS (SELECT 1 FROM receta_medicamentos busqueda '
            'WHERE busqueda.receta_id=r.id AND busqueda.tenant_id=r.tenant_id '
            'AND busqueda.medicamento LIKE %s))'
        )
        params.extend([patron] * 6)
    if paciente_id:
        query += ' AND r.paciente_id=%s'
        params.append(paciente_id)
    if medico_id:
        query += ' AND r.medico_id=%s'
        params.append(medico_id)
    if estado in ['Emitida', 'Anulada']:
        query += ' AND r.estado=%s'
        params.append(estado)
    query += ' GROUP BY r.id'
    recetas, pagination = execute_paginated_query(
        query,
        params,
        'r.fecha DESC, r.id DESC',
    )
    pacientes = execute_query(
        'SELECT id, nombre FROM pacientes WHERE tenant_id=%s ORDER BY nombre',
        (tenant_id,), fetch='all'
    ) or []
    medicos = execute_query(
        'SELECT id, nombre FROM medicos WHERE tenant_id=%s AND activo=1 ORDER BY nombre',
        (tenant_id,), fetch='all'
    ) or []
    return render_template(
        'facturacion/recetas_medicas.html',
        recetas=recetas, pacientes=pacientes, medicos=medicos,
        filtros=request.args, pagination=pagination
    )


@app.route('/facturacion/recetas-medicas/nueva', methods=['GET', 'POST'])
@login_required
@roles_required('Administrador', 'Nivel 2')
@transactional_methods('POST')
def facturacion_recetas_medicas_nueva():
    tenant_id = get_current_tenant_id()
    consulta_id = validate_int(
        request.args.get('consulta_id') or request.form.get('consulta_id'),
        min_value=1, default=None
    )
    consulta = None
    if consulta_id:
        consulta = execute_query('''
            SELECT c.id, c.paciente_id, c.medico_id, c.fecha,
                   c.diagnostico_principal, c.codigo_cie10,
                   p.nombre AS paciente_nombre
            FROM consultas_clinicas c
            JOIN pacientes p ON p.id=c.paciente_id AND p.tenant_id=c.tenant_id
            WHERE c.id=%s AND c.tenant_id=%s
        ''', (consulta_id, tenant_id))
        if not consulta:
            flash('La consulta seleccionada no existe', 'error')
            return redirect(url_for('facturacion_recetas_medicas'))
    paciente_preseleccionado = validate_int(
        request.args.get('paciente_id') or request.form.get('paciente_id'),
        min_value=1, default=None
    )
    if consulta:
        paciente_preseleccionado = consulta['paciente_id']
    pacientes = execute_query(
        'SELECT id, nombre, cedula, fecha_nacimiento FROM pacientes '
        'WHERE tenant_id=%s ORDER BY nombre',
        (tenant_id,), fetch='all'
    ) or []
    medicos = execute_query(
        'SELECT id, nombre, especialidad FROM medicos '
        'WHERE tenant_id=%s AND activo=1 ORDER BY nombre',
        (tenant_id,), fetch='all'
    ) or []
    consultas = execute_query('''
        SELECT c.id, c.paciente_id, c.medico_id, c.fecha,
               c.diagnostico_principal, c.codigo_cie10, m.nombre AS medico_nombre
        FROM consultas_clinicas c
        JOIN medicos m ON m.id=c.medico_id AND m.tenant_id=c.tenant_id
        WHERE c.tenant_id=%s
        ORDER BY c.fecha DESC, c.id DESC LIMIT 300
    ''', (tenant_id,), fetch='all') or []
    if request.method == 'POST':
        paciente_id = validate_int(
            request.form.get('paciente_id'), min_value=1, default=None
        )
        medico_id = validate_int(
            request.form.get('medico_id'), min_value=1, default=None
        )
        fecha = request.form.get('fecha', '').strip()
        diagnostico = sanitize_input(request.form.get('diagnostico', ''), 5000)
        codigo_cie10 = sanitize_input(
            request.form.get('codigo_cie10', ''), 30
        ).upper()
        indicaciones_generales = sanitize_input(
            request.form.get('indicaciones_generales', ''), 5000
        )
        try:
            fecha_obj = datetime.strptime(fecha, '%Y-%m-%d').date()
        except ValueError:
            fecha_obj = None
        paciente = execute_query(
            'SELECT id FROM pacientes WHERE id=%s AND tenant_id=%s',
            (paciente_id, tenant_id)
        ) if paciente_id else None
        medico = execute_query(
            'SELECT id FROM medicos WHERE id=%s AND tenant_id=%s AND activo=1',
            (medico_id, tenant_id)
        ) if medico_id else None
        if not paciente or not medico or not fecha_obj:
            flash('Paciente, médico y fecha son obligatorios', 'error')
        elif fecha_obj > datetime.now().date():
            flash('La fecha de emisión no puede ser futura', 'error')
        elif consulta and (
            consulta['paciente_id'] != paciente_id
            or consulta['medico_id'] != medico_id
        ):
            flash('El paciente y médico deben coincidir con la Historia Clínica', 'error')
        else:
            nombres = request.form.getlist('medicamento[]')
            presentaciones = request.form.getlist('presentacion[]')
            dosis = request.form.getlist('dosis[]')
            vias = request.form.getlist('via[]')
            frecuencias = request.form.getlist('frecuencia[]')
            duraciones = request.form.getlist('duracion[]')
            cantidades = request.form.getlist('cantidad[]')
            indicaciones = request.form.getlist('indicaciones[]')
            medicamentos = []
            for indice, nombre in enumerate(nombres):
                nombre = sanitize_input(nombre, 250)
                if not nombre:
                    continue
                dosis_item = sanitize_input(
                    dosis[indice] if indice < len(dosis) else '', 150
                )
                frecuencia = sanitize_input(
                    frecuencias[indice] if indice < len(frecuencias) else '', 150
                )
                duracion = sanitize_input(
                    duraciones[indice] if indice < len(duraciones) else '', 150
                )
                if not all([dosis_item, frecuencia, duracion]):
                    medicamentos = []
                    flash(
                        'Cada medicamento requiere dosis, frecuencia y duración',
                        'error'
                    )
                    break
                medicamentos.append({
                    'medicamento': nombre,
                    'presentacion': sanitize_input(
                        presentaciones[indice] if indice < len(presentaciones) else '', 150
                    ),
                    'dosis': dosis_item,
                    'via': sanitize_input(
                        vias[indice] if indice < len(vias) else '', 100
                    ),
                    'frecuencia': frecuencia,
                    'duracion': duracion,
                    'cantidad': sanitize_input(
                        cantidades[indice] if indice < len(cantidades) else '', 100
                    ),
                    'indicaciones': sanitize_input(
                        indicaciones[indice] if indice < len(indicaciones) else '', 2000
                    )
                })
            if medicamentos:
                codigo_temporal = f"TMP-{secrets.token_hex(8)}"
                receta_id = execute_update('''
                    INSERT INTO recetas_medicas (
                        tenant_id, codigo, paciente_id, medico_id, consulta_id,
                        fecha, diagnostico, codigo_cie10,
                        indicaciones_generales, estado, created_by
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,'Emitida',%s)
                ''', (
                    tenant_id, codigo_temporal, paciente_id, medico_id,
                    consulta_id, fecha_obj, diagnostico or None,
                    codigo_cie10 or None, indicaciones_generales or None,
                    current_user.id
                ))
                codigo = f"REC-{fecha_obj.year}-{receta_id:06d}"
                execute_update(
                    'UPDATE recetas_medicas SET codigo=%s '
                    'WHERE id=%s AND tenant_id=%s',
                    (codigo, receta_id, tenant_id)
                )
                for orden, item in enumerate(medicamentos, 1):
                    execute_update('''
                        INSERT INTO receta_medicamentos (
                            tenant_id, receta_id, medicamento, presentacion,
                            dosis, via, frecuencia, duracion, cantidad,
                            indicaciones, orden
                        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ''', (
                        tenant_id, receta_id, item['medicamento'],
                        item['presentacion'] or None, item['dosis'],
                        item['via'] or None, item['frecuencia'],
                        item['duracion'], item['cantidad'] or None,
                        item['indicaciones'] or None, orden
                    ))
                flash('Receta médica emitida correctamente', 'success')
                return redirect(url_for(
                    'facturacion_receta_medica_ver', receta_id=receta_id
                ))
        form_data = request.form
    else:
        form_data = {}
    return render_template(
        'facturacion/receta_medica_form.html',
        pacientes=pacientes, medicos=medicos, consultas=consultas,
        consulta=consulta, paciente_preseleccionado=paciente_preseleccionado,
        form_data=form_data, fecha_actual=datetime.now().strftime('%Y-%m-%d')
    )


@app.route('/facturacion/recetas-medicas/<int:receta_id>')
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_receta_medica_ver(receta_id):
    receta = obtener_receta_medica(receta_id, get_current_tenant_id())
    if not receta:
        flash('Receta médica no encontrada', 'error')
        return redirect(url_for('facturacion_recetas_medicas'))
    receta['edad'] = calcular_edad_clinica(
        receta.get('fecha_nacimiento'), receta['fecha']
    )
    return render_template(
        'facturacion/receta_medica_ver.html', receta=receta, imprimir=False
    )


@app.route('/facturacion/recetas-medicas/<int:receta_id>/imprimir')
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_receta_medica_imprimir(receta_id):
    receta = obtener_receta_medica(receta_id, get_current_tenant_id())
    if not receta:
        flash('Receta médica no encontrada', 'error')
        return redirect(url_for('facturacion_recetas_medicas'))
    receta['edad'] = calcular_edad_clinica(
        receta.get('fecha_nacimiento'), receta['fecha']
    )
    return render_template(
        'facturacion/receta_medica_ver.html', receta=receta, imprimir=True
    )


@app.route('/facturacion/recetas-medicas/<int:receta_id>/anular', methods=['POST'])
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_receta_medica_anular(receta_id):
    tenant_id = get_current_tenant_id()
    receta = execute_query(
        'SELECT id, estado FROM recetas_medicas WHERE id=%s AND tenant_id=%s',
        (receta_id, tenant_id)
    )
    motivo = sanitize_input(request.form.get('motivo_anulacion', ''), 2000)
    if not receta:
        flash('Receta médica no encontrada', 'error')
        return redirect(url_for('facturacion_recetas_medicas'))
    if receta['estado'] == 'Anulada':
        flash('La receta ya está anulada', 'warning')
    elif not motivo:
        flash('Indique el motivo de anulación', 'error')
    else:
        execute_update('''
            UPDATE recetas_medicas SET estado='Anulada', anulada_por=%s,
                fecha_anulacion=NOW(), motivo_anulacion=%s
            WHERE id=%s AND tenant_id=%s
        ''', (current_user.id, motivo, receta_id, tenant_id))
        flash('Receta anulada; permanece en el historial', 'success')
    return redirect(url_for(
        'facturacion_receta_medica_ver', receta_id=receta_id
    ))


@app.route('/facturacion/historias-emergencia')
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_historias_emergencia():
    """Listado de historias clínicas de emergencia del tenant."""
    tenant_id = get_current_tenant_id()
    historias = execute_query('''
        SELECT id, fecha, hora_servicio, nombre_paciente, edad, sexo,
               motivo_emergencia, estatus_paciente, medico_nombre
        FROM historias_emergencia
        WHERE tenant_id = %s
        ORDER BY fecha DESC, hora_servicio DESC, id DESC
    ''', (tenant_id,), fetch='all') or []
    return render_template(
        'facturacion/historias_emergencia.html',
        historias=historias
    )


@app.route('/facturacion/historias-emergencia/nueva', methods=['GET', 'POST'])
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_historias_emergencia_nueva():
    """Registrar una historia clínica de emergencia."""
    tenant_id = get_current_tenant_id()

    if request.method == 'POST':
        paciente_id = request.form.get('paciente_id', '').strip()
        medico_id = request.form.get('medico_id', '').strip()
        fecha = request.form.get('fecha', '').strip()
        hora_servicio = request.form.get('hora_servicio', '').strip()
        autorizacion = sanitize_input(request.form.get('autorizacion', ''), 100)
        numero_afiliado = sanitize_input(request.form.get('numero_afiliado', ''), 100)
        edad = validate_int(request.form.get('edad'), min_value=0, max_value=130, default=None)
        sexo_historia = request.form.get('sexo_historia', '').strip()
        motivo = sanitize_input(request.form.get('motivo_emergencia', ''), 4000)
        historia_actual = sanitize_input(request.form.get('historia_enfermedad', ''), 8000)
        diagnostico = sanitize_input(request.form.get('diagnostico_impresion', ''), 4000)
        estatus = request.form.get('estatus_paciente', '').strip()
        origen = request.form.get('origen_enfermedad', '').strip()
        observaciones = sanitize_input(request.form.get('observaciones', ''), 4000)

        if (not all([paciente_id, medico_id, fecha, hora_servicio, sexo_historia,
                     motivo, historia_actual, diagnostico, estatus, origen])
                or edad is None):
            flash('Complete todos los campos obligatorios de la historia', 'error')
            return redirect(url_for('facturacion_historias_emergencia_nueva'))

        paciente = execute_query('''
            SELECT p.*, a.nombre AS ars_nombre
            FROM pacientes p
            LEFT JOIN ars a
              ON p.ars_id = a.id AND a.tenant_id = p.tenant_id
            WHERE p.id = %s AND p.tenant_id = %s
        ''', (paciente_id, tenant_id))
        medico = execute_query(
            'SELECT id, nombre FROM medicos WHERE id = %s AND tenant_id = %s AND activo = 1',
            (medico_id, tenant_id)
        )
        if not paciente or not medico:
            flash('El paciente o médico seleccionado no es válido', 'error')
            return redirect(url_for('facturacion_historias_emergencia_nueva'))
        if paciente_adulto_sin_cedula(paciente):
            flash('Debe actualizar la cédula propia del paciente antes de registrar la emergencia', 'warning')
            return redirect(url_for('facturacion_paciente_acciones', paciente_id=paciente['id']))

        try:
            datetime.strptime(fecha, '%Y-%m-%d')
            datetime.strptime(hora_servicio, '%H:%M')
        except ValueError:
            flash('La fecha o la hora del servicio no es válida', 'error')
            return redirect(url_for('facturacion_historias_emergencia_nueva'))

        estatus_validos = ['Dado de alta', 'Referido', 'Alta a petición', 'Admitido', 'Fallecido']
        origenes_validos = ['Enfermedad común', 'Accidente de tránsito', 'Maternidad', 'Accidente laboral']
        if (estatus not in estatus_validos or origen not in origenes_validos
                or sexo_historia not in ['M', 'F', 'Otro']):
            flash('Seleccione un estatus y origen válidos', 'error')
            return redirect(url_for('facturacion_historias_emergencia_nueva'))

        pruebas_validas = {'Hemograma', 'Examen de orina', 'HCG suero', 'Glucosa',
                           'Radiografía', 'Sonografía', 'EKG'}
        manejos_validos = {'Hidratación', 'Nebulizaciones', 'RCP', 'Cura',
                           'Inmovilización', 'Oxígeno', 'Sutura'}
        pruebas = [valor for valor in request.form.getlist('pruebas')
                   if valor in pruebas_validas]
        manejos = [valor for valor in request.form.getlist('manejos')
                   if valor in manejos_validos]

        datos_clinicos = {
            'atenciones_previas': request.form.get('atenciones_previas') == 'si',
            'atenciones_previas_donde': sanitize_input(request.form.get('atenciones_previas_donde', ''), 500),
            'alergias': request.form.get('alergias') == 'si',
            'alergias_detalle': sanitize_input(request.form.get('alergias_detalle', ''), 500),
            'antecedentes': sanitize_input(request.form.get('antecedentes', ''), 2000),
            'hallazgos_examen': sanitize_input(request.form.get('hallazgos_examen', ''), 4000),
            'ta': sanitize_input(request.form.get('ta', ''), 30),
            'fc': sanitize_input(request.form.get('fc', ''), 30),
            'fr': sanitize_input(request.form.get('fr', ''), 30),
            'temperatura': sanitize_input(request.form.get('temperatura', ''), 30),
            'pruebas': pruebas,
            'otras_pruebas': sanitize_input(request.form.get('otras_pruebas', ''), 500),
            'manejos': manejos,
            'oxigeno_inicio': sanitize_input(request.form.get('oxigeno_inicio', ''), 20),
            'oxigeno_final': sanitize_input(request.form.get('oxigeno_final', ''), 20),
            'oxigeno_total_hora': sanitize_input(request.form.get('oxigeno_total_hora', ''), 50),
            'medicamentos': sanitize_input(request.form.get('medicamentos', ''), 4000)
        }

        historia_id = execute_update('''
            INSERT INTO historias_emergencia (
                tenant_id, paciente_id, medico_id, fecha, hora_servicio, autorizacion,
                nombre_paciente, edad, sexo, ars_nombre, numero_afiliado, nss,
                motivo_emergencia, historia_enfermedad, datos_clinicos,
                diagnostico_impresion, estatus_paciente, origen_enfermedad,
                observaciones, medico_nombre, created_by
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
        ''', (
            tenant_id, paciente['id'], medico['id'], fecha, hora_servicio,
            autorizacion or None, paciente['nombre'], edad, sexo_historia,
            paciente.get('ars_nombre'), numero_afiliado or None, paciente.get('nss'),
            motivo, historia_actual, json.dumps(datos_clinicos, ensure_ascii=False),
            diagnostico, estatus, origen, observaciones or None, medico['nombre'],
            current_user.id
        ))
        flash('Historia de emergencia registrada exitosamente', 'success')
        return redirect(url_for('facturacion_historia_emergencia_ver', historia_id=historia_id))

    pacientes = execute_query('''
        SELECT p.id, p.nombre, p.fecha_nacimiento, p.sexo, p.cedula, p.nss,
               p.ars_id, a.nombre AS ars_nombre
        FROM pacientes p
        LEFT JOIN ars a
          ON p.ars_id = a.id AND a.tenant_id = p.tenant_id
        WHERE p.tenant_id = %s
        ORDER BY p.nombre
    ''', (tenant_id,), fetch='all') or []
    medicos = execute_query(
        'SELECT id, nombre FROM medicos WHERE tenant_id = %s AND activo = 1 ORDER BY nombre',
        (tenant_id,), fetch='all'
    ) or []
    paciente_preseleccionado = validate_int(
        request.args.get('paciente_id'), min_value=1, default=None
    )
    if not any(paciente['id'] == paciente_preseleccionado for paciente in pacientes):
        paciente_preseleccionado = None
    if paciente_preseleccionado:
        paciente_seleccionado = next(
            paciente for paciente in pacientes
            if paciente['id'] == paciente_preseleccionado
        )
        if paciente_adulto_sin_cedula(paciente_seleccionado):
            flash('Debe actualizar la cédula propia del paciente antes de registrar la emergencia', 'warning')
            return redirect(url_for(
                'facturacion_paciente_acciones',
                paciente_id=paciente_preseleccionado
            ))
    return render_template(
        'facturacion/historia_emergencia_form.html',
        pacientes=pacientes,
        medicos=medicos,
        paciente_preseleccionado=paciente_preseleccionado,
        fecha_actual=datetime.now().strftime('%Y-%m-%d'),
        hora_actual=datetime.now().strftime('%H:%M')
    )


def obtener_historia_emergencia(historia_id, tenant_id):
    historia = execute_query(
        'SELECT * FROM historias_emergencia WHERE id = %s AND tenant_id = %s',
        (historia_id, tenant_id)
    )
    if historia:
        try:
            historia['datos'] = json.loads(historia.get('datos_clinicos') or '{}')
        except (TypeError, ValueError):
            historia['datos'] = {}
    return historia


@app.route('/facturacion/historias-emergencia/<int:historia_id>')
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_historia_emergencia_ver(historia_id):
    historia = obtener_historia_emergencia(historia_id, get_current_tenant_id())
    if not historia:
        flash('Historia de emergencia no encontrada', 'error')
        return redirect(url_for('facturacion_historias_emergencia'))
    return render_template('facturacion/historia_emergencia_ver.html', historia=historia, imprimir=False)


@app.route('/facturacion/historias-emergencia/<int:historia_id>/imprimir')
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_historia_emergencia_imprimir(historia_id):
    historia = obtener_historia_emergencia(historia_id, get_current_tenant_id())
    if not historia:
        flash('Historia de emergencia no encontrada', 'error')
        return redirect(url_for('facturacion_historias_emergencia'))
    return render_template('facturacion/historia_emergencia_ver.html', historia=historia, imprimir=True)


@app.route('/facturacion/hojas-enfermeria')
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_hojas_enfermeria():
    """Listado de medicamentos y materiales suministrados en emergencia."""
    tenant_id = get_current_tenant_id()
    buscar = request.args.get('buscar', '').strip()
    query = '''
        SELECT h.id, h.fecha_servicio, h.hora_servicio, h.nombre_paciente,
               h.responsable, h.firma_responsable
        FROM hojas_enfermeria h
        WHERE h.tenant_id=%s
    '''
    params = [tenant_id]
    if buscar:
        patron = f'%{buscar}%'
        query += ' AND (h.nombre_paciente LIKE %s OR h.responsable LIKE %s)'
        params.extend([patron, patron])
    query += ' ORDER BY h.fecha_servicio DESC, h.hora_servicio DESC, h.id DESC'
    hojas = execute_query(query, tuple(params), fetch='all') or []
    return render_template(
        'facturacion/hojas_enfermeria.html',
        hojas=hojas,
        buscar=buscar
    )


@app.route('/facturacion/hojas-enfermeria/nueva', methods=['GET', 'POST'])
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_hojas_enfermeria_nueva():
    """Registrar una hoja de enfermería asociada a un paciente."""
    tenant_id = get_current_tenant_id()
    pacientes = execute_query('''
        SELECT p.id, p.nombre, p.fecha_nacimiento, p.sexo, p.direccion,
               p.nombre_pariente, p.telefono_pariente, a.nombre AS ars_nombre
        FROM pacientes p
        LEFT JOIN ars a ON a.id=p.ars_id AND a.tenant_id=p.tenant_id
        WHERE p.tenant_id=%s
        ORDER BY p.nombre
    ''', (tenant_id,), fetch='all') or []
    emergencias = execute_query('''
        SELECT id, paciente_id, fecha, motivo_emergencia
        FROM historias_emergencia
        WHERE tenant_id=%s
        ORDER BY fecha DESC, id DESC
    ''', (tenant_id,), fetch='all') or []
    paciente_preseleccionado = validate_int(
        request.args.get('paciente_id') or request.form.get('paciente_id'),
        min_value=1, default=None
    )

    if request.method == 'POST':
        paciente_id = validate_int(request.form.get('paciente_id'), min_value=1, default=None)
        emergencia_id = validate_int(
            request.form.get('historia_emergencia_id'), min_value=1, default=None
        )
        fecha_servicio = request.form.get('fecha_servicio', '').strip()
        hora_servicio = request.form.get('hora_servicio', '').strip()
        responsable = sanitize_input(request.form.get('responsable', ''), 200)
        telefono = re.sub(r'\D', '', request.form.get('telefono_responsable', ''))
        observaciones = sanitize_input(request.form.get('observaciones', ''), 3000)
        firma = sanitize_input(request.form.get('firma_responsable', ''), 200)

        paciente = execute_query('''
            SELECT p.*, a.nombre AS ars_nombre
            FROM pacientes p
            LEFT JOIN ars a ON a.id=p.ars_id AND a.tenant_id=p.tenant_id
            WHERE p.id=%s AND p.tenant_id=%s
        ''', (paciente_id, tenant_id)) if paciente_id else None
        if not paciente or not all([
            fecha_servicio, hora_servicio, responsable, telefono, firma
        ]):
            flash('Complete todos los datos obligatorios de la hoja', 'error')
            return render_template(
                'facturacion/hoja_enfermeria_form.html',
                pacientes=pacientes, emergencias=emergencias,
                paciente_preseleccionado=paciente_preseleccionado,
                fecha_actual=fecha_servicio, hora_actual=hora_servicio
            )
        if not validate_digits(telefono, 10):
            flash('El teléfono del responsable debe contener exactamente 10 números', 'error')
            return render_template(
                'facturacion/hoja_enfermeria_form.html',
                pacientes=pacientes, emergencias=emergencias,
                paciente_preseleccionado=paciente_id,
                fecha_actual=fecha_servicio, hora_actual=hora_servicio
            )
        try:
            fecha_obj = datetime.strptime(fecha_servicio, '%Y-%m-%d').date()
            datetime.strptime(hora_servicio, '%H:%M')
        except ValueError:
            flash('La fecha u hora del servicio no es válida', 'error')
            return render_template(
                'facturacion/hoja_enfermeria_form.html',
                pacientes=pacientes, emergencias=emergencias,
                paciente_preseleccionado=paciente_id,
                fecha_actual=fecha_servicio, hora_actual=hora_servicio
            )
        if emergencia_id:
            emergencia = execute_query(
                'SELECT id FROM historias_emergencia '
                'WHERE id=%s AND paciente_id=%s AND tenant_id=%s',
                (emergencia_id, paciente_id, tenant_id)
            )
            if not emergencia:
                flash('La historia de emergencia no pertenece al paciente', 'error')
                return redirect(url_for(
                    'facturacion_hojas_enfermeria_nueva',
                    paciente_id=paciente_id
                ))

        items = request.form.getlist('item[]')
        fechas = request.form.getlist('fecha_linea[]')
        horas = request.form.getlist('hora_linea[]')
        cantidades = request.form.getlist('cantidad[]')
        dosis_vias = request.form.getlist('dosis_via[]')
        notas = request.form.getlist('notas[]')
        responsables_linea = request.form.getlist('responsable_linea[]')
        suministros = []
        for indice, item_raw in enumerate(items):
            item = sanitize_input(item_raw, 500)
            if not item:
                continue
            fecha_linea = fechas[indice] if indice < len(fechas) else fecha_servicio
            hora_linea = horas[indice] if indice < len(horas) else hora_servicio
            try:
                datetime.strptime(fecha_linea, '%Y-%m-%d')
                datetime.strptime(hora_linea, '%H:%M')
            except ValueError:
                flash('Revise las fechas y horas de los suministros', 'error')
                return redirect(url_for(
                    'facturacion_hojas_enfermeria_nueva',
                    paciente_id=paciente_id
                ))
            suministros.append({
                'fecha': fecha_linea,
                'hora': hora_linea,
                'item': item,
                'cantidad': sanitize_input(
                    cantidades[indice] if indice < len(cantidades) else '', 100
                ),
                'dosis_via': sanitize_input(
                    dosis_vias[indice] if indice < len(dosis_vias) else '', 200
                ),
                'notas': sanitize_input(
                    notas[indice] if indice < len(notas) else '', 500
                ),
                'responsable': sanitize_input(
                    responsables_linea[indice]
                    if indice < len(responsables_linea) else responsable,
                    200
                )
            })
        if not suministros:
            flash('Agregue al menos un medicamento o material suministrado', 'error')
            return redirect(url_for(
                'facturacion_hojas_enfermeria_nueva',
                paciente_id=paciente_id
            ))

        hoja_id = execute_update('''
            INSERT INTO hojas_enfermeria (
                tenant_id, paciente_id, historia_emergencia_id,
                fecha_servicio, hora_servicio, nombre_paciente, edad, sexo,
                direccion, responsable, telefono_responsable, ars_nombre,
                medicamentos_materiales, observaciones, firma_responsable,
                created_by
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s
            )
        ''', (
            tenant_id, paciente_id, emergencia_id, fecha_servicio, hora_servicio,
            paciente['nombre'], calcular_edad_clinica(
                paciente.get('fecha_nacimiento'), fecha_obj
            ), paciente.get('sexo'), paciente.get('direccion'), responsable,
            telefono, paciente.get('ars_nombre'),
            json.dumps(suministros, ensure_ascii=False),
            observaciones or None, firma, current_user.id
        ))
        flash('Hoja de enfermería registrada exitosamente', 'success')
        return redirect(url_for(
            'facturacion_hoja_enfermeria_ver', hoja_id=hoja_id
        ))

    return render_template(
        'facturacion/hoja_enfermeria_form.html',
        pacientes=pacientes,
        emergencias=emergencias,
        paciente_preseleccionado=paciente_preseleccionado,
        fecha_actual=datetime.now().strftime('%Y-%m-%d'),
        hora_actual=datetime.now().strftime('%H:%M')
    )


def obtener_hoja_enfermeria(hoja_id, tenant_id):
    hoja = execute_query(
        'SELECT * FROM hojas_enfermeria WHERE id=%s AND tenant_id=%s',
        (hoja_id, tenant_id)
    )
    if hoja:
        try:
            hoja['suministros'] = json.loads(
                hoja.get('medicamentos_materiales') or '[]'
            )
        except (TypeError, ValueError):
            hoja['suministros'] = []
    return hoja


@app.route('/facturacion/hojas-enfermeria/<int:hoja_id>')
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_hoja_enfermeria_ver(hoja_id):
    hoja = obtener_hoja_enfermeria(hoja_id, get_current_tenant_id())
    if not hoja:
        flash('Hoja de enfermería no encontrada', 'error')
        return redirect(url_for('facturacion_hojas_enfermeria'))
    return render_template(
        'facturacion/hoja_enfermeria_ver.html',
        hoja=hoja, imprimir=False,
        centro=get_empresa_info(get_current_tenant_id())
    )


@app.route('/facturacion/hojas-enfermeria/<int:hoja_id>/imprimir')
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_hoja_enfermeria_imprimir(hoja_id):
    hoja = obtener_hoja_enfermeria(hoja_id, get_current_tenant_id())
    if not hoja:
        flash('Hoja de enfermería no encontrada', 'error')
        return redirect(url_for('facturacion_hojas_enfermeria'))
    return render_template(
        'facturacion/hoja_enfermeria_ver.html',
        hoja=hoja, imprimir=True,
        centro=get_empresa_info(get_current_tenant_id())
    )


@app.route('/facturacion/reclamaciones')
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_reclamaciones():
    """Lista de reclamaciones - Filtrado por tenant"""
    tenant_id = get_current_tenant_id()
    query = '''
        SELECT r.*, f.numero_factura, f.nombre_paciente, f.nombre_ars, f.total as total_factura
        FROM reclamaciones r
        JOIN facturas f
          ON r.factura_id = f.id AND f.tenant_id = r.tenant_id
        WHERE r.tenant_id = %s
    '''
    reclamaciones_list, pagination = execute_paginated_query(
        query,
        (tenant_id,),
        'r.fecha_reclamacion DESC, r.id DESC',
    )
    return render_template(
        'facturacion/reclamaciones.html',
        reclamaciones_list=reclamaciones_list,
        pagination=pagination,
    )

@app.route('/facturacion/reclamaciones/nueva', methods=['GET', 'POST'])
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_reclamaciones_nueva():
    """Crear nueva reclamación"""
    tenant_id = get_current_tenant_id()
    
    if request.method == 'POST':
        factura_id = request.form.get('factura_id')
        monto_reclamado = request.form.get('monto_reclamado')
        fecha_reclamacion = request.form.get('fecha_reclamacion')
        observaciones = request.form.get('observaciones', '').strip()
        
        if not all([factura_id, monto_reclamado, fecha_reclamacion]):
            flash('Factura, monto y fecha son obligatorios', 'error')
            return redirect(url_for('facturacion_reclamaciones_nueva'))
        
        # Verificar que la factura existe y pertenece al tenant
        factura = execute_query('SELECT id, total FROM facturas WHERE id = %s AND tenant_id = %s', (factura_id, tenant_id))
        if not factura:
            flash('Factura no encontrada', 'error')
            return redirect(url_for('facturacion_reclamaciones_nueva'))
        
        try:
            monto_reclamado = float(monto_reclamado)
            if monto_reclamado <= 0:
                flash('El monto debe ser mayor a cero', 'error')
                return redirect(url_for('facturacion_reclamaciones_nueva'))
        except ValueError:
            flash('Monto inválido', 'error')
            return redirect(url_for('facturacion_reclamaciones_nueva'))
        
        execute_update('''
            INSERT INTO reclamaciones (factura_id, monto_reclamado, fecha_reclamacion, observaciones, tenant_id, created_by, estado)
            VALUES (%s, %s, %s, %s, %s, %s, 'Pendiente')
        ''', (factura_id, monto_reclamado, fecha_reclamacion, observaciones or None, tenant_id, current_user.id))
        
        flash('Reclamación creada exitosamente', 'success')
        return redirect(url_for('facturacion_reclamaciones'))
    
    # Obtener facturas disponibles para reclamar
    facturas_list = execute_query('''
        SELECT f.id, f.numero_factura, f.nombre_paciente, f.nombre_ars, f.total, f.fecha_emision, f.estado
        FROM facturas f
        WHERE f.tenant_id = %s AND f.estado != 'Anulada'
        ORDER BY f.fecha_emision DESC, f.numero_factura DESC
        LIMIT 100
    ''', (tenant_id,), fetch='all') or []
    
    fecha_actual = datetime.now().strftime('%Y-%m-%d')
    return render_template('facturacion/reclamacion_form.html', facturas_list=facturas_list, fecha_actual=fecha_actual)


@app.route('/facturacion/reclamaciones/<int:reclamacion_id>')
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_reclamacion_detalle(reclamacion_id):
    """Mostrar una reclamación perteneciente a la empresa activa."""
    tenant_id = get_current_tenant_id()
    reclamacion = execute_query('''
        SELECT r.*, f.numero_factura, f.ncf, f.nombre_ars,
               f.total AS total_factura, f.estado AS estado_factura
        FROM reclamaciones r
        JOIN facturas f
          ON f.id = r.factura_id AND f.tenant_id = r.tenant_id
        WHERE r.id = %s AND r.tenant_id = %s
    ''', (reclamacion_id, tenant_id))
    if not reclamacion:
        flash('Reclamación no encontrada', 'error')
        return redirect(url_for('facturacion_reclamaciones'))
    return render_template(
        'facturacion/reclamacion_detalle.html',
        reclamacion=reclamacion,
    )


@app.route(
    '/facturacion/reclamaciones/<int:reclamacion_id>/estado',
    methods=['POST'],
)
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_reclamacion_cambiar_estado(reclamacion_id):
    """Actualizar el estado sin permitir acceso entre empresas."""
    tenant_id = get_current_tenant_id()
    estado = request.form.get('estado', '').strip()
    observaciones = request.form.get('observaciones_estado', '').strip()
    estados_permitidos = {'Pendiente', 'Procesada', 'Rechazada'}

    if estado not in estados_permitidos:
        flash('Estado de reclamación inválido', 'error')
        return redirect(url_for(
            'facturacion_reclamacion_detalle',
            reclamacion_id=reclamacion_id,
        ))
    if estado == 'Rechazada' and not observaciones:
        flash('Indique el motivo del rechazo', 'error')
        return redirect(url_for(
            'facturacion_reclamacion_detalle',
            reclamacion_id=reclamacion_id,
        ))

    reclamacion = execute_query(
        'SELECT id FROM reclamaciones WHERE id = %s AND tenant_id = %s',
        (reclamacion_id, tenant_id),
    )
    if not reclamacion:
        flash('Reclamación no encontrada', 'error')
        return redirect(url_for('facturacion_reclamaciones'))

    execute_update('''
        UPDATE reclamaciones
        SET estado = %s,
            observaciones = CASE
                WHEN %s <> '' THEN %s
                ELSE observaciones
            END
        WHERE id = %s AND tenant_id = %s
    ''', (
        estado,
        observaciones,
        observaciones,
        reclamacion_id,
        tenant_id,
    ))
    flash('Estado de reclamación actualizado', 'success')
    return redirect(url_for(
        'facturacion_reclamacion_detalle',
        reclamacion_id=reclamacion_id,
    ))


@app.route('/facturacion/pagos')
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_pagos():
    """Lista de pagos - Filtrado por tenant"""
    tenant_id = get_current_tenant_id()
    query = '''
        SELECT p.*,
               CONCAT('PAGO-', LPAD(p.id, 6, '0')) AS numero_pago,
               COALESCE(SUM(pf.monto_aplicado), MAX(p.monto), 0) AS monto_total,
               CASE WHEN COUNT(pf.id) > 0 THEN COUNT(pf.id) ELSE 1 END AS cantidad_facturas,
               COALESCE(
                   NULLIF(GROUP_CONCAT(f.numero_factura SEPARATOR ', '), ''),
                   MAX(factura_directa.numero_factura)
               ) AS facturas_numeros
        FROM pagos p
        LEFT JOIN pago_facturas pf
          ON p.id = pf.pago_id AND pf.tenant_id = p.tenant_id
        LEFT JOIN facturas f
          ON pf.factura_id = f.id AND f.tenant_id = p.tenant_id
        LEFT JOIN facturas factura_directa
          ON p.factura_id = factura_directa.id
         AND factura_directa.tenant_id = p.tenant_id
        WHERE p.tenant_id = %s
        GROUP BY p.id
    '''
    pagos_list, pagination = execute_paginated_query(
        query,
        (tenant_id,),
        'p.fecha_pago DESC, p.id DESC',
    )
    return render_template(
        'facturacion/pagos.html',
        pagos_list=pagos_list,
        pagination=pagination,
    )

@app.route('/facturacion/pagos/nuevo', methods=['GET', 'POST'])
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_pagos_nuevo():
    """Crear nuevo pago"""
    tenant_id = get_current_tenant_id()
    
    if request.method == 'POST':
        fecha_pago = request.form.get('fecha_pago')
        metodo_pago = request.form.get('metodo_pago')
        referencia = request.form.get('referencia', '').strip()
        observaciones = request.form.get('observaciones', '').strip()
        facturas_ids = request.form.getlist('facturas_ids[]')
        montos = request.form.getlist('montos[]')
        
        if not all([fecha_pago, metodo_pago]):
            flash('Fecha y método de pago son obligatorios', 'error')
            return redirect(url_for('facturacion_pagos_nuevo'))
        
        if not facturas_ids or not montos:
            flash('Debe seleccionar al menos una factura', 'error')
            return redirect(url_for('facturacion_pagos_nuevo'))
        
        # Validar identificadores y montos antes de bloquear las facturas.
        facturas_data = []
        facturas_vistas = set()
        for i, factura_id in enumerate(facturas_ids):
            if i < len(montos) and montos[i]:
                try:
                    factura_id_int = int(factura_id)
                    monto = Decimal(str(montos[i])).quantize(Decimal('0.01'))
                    if (
                        factura_id_int > 0
                        and monto > 0
                        and factura_id_int not in facturas_vistas
                    ):
                        facturas_vistas.add(factura_id_int)
                        facturas_data.append((factura_id_int, monto))
                except (InvalidOperation, TypeError, ValueError):
                    flash('Uno de los montos no es válido', 'error')
                    return redirect(url_for('facturacion_pagos_nuevo'))

        if not facturas_data:
            flash('El monto total debe ser mayor a cero', 'error')
            return redirect(url_for('facturacion_pagos_nuevo'))

        # Generar número de pago
        numero_pago = f"PAGO-{datetime.now().strftime('%Y%m%d')}-{secrets.token_hex(4).upper()}"

        try:
            with database_transaction():
                ids = [factura_id for factura_id, _monto in facturas_data]
                placeholders = ','.join(['%s'] * len(ids))
                facturas_bloqueadas = execute_query(f'''
                    SELECT id, total
                    FROM facturas
                    WHERE tenant_id = %s AND id IN ({placeholders})
                      AND estado != 'Anulada'
                    FOR UPDATE
                ''', (tenant_id, *ids), fetch='all') or []
                facturas_por_id = {
                    int(factura['id']): factura for factura in facturas_bloqueadas
                }
                if len(facturas_por_id) != len(ids):
                    raise ValueError(
                        'Una factura no existe, fue anulada o pertenece a otra empresa'
                    )

                pagos_previos = execute_query(f'''
                    SELECT pf.factura_id,
                           COALESCE(SUM(pf.monto_aplicado), 0) AS pagado
                    FROM pago_facturas pf
                    JOIN facturas f
                      ON f.id = pf.factura_id
                     AND f.tenant_id = pf.tenant_id
                    WHERE pf.tenant_id = %s
                      AND pf.factura_id IN ({placeholders})
                    GROUP BY pf.factura_id
                ''', (tenant_id, *ids), fetch='all') or []
                pagado_por_factura = {
                    int(item['factura_id']): Decimal(str(item['pagado'] or 0))
                    for item in pagos_previos
                }

                monto_total = Decimal('0.00')
                for factura_id, monto in facturas_data:
                    total_factura = Decimal(
                        str(facturas_por_id[factura_id]['total'])
                    )
                    pagado = pagado_por_factura.get(
                        factura_id, Decimal('0.00')
                    )
                    if monto > total_factura - pagado:
                        raise ValueError(
                            f'El pago supera el saldo de la factura {factura_id}'
                        )
                    monto_total += monto

                pago_id = execute_update('''
                    INSERT INTO pagos
                    (numero_pago, monto_total, fecha_pago, metodo_pago,
                     referencia, observaciones, tenant_id, created_by)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ''', (
                    numero_pago, monto_total, fecha_pago, metodo_pago,
                    referencia or None, observaciones or None,
                    tenant_id, current_user.id
                ))
                if not pago_id:
                    raise RuntimeError('No se pudo crear el pago')

                for factura_id, monto in facturas_data:
                    execute_update('''
                        INSERT INTO pago_facturas
                        (pago_id, factura_id, monto_aplicado, tenant_id)
                        VALUES (%s, %s, %s, %s)
                    ''', (pago_id, factura_id, monto, tenant_id))
                    acumulado = (
                        pagado_por_factura.get(factura_id, Decimal('0.00'))
                        + monto
                    )
                    if acumulado >= Decimal(
                        str(facturas_por_id[factura_id]['total'])
                    ):
                        execute_update('''
                            UPDATE facturas
                            SET estado = 'Pagada'
                            WHERE id = %s AND tenant_id = %s
                        ''', (factura_id, tenant_id))
        except ValueError as error:
            flash(str(error), 'error')
            return redirect(url_for('facturacion_pagos_nuevo'))
        except Exception:
            logger.error('Error al registrar pago', exc_info=True)
            flash('No se pudo registrar el pago. No se aplicó ningún cambio.', 'error')
            return redirect(url_for('facturacion_pagos_nuevo'))
        
        flash('Pago registrado exitosamente', 'success')
        return redirect(url_for('facturacion_pagos'))
    
    # Obtener facturas disponibles para pagar
    facturas_list = execute_query('''
        SELECT f.id, f.numero_factura, f.nombre_paciente, f.nombre_ars, f.total, f.fecha_emision, f.estado,
               COALESCE(SUM(pf.monto_aplicado), 0) as monto_pagado
        FROM facturas f
        LEFT JOIN pago_facturas pf
          ON f.id = pf.factura_id AND pf.tenant_id = f.tenant_id
        WHERE f.tenant_id = %s AND f.estado != 'Anulada'
        GROUP BY f.id
        HAVING (f.total - COALESCE(SUM(pf.monto_aplicado), 0)) > 0
        ORDER BY f.fecha_emision DESC, f.numero_factura DESC
        LIMIT 100
    ''', (tenant_id,), fetch='all') or []
    
    fecha_actual = datetime.now().strftime('%Y-%m-%d')
    return render_template('facturacion/pago_form.html', facturas_list=facturas_list, fecha_actual=fecha_actual)

@app.route('/facturacion/pacientes/exportar-excel')
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_pacientes_exportar_excel():
    """Exportar lista de pacientes a Excel"""
    if not OPENPYXL_AVAILABLE:
        flash('La funcionalidad de Excel no está disponible', 'error')
        return redirect(url_for('facturacion_pacientes'))
    
    tenant_id = get_current_tenant_id()
    search = request.args.get('search', '').strip()
    
    # Obtener pacientes con el mismo filtro que la vista
    query = '''
        SELECT p.*, a.nombre as ars_nombre 
        FROM pacientes p
        LEFT JOIN ars a
          ON p.ars_id = a.id AND a.tenant_id = p.tenant_id
        WHERE p.tenant_id = %s
    '''
    params = [tenant_id]
    
    if search:
        query += ' AND (p.nombre LIKE %s OR p.nss LIKE %s OR p.cedula LIKE %s)'
        search_pattern = f'%{search}%'
        params.extend([search_pattern, search_pattern, search_pattern])
    
    query += ' ORDER BY p.nombre'
    
    pacientes_list = execute_query(query, tuple(params), fetch='all') or []
    
    # Crear workbook
    wb = Workbook()
    ws = wb.active
    ws.title = "Pacientes"
    
    # Estilos para encabezados
    header_fill = PatternFill(start_color="366092", end_color="366092", fill_type="solid")
    header_font = Font(bold=True, color="FFFFFF", size=12)
    header_alignment = Alignment(horizontal="center", vertical="center")
    
    # Encabezados
    headers = ['NSS', 'Nombre Completo', 'Cédula', 'Teléfono', 'Email', 'Fecha de Nacimiento', 
               'Sexo', 'ARS', 'Tipo de Afiliación', 'Dirección']
    for col_num, header in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col_num, value=header)
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = header_alignment
    
    # Datos
    for row_num, paciente in enumerate(pacientes_list, 2):
        ws.cell(row=row_num, column=1, value=paciente.get('nss') or '')
        ws.cell(row=row_num, column=2, value=paciente.get('nombre') or '')
        ws.cell(row=row_num, column=3, value=paciente.get('cedula') or '')
        ws.cell(row=row_num, column=4, value=paciente.get('telefono') or '')
        ws.cell(row=row_num, column=5, value=paciente.get('email') or '')
        ws.cell(row=row_num, column=6, value=paciente.get('fecha_nacimiento') or '')
        ws.cell(row=row_num, column=7, value=paciente.get('sexo') or '')
        ws.cell(row=row_num, column=8, value=paciente.get('ars_nombre') or 'Sin ARS')
        ws.cell(row=row_num, column=9, value=paciente.get('tipo_afiliacion') or '')
        ws.cell(row=row_num, column=10, value=paciente.get('direccion') or '')
    
    # Ajustar ancho de columnas
    column_widths = [15, 30, 15, 15, 25, 15, 10, 20, 15, 40]
    for col_num, width in enumerate(column_widths, 1):
        ws.column_dimensions[get_column_letter(col_num)].width = width
    
    # Guardar en BytesIO
    output = BytesIO()
    wb.save(output)
    output.seek(0)
    
    # Nombre del archivo con fecha
    fecha_actual = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'pacientes_{fecha_actual}.xlsx'
    
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=filename
    )

@app.route('/facturacion/historico')
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_historico():
    """Histórico de facturas - Filtrado por tenant"""
    tenant_id = get_current_tenant_id()
    query = '''
        SELECT f.*, f.fecha_emision as fecha_factura
        FROM facturas f
        WHERE f.tenant_id = %s
    '''
    facturas, pagination = execute_paginated_query(
        query,
        (tenant_id,),
        'f.id DESC',
        default_per_page=50,
    )
    return render_template(
        'facturacion/historico.html',
        facturas=facturas,
        page=pagination['page'],
        per_page=pagination['per_page'],
        total_pages=pagination['total_pages'],
        total_facturas=pagination['total'],
        pagination=pagination,
    )

@app.route('/facturacion/facturas/<int:factura_id>/ver')
@login_required
def facturacion_ver_factura(factura_id):
    """Ver factura generada"""
    # Validar que el ID sea válido
    if not validate_int(factura_id, min_value=1):
        flash('ID de factura inválido', 'error')
        return redirect(url_for('facturacion_historico'))
    
    # Validar acceso al tenant
    if not validate_tenant_access('facturas', factura_id):
        flash('No tienes acceso a esta factura', 'error')
        return redirect(url_for('facturacion_historico'))
    
    tenant_id = get_current_tenant_id()
    
    factura = execute_query('''
        SELECT f.*, a.nombre as nombre_ars, a.rnc as ars_rnc,
               m.nombre as medico_nombre, m.especialidad as medico_especialidad,
               m.cedula as medico_cedula, m.exequatur as medico_exequatur
        FROM facturas f
        LEFT JOIN ars a
          ON f.ars_id = a.id AND a.tenant_id = f.tenant_id
        LEFT JOIN medicos m
          ON f.medico_id = m.id AND m.tenant_id = f.tenant_id
        WHERE f.id = %s AND f.tenant_id = %s
    ''', (factura_id, tenant_id))
    
    if not factura:
        flash('Factura no encontrada', 'error')
        return redirect(url_for('facturacion_historico'))
    
    # Obtener detalles de la factura (pacientes/servicios)
    detalles = execute_query('''
        SELECT * FROM factura_detalles
        WHERE factura_id = %s AND tenant_id = %s
        ORDER BY id
    ''', (factura_id, tenant_id), fetch='all') or []
    
    # Procesar detalles para mostrar como pacientes
    pacientes = []
    for detalle in detalles:
        # Extraer información del detalle
        descripcion = detalle.get('descripcion', '')
        # Intentar extraer autorización de la descripción si está presente
        autorizacion = ''
        descripcion_servicio = descripcion
        if ' - Autorización:' in descripcion:
            partes = descripcion.split(' - Autorización:')
            descripcion_servicio = partes[0].strip()
            autorizacion = partes[1].strip() if len(partes) > 1 else ''
        
        paciente = {
            'nombre_paciente': factura.get('nombre_paciente', 'N/A'),
            'nss': factura.get('nss_paciente', ''),
            'fecha_servicio': factura.get('fecha_emision', ''),
            'autorizacion': autorizacion,
            'descripcion_servicio': descripcion_servicio if descripcion_servicio else '',
            'monto_estimado': float(detalle.get('precio_unitario', 0) or 0),
            'monto': float(detalle.get('precio_unitario', 0) or 0)
        }
        pacientes.append(paciente)
    
    # Obtener centro médico
    centro_medico = None
    if factura.get('centro_medico_id'):
        centro_medico = execute_query('SELECT * FROM centros_medicos WHERE id = %s AND tenant_id = %s', 
                                     (factura['centro_medico_id'], tenant_id))
    
    if not centro_medico:
        centro_medico = execute_query('SELECT * FROM centros_medicos WHERE tenant_id = %s LIMIT 1', (tenant_id,))
    
    if not centro_medico:
        centro_medico = {
            'nombre': 'Centro Médico',
            'direccion': ''
        }
    
    # Calcular totales
    subtotal = float(factura.get('subtotal', 0) or 0)
    total = float(factura.get('total', 0) or 0)
    
    # Obtener información de la empresa para determinar tipo
    empresa_info = get_empresa_info(tenant_id)
    tipo_empresa = empresa_info.get('tipo_empresa') if empresa_info else None
    
    # Obtener médico o empresa según tipo (igual que en vista_previa)
    medico_factura = None
    if tipo_empresa == 'centro_salud':
        medico_factura = {
            'id': empresa_info.get('id'),
            'nombre': empresa_info.get('razon_social', empresa_info.get('nombre', 'N/A')),
            'especialidad': 'Centro de Salud',
            'cedula': empresa_info.get('rnc', ''),
            'telefono': empresa_info.get('telefono', ''),
            'email': empresa_info.get('email', '')
        }
    else:
        # Obtener datos completos del médico
        medico_completo = execute_query(
            'SELECT * FROM medicos WHERE id = %s AND tenant_id = %s',
            (factura.get('medico_id'), tenant_id),
        )
        if medico_completo:
            medico_factura = {
                'id': medico_completo.get('id'),
                'nombre': medico_completo.get('nombre', factura.get('medico_nombre', 'N/A')),
                'especialidad': medico_completo.get('especialidad', factura.get('medico_especialidad', '')),
                'cedula': medico_completo.get('cedula', factura.get('medico_cedula', '')),
                'exequatur': medico_completo.get('exequatur', factura.get('medico_exequatur', '')),
                'telefono': medico_completo.get('telefono', ''),
                'email': medico_completo.get('email', '')
            }
        else:
            medico_factura = {
                'id': factura.get('medico_id'),
                'nombre': factura.get('medico_nombre', 'N/A'),
                'especialidad': factura.get('medico_especialidad', ''),
                'cedula': factura.get('medico_cedula', ''),
                'exequatur': factura.get('medico_exequatur', ''),
                'telefono': '',
                'email': ''
            }
    
    # Obtener NCF completo y descripción
    ncf_numero = factura.get('ncf', '')
    ncf_prefijo = ncf_numero[:3] if len(ncf_numero) >= 3 else ''
    factura_ecf = None
    if factura.get('tipo_factura') == 'ELECTRONICA':
        factura_ecf = execute_query(
            'SELECT * FROM facturas_ecf WHERE factura_id=%s AND tenant_id=%s',
            (factura_id, tenant_id)
        )
        ncf_obj = {'id': None, 'tipo': 'E31', 'prefijo': 'E31'}
        ncf_tipo_descripcion = 'Factura de Crédito Fiscal Electrónica'
        ncf_fecha_fin = ''
    else:
        ncf_obj = execute_query(
            'SELECT * FROM ncf WHERE prefijo = %s AND tenant_id = %s LIMIT 1',
            (ncf_prefijo, tenant_id)
        )
        if not ncf_obj:
            logger.warning(
                'NCF no encontrado en tenant=%s para prefijo=%s',
                tenant_id,
                ncf_prefijo,
            )
        ncf_tipos_descripciones = {
            'B01': 'Factura de Crédito Fiscal',
            'B02': 'Factura de Consumo',
            'B14': 'Registro Único de Ingresos',
            'B15': 'GUBERNAMENTAL'
        }
        ncf_tipo_descripcion = (
            ncf_tipos_descripciones.get(ncf_obj.get('tipo', ''), '')
            if ncf_obj else ''
        )
        ncf_fecha_fin = ncf_obj.get('fecha_fin', '') if ncf_obj else ''
    ncf_completo = ncf_numero
    
    # Intentar obtener pacientes desde pacientes_pendientes que fueron facturados
    fecha_factura = factura.get('fecha_emision', '')
    pacientes_pendientes_facturados = []
    try:
        pacientes_pendientes_facturados = execute_query('''
            SELECT pp.*, a.nombre as ars_nombre
            FROM pacientes_pendientes pp
            LEFT JOIN ars a
              ON pp.ars_id = a.id AND a.tenant_id = pp.tenant_id
            WHERE pp.estado = 'Facturado'
              AND pp.ars_id = %s
              AND DATE(pp.updated_at) = DATE(%s)
              AND pp.tenant_id = %s
            ORDER BY pp.id
        ''', (
            factura.get('ars_id'),
            fecha_factura,
            tenant_id,
        ), fetch='all') or []
    except Exception as e:
        logger.error(f"Error al obtener pacientes_pendientes_facturados: {str(e)}")
        pacientes_pendientes_facturados = []
    
    # Procesar pacientes desde detalles y pacientes_pendientes (igual que en vista_previa)
    pacientes_procesados = []
    if pacientes_pendientes_facturados and len(pacientes_pendientes_facturados) == len(detalles):
        # Si encontramos pacientes_pendientes que coinciden, usarlos
        for idx, (detalle, pp) in enumerate(zip(detalles, pacientes_pendientes_facturados), 1):
            servicio_completo = pp.get('servicios_realizados', '') or ''
            if ' - Autorización:' in servicio_completo:
                partes = servicio_completo.split(' - Autorización:')
                descripcion_servicio = partes[0].strip()
                autorizacion = partes[1].strip() if len(partes) > 1 else ''
            else:
                descripcion_servicio = servicio_completo.strip()
                autorizacion = ''
            
            paciente = {
                'nombre_paciente': pp.get('nombre_paciente', factura.get('nombre_paciente', 'N/A')),
                'nss': pp.get('nss', factura.get('nss_paciente', '')),
                'fecha_servicio': pp.get('fecha_servicio', fecha_factura),
                'autorizacion': autorizacion,
                'descripcion_servicio': descripcion_servicio if descripcion_servicio else detalle.get('descripcion', ''),
                'monto_estimado': float(detalle.get('precio_unitario', 0) or 0),
                'monto': float(detalle.get('precio_unitario', 0) or 0)
            }
            pacientes_procesados.append(paciente)
    else:
        # Si no encontramos pacientes_pendientes, usar datos de la factura
        for idx, detalle in enumerate(detalles, 1):
            descripcion = detalle.get('descripcion', '')
            # Intentar extraer autorización de la descripción si está presente
            autorizacion = ''
            descripcion_servicio = descripcion
            if ' - Autorización:' in descripcion:
                partes = descripcion.split(' - Autorización:')
                descripcion_servicio = partes[0].strip()
                autorizacion = partes[1].strip() if len(partes) > 1 else ''
            
            paciente = {
                'nombre_paciente': factura.get('nombre_paciente', 'N/A'),
                'nss': factura.get('nss_paciente', ''),
                'fecha_servicio': fecha_factura,
                'autorizacion': autorizacion,
                'descripcion_servicio': descripcion_servicio if descripcion_servicio else '',
                'monto_estimado': float(detalle.get('precio_unitario', 0) or 0),
                'monto': float(detalle.get('precio_unitario', 0) or 0)
            }
            pacientes_procesados.append(paciente)
    
    # Preparar datos de ARS
    ars = {
        'id': factura.get('ars_id'),
        'nombre': factura.get('nombre_ars', 'N/A'),
        'rnc': factura.get('ars_rnc', '')
    }
    
    # Preparar datos de NCF
    ncf = {
        'id': ncf_obj.get('id') if ncf_obj else None,
        'prefijo': ncf_prefijo,
        'tipo': ncf_obj.get('tipo', '') if ncf_obj else '',
        'fecha_fin': ncf_fecha_fin
    }
    
    return render_template('facturacion/ver_factura.html',
                          factura=factura,
                          pacientes=pacientes_procesados,
                          centro_medico=centro_medico,
                          subtotal=subtotal,
                          total=total,
                          ars=ars,
                          ncf=ncf,
                          ncf_completo=ncf_completo,
                          ncf_tipo_descripcion=ncf_tipo_descripcion,
                          medico=medico_factura,
                          tipo_empresa=tipo_empresa,
                          empresa_info=empresa_info,
                          fecha_factura=fecha_factura,
                          factura_ecf=factura_ecf)

@app.route('/facturacion/facturas/<int:factura_id>/ecf/xml')
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_ver_xml_ecf(factura_id):
    """Mostrar el XML E31 generado, limitado al tenant de la factura."""
    if not validate_tenant_access('facturas', factura_id):
        flash('No tienes acceso a esta factura', 'error')
        return redirect(url_for('facturacion_historico'))

    tenant_id = get_current_tenant_id()
    document = execute_query('''
        SELECT e_ncf, xml_generado, xml_firmado
        FROM facturas_ecf
        WHERE factura_id=%s AND tenant_id=%s
        LIMIT 1
    ''', (factura_id, tenant_id))
    xml_document = (
        (document or {}).get('xml_firmado')
        or (document or {}).get('xml_generado')
    )
    if not xml_document:
        flash('Esta factura todavía no tiene un XML generado', 'warning')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))

    response = make_response(xml_document)
    response.headers['Content-Type'] = 'application/xml; charset=utf-8'
    response.headers['Content-Disposition'] = (
        f"inline; filename={document['e_ncf']}.xml"
    )
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


def _obtener_ecf_aceptado_para_ri(factura_id, tenant_id):
    document = execute_query('''
        SELECT e_ncf, estado, xml_firmado, track_id
        FROM facturas_ecf
        WHERE factura_id=%s AND tenant_id=%s
        LIMIT 1
    ''', (factura_id, tenant_id))
    if not document or document.get('estado') != 'ACEPTADO':
        raise ECFPrintableError(
            'La representación impresa se habilita cuando DGII acepta el e-CF'
        )
    if not document.get('xml_firmado'):
        raise ECFPrintableError('El e-CF aceptado no tiene XML firmado')
    return document


@app.route('/facturacion/facturas/<int:factura_id>/ecf/qr')
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_qr_ecf(factura_id):
    """Mostrar el QR fiscal de un e-CF aceptado por DGII."""
    if not validate_tenant_access('facturas', factura_id):
        flash('No tienes acceso a esta factura', 'error')
        return redirect(url_for('facturacion_historico'))

    try:
        document = _obtener_ecf_aceptado_para_ri(
            factura_id, get_current_tenant_id()
        )
        config = app.config['ECF_CONFIG']
        stamp = build_stamp(document['xml_firmado'], config.stamp_url)
        qr = generate_qr(stamp)
    except ECFPrintableError as error:
        flash(str(error), 'warning')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))
    except ValueError as error:
        logger.error('No se pudo generar QR e-CF %s: %s', factura_id, error)
        flash('No fue posible generar el QR fiscal del e-CF', 'error')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))

    response = make_response(qr.png)
    response.headers['Content-Type'] = 'image/png'
    response.headers['Content-Disposition'] = (
        f"inline; filename={document['e_ncf']}_qr.png"
    )
    response.headers['Cache-Control'] = 'private, no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


@app.route('/facturacion/facturas/<int:factura_id>/ecf/representacion-impresa')
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_representacion_impresa_ecf(factura_id):
    """Abrir la representación impresa fiscal del e-CF 31 aceptado."""
    if not validate_tenant_access('facturas', factura_id):
        flash('No tienes acceso a esta factura', 'error')
        return redirect(url_for('facturacion_historico'))

    try:
        document = _obtener_ecf_aceptado_para_ri(
            factura_id, get_current_tenant_id()
        )
        result = generate_e31_pdf(
            document['xml_firmado'],
            app.config['ECF_CONFIG'].stamp_url,
            dgii_status=document['estado'],
            track_id=document.get('track_id') or '',
        )
    except ECFPrintableError as error:
        logger.error(
            'No se pudo generar representación impresa e-CF %s: %s',
            factura_id,
            error,
        )
        flash(str(error), 'error')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))

    return send_file(
        result.pdf,
        mimetype='application/pdf',
        as_attachment=False,
        download_name=f"{document['e_ncf']}_representacion_impresa.pdf",
        max_age=0,
    )


@app.route(
    '/facturacion/facturas/<int:factura_id>/ecf/consultar-estado',
    methods=['POST']
)
@login_required
def facturacion_consultar_estado_ecf(factura_id):
    """Consultar una vez el resultado fiscal vigente en DGII."""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos para consultar este documento', 'error')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))
    if not validate_tenant_access('facturas', factura_id):
        flash('No tienes acceso a esta factura', 'error')
        return redirect(url_for('facturacion_historico'))
    tenant_id = get_current_tenant_id()
    if not ecf_habilitado_para_tenant(tenant_id, solo_consulta=True):
        flash('La cuenta no está habilitada para consultar e-CF', 'warning')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))

    document = execute_query('''
        SELECT id
        FROM facturas_ecf
        WHERE factura_id=%s AND tenant_id=%s
        LIMIT 1
    ''', (factura_id, tenant_id))
    if not document:
        flash('La factura seleccionada no es electrónica', 'error')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))

    try:
        success, status, message = consultar_resultado_ecf_dgii(
            document['id'],
            tenant_id,
            current_user.id
        )
    except Exception as error:
        logger.error(
            'Error consultando resultado DGII para factura %s: %s',
            factura_id,
            error,
            exc_info=True
        )
        flash('No fue posible completar la consulta a DGII', 'error')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))

    if success and status == 'ACEPTADO':
        flash('Comprobante aceptado por DGII', 'success')
    elif success and status == 'RECHAZADO':
        flash(f'Comprobante rechazado por DGII: {message}', 'error')
    elif success:
        flash(f'DGII todavía está procesando el comprobante: {message}', 'info')
    else:
        flash(message, 'warning')
    return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))

@app.route('/facturacion/facturas/<int:factura_id>/editar', methods=['GET', 'POST'])
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_editar_factura(factura_id):
    """Editar factura generada"""
    tenant_id = get_current_tenant_id()
    if not validate_tenant_access('facturas', factura_id):
        flash('No tienes acceso a esta factura', 'error')
        return redirect(url_for('facturacion_historico'))

    factura = execute_query('''
        SELECT f.*, a.nombre as nombre_ars, a.rnc as ars_rnc,
               m.nombre as medico_nombre, m.especialidad as medico_especialidad,
               m.cedula as medico_cedula, m.exequatur as medico_exequatur
        FROM facturas f
        LEFT JOIN ars a
          ON f.ars_id = a.id AND a.tenant_id = f.tenant_id
        LEFT JOIN medicos m
          ON f.medico_id = m.id AND m.tenant_id = f.tenant_id
        WHERE f.id = %s AND f.tenant_id = %s
    ''', (factura_id, tenant_id))
    
    if not factura:
        flash('Factura no encontrada', 'error')
        return redirect(url_for('facturacion_historico'))
    
    # Calcular días transcurridos desde la creación
    from datetime import datetime, date
    fecha_creacion = factura.get('created_at')
    if isinstance(fecha_creacion, str):
        try:
            fecha_creacion = datetime.strptime(fecha_creacion, '%Y-%m-%d %H:%M:%S').date()
        except:
            fecha_creacion = date.today()
    elif isinstance(fecha_creacion, datetime):
        fecha_creacion = fecha_creacion.date()
    elif isinstance(fecha_creacion, date):
        pass
    else:
        fecha_creacion = date.today()
    
    fecha_actual = date.today()
    dias_transcurridos = (fecha_actual - fecha_creacion).days
    dias_restantes = 30 - dias_transcurridos
    
    # Verificar si se puede editar (menos de 30 días)
    if dias_transcurridos >= 30:
        flash('Esta factura no se puede editar. Han pasado más de 30 días desde su creación.', 'error')
        return redirect(url_for('facturacion_historico'))
    
    # Si es POST, procesar la actualización
    if request.method == 'POST':
        # Aquí se procesaría la actualización de la factura
        # Por ahora, solo redirigir
        flash('Funcionalidad de edición en desarrollo', 'info')
        return redirect(url_for('facturacion_historico'))
    
    # Obtener detalles de la factura (pacientes/servicios)
    detalles = execute_query('''
        SELECT * FROM factura_detalles
        WHERE factura_id = %s AND tenant_id = %s
        ORDER BY id
    ''', (factura_id, tenant_id), fetch='all') or []
    
    # Procesar detalles para mostrar como pacientes
    pacientes = []
    for detalle in detalles:
        # Extraer información del servicio desde la descripción
        descripcion_servicio = detalle.get('descripcion', '')
        servicio_nombre = descripcion_servicio
        if ' - Autorización:' in descripcion_servicio:
            servicio_nombre = descripcion_servicio.split(' - Autorización:')[0].strip()
        
        paciente = {
            'id': detalle.get('id'),
            'nombre_paciente': factura.get('nombre_paciente', 'N/A'),
            'nss': factura.get('nss_paciente', ''),
            'fecha_servicio': factura.get('fecha_emision', ''),
            'autorizacion': '',
            'descripcion_servicio': descripcion_servicio,
            'servicio_nombre': servicio_nombre,
            'medico_nombre': factura.get('medico_nombre', 'N/A'),
            'monto_estimado': float(detalle.get('precio_unitario', 0) or 0),
            'monto': float(detalle.get('precio_unitario', 0) or 0)
        }
        pacientes.append(paciente)
    
    # Agregar campos adicionales a factura para el template
    factura['fecha_factura'] = factura.get('fecha_emision', '')
    factura['ncf_numero'] = factura.get('ncf', '')
    
    return render_template('facturacion/editar_factura.html',
                          factura=factura,
                          pacientes_factura=pacientes,  # Cambiado de pacientes a pacientes_factura
                          pacientes_disponibles=[],  # Lista vacía por ahora, se puede poblar después
                          dias_transcurridos=dias_transcurridos,
                          dias_restantes=dias_restantes)

def generar_pdf_factura_vista_previa(factura_id, tenant_id=None):
    """Generar PDF de factura con el mismo formato que la vista previa"""
    if not REPORTLAB_AVAILABLE:
        return None
    
    if tenant_id is None:
        tenant_id = get_current_tenant_id()
    
    factura = execute_query('''
        SELECT f.*, a.nombre as nombre_ars, a.rnc as ars_rnc,
               m.nombre as medico_nombre, m.especialidad as medico_especialidad,
               m.cedula as medico_cedula, m.exequatur as medico_exequatur,
               m.id as medico_id
        FROM facturas f
        LEFT JOIN ars a
          ON f.ars_id = a.id AND a.tenant_id = f.tenant_id
        LEFT JOIN medicos m
          ON f.medico_id = m.id AND m.tenant_id = f.tenant_id
        WHERE f.id = %s AND f.tenant_id = %s
    ''', (factura_id, tenant_id))
    
    if not factura:
        logger.error(f"Factura {factura_id} no encontrada para tenant {tenant_id}")
        print(f"ERROR: Factura {factura_id} no encontrada para tenant {tenant_id}")
        return None
    
    logger.info(f"Iniciando generación de PDF para factura {factura_id}")
    print(f"INFO: Factura {factura_id} encontrada. Datos básicos: ncf={factura.get('ncf')}, fecha_emision={factura.get('fecha_emision')}, ars_id={factura.get('ars_id')}")
    
    # Obtener información de la empresa para determinar tipo
    empresa_info = get_empresa_info(tenant_id)
    tipo_empresa = empresa_info.get('tipo_empresa') if empresa_info else None
    
    # Obtener médico o empresa según tipo
    medico_factura = None
    if tipo_empresa == 'centro_salud':
        medico_factura = {
            'id': empresa_info.get('id'),
            'nombre': empresa_info.get('razon_social', empresa_info.get('nombre', 'N/A')),
            'especialidad': 'Centro de Salud',
            'cedula': empresa_info.get('rnc', '')
        }
    else:
        medico_factura = {
            'id': factura.get('medico_id'),
            'nombre': factura.get('medico_nombre', 'N/A'),
            'especialidad': factura.get('medico_especialidad', ''),
            'cedula': factura.get('medico_cedula', '')
        }
    
    # Obtener ARS
    ars = {
        'id': factura.get('ars_id'),
        'nombre': factura.get('nombre_ars', 'N/A'),
        'rnc': factura.get('ars_rnc', '')
    }
    
    # Obtener NCF
    ncf_numero = factura.get('ncf', '')
    ncf_prefijo = ncf_numero[:3] if len(ncf_numero) >= 3 else ''
    ncf_obj = execute_query('SELECT * FROM ncf WHERE prefijo = %s AND tenant_id = %s LIMIT 1', (ncf_prefijo, tenant_id))
    
    ncf_tipos_descripciones = {
        'B01': 'Factura de Crédito Fiscal',
        'B02': 'Factura de Consumo',
        'B14': 'Registro Único de Ingresos',
        'B15': 'GUBERNAMENTAL'
    }
    ncf_tipo_descripcion = ncf_tipos_descripciones.get(ncf_obj.get('tipo', '') if ncf_obj else '', '') if ncf_obj else ''
    ncf_fecha_fin = ncf_obj.get('fecha_fin', '') if ncf_obj else ''
    
    # Obtener fecha de factura para usar en consultas
    fecha_factura = factura.get('fecha_emision', '')
    
    # Obtener detalles de la factura (pacientes/servicios)
    detalles = execute_query('''
        SELECT * FROM factura_detalles
        WHERE factura_id = %s AND tenant_id = %s
        ORDER BY id
    ''', (factura_id, tenant_id), fetch='all') or []
    
    # Intentar obtener pacientes desde pacientes_pendientes que fueron facturados
    # Buscar pacientes_pendientes con estado 'Facturado' que coincidan con esta factura
    # Por fecha y ARS como aproximación
    pacientes_pendientes_facturados = []
    try:
        pacientes_pendientes_facturados = execute_query('''
            SELECT pp.*, a.nombre as ars_nombre
            FROM pacientes_pendientes pp
            LEFT JOIN ars a
              ON pp.ars_id = a.id AND a.tenant_id = pp.tenant_id
            WHERE pp.estado = 'Facturado'
              AND pp.ars_id = %s
              AND DATE(pp.updated_at) = DATE(%s)
              AND pp.tenant_id = %s
            ORDER BY pp.id
        ''', (
            factura.get('ars_id'),
            fecha_factura,
            tenant_id,
        ), fetch='all') or []
    except Exception as e:
        logger.error(f"Error al obtener pacientes_pendientes_facturados: {str(e)}")
        pacientes_pendientes_facturados = []
    
    # Validar que hay detalles antes de procesar
    if not detalles:
        logger.error(f"Factura {factura_id} no tiene detalles asociados. Query ejecutada: SELECT * FROM factura_detalles WHERE factura_id = {factura_id}")
        return None
    
    logger.info(f"Factura {factura_id} tiene {len(detalles)} detalles. Primer detalle: {detalles[0] if detalles else 'N/A'}")
    
    # Procesar pacientes desde detalles y pacientes_pendientes
    pacientes = []
    if pacientes_pendientes_facturados and len(pacientes_pendientes_facturados) == len(detalles):
        # Si encontramos pacientes_pendientes que coinciden, usarlos
        for idx, (detalle, pp) in enumerate(zip(detalles, pacientes_pendientes_facturados), 1):
            servicio_completo = pp.get('servicios_realizados', '') or ''
            if ' - Autorización:' in servicio_completo:
                partes = servicio_completo.split(' - Autorización:')
                descripcion_servicio = partes[0].strip()
                autorizacion = partes[1].strip() if len(partes) > 1 else ''
            else:
                descripcion_servicio = servicio_completo.strip()
                autorizacion = ''
            
            paciente = {
                'nombre_paciente': pp.get('nombre_paciente', factura.get('nombre_paciente', 'N/A')),
                'nss': pp.get('nss', factura.get('nss_paciente', '')),
                'fecha_servicio': pp.get('fecha_servicio', factura.get('fecha_emision', '')),
                'autorizacion': autorizacion,
                'descripcion_servicio': descripcion_servicio if descripcion_servicio else detalle.get('descripcion', ''),
                'monto_estimado': float(detalle.get('precio_unitario', 0) or 0),
                'monto': float(detalle.get('precio_unitario', 0) or 0)
            }
            pacientes.append(paciente)
    else:
        # Si no encontramos pacientes_pendientes, usar datos de la factura (como en ver_factura)
        for idx, detalle in enumerate(detalles, 1):
            descripcion = detalle.get('descripcion', '')
            # Intentar extraer autorización de la descripción si está presente
            autorizacion = ''
            descripcion_servicio = descripcion
            if ' - Autorización:' in descripcion:
                partes = descripcion.split(' - Autorización:')
                descripcion_servicio = partes[0].strip()
                autorizacion = partes[1].strip() if len(partes) > 1 else ''
            
            paciente = {
                'nombre_paciente': factura.get('nombre_paciente', 'N/A'),
                'nss': factura.get('nss_paciente', ''),
                'fecha_servicio': fecha_factura,
                'autorizacion': autorizacion,
                'descripcion_servicio': descripcion_servicio if descripcion_servicio else '',
                'monto_estimado': float(detalle.get('precio_unitario', 0) or 0),
                'monto': float(detalle.get('precio_unitario', 0) or 0)
            }
            pacientes.append(paciente)
    
    # Obtener centro médico
    centro_medico = None
    if factura.get('centro_medico_id'):
        centro_medico = execute_query('SELECT * FROM centros_medicos WHERE id = %s AND tenant_id = %s', 
                                     (factura['centro_medico_id'], tenant_id))
    
    if not centro_medico:
        centro_medico = execute_query('SELECT * FROM centros_medicos WHERE tenant_id = %s LIMIT 1', (tenant_id,))
    
    if not centro_medico:
        centro_medico = {
            'nombre': 'Centro Médico',
            'direccion': ''
        }
    
    # Calcular totales
    subtotal = float(factura.get('subtotal', 0) or 0)
    total = float(factura.get('total', 0) or 0)
    
    # Obtener datos completos del médico para el footer y remitente (antes de generar PDF)
    medico_completo = None
    if tipo_empresa != 'centro_salud' and medico_factura.get('id'):
        medico_completo = execute_query(
            'SELECT * FROM medicos WHERE id = %s AND tenant_id = %s',
            (medico_factura.get('id'), tenant_id),
        )
        # Actualizar medico_factura con datos completos si están disponibles
        if medico_completo:
            medico_factura['nombre'] = medico_completo.get('nombre', medico_factura.get('nombre', 'N/A'))
            medico_factura['especialidad'] = medico_completo.get('especialidad', medico_factura.get('especialidad', ''))
            medico_factura['cedula'] = medico_completo.get('cedula', medico_factura.get('cedula', ''))
            medico_factura['exequatur'] = medico_completo.get('exequatur', '')
    
    # Validar datos mínimos necesarios antes de generar PDF
    if not pacientes:
        logger.error(f"Factura {factura_id} no tiene pacientes procesados después de procesar {len(detalles)} detalles")
        logger.error(f"Detalles procesados: {detalles}")
        logger.error(f"Pacientes pendientes encontrados: {len(pacientes_pendientes_facturados)}")
        return None
    
    # Validar que tenemos datos esenciales
    if not fecha_factura:
        logger.error(f"Factura {factura_id} no tiene fecha_emision. factura['fecha_emision'] = {factura.get('fecha_emision')}")
        return None
    
    if not ars.get('nombre'):
        logger.error(f"Factura {factura_id} no tiene nombre de ARS. ars = {ars}, factura['nombre_ars'] = {factura.get('nombre_ars')}")
        return None
    
    if not ncf_numero:
        logger.error(f"Factura {factura_id} no tiene número de NCF. factura['ncf'] = {factura.get('ncf')}")
        return None
    
    logger.info(f"Iniciando generación de PDF para factura {factura_id}: {len(pacientes)} pacientes, subtotal: {subtotal}, total: {total}")
    logger.info(f"Datos validados: fecha_factura={fecha_factura}, ars={ars.get('nombre')}, ncf={ncf_numero}, tipo_empresa={tipo_empresa}")
    
    # Generar PDF
    try:
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, 
                                leftMargin=0.5*inch, rightMargin=0.5*inch,
                                topMargin=0.5*inch, bottomMargin=0.5*inch)
        story = []
        
        styles = getSampleStyleSheet()
        
        # Color primario (puede obtenerse del tema, por defecto usamos un color)
        primary_color_hex = '#CEB0B7'
        primary_color = colors.HexColor(primary_color_hex)
        primary_dark = colors.HexColor('#B89CA3')
        
        # Estilo para título
        title_style = ParagraphStyle(
            'FacturaTitle',
            parent=styles['Heading1'],
            fontSize=28,
            textColor=primary_color,
            spaceAfter=15,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        # Header: FACTURA centrado
        story.append(Paragraph("FACTURA", title_style))
        story.append(Spacer(1, 0.25*inch))
        
        # Información en 3 columnas (simuladas con tabla) - Formato como imagen
        info_box_style = ParagraphStyle(
            'InfoBox',
            parent=styles['Normal'],
            fontSize=8,
            leading=11,
            textColor=colors.black
        )
        
        info_header_style = ParagraphStyle(
            'InfoHeader',
            parent=styles['Normal'],
            fontSize=7,
            textColor=colors.white,
            fontName='Helvetica-Bold',
            spaceAfter=4
        )
        
        # Columna 1: Información de Factura
        info_factura_data = [
            [Paragraph('<b>Información de Factura</b>', info_header_style)],
            [Paragraph(f"<b>Fecha:</b> {escape(str(fecha_factura))}", info_box_style)],
            [Paragraph(f"<b>Cliente:</b> {escape(str(ars.get('nombre', 'N/A')))}", info_box_style)],
        ]
        if ars.get('rnc'):
            info_factura_data.append([Paragraph(f"<b>RNC:</b> {escape(str(ars.get('rnc')))}", info_box_style)])
        
        info_factura_table = Table(info_factura_data, colWidths=[2.4*inch])
        info_factura_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), primary_color),
            ('TEXTCOLOR', (0, 0), (0, 0), colors.white),
            ('BACKGROUND', (0, 1), (0, -1), colors.white),
            ('LEFTPADDING', (0, 0), (0, -1), 8),
            ('RIGHTPADDING', (0, 0), (0, -1), 8),
            ('TOPPADDING', (0, 0), (0, -1), 8),
            ('BOTTOMPADDING', (0, 0), (0, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, primary_color),  # Borde delgado
            ('BOX', (0, 0), (-1, -1), 1, primary_color),  # Borde alrededor de toda la tabla
        ]))
        
        # Columna 2: NCF
        ncf_data = [
            [Paragraph('<b>NCF</b>', info_header_style)],
            [Paragraph(f"<font color='{primary_color_hex}'>{escape(str(ncf_numero))}</font>", ParagraphStyle('NCFNumber', parent=info_box_style, fontSize=10, textColor=primary_color))],
        ]
        if ncf_tipo_descripcion:
            ncf_data.append([Paragraph(f"<b>Tipo:</b> {escape(str(ncf_tipo_descripcion))}", info_box_style)])
        if ncf_fecha_fin:
            ncf_data.append([Paragraph(f"<b>Válido hasta:</b> {escape(str(ncf_fecha_fin))}", info_box_style)])
        
        ncf_table = Table(ncf_data, colWidths=[2.4*inch])
        ncf_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), primary_color),
            ('TEXTCOLOR', (0, 0), (0, 0), colors.white),
            ('BACKGROUND', (0, 1), (0, -1), colors.white),
            ('LEFTPADDING', (0, 0), (0, -1), 8),
            ('RIGHTPADDING', (0, 0), (0, -1), 8),
            ('TOPPADDING', (0, 0), (0, -1), 8),
            ('BOTTOMPADDING', (0, 0), (0, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, primary_color),  # Borde delgado
            ('BOX', (0, 0), (-1, -1), 1, primary_color),  # Borde alrededor de toda la tabla
        ]))
        
        # Columna 3: Remitente
        remitente_data = [
            [Paragraph('<b>Remitente</b>', info_header_style)],
        ]
        if tipo_empresa == 'centro_salud':
            remitente_data.append([Paragraph(f"<b>{empresa_info.get('razon_social', empresa_info.get('nombre', 'N/A'))}</b>", info_box_style)])
            if empresa_info.get('rnc'):
                remitente_data.append([Paragraph(f"<b>RNC:</b> {empresa_info.get('rnc')}", info_box_style)])
        else:
            # Nombre del médico sin label "Médico:" - en negrita
            remitente_data.append([Paragraph(f"<b>{medico_factura.get('nombre', 'N/A')}</b>", info_box_style)])
            if medico_factura.get('especialidad'):
                especialidad_style = ParagraphStyle('Especialidad', parent=info_box_style, fontSize=7, textColor=colors.HexColor('#666'))
                remitente_data.append([Paragraph(medico_factura.get('especialidad', ''), especialidad_style)])
            if medico_factura.get('cedula'):
                remitente_data.append([Paragraph(f"<b>Código:</b> {medico_factura.get('cedula', '')}", info_box_style)])
            if medico_completo and medico_completo.get('exequatur'):
                remitente_data.append([Paragraph(f"<b>Exequátur:</b> {medico_completo.get('exequatur', '')}", info_box_style)])
        
        remitente_table = Table(remitente_data, colWidths=[2.4*inch])
        remitente_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), primary_color),
            ('TEXTCOLOR', (0, 0), (0, 0), colors.white),
            ('BACKGROUND', (0, 1), (0, -1), colors.white),
            ('LEFTPADDING', (0, 0), (0, -1), 8),
            ('RIGHTPADDING', (0, 0), (0, -1), 8),
            ('TOPPADDING', (0, 0), (0, -1), 8),
            ('BOTTOMPADDING', (0, 0), (0, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, primary_color),  # Borde delgado
            ('BOX', (0, 0), (-1, -1), 1, primary_color),  # Borde alrededor de toda la tabla
        ]))
        
        # Combinar las 3 columnas en una tabla con espaciado entre columnas
        info_combined = Table([[info_factura_table, ncf_table, remitente_table]], colWidths=[2.4*inch, 2.4*inch, 2.4*inch])
        info_combined.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 0),
            ('RIGHTPADDING', (0, 0), (-1, -1), 0),
            ('TOPPADDING', (0, 0), (-1, -1), 0),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ]))
        story.append(info_combined)
        story.append(Spacer(1, 0.25*inch))
        
        # Tabla de pacientes/servicios
        if pacientes:
            tabla_headers = ['No.', 'NOMBRES PACIENTE', 'NSS/CONTRATO', 'FECHA', 'AUTORIZACIÓN', 'SERVICIO', 'V/UNITARIO']
            tabla_data = [tabla_headers]
            
            for idx, paciente in enumerate(pacientes, 1):
                monto = float(paciente.get('monto') or paciente.get('monto_estimado', 0) or 0)
                tabla_data.append([
                    str(idx),
                    Paragraph(f"<b>{escape(str(paciente.get('nombre_paciente', 'N/A')))}</b>", info_box_style),
                    escape(str(paciente.get('nss', ''))),
                    escape(str(paciente.get('fecha_servicio', ''))),
                    escape(str(paciente.get('autorizacion', ''))),
                    escape(str(paciente.get('descripcion_servicio', ''))),
                    Paragraph(f"<b>{monto:,.2f}</b>", ParagraphStyle('Monto', parent=info_box_style, alignment=TA_RIGHT, fontName='Helvetica-Bold'))
                ])
            
            # Ajustar anchos de columnas según la imagen: No. (4%), NOMBRES (30%), NSS (10%), FECHA (12%), AUTORIZACIÓN (12%), SERVICIO (20%), V/UNITARIO (12%)
            # Ancho total disponible: ~7.5 inch (letter size - márgenes)
            tabla = Table(tabla_data, colWidths=[0.3*inch, 2.25*inch, 0.75*inch, 0.9*inch, 0.9*inch, 1.5*inch, 0.9*inch])
            tabla.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), primary_color),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 7),
                ('ALIGN', (0, 0), (0, -1), 'CENTER'),  # No.
                ('ALIGN', (3, 1), (3, -1), 'CENTER'),  # FECHA
                ('ALIGN', (6, 1), (6, -1), 'RIGHT'),  # V/UNITARIO
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#DDD')),
                ('LEFTPADDING', (0, 0), (-1, -1), 4),
                ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('FONTSIZE', (0, 1), (-1, -1), 7),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            story.append(tabla)
        
        story.append(Spacer(1, 0.25*inch))
        
        # Totales - alineados a la derecha
        total_style = ParagraphStyle('Total', parent=styles['Normal'], fontSize=9, alignment=TA_RIGHT, fontName='Helvetica-Bold')
        total_label_style = ParagraphStyle('TotalLabel', parent=styles['Normal'], fontSize=9, alignment=TA_RIGHT, fontName='Helvetica-Bold')
        total_final_style = ParagraphStyle('TotalFinal', parent=styles['Normal'], fontSize=12, alignment=TA_RIGHT, fontName='Helvetica-Bold', textColor=primary_color)
        
        # Crear tabla de totales alineada a la derecha
        totales_data = [
            [Paragraph('SUB-TOTAL:', total_label_style), Paragraph(f"{subtotal:,.2f}", total_style)],
            [Paragraph('ITBIS:', total_label_style), Paragraph('*E', total_style)],
            [Paragraph('TOTAL:', total_label_style), Paragraph(f"{total:,.2f}", total_final_style)],
        ]
        
        # Tabla de totales más ancha y alineada a la derecha
        totales_table = Table(totales_data, colWidths=[1.2*inch, 1.2*inch])
        totales_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LINEABOVE', (0, -1), (-1, -1), 1, primary_color),
            ('TOPPADDING', (0, -1), (-1, -1), 8),
        ]))
        
        # Contenedor para alinear totales a la derecha
        from reportlab.platypus import KeepTogether
        totales_container = Table([[totales_table]], colWidths=[7.5*inch])
        totales_container.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, 0), 'RIGHT'),
            ('VALIGN', (0, 0), (0, 0), 'TOP'),
        ]))
        story.append(totales_container)
        
        story.append(Spacer(1, 0.4*inch))
        
        # Footer
        footer_style = ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, alignment=TA_CENTER, textColor=colors.HexColor('#666'))
        footer_bold_style = ParagraphStyle('FooterBold', parent=styles['Normal'], fontSize=9, alignment=TA_CENTER, textColor=primary_color, fontName='Helvetica-Bold')
        
        if tipo_empresa == 'centro_salud':
            footer_data = [
                [Paragraph(f"<b>{empresa_info.get('razon_social', empresa_info.get('nombre', 'N/A'))}</b>", footer_bold_style)],
            ]
            if empresa_info.get('direccion'):
                footer_data.append([Paragraph(empresa_info.get('direccion', ''), footer_style)])
            footer_text = []
            if empresa_info.get('rnc'):
                footer_text.append(f"RNC: {empresa_info.get('rnc')}")
            if empresa_info.get('telefono'):
                footer_text.append(f"Tel: {empresa_info.get('telefono')}")
            if empresa_info.get('email'):
                footer_text.append(f"Email: {empresa_info.get('email')}")
            if footer_text:
                footer_data.append([Paragraph(' | '.join(footer_text), footer_style)])
        else:
            # Footer para médico - formato como ejemplo del PDF
            footer_data = [
                [Paragraph(f"<b>{medico_factura.get('nombre', 'N/A')}</b>", footer_bold_style)],
            ]
            
            # Segunda línea: Especialidad | Cédula | EXEQUATUR (en mayúsculas)
            footer_text_line1 = []
            if medico_factura.get('especialidad'):
                footer_text_line1.append(medico_factura.get('especialidad', ''))
            if medico_factura.get('cedula'):
                footer_text_line1.append(f"Cédula: {medico_factura.get('cedula', '')}")
            if medico_completo and medico_completo.get('exequatur'):
                footer_text_line1.append(f"EXEQUATUR: {medico_completo.get('exequatur', '')}")
            if footer_text_line1:
                footer_data.append([Paragraph(' | '.join(footer_text_line1), footer_style)])
            
            # Tercera línea: Dirección del centro médico (si está disponible)
            if centro_medico and centro_medico.get('nombre'):
                centro_text = centro_medico.get('nombre', '')
                if centro_medico.get('direccion'):
                    centro_text += f", {centro_medico.get('direccion', '')}"
                footer_data.append([Paragraph(centro_text, footer_style)])
        
        footer_table = Table(footer_data, colWidths=[7*inch])
        footer_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, -1), 'CENTER'),
            ('TOPPADDING', (0, 0), (0, -1), 4),
            ('BOTTOMPADDING', (0, 0), (0, -1), 4),
        ]))
        story.append(footer_table)
        
        # Construir PDF
        try:
            logger.info(f"Construyendo PDF para factura {factura_id} con {len(story)} elementos en story")
            doc.build(story)
            logger.info(f"PDF construido exitosamente para factura {factura_id}")
            
            # Obtener el contenido del buffer y crear un nuevo BytesIO para retornar
            buffer.seek(0)
            buffer_content = buffer.read()
            
            # Verificar que el buffer tiene contenido
            buffer_size = len(buffer_content) if buffer_content else 0
            if buffer_size == 0:
                logger.error(f"PDF generado para factura {factura_id} está vacío (buffer_size=0)")
                return None
            
            # Crear un nuevo BytesIO con el contenido del PDF para evitar problemas de lectura
            pdf_buffer = BytesIO(buffer_content)
            pdf_buffer.seek(0)
            
            logger.info(f"PDF generado exitosamente para factura {factura_id}, tamaño: {buffer_size} bytes")
            return pdf_buffer
        except Exception as build_error:
            import traceback
            error_trace = traceback.format_exc()
            logger.error(f"Error al construir PDF para factura {factura_id}: {error_trace}")
            print(f"Error al construir PDF para factura {factura_id}: {str(build_error)}")
            print(f"Traceback: {error_trace}")
            return None
        
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        logger.error(f"Error al generar PDF para factura {factura_id}: {error_trace}")
        logger.error(f"Tipo de error: {type(e).__name__}, Mensaje: {str(e)}")
        print(f"ERROR CRÍTICO al generar PDF para factura {factura_id}: {str(e)}")
        print(f"Traceback completo: {error_trace}")
        # También imprimir información de debug
        print(f"DEBUG - factura encontrada: {factura is not None}")
        print(f"DEBUG - detalles encontrados: {len(detalles) if detalles else 0}")
        print(f"DEBUG - pacientes procesados: {len(pacientes) if 'pacientes' in locals() else 'N/A'}")
        return None

@app.route('/facturacion/facturas/<int:factura_id>/pdf')
@login_required
def facturacion_descargar_pdf(factura_id):
    """Descargar PDF de factura"""
    if not REPORTLAB_AVAILABLE:
        flash('ReportLab no está disponible. Por favor, instale la librería reportlab.', 'error')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))
    
    tenant_id = get_current_tenant_id()
    if not validate_tenant_access('facturas', factura_id):
        flash('No tienes acceso a esta factura', 'error')
        return redirect(url_for('facturacion_historico'))
    
    try:
        factura_check = execute_query(
            'SELECT id FROM facturas WHERE id = %s AND tenant_id = %s',
            (factura_id, tenant_id),
        )
        
        if not factura_check:
            flash('La factura no existe o no tiene permisos para acceder a ella.', 'error')
            return redirect(url_for('facturacion_historico'))
        
        logger.info(f"Iniciando descarga de PDF para factura {factura_id}, tenant_id={tenant_id}")
        print(f"=== INICIANDO DESCARGA PDF FACTURA {factura_id} ===")
        
        factura_data = execute_query(
            '''
            SELECT id, ncf, fecha_emision, ars_id, subtotal, total
            FROM facturas
            WHERE id = %s AND tenant_id = %s
            ''',
            (factura_id, tenant_id),
        )
        
        if factura_data:
            logger.info(f"Datos de factura {factura_id}: ncf={factura_data.get('ncf')}, fecha={factura_data.get('fecha_emision')}, ars_id={factura_data.get('ars_id')}")
            print(f"Factura encontrada: ncf={factura_data.get('ncf')}, fecha={factura_data.get('fecha_emision')}, ars_id={factura_data.get('ars_id')}")
        else:
            logger.error(f"No se encontraron datos básicos de factura {factura_id}")
            print(f"ERROR: No se encontraron datos básicos de factura {factura_id}")
        
        detalles_check = execute_query(
            '''
            SELECT COUNT(*) as count
            FROM factura_detalles
            WHERE factura_id = %s AND tenant_id = %s
            ''',
            (factura_id, tenant_id),
        )
        detalles_count = detalles_check.get('count', 0) if detalles_check else 0
        logger.info(f"Factura {factura_id} tiene {detalles_count} detalles")
        print(f"Detalles encontrados: {detalles_count}")
        
        if detalles_count == 0:
            logger.error(f"Factura {factura_id} no tiene detalles. No se puede generar PDF.")
            print(f"ERROR: Factura {factura_id} no tiene detalles")
            flash('Error: La factura no tiene detalles asociados. No se puede generar el PDF.', 'error')
            return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))
        
        print(f"Llamando a generar_pdf_factura_vista_previa para factura {factura_id}...")
        buffer = generar_pdf_factura_vista_previa(factura_id, tenant_id)
        
        if buffer is None:
            logger.error(f"No se pudo generar PDF para factura {factura_id}")
            print(f"ERROR: generar_pdf_factura_vista_previa retornó None para factura {factura_id}")
            flash('Error al generar PDF. Verifique que la factura tiene datos válidos y detalles asociados.', 'error')
            return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))
        
        print(f"PDF generado exitosamente. Buffer tipo: {type(buffer)}")
        
        # Verificar que el buffer tiene contenido y prepararlo para envío
        try:
            # Asegurarse de que el buffer esté al inicio
            buffer.seek(0)
            
            # Verificar que el buffer tiene contenido sin leerlo (para no consumirlo)
            buffer_size = len(buffer.getvalue()) if hasattr(buffer, 'getvalue') else 0
            
            if buffer_size == 0:
                logger.error(f"PDF generado para factura {factura_id} está vacío en facturacion_descargar_pdf")
                flash('Error: El PDF generado está vacío.', 'error')
                return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))
            
            logger.info(f"PDF listo para descarga: factura {factura_id}, tamaño: {buffer_size} bytes")
            
            # Asegurarse de que el buffer esté al inicio antes de enviarlo
            buffer.seek(0)
            
            factura = execute_query(
                '''
                SELECT numero_factura
                FROM facturas
                WHERE id = %s AND tenant_id = %s
                ''',
                (factura_id, tenant_id),
            )
            filename = f"factura_{factura_id}_{factura.get('numero_factura', '') if factura else ''}.pdf"
            
            logger.info(f"Enviando PDF: factura {factura_id}, filename={filename}")
            return send_file(buffer, mimetype='application/pdf', as_attachment=True, download_name=filename)
        except Exception as buffer_error:
            import traceback
            error_trace = traceback.format_exc()
            logger.error(f"Error al preparar/enviar buffer para factura {factura_id}: {str(buffer_error)}")
            logger.error(f"Traceback: {error_trace}")
            flash(f'Error al generar/enviar PDF: {str(buffer_error)}', 'error')
            return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        logger.error(f"Error en facturacion_descargar_pdf para factura {factura_id}: {error_trace}")
        flash(f'Error al generar PDF: {str(e)}', 'error')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))

@app.route('/facturacion/facturas/<int:factura_id>/enviar-email', methods=['POST'])
@login_required
@roles_required('Administrador', 'Nivel 2')
def facturacion_enviar_email(factura_id):
    """Enviar factura por email"""
    tenant_id = get_current_tenant_id()
    if not validate_tenant_access('facturas', factura_id):
        flash('No tienes acceso a esta factura', 'error')
        return redirect(url_for('facturacion_historico'))
    
    # Obtener email del destinatario
    destinatario = request.form.get('destinatario', '').strip()
    if not destinatario:
        flash('Debe especificar un email destinatario', 'error')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))
    
    # Validar email
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, destinatario):
        flash('Email inválido', 'error')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))
    
    factura = execute_query('''
        SELECT f.*, a.nombre as nombre_ars, a.rnc as ars_rnc,
               m.nombre as medico_nombre, m.especialidad as medico_especialidad,
               m.cedula as medico_cedula, m.exequatur as medico_exequatur,
               m.email as medico_email
        FROM facturas f
        LEFT JOIN ars a
          ON f.ars_id = a.id AND a.tenant_id = f.tenant_id
        LEFT JOIN medicos m
          ON f.medico_id = m.id AND m.tenant_id = f.tenant_id
        WHERE f.id = %s AND f.tenant_id = %s
    ''', (factura_id, tenant_id))
    
    if not factura:
        flash('Factura no encontrada', 'error')
        return redirect(url_for('facturacion_historico'))
    
    # Si SendGrid está disponible, enviar email
    if SENDGRID_AVAILABLE and REPORTLAB_AVAILABLE:
        try:
            # Generar PDF usando la función auxiliar
            buffer = generar_pdf_factura_vista_previa(factura_id, tenant_id)
            
            if not buffer:
                flash('Error al generar PDF', 'error')
                return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))
            
            pdf_data = buffer.getvalue()
            
            # Enviar email con SendGrid
            sendgrid_api_key = os.getenv('SENDGRID_API_KEY')
            sendgrid_from_email = os.getenv('SENDGRID_FROM_EMAIL', 'noreply@facturacion.com')
            
            if not sendgrid_api_key:
                flash('Configuración de email no disponible. Contacte al administrador.', 'error')
                return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))
            
            message = Mail(
                from_email=sendgrid_from_email,
                to_emails=destinatario,
                subject=f"Factura #{factura.get('numero_factura', factura_id)} - {factura.get('nombre_ars', 'N/A')}",
                html_content=f"""
                <html>
                <body>
                    <h2>Factura #{factura.get('numero_factura', factura_id)}</h2>
                    <p><strong>Fecha:</strong> {factura.get('fecha_emision', '')}</p>
                    <p><strong>NCF:</strong> {factura.get('ncf', '')}</p>
                    <p><strong>Cliente:</strong> {factura.get('nombre_ars', 'N/A')}</p>
                    <p><strong>Total:</strong> RD$ {factura.get('total', 0):,.2f}</p>
                    <p>Se adjunta el PDF de la factura.</p>
                </body>
                </html>
                """
            )
            
            # Adjuntar PDF
            encoded_pdf = base64.b64encode(pdf_data).decode()
            attachment = {
                'content': encoded_pdf,
                'filename': f"factura_{factura_id}_{factura.get('numero_factura', '')}.pdf",
                'type': 'application/pdf',
                'disposition': 'attachment'
            }
            message.attachment = attachment
            
            sg = SendGridAPIClient(sendgrid_api_key)
            response = sg.send(message)
            
            if response.status_code in [200, 202]:
                flash(f'Factura enviada exitosamente a {destinatario}', 'success')
            else:
                flash(f'Error al enviar email. Código: {response.status_code}', 'error')
            
        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            print(f"Error al enviar email: {error_trace}")
            flash(f'Error al enviar email: {str(e)}', 'error')
    else:
        flash('El servicio de envío de emails no está disponible. Contacte al administrador.', 'error')
    
    return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))

@app.route('/facturacion/dashboard')
@login_required
def facturacion_dashboard():
    """Dashboard de facturación"""
    from datetime import datetime, timedelta
    
    # Fechas por defecto (último mes)
    fecha_hasta = request.args.get('fecha_hasta', datetime.now().strftime('%Y-%m-%d'))
    fecha_desde = request.args.get('fecha_desde', (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d'))
    
    # Estadísticas básicas
    total_facturas = 0
    total_facturado = 0.0
    monto_pendiente = 0.0
    ars_pendientes_nombres = []
    
    try:
        tenant_id = get_current_tenant_id()
        
        # Total de facturas
        result = execute_query('''
            SELECT COUNT(*) as total FROM facturas 
            WHERE tenant_id = %s
        ''', (tenant_id,))
        total_facturas = result['total'] if result else 0
        
        # Total facturado
        result = execute_query('''
            SELECT COALESCE(SUM(total), 0) as total FROM facturas 
            WHERE tenant_id = %s
        ''', (tenant_id,))
        total_facturado = float(result['total']) if result and result['total'] else 0.0
        
        # Monto pendiente (si existe tabla pacientes con monto)
        try:
            result = execute_query('''
                SELECT COALESCE(SUM(monto), 0) as total FROM pacientes 
                WHERE tenant_id = %s
            ''', (tenant_id,))
            monto_pendiente = float(result['total']) if result and result['total'] else 0.0
        except:
            monto_pendiente = 0.0
        
        # ARS pendientes
        result = execute_query('''
            SELECT DISTINCT a.nombre 
            FROM pacientes_pendientes pp 
            JOIN ars a
              ON pp.ars_id = a.id
             AND a.tenant_id = pp.tenant_id
            WHERE pp.estado = 'Pendiente'
              AND pp.tenant_id = %s
        ''', (tenant_id,), fetch='all')
        ars_pendientes_nombres = [r['nombre'] for r in result] if result else []
        
    except Exception as e:
        print(f"Error en dashboard: {e}")
    
    # Facturación por mes
    facturacion_por_mes = []
    try:
        result = execute_query('''
            SELECT DATE_FORMAT(fecha_emision, '%%Y-%%m') as mes, 
                   SUM(total) as total_monto
            FROM facturas
            WHERE fecha_emision BETWEEN %s AND %s
              AND tenant_id = %s
            GROUP BY DATE_FORMAT(fecha_emision, '%%Y-%%m')
            ORDER BY mes
        ''', (fecha_desde, fecha_hasta, tenant_id), fetch='all')
        facturacion_por_mes = [{'mes': r['mes'], 'total_monto': float(r['total_monto'])} for r in result] if result else []
    except:
        facturacion_por_mes = []
    
    # Facturación por ARS y mes
    facturacion_ars_mes = []
    try:
        result = execute_query('''
            SELECT DATE_FORMAT(f.fecha_emision, '%%Y-%%m') as mes,
                   a.nombre as nombre_ars,
                   SUM(f.total) as total_monto
            FROM facturas f
            JOIN ars a
              ON f.ars_id = a.id
             AND a.tenant_id = f.tenant_id
            WHERE f.fecha_emision BETWEEN %s AND %s
              AND f.tenant_id = %s
            GROUP BY DATE_FORMAT(f.fecha_emision, '%%Y-%%m'), a.nombre
            ORDER BY mes, a.nombre
        ''', (fecha_desde, fecha_hasta, tenant_id), fetch='all')
        facturacion_ars_mes = [{'mes': r['mes'], 'nombre_ars': r['nombre_ars'], 'total_monto': float(r['total_monto'])} for r in result] if result else []
    except:
        facturacion_ars_mes = []
    
    # Listas para filtros
    tenant_id = get_current_tenant_id()
    ars_list = execute_query('SELECT * FROM ars WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    medicos_factura_list = execute_query('SELECT * FROM medicos WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    medicos_consulta_list = medicos_factura_list  # Usar la misma lista
    
    return render_template('facturacion/dashboard.html',
                          total_facturas=total_facturas,
                          total_facturado=total_facturado,
                          monto_pendiente=monto_pendiente,
                          ars_pendientes_nombres=ars_pendientes_nombres,
                          facturacion_por_mes=facturacion_por_mes,
                          facturacion_ars_mes=facturacion_ars_mes,
                          ars_list=ars_list,
                          medicos_factura_list=medicos_factura_list,
                          medicos_consulta_list=medicos_consulta_list,
                          fecha_desde=fecha_desde,
                          fecha_hasta=fecha_hasta,
                          es_administrador=(current_user.perfil == 'Administrador'),
                          ars_ids_seleccionados=[],
                          medico_factura_ids_seleccionados=[],
                          medico_consulta_ids_seleccionados=[])

def registrar_consultas_pendientes_atomico(
    lineas,
    tenant_id,
    ars_id,
    medico_id,
    centro_medico_id,
    usuario_id,
):
    """Crear pacientes/pendientes como una unidad, sin consultas N+1."""
    normalizadas = []
    nss_vistos = set()
    for linea in lineas:
        nss = sanitize_input(linea.get('nss', ''), 50)
        nombre = sanitize_input(linea.get('nombre', ''), 200)
        if not nss or not nombre:
            continue
        if nss in nss_vistos:
            raise ValueError(f'El NSS {nss} está repetido en la carga')
        nss_vistos.add(nss)
        try:
            monto = Decimal(str(linea.get('monto', 0))).quantize(
                Decimal('0.01')
            )
        except (InvalidOperation, TypeError, ValueError):
            raise ValueError(f'El monto del paciente {nombre} no es válido')
        if monto < 0:
            raise ValueError(f'El monto del paciente {nombre} no puede ser negativo')
        normalizadas.append({
            'nss': nss,
            'nombre': nombre,
            'fecha': linea.get('fecha'),
            'autorizacion': sanitize_input(linea.get('autorizacion', ''), 50),
            'servicio': sanitize_input(linea.get('servicio', ''), 200),
            'monto': monto,
        })

    if not normalizadas:
        raise ValueError('No hay pacientes válidos para registrar')

    with database_transaction():
        placeholders = ','.join(['%s'] * len(normalizadas))
        existentes = execute_query(f'''
            SELECT id, nss, cedula, fecha_nacimiento
            FROM pacientes
            WHERE tenant_id = %s AND ars_id = %s
              AND nss IN ({placeholders})
            FOR UPDATE
        ''', (
            tenant_id,
            ars_id,
            *[linea['nss'] for linea in normalizadas],
        ), fetch='all') or []
        pacientes_por_nss = {paciente['nss']: paciente for paciente in existentes}

        for linea in normalizadas:
            paciente = pacientes_por_nss.get(linea['nss'])
            if paciente:
                if paciente_adulto_sin_cedula(paciente):
                    raise ValueError(
                        f"{linea['nombre']} ya cumplió 18 años y requiere "
                        'registrar su cédula antes de continuar'
                    )
                paciente_id = paciente['id']
                execute_update('''
                    UPDATE pacientes
                    SET nombre = %s, updated_at = NOW()
                    WHERE id = %s AND tenant_id = %s
                ''', (linea['nombre'], paciente_id, tenant_id))
            else:
                paciente_id = execute_update('''
                    INSERT INTO pacientes
                    (tenant_id, nombre, nss, ars_id, created_by)
                    VALUES (%s, %s, %s, %s, %s)
                ''', (
                    tenant_id, linea['nombre'], linea['nss'],
                    ars_id, usuario_id
                ))
                if not paciente_id:
                    raise RuntimeError('No se pudo crear el paciente')
                pacientes_por_nss[linea['nss']] = {
                    'id': paciente_id,
                    'nss': linea['nss'],
                }

            servicios = linea['servicio']
            if linea['autorizacion']:
                servicios += f" - Autorización: {linea['autorizacion']}"
            pendiente_id = execute_update('''
                INSERT INTO pacientes_pendientes
                (tenant_id, paciente_id, nombre_paciente, nss, ars_id,
                 fecha_servicio, servicios_realizados, monto_estimado,
                 estado, medico_id, centro_medico_id, created_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s,
                        'Pendiente', %s, %s, %s)
            ''', (
                tenant_id, paciente_id, linea['nombre'], linea['nss'], ars_id,
                linea['fecha'], servicios, linea['monto'], medico_id,
                centro_medico_id, usuario_id
            ))
            if not pendiente_id:
                raise RuntimeError('No se pudo crear la consulta pendiente')

    return len(normalizadas)


@app.route('/facturacion/facturas/nueva', methods=['GET', 'POST'])
@login_required
def facturacion_facturas_nueva():
    """Agregar pacientes para facturar"""
    tenant_id = get_current_tenant_id()
    
    if request.method == 'POST':
        # Obtener datos del formulario
        # Validar y sanitizar entrada
        medico_id = validate_int(request.form.get('medico_id'), min_value=1)
        ars_id = validate_int(request.form.get('ars_id'), min_value=1)
        centro_medico_id = validate_int(request.form.get('centro_medico_id'), min_value=1) if request.form.get('centro_medico_id') else None
        lineas_json = request.form.get('lineas_json', '').strip()
        
        if not medico_id or not ars_id or not lineas_json:
            flash('Faltan datos obligatorios (Médico, ARS o pacientes)', 'error')
            return redirect(url_for('facturacion_facturas_nueva'))
        
        # Validar que los IDs pertenezcan al tenant
        tenant_id = get_current_tenant_id()
        if not validate_tenant_access('medicos', medico_id) or \
           not validate_tenant_access('ars', ars_id):
            flash('No tienes acceso a uno o más de los recursos seleccionados', 'error')
            return redirect(url_for('facturacion_facturas_nueva'))
        
        if centro_medico_id and not validate_tenant_access('centros_medicos', centro_medico_id):
            flash('Centro médico no válido', 'error')
            return redirect(url_for('facturacion_facturas_nueva'))
        
        # Validar JSON
        try:
            import json
            lineas = json.loads(lineas_json)
            # Limitar número de pacientes por request (prevenir DoS)
            if len(lineas) > 1000:
                flash('Demasiados pacientes en una sola operación (máximo 1000)', 'error')
                return redirect(url_for('facturacion_facturas_nueva'))
        except json.JSONDecodeError as e:
            logger.error(f"Error al parsear JSON: {e}")
            flash('Error al procesar los datos de los pacientes', 'error')
            return redirect(url_for('facturacion_facturas_nueva'))
        
        if not lineas or len(lineas) == 0:
            flash('Debe agregar al menos un paciente', 'error')
            return redirect(url_for('facturacion_facturas_nueva'))
        
        try:
            pacientes_agregados = registrar_consultas_pendientes_atomico(
                lineas,
                tenant_id,
                ars_id,
                medico_id,
                centro_medico_id,
                current_user.id,
            )
        except ValueError as error:
            flash(str(error), 'error')
            return redirect(url_for('facturacion_facturas_nueva'))
        except Exception:
            logger.error(
                'Error al registrar consultas pendientes',
                exc_info=True,
            )
            flash(
                'No se pudo completar el registro. No se aplicó ningún cambio.',
                'error',
            )
            return redirect(url_for('facturacion_facturas_nueva'))
        
        flash(f'{pacientes_agregados} paciente(s) agregado(s) como pendientes de facturación', 'success')
        return redirect(url_for('facturacion_pacientes_pendientes'))
    
    # GET: Mostrar formulario
    ars_list = execute_query('SELECT * FROM ars WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    medicos = execute_query('SELECT * FROM medicos WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    
    # Obtener relaciones médico-centro para poblar el dropdown de centros médicos
    centros_medicos = execute_query('''
        SELECT 
            mc.medico_id,
            mc.centro_medico_id as centro_id,
            cm.nombre as centro_nombre,
            mc.es_defecto
        FROM medico_centro mc
        INNER JOIN centros_medicos cm
          ON mc.centro_medico_id = cm.id AND cm.tenant_id = mc.tenant_id
        WHERE mc.tenant_id = %s AND cm.activo = 1
        ORDER BY mc.medico_id, mc.es_defecto DESC, cm.nombre
    ''', (tenant_id,), fetch='all') or []
    
    # Obtener servicios para el datalist
    servicios_list = execute_query('''
        SELECT descripcion, precio_base 
        FROM servicios 
        WHERE tenant_id = %s AND activo = 1 
        ORDER BY descripcion
    ''', (tenant_id,), fetch='all') or []

    paciente_preseleccionado = None
    paciente_id = validate_int(request.args.get('paciente_id'), min_value=1, default=None)
    if paciente_id:
        paciente_preseleccionado = execute_query(
            'SELECT id, nombre, cedula, fecha_nacimiento, nss, ars_id '
            'FROM pacientes WHERE id=%s AND tenant_id=%s',
            (paciente_id, tenant_id)
        )
        if paciente_adulto_sin_cedula(paciente_preseleccionado):
            flash('Debe actualizar la cédula propia del paciente antes de registrar la consulta', 'warning')
            return redirect(url_for('facturacion_paciente_acciones', paciente_id=paciente_id))
    
    return render_template('facturacion/facturas_form.html', 
                         ars_list=ars_list, 
                         medicos=medicos, 
                         centros_medicos=centros_medicos,
                         servicios_list=servicios_list,
                         paciente_preseleccionado=paciente_preseleccionado)

@app.route('/facturacion/pacientes-pendientes')
@login_required
def facturacion_pacientes_pendientes():
    """Estado de facturación - Pacientes pendientes"""
    # Obtener filtros de la query string
    medico_id_filtro = request.args.get('medico_id', '')
    ars_id_filtro = request.args.get('ars_id', '')
    estado_filtro = request.args.get('estado', 'pendiente')  # Por defecto 'pendiente'
    
    # Construir query con filtros - consultar tabla pacientes_pendientes
    tenant_id = get_current_tenant_id()
    
    # Construir query base
    query = '''
        SELECT pp.*, 
               a.nombre as nombre_ars,
               m.nombre as medico_nombre,
               m.especialidad as medico_especialidad,
               pp.servicios_realizados as descripcion_servicio,
               pp.monto_estimado as monto
        FROM pacientes_pendientes pp
        LEFT JOIN ars a
          ON pp.ars_id = a.id AND a.tenant_id = pp.tenant_id
        LEFT JOIN medicos m
          ON pp.medico_id = m.id AND m.tenant_id = pp.tenant_id
        WHERE pp.tenant_id = %s
    '''
    params = [tenant_id]
    
    # Filtro por estado
    if estado_filtro:
        # Convertir 'pendiente' a 'Pendiente' y 'facturado' a 'Facturado'
        estado_db = estado_filtro.capitalize()
        if estado_db == 'Facturado':
            query += ' AND pp.estado = %s'
            params.append('Facturado')
        elif estado_db == 'Pendiente':
            query += ' AND pp.estado = %s'
            params.append('Pendiente')
    
    # Filtro por médico
    if medico_id_filtro:
        medico_id_filtro = validate_int(
            medico_id_filtro, min_value=1, default=None
        )
        query += ' AND pp.medico_id = %s'
        params.append(medico_id_filtro)
    
    # Filtro por ARS
    if ars_id_filtro:
        ars_id_filtro = validate_int(
            ars_id_filtro, min_value=1, default=None
        )
        query += ' AND pp.ars_id = %s'
        params.append(ars_id_filtro)
    
    pendientes, pagination = execute_paginated_query(
        query,
        params,
        'pp.fecha_servicio DESC, pp.id DESC',
        default_per_page=50,
    )
    
    # Obtener listas para filtros
    medicos = execute_query('SELECT * FROM medicos WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    ars_list = execute_query('SELECT * FROM ars WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    
    # Obtener nombres para mostrar en los badges de filtros activos
    medico_seleccionado = None
    if medico_id_filtro:
        medico = execute_query(
            'SELECT nombre FROM medicos WHERE id = %s AND tenant_id = %s',
            (medico_id_filtro, tenant_id),
        )
        if medico:
            medico_seleccionado = medico['nombre']
    
    ars_seleccionada = None
    if ars_id_filtro:
        ars = execute_query(
            'SELECT nombre FROM ars WHERE id = %s AND tenant_id = %s',
            (ars_id_filtro, tenant_id),
        )
        if ars:
            ars_seleccionada = ars['nombre']
    
    # Obtener servicios para el combobox
    servicios_list = execute_query('''
        SELECT descripcion, precio_base 
        FROM servicios 
        WHERE tenant_id = %s AND activo = 1 
        ORDER BY descripcion
    ''', (tenant_id,), fetch='all') or []
    
    return render_template('facturacion/pacientes_pendientes.html', 
                          pendientes=pendientes,
                          medicos=medicos,
                          ars_list=ars_list,
                          servicios_list=servicios_list,
                          medico_id_filtro=medico_id_filtro,
                          ars_id_filtro=ars_id_filtro,
                          estado_filtro=estado_filtro,
                          medico_seleccionado=medico_seleccionado,
                          ars_seleccionada=ars_seleccionada,
                          pagination=pagination)

@app.route('/facturacion/pacientes-pendientes/pdf')
@login_required
def facturacion_pacientes_pendientes_pdf():
    """Descargar PDF de pacientes pendientes"""
    flash('Funcionalidad de PDF en desarrollo', 'info')
    return redirect(url_for('facturacion_pacientes_pendientes'))

@app.route('/descargar-plantilla-excel')
@login_required
def descargar_plantilla_excel():
    """Descargar plantilla Excel para importar pacientes"""
    try:
        if not OPENPYXL_AVAILABLE:
            flash('La funcionalidad de Excel no está disponible', 'error')
            return redirect(url_for('facturacion_facturas_nueva'))
        
        tenant_id = get_current_tenant_id()
        if tenant_id is None:
            flash('Error al obtener el tenant', 'error')
            return redirect(url_for('facturacion_facturas_nueva'))
        
        # Obtener tema del usuario
        TEMAS = {
            'cyan': {'primary': '#06B6D4', 'primary_dark': '#0891B2'},
            'ocean': {'primary': '#0EA5E9', 'primary_dark': '#0284C7'},
            'emerald': {'primary': '#10B981', 'primary_dark': '#059669'},
            'teal': {'primary': '#14B8A6', 'primary_dark': '#0D9488'},
            'coral': {'primary': '#FF6B6B', 'primary_dark': '#EE5A52'},
            'sunset': {'primary': '#F59E0B', 'primary_dark': '#D97706'},
            'rose': {'primary': '#F43F5E', 'primary_dark': '#E11D48'},
            'amber': {'primary': '#F59E0B', 'primary_dark': '#D97706'},
            'indigo': {'primary': '#6366F1', 'primary_dark': '#4F46E5'},
            'purple': {'primary': '#A855F7', 'primary_dark': '#9333EA'},
            'violet': {'primary': '#8B5CF6', 'primary_dark': '#7C3AED'},
            'slate': {'primary': '#64748B', 'primary_dark': '#475569'},
            'navy': {'primary': '#1E3A8A', 'primary_dark': '#1E40AF'},
            'forest': {'primary': '#166534', 'primary_dark': '#14532D'},
            'wine': {'primary': '#7F1D1D', 'primary_dark': '#991B1B'},
            'bronze': {'primary': '#92400E', 'primary_dark': '#78350F'}
        }
        
        tema_actual = 'cyan'  # Default
        if current_user.is_authenticated and hasattr(current_user, 'tema_color') and current_user.tema_color:
            tema_actual = current_user.tema_color
        
        # Asegurar que tema_actual sea válido
        if tema_actual not in TEMAS:
            tema_actual = 'cyan'
        
        tema = TEMAS.get(tema_actual, TEMAS['cyan'])
        if not tema or 'primary' not in tema:
            tema = TEMAS['cyan']
        
        color_primary = tema.get('primary', '#06B6D4')
        if not color_primary:
            color_primary = '#06B6D4'
        
        # Convertir color hexadecimal a formato de openpyxl (sin #)
        color_hex_clean = color_primary.lstrip('#')
        if not color_hex_clean:
            color_hex_clean = '06B6D4'
        
        # Convertir color hexadecimal a RGB
        def hex_to_rgb(hex_color):
            if not hex_color:
                hex_color = '#06B6D4'
            hex_color = hex_color.lstrip('#')
            if not hex_color or len(hex_color) < 6:
                hex_color = '06B6D4'
            try:
                return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
            except Exception:
                return (6, 182, 212)  # Color cyan por defecto
        
        rgb_color = hex_to_rgb(color_primary)
        
        # Obtener servicios activos del tenant
        try:
            servicios_result = execute_query(
                'SELECT descripcion FROM servicios WHERE tenant_id = %s AND activo = 1 ORDER BY descripcion', 
                (tenant_id,), fetch='all'
            )
            if servicios_result is None:
                servicios_list = []
            elif isinstance(servicios_result, list):
                servicios_list = [s for s in servicios_result if s and isinstance(s, dict)]
            else:
                servicios_list = []
        except Exception as e:
            servicios_list = []
        
        # Crear workbook
        wb = Workbook()
        
        # Eliminar hoja por defecto (si existe)
        if wb.active is not None:
            try:
                wb.remove(wb.active)
            except Exception:
                pass  # Si hay error al eliminar, continuar
    
        # ========== HOJA 1: INSTRUCCIONES ==========
        ws_instrucciones = wb.create_sheet("Instrucciones", 0)
        if ws_instrucciones is None:
            raise ValueError("No se pudo crear la hoja de Instrucciones")
        
        # Título
        title_cell = ws_instrucciones.cell(row=1, column=1, value="INSTRUCCIONES PARA CARGAR PACIENTES")
        title_cell.font = Font(bold=True, size=16, color="8B5A9F")
        ws_instrucciones.merge_cells('A1:D1')
        
        # Instrucciones numeradas
        instrucciones = [
            "Complete la hoja \"Pacientes\" con los datos de los pacientes",
            "NSS: Solo números y guiones (ej: 001-234-5678)",
            "NOMBRE: Nombre completo del paciente",
            "FECHA: Formato AAAA-MM-DD (ej: 2025-10-16)",
            "AUTORIZACIÓN: Solo números, debe ser única para cada paciente",
            "SERVICIO: Seleccione de la lista desplegable (se alimenta de la hoja \"Servicios\")",
            "MONTO: Cantidad en pesos (solo números)"
        ]
        
        row = 3
        if instrucciones and isinstance(instrucciones, list):
            for i, instruccion in enumerate(instrucciones, 1):
                if instruccion is not None:
                    num_cell = ws_instrucciones.cell(row=row, column=1, value=f"{i}.")
                    num_cell.font = Font(bold=True)
                    text_cell = ws_instrucciones.cell(row=row, column=2, value=instruccion)
                    ws_instrucciones.merge_cells(f'B{row}:D{row}')
                    row += 1
        
        # Sección IMPORTANTE
        row += 1
        importante_cell = ws_instrucciones.cell(row=row, column=1, value="IMPORTANTE:")
        importante_cell.font = Font(bold=True, size=12, color="8B5A9F")
        row += 1
        
        importantes = [
            "Los encabezados están protegidos y NO se pueden modificar",
            "La columna SERVICIO tiene lista desplegable - haga clic en la flecha para seleccionar",
            "Cada autorización debe ser única",
            "Complete directamente desde la fila 2"
        ]
        
        if importantes and isinstance(importantes, list):
            for importante in importantes:
                if importante is not None:
                    bullet_cell = ws_instrucciones.cell(row=row, column=1, value="•")
                    bullet_cell.font = Font(bold=True)
                    text_cell = ws_instrucciones.cell(row=row, column=2, value=importante)
                    ws_instrucciones.merge_cells(f'B{row}:D{row}')
                    row += 1
        
        # Sección NOTA
        row += 1
        nota_title = ws_instrucciones.cell(row=row, column=1, value="NOTA:")
        nota_title.font = Font(bold=True, size=12, color="8B5A9F")
        row += 1
        nota_text = ws_instrucciones.cell(row=row, column=1, value="Antes de cargar, debe seleccionar el Médico y ARS en la página web")
        ws_instrucciones.merge_cells(f'A{row}:D{row}')
        
        # Ajustar ancho de columnas
        ws_instrucciones.column_dimensions['A'].width = 5
        ws_instrucciones.column_dimensions['B'].width = 80
        ws_instrucciones.column_dimensions['C'].width = 10
        ws_instrucciones.column_dimensions['D'].width = 10
        
        # Proteger hoja de instrucciones
        try:
            if ws_instrucciones is not None:
                # Iterar sobre las filas que tienen datos
                rows_iter = ws_instrucciones.iter_rows(min_row=1, max_row=100)
                if rows_iter is not None:
                    for row in rows_iter:
                        if row is not None:
                            for cell in row:
                                if cell is not None:
                                    cell.protection = Protection(locked=True)
            if ws_instrucciones is not None:
                ws_instrucciones.protection.sheet = True
        except Exception as e:
            # Si hay error, solo activar la protección sin bloquear celdas
            try:
                if ws_instrucciones is not None:
                    ws_instrucciones.protection.sheet = True
            except:
                pass
        
        # ========== HOJA 2: SERVICIOS ==========
        ws_servicios = wb.create_sheet("Servicios", 1)
        if ws_servicios is None:
            raise ValueError("No se pudo crear la hoja de Servicios")
        
        # Encabezado (usar color del tema del usuario)
        header_cell = ws_servicios.cell(row=1, column=1, value="SERVICIOS DISPONIBLES")
        header_cell.font = Font(bold=True, size=14, color="FFFFFF")
        header_cell.fill = PatternFill(start_color=color_hex_clean, end_color=color_hex_clean, fill_type="solid")
        header_cell.alignment = Alignment(horizontal="center", vertical="center")
        ws_servicios.merge_cells('A1:B1')
        
        # Encabezados de tabla
        ws_servicios.cell(row=2, column=1, value="Servicio").font = Font(bold=True)
        ws_servicios.cell(row=2, column=1).fill = PatternFill(start_color="E0E0E0", end_color="E0E0E0", fill_type="solid")
        
        # Agregar servicios
        if servicios_list and isinstance(servicios_list, list) and len(servicios_list) > 0:
            try:
                for idx, servicio in enumerate(servicios_list, 3):
                    if servicio and isinstance(servicio, dict):
                        descripcion = servicio.get('descripcion', '')
                        if descripcion:
                            ws_servicios.cell(row=idx, column=1, value=descripcion)
            except Exception as e:
                ws_servicios.cell(row=3, column=1, value="Error al cargar servicios")
        else:
            ws_servicios.cell(row=3, column=1, value="No hay servicios disponibles")
        
        # Ajustar ancho
        ws_servicios.column_dimensions['A'].width = 50
        ws_servicios.column_dimensions['B'].width = 10
        
        # Proteger hoja de servicios
        try:
            if ws_servicios is not None:
                # Iterar sobre las filas que tienen datos
                rows_iter = ws_servicios.iter_rows(min_row=1, max_row=100)
                if rows_iter is not None:
                    for row in rows_iter:
                        if row is not None:
                            for cell in row:
                                if cell is not None:
                                    cell.protection = Protection(locked=True)
            if ws_servicios is not None:
                ws_servicios.protection.sheet = True
        except Exception as e:
            # Si hay error, solo activar la protección sin bloquear celdas
            try:
                if ws_servicios is not None:
                    ws_servicios.protection.sheet = True
            except:
                pass
        
        # ========== HOJA 3: PACIENTES ==========
        ws = wb.create_sheet("Pacientes", 2)
        if ws is None:
            raise ValueError("No se pudo crear la hoja de Pacientes")
        
        # Estilos para encabezados (usar color del tema del usuario)
        header_fill = PatternFill(start_color=color_hex_clean, end_color=color_hex_clean, fill_type="solid")
        header_font = Font(bold=True, color="FFFFFF", size=12)
        header_alignment = Alignment(horizontal="center", vertical="center")
        
        # Primero, desbloquear TODAS las celdas por defecto
        # Luego bloquearemos solo la fila 1 (encabezado)
        if ws is not None:
            try:
                # Desbloquear todas las celdas primero (fila 2 en adelante, hasta fila 1000)
                for row_num in range(2, 1001):
                    for col_num in range(1, 7):  # 6 columnas (A-F)
                        try:
                            cell = ws.cell(row=row_num, column=col_num)
                            if cell is not None:
                                cell.protection = Protection(locked=False)
                        except Exception:
                            pass
            except Exception:
                pass
        
        # Encabezados (bloqueados) - Solo la fila 1 estará protegida
        headers = ['NSS', 'Nombre Completo', 'Fecha', 'Autorización', 'Servicio', 'Monto']
        if headers and isinstance(headers, list):
            for col_num, header in enumerate(headers, 1):
                if header is not None:
                    cell = ws.cell(row=1, column=col_num, value=header)
                    cell.fill = header_fill
                    cell.font = header_font
                    cell.alignment = header_alignment
                    cell.protection = Protection(locked=True)  # Bloquear solo el encabezado
        
        # No agregar fila de ejemplo - el usuario llenará desde la fila 2
        
        # Validación de datos: Lista desplegable para SERVICIO (columna E)
        servicios_nombres = []
        if servicios_list and isinstance(servicios_list, list) and len(servicios_list) > 0:
            try:
                # Validar cada elemento antes de procesarlo
                for s in servicios_list:
                    if s is not None and isinstance(s, dict):
                        descripcion = s.get('descripcion', '')
                        if descripcion:
                            servicios_nombres.append(descripcion)
            except Exception as e:
                servicios_nombres = []
            
            if servicios_nombres and len(servicios_nombres) > 0:
                # Crear referencia a la hoja Servicios
                servicios_range = f"Servicios!$A$3:$A${2 + len(servicios_nombres)}"
                dv_servicio = DataValidation(type="list", formula1=servicios_range, allow_blank=False)
                dv_servicio.error = "Seleccione un servicio de la lista"
                dv_servicio.errorTitle = "Servicio inválido"
                dv_servicio.prompt = "Seleccione un servicio de la lista desplegable"
                dv_servicio.promptTitle = "Seleccionar Servicio"
                # Aplicar a toda la columna E (Servicio) desde la fila 2
                ws.add_data_validation(dv_servicio)
                dv_servicio.add(f"E2:E1048576")  # Aplicar a toda la columna E desde fila 2
        
        # Validación de datos: Autorización única (columna D)
        # Usar fórmula personalizada para verificar que no haya duplicados
        # COUNTIF($D:$D, D2) debe ser igual a 1 (solo una ocurrencia)
        dv_autorizacion = DataValidation(
            type="custom",
            formula1="COUNTIF($D:$D,D2)=1",
            allow_blank=False
        )
        dv_autorizacion.error = "Esta autorización ya existe. Cada autorización debe ser única."
        dv_autorizacion.errorTitle = "Autorización duplicada"
        dv_autorizacion.prompt = "Ingrese una autorización única (solo números)"
        dv_autorizacion.promptTitle = "Autorización"
        ws.add_data_validation(dv_autorizacion)
        dv_autorizacion.add(f"D2:D1048576")  # Aplicar a toda la columna D desde fila 2
        
        # Validación de datos: Solo números para MONTO (columna F)
        dv_monto = DataValidation(type="decimal", operator="greaterThan", formula1=0, allow_blank=False)
        dv_monto.error = "El monto debe ser un número mayor a cero"
        dv_monto.errorTitle = "Monto inválido"
        dv_monto.prompt = "Ingrese solo números (ej: 500.00)"
        dv_monto.promptTitle = "Monto"
        ws.add_data_validation(dv_monto)
        dv_monto.add(f"F2:F1048576")  # Aplicar a toda la columna F desde fila 2
        
        # Ajustar ancho de columnas
        column_widths = [15, 35, 12, 15, 30, 12]
        if column_widths and isinstance(column_widths, list):
            for col_num, width in enumerate(column_widths, 1):
                if width is not None:
                    try:
                        ws.column_dimensions[get_column_letter(col_num)].width = width
                    except Exception:
                        pass
        
        # Proteger la hoja - Solo el encabezado (fila 1) estará protegido
        # Las celdas de datos (fila 2 en adelante) permanecerán desbloqueadas
        try:
            if ws is not None and hasattr(ws, 'protection') and ws.protection is not None:
                ws.protection.sheet = True
                ws.protection.password = None
                ws.protection.formatCells = False
                ws.protection.formatColumns = False
                ws.protection.formatRows = False
                ws.protection.insertColumns = True
                ws.protection.insertRows = True
                ws.protection.insertHyperlinks = True
                ws.protection.deleteColumns = True
                ws.protection.deleteRows = True
                ws.protection.selectLockedCells = True
                ws.protection.sort = True
                ws.protection.autoFilter = True
                ws.protection.pivotTables = True
                ws.protection.selectUnlockedCells = True
            elif ws is not None:
                # Si protection no existe, solo activar la protección básica
                ws.protection.sheet = True
        except Exception as e:
            # Si hay error con la protección, continuar sin ella (no es crítico)
            try:
                if ws is not None:
                    ws.protection.sheet = True
            except:
                pass
    
        # Guardar en BytesIO
        output = BytesIO()
        wb.save(output)
        output.seek(0)
        
        # Nombre del archivo
        filename = 'plantilla_pacientes.xlsx'
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )
    except TypeError as e:
        import traceback
        error_details = traceback.format_exc()
        flash(f'Error al generar la plantilla: {str(e)}. Detalles: {error_details[:200]}', 'error')
        return redirect(url_for('facturacion_facturas_nueva'))
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        flash(f'Error inesperado al generar la plantilla: {str(e)}. Detalles: {error_details[:200]}', 'error')
        return redirect(url_for('facturacion_facturas_nueva'))

@app.route('/facturacion/procesar-excel', methods=['POST'])
@login_required
def facturacion_procesar_excel():
    """Procesar archivo Excel y devolver pacientes en formato JSON"""
    try:
        if not OPENPYXL_AVAILABLE:
            return jsonify({
                'error': True,
                'mensaje': 'La funcionalidad de Excel no está disponible',
                'errores': ['OpenPyXL no está instalado'],
                'total_errores': 1
            }), 400
        
        # Verificar que se haya enviado un archivo
        if 'archivo_excel' not in request.files:
            return jsonify({
                'error': True,
                'mensaje': 'No se recibió ningún archivo',
                'errores': ['Debe seleccionar un archivo Excel'],
                'total_errores': 1
            }), 400
        
        file = request.files['archivo_excel']
        if file.filename == '':
            return jsonify({
                'error': True,
                'mensaje': 'No se seleccionó ningún archivo',
                'errores': ['Debe seleccionar un archivo Excel'],
                'total_errores': 1
            }), 400
        
        # OpenPyXL solo procesa el formato OOXML (.xlsx).
        if not file.filename.lower().endswith('.xlsx'):
            return jsonify({
                'error': True,
                'mensaje': 'Formato de archivo inválido',
                'errores': ['El archivo debe ser .xlsx'],
                'total_errores': 1
            }), 400

        if not zipfile.is_zipfile(file.stream):
            return jsonify({
                'error': True,
                'mensaje': 'Archivo Excel inválido',
                'errores': ['El contenido no corresponde a un archivo .xlsx válido'],
                'total_errores': 1
            }), 400
        file.stream.seek(0)

        # Leer el archivo Excel
        from openpyxl import load_workbook
        wb = load_workbook(file, data_only=True, read_only=True)
        
        # Buscar la hoja "Pacientes"
        if 'Pacientes' not in wb.sheetnames:
            return jsonify({
                'error': True,
                'mensaje': 'Hoja "Pacientes" no encontrada',
                'errores': ['El archivo Excel debe contener una hoja llamada "Pacientes"'],
                'total_errores': 1
            }), 400
        
        ws = wb['Pacientes']
        max_excel_rows = int(os.getenv('MAX_EXCEL_ROWS', '5000'))
        if ws.max_row and ws.max_row - 1 > max_excel_rows:
            wb.close()
            return jsonify({
                'error': True,
                'mensaje': 'El archivo supera el límite permitido',
                'errores': [f'Máximo permitido: {max_excel_rows} pacientes'],
                'total_errores': 1
            }), 400
        
        # Obtener tenant_id
        tenant_id = get_current_tenant_id()
        if not tenant_id:
            return jsonify({
                'error': True,
                'mensaje': 'Error al obtener el tenant',
                'errores': ['No se pudo identificar la empresa'],
                'total_errores': 1
            }), 400
        
        # Obtener servicios válidos del tenant
        servicios_result = execute_query(
            'SELECT descripcion FROM servicios WHERE tenant_id = %s AND activo = 1',
            (tenant_id,), fetch='all'
        ) or []
        servicios_validos = [s['descripcion'].upper() for s in servicios_result if s and s.get('descripcion')]
        
        # Leer datos desde la fila 2 (la fila 1 es el encabezado)
        pacientes = []
        errores = []
        autorizaciones_vistas = set()
        numero_fila = 1
        
        for row in ws.iter_rows(min_row=2, values_only=False):
            numero_fila += 1
            
            # Obtener valores de las celdas
            nss = str(row[0].value).strip() if row[0].value else ''  # Columna A
            nombre = str(row[1].value).strip() if row[1].value else ''  # Columna B
            # Fecha puede venir como datetime de Excel o como string
            fecha_raw = row[2].value if row[2].value else ''
            if fecha_raw:
                # Si es datetime de Excel, convertir a string primero
                from datetime import datetime, date
                if isinstance(fecha_raw, (datetime, date)):
                    fecha = fecha_raw.strftime('%Y-%m-%d')
                else:
                    fecha = str(fecha_raw).strip()
            else:
                fecha = ''
            autorizacion = str(row[3].value).strip() if row[3].value else ''  # Columna D
            servicio = str(row[4].value).strip() if row[4].value else ''  # Columna E
            monto = row[5].value if row[5].value else ''  # Columna F
            
            # Si la fila está vacía, saltarla
            if not nss and not nombre and not fecha and not autorizacion and not servicio and not monto:
                continue
            
            # Validaciones
            errores_fila = []
            
            # Validar NSS
            if not nss:
                errores_fila.append(f'Fila {numero_fila}: NSS es obligatorio')
            elif len(nss) > 50:
                errores_fila.append(f'Fila {numero_fila}: NSS muy largo (máximo 50 caracteres)')
            
            # Validar Nombre
            if not nombre:
                errores_fila.append(f'Fila {numero_fila}: Nombre es obligatorio')
            elif len(nombre) > 200:
                errores_fila.append(f'Fila {numero_fila}: Nombre muy largo (máximo 200 caracteres)')
            
            # Validar y normalizar Fecha
            if not fecha:
                errores_fila.append(f'Fila {numero_fila}: Fecha es obligatoria')
            else:
                try:
                    from datetime import datetime, date
                    fecha_normalizada = None
                    
                    # Si ya está en formato AAAA-MM-DD, validar y usar directamente
                    try:
                        datetime.strptime(fecha, '%Y-%m-%d')
                        fecha_normalizada = fecha  # Ya está en el formato correcto
                    except ValueError:
                        # Si no está en formato AAAA-MM-DD, intentar normalizar
                        # Normalizar separadores: convertir "/" a "-"
                        fecha_str = fecha.replace('/', '-').strip()
                        
                        # Intentar parsear diferentes formatos
                        formatos_fecha = [
                            '%Y-%m-%d',      # AAAA-MM-DD (formato estándar)
                            '%d-%m-%Y',      # DD-MM-AAAA
                            '%m-%d-%Y',      # MM-DD-AAAA
                            '%Y/%m/%d',      # AAAA/MM/DD (por si acaso quedó algún /)
                            '%d/%m/%Y',      # DD/MM/AAAA
                            '%m/%d/%Y',      # MM/DD/AAAA
                        ]
                        
                        fecha_obj = None
                        for formato in formatos_fecha:
                            try:
                                fecha_obj = datetime.strptime(fecha_str, formato)
                                break
                            except ValueError:
                                continue
                        
                        if fecha_obj:
                            # Convertir a formato estándar AAAA-MM-DD
                            fecha_normalizada = fecha_obj.strftime('%Y-%m-%d')
                        else:
                            # Si no se pudo parsear, intentar con el valor original
                            raise ValueError(f'No se pudo parsear la fecha: {fecha}')
                    
                    if fecha_normalizada:
                        # Validar que el formato sea correcto (AAAA-MM-DD)
                        datetime.strptime(fecha_normalizada, '%Y-%m-%d')
                        fecha = fecha_normalizada
                    else:
                        raise ValueError(f'Fecha no válida: {fecha}')
                        
                except Exception as e:
                    errores_fila.append(f'Fila {numero_fila}: Fecha inválida "{fecha}" (formato esperado: AAAA-MM-DD o DD/MM/AAAA)')
            
            # Validar Autorización
            if not autorizacion:
                errores_fila.append(f'Fila {numero_fila}: Autorización es obligatoria')
            elif len(autorizacion) > 50:
                errores_fila.append(f'Fila {numero_fila}: Autorización muy larga (máximo 50 caracteres)')
            elif autorizacion.upper() in autorizaciones_vistas:
                errores_fila.append(f'Fila {numero_fila}: Autorización duplicada ({autorizacion})')
            else:
                autorizaciones_vistas.add(autorizacion.upper())
            
            # Validar Servicio
            if not servicio:
                errores_fila.append(f'Fila {numero_fila}: Servicio es obligatorio')
            elif servicios_validos and servicio.upper() not in servicios_validos:
                errores_fila.append(f'Fila {numero_fila}: Servicio "{servicio}" no existe. Servicios válidos: {", ".join(servicios_validos[:5])}...')
            
            # Validar Monto
            try:
                if monto == '' or monto is None:
                    errores_fila.append(f'Fila {numero_fila}: Monto es obligatorio')
                else:
                    monto_float = float(monto)
                    if monto_float <= 0:
                        errores_fila.append(f'Fila {numero_fila}: Monto debe ser mayor a cero')
            except (ValueError, TypeError):
                errores_fila.append(f'Fila {numero_fila}: Monto inválido (debe ser un número)')
            
            # Si hay errores en esta fila, agregarlos y continuar
            if errores_fila:
                errores.extend(errores_fila)
                continue
            
            # Si no hay errores, agregar el paciente
            pacientes.append({
                'nss': nss,
                'nombre': nombre.upper(),
                'fecha': fecha,
                'autorizacion': autorizacion.upper(),
                'servicio': servicio.upper(),
                'monto': float(monto)
            })
        
        # Si hay errores, devolverlos
        if errores:
            wb.close()
            return jsonify({
                'error': True,
                'mensaje': f'Se encontraron {len(errores)} error(es) en el archivo',
                'errores': errores,
                'total_errores': len(errores),
                'pacientes': []
            }), 400
        
        # Si no hay pacientes, devolver error
        if not pacientes:
            wb.close()
            return jsonify({
                'error': True,
                'mensaje': 'No se encontraron pacientes válidos en el archivo',
                'errores': ['El archivo Excel no contiene datos válidos en la hoja "Pacientes"'],
                'total_errores': 1,
                'pacientes': []
            }), 400
        
        # Si todo está bien, devolver los pacientes
        wb.close()
        return jsonify({
            'error': False,
            'mensaje': f'Se procesaron {len(pacientes)} paciente(s) correctamente',
            'pacientes': pacientes,
            'total': len(pacientes)
        }), 200
        
    except Exception as e:
        logger.error('Error al procesar archivo Excel', exc_info=True)
        return jsonify({
            'error': True,
            'mensaje': 'No fue posible procesar el archivo',
            'errores': ['Verifica el formato y vuelve a intentarlo'],
            'total_errores': 1,
        }), 500

@app.route('/facturacion/generar', methods=['GET', 'POST'])
@login_required
def facturacion_generar():
    """Generar factura"""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos para acceder a esta sección', 'error')
        return redirect(url_for('facturacion_menu'))
    
    # Si es POST, redirigir al step 2
    if request.method == 'POST':
        # Validar y sanitizar entrada
        tipo_factura = request.form.get('tipo_factura', 'TRADICIONAL').strip().upper()
        ars_id = validate_int(request.form.get('ars_id'), min_value=1)
        ncf_id = (
            validate_int(request.form.get('ncf_id'), min_value=1)
            if tipo_factura == 'TRADICIONAL' else None
        )
        medico_factura_id = validate_int(request.form.get('medico_factura_id'), min_value=1)
        fecha_factura = request.form.get('fecha_factura', '').strip()

        if tipo_factura not in ['TRADICIONAL', 'ELECTRONICA']:
            flash('Tipo de factura inválido', 'error')
            return redirect(url_for('facturacion_generar'))
        if (
            tipo_factura == 'ELECTRONICA'
            and not ecf_habilitado_para_tenant(get_current_tenant_id())
        ):
            flash('La cuenta no está habilitada para facturación electrónica', 'error')
            return redirect(url_for('facturacion_generar'))
        
        # Validar fecha
        if fecha_factura:
            try:
                datetime.strptime(fecha_factura, '%Y-%m-%d')
            except ValueError:
                flash('Fecha inválida', 'error')
                return redirect(url_for('facturacion_generar'))
        
        if not all([ars_id, medico_factura_id, fecha_factura]) or (
            tipo_factura == 'TRADICIONAL' and not ncf_id
        ):
            flash('Todos los campos son obligatorios', 'error')
            return redirect(url_for('facturacion_generar'))
        
        # Validar que los IDs pertenezcan al tenant
        tenant_id = get_current_tenant_id()
        empresa_actual = get_empresa_info(tenant_id)
        es_centro_salud = (
            empresa_actual
            and empresa_actual.get('tipo_empresa') == 'centro_salud'
        )
        emisor_valido = (
            medico_factura_id == tenant_id
            if es_centro_salud
            else validate_tenant_access('medicos', medico_factura_id)
        )
        ncf_valido = (
            validate_tenant_access('ncf', ncf_id)
            if tipo_factura == 'TRADICIONAL' else True
        )
        if not validate_tenant_access('ars', ars_id) or \
           not ncf_valido or not emisor_valido:
            flash('No tienes acceso a uno o más de los recursos seleccionados', 'error')
            return redirect(url_for('facturacion_generar'))
        
        # Redirigir al step 2 con los parámetros
        return redirect(url_for('facturacion_generar_step2', 
                              tipo_factura=tipo_factura,
                              ars_id=ars_id, 
                              ncf_id=ncf_id, 
                              medico_factura_id=medico_factura_id,
                              fecha_factura=fecha_factura))
    
    tenant_id = get_current_tenant_id()
    
    # Obtener ARS activas
    ars_list = execute_query('''
        SELECT * FROM ars 
        WHERE activo = 1 AND tenant_id = %s 
        ORDER BY nombre
    ''', (tenant_id,), fetch='all') or []
    
    # Obtener NCF activos
    ncf_list = execute_query('''
        SELECT * FROM ncf 
        WHERE activo = 1 AND tenant_id = %s 
        ORDER BY tipo, prefijo
    ''', (tenant_id,), fetch='all') or []
    
    # Obtener información de la empresa para determinar tipo
    empresa_info = get_empresa_info(tenant_id)
    tipo_empresa = empresa_info.get('tipo_empresa') if empresa_info else None
    
    # Obtener médicos activos o razón social según tipo de empresa
    medicos_habilitados = []
    if tipo_empresa == 'centro_salud':
        # Si es centro de salud, usar la razón social de la empresa
        if empresa_info and empresa_info.get('razon_social'):
            medicos_habilitados = [{
                'id': empresa_info.get('id'),
                'nombre': empresa_info.get('razon_social'),
                'especialidad': 'Centro de Salud'
            }]
    else:
        # Si es médico o no tiene tipo definido, usar médicos
        medicos_habilitados = execute_query('''
            SELECT * FROM medicos 
            WHERE activo = 1 AND tenant_id = %s 
            ORDER BY nombre
        ''', (tenant_id,), fetch='all') or []
    
    pendientes = execute_query('''
        SELECT pp.*, a.nombre as ars_nombre
        FROM pacientes_pendientes pp
        LEFT JOIN ars a
          ON pp.ars_id = a.id AND a.tenant_id = pp.tenant_id
        WHERE pp.estado = 'Pendiente' AND pp.tenant_id = %s
        ORDER BY pp.created_at
    ''', (tenant_id,), fetch='all') or []
    
    # Obtener fecha actual en formato YYYY-MM-DD
    from datetime import date
    fecha_actual = date.today().strftime('%Y-%m-%d')
    
    return render_template('facturacion/generar_factura.html', 
                          pendientes=pendientes,
                          ars_list=ars_list,
                          ncf_list=ncf_list,
                          medicos_habilitados=medicos_habilitados,
                          fecha_actual=fecha_actual,
                          tipo_empresa=tipo_empresa,
                          ecf_habilitado=ecf_habilitado_para_tenant(tenant_id))

@app.route('/facturacion/generar/step2', methods=['GET', 'POST'])
@login_required
def facturacion_generar_step2():
    """Generar factura - Paso 2: Selección de pacientes"""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos para acceder a esta sección', 'error')
        return redirect(url_for('facturacion_menu'))
    
    # Si es POST, redirigir a vista previa
    if request.method == 'POST':
        tipo_factura = request.form.get('tipo_factura', 'TRADICIONAL').strip().upper()
        pacientes_ids_json = request.form.get('pacientes_ids')
        ars_id = request.form.get('ars_id')
        ncf_id = request.form.get('ncf_id')
        medico_factura_id = request.form.get('medico_factura_id')
        fecha_factura = request.form.get('fecha_factura')
        
        if tipo_factura not in ['TRADICIONAL', 'ELECTRONICA']:
            flash('Tipo de factura inválido', 'error')
            return redirect(url_for('facturacion_generar'))
        if (
            tipo_factura == 'ELECTRONICA'
            and not ecf_habilitado_para_tenant(get_current_tenant_id())
        ):
            flash('La cuenta no está habilitada para facturación electrónica', 'error')
            return redirect(url_for('facturacion_generar'))

        if not all([pacientes_ids_json, ars_id, medico_factura_id, fecha_factura]) or (
            tipo_factura == 'TRADICIONAL' and not ncf_id
        ):
            flash('Faltan datos obligatorios', 'error')
            return redirect(url_for('facturacion_generar'))
        
        try:
            import json
            pacientes_ids = json.loads(pacientes_ids_json)
        except json.JSONDecodeError:
            flash('Error al procesar los IDs de pacientes', 'error')
            return redirect(url_for('facturacion_generar'))
        
        if not pacientes_ids or len(pacientes_ids) == 0:
            flash('Debe seleccionar al menos un paciente', 'error')
            return redirect(url_for('facturacion_generar_step2',
                                  tipo_factura=tipo_factura,
                                  ars_id=ars_id,
                                  ncf_id=ncf_id,
                                  medico_factura_id=medico_factura_id,
                                  fecha_factura=fecha_factura))
        
        # Redirigir a vista previa
        return redirect(url_for('facturacion_vista_previa',
                              tipo_factura=tipo_factura,
                              pacientes_ids=','.join(map(str, pacientes_ids)),
                              ars_id=ars_id,
                              ncf_id=ncf_id,
                              medico_factura_id=medico_factura_id,
                              fecha_factura=fecha_factura))
    
    # Obtener parámetros de la URL (GET)
    tipo_factura = request.args.get('tipo_factura', 'TRADICIONAL').strip().upper()
    ars_id = request.args.get('ars_id')
    ncf_id = request.args.get('ncf_id')
    medico_factura_id = request.args.get('medico_factura_id')
    fecha_factura = request.args.get('fecha_factura')
    
    if tipo_factura not in ['TRADICIONAL', 'ELECTRONICA']:
        flash('Tipo de factura inválido', 'error')
        return redirect(url_for('facturacion_generar'))
    if (
        tipo_factura == 'ELECTRONICA'
        and not ecf_habilitado_para_tenant(get_current_tenant_id())
    ):
        flash('La cuenta no está habilitada para facturación electrónica', 'error')
        return redirect(url_for('facturacion_generar'))

    if not all([ars_id, medico_factura_id, fecha_factura]) or (
        tipo_factura == 'TRADICIONAL' and not ncf_id
    ):
        flash('Faltan parámetros obligatorios', 'error')
        return redirect(url_for('facturacion_generar'))
    
    tenant_id = get_current_tenant_id()
    
    # Obtener ARS
    ars = execute_query('SELECT * FROM ars WHERE id = %s AND tenant_id = %s', (ars_id, tenant_id))
    if not ars:
        flash('ARS no encontrada', 'error')
        return redirect(url_for('facturacion_generar'))
    
    # Obtener NCF tradicional o representar el e-CF inicial habilitado.
    if tipo_factura == 'TRADICIONAL':
        ncf = execute_query(
            'SELECT * FROM ncf WHERE id = %s AND tenant_id = %s',
            (ncf_id, tenant_id)
        )
        if not ncf:
            flash('NCF no encontrado', 'error')
            return redirect(url_for('facturacion_generar'))
    else:
        ncf = {'id': '', 'tipo': 'E31', 'prefijo': 'E31'}
    
    # Obtener información de la empresa para determinar tipo
    empresa_info = get_empresa_info(tenant_id)
    tipo_empresa = empresa_info.get('tipo_empresa') if empresa_info else None
    
    # Obtener médico o empresa según tipo
    medico_factura = None
    medico_factura_nombre = 'N/A'
    
    if tipo_empresa == 'centro_salud':
        # Si es centro de salud, buscar en empresas
        empresa_factura = execute_query('SELECT * FROM empresas WHERE id = %s', (medico_factura_id,))
        if empresa_factura and empresa_factura.get('id') == tenant_id:
            medico_factura = {
                'id': empresa_factura.get('id'),
                'nombre': empresa_factura.get('razon_social', empresa_factura.get('nombre', 'N/A')),
                'especialidad': 'Centro de Salud'
            }
            medico_factura_nombre = empresa_factura.get('razon_social', empresa_factura.get('nombre', 'N/A'))
        else:
            flash('Empresa no encontrada', 'error')
            return redirect(url_for('facturacion_generar'))
    else:
        # Si es médico, buscar en medicos
        medico_factura = execute_query('SELECT * FROM medicos WHERE id = %s AND tenant_id = %s', (medico_factura_id, tenant_id))
        if not medico_factura:
            flash('Médico no encontrado', 'error')
            return redirect(url_for('facturacion_generar'))
        medico_factura_nombre = medico_factura.get('nombre', 'N/A')
    
    pendientes_raw = execute_query('''
        SELECT pp.*, a.nombre as ars_nombre, m.nombre as medico_nombre
        FROM pacientes_pendientes pp
        LEFT JOIN ars a
          ON pp.ars_id = a.id AND a.tenant_id = pp.tenant_id
        LEFT JOIN medicos m
          ON pp.medico_id = m.id AND m.tenant_id = pp.tenant_id
        WHERE pp.estado = 'Pendiente'
          AND pp.ars_id = %s
          AND pp.tenant_id = %s
        ORDER BY pp.created_at
    ''', (ars_id, tenant_id), fetch='all') or []
    
    # Procesar los datos para extraer autorización y servicio
    pendientes = []
    for p in pendientes_raw:
        servicio_completo = p.get('servicios_realizados', '') or ''
        # Extraer servicio y autorización
        if ' - Autorización:' in servicio_completo:
            partes = servicio_completo.split(' - Autorización:')
            descripcion_servicio = partes[0].strip()
            autorizacion = partes[1].strip() if len(partes) > 1 else ''
        else:
            descripcion_servicio = servicio_completo.strip()
            autorizacion = ''
        
        p['descripcion_servicio'] = descripcion_servicio
        p['autorizacion'] = autorizacion
        p['paciente_nombre_completo'] = p.get('nombre_paciente', '')
        pendientes.append(p)
    
    # Obtener todos los médicos para el filtro
    medicos = execute_query('SELECT id, nombre FROM medicos WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    
    return render_template('facturacion/generar_factura_step2.html',
                          ars=ars,
                          ncf=ncf,
                          medico_factura_id=medico_factura_id,
                          medico_factura_nombre=medico_factura_nombre,
                          fecha_factura=fecha_factura,
                          tipo_factura=tipo_factura,
                          pendientes=pendientes,
                          medicos=medicos)

@app.route('/facturacion/vista-previa')
@login_required
def facturacion_vista_previa():
    """Vista previa de factura antes de generar"""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos para acceder a esta sección', 'error')
        return redirect(url_for('facturacion_menu'))
    
    # Obtener parámetros
    tipo_factura = request.args.get('tipo_factura', 'TRADICIONAL').strip().upper()
    pacientes_ids_str = request.args.get('pacientes_ids', '')
    ars_id = request.args.get('ars_id')
    ncf_id = request.args.get('ncf_id')
    medico_factura_id = request.args.get('medico_factura_id')
    fecha_factura = request.args.get('fecha_factura')
    
    if tipo_factura not in ['TRADICIONAL', 'ELECTRONICA']:
        flash('Tipo de factura inválido', 'error')
        return redirect(url_for('facturacion_generar'))
    if (
        tipo_factura == 'ELECTRONICA'
        and not ecf_habilitado_para_tenant(get_current_tenant_id())
    ):
        flash('La cuenta no está habilitada para facturación electrónica', 'error')
        return redirect(url_for('facturacion_generar'))

    if not all([pacientes_ids_str, ars_id, medico_factura_id, fecha_factura]) or (
        tipo_factura == 'TRADICIONAL' and not ncf_id
    ):
        flash('Faltan parámetros obligatorios', 'error')
        return redirect(url_for('facturacion_generar'))
    
    # Convertir IDs de pacientes
    try:
        pacientes_ids = [int(id) for id in pacientes_ids_str.split(',') if id.strip()]
    except ValueError:
        flash('Error en los IDs de pacientes', 'error')
        return redirect(url_for('facturacion_generar'))
    
    if not pacientes_ids:
        flash('Debe seleccionar al menos un paciente', 'error')
        return redirect(url_for('facturacion_generar'))
    
    tenant_id = get_current_tenant_id()
    
    # Obtener datos de ARS, NCF y Médico
    ars = execute_query('SELECT * FROM ars WHERE id = %s AND tenant_id = %s', (ars_id, tenant_id))
    if not ars:
        flash('ARS no encontrada', 'error')
        return redirect(url_for('facturacion_generar'))
    
    if tipo_factura == 'TRADICIONAL':
        ncf = execute_query(
            'SELECT * FROM ncf WHERE id = %s AND tenant_id = %s',
            (ncf_id, tenant_id)
        )
        if not ncf:
            flash('NCF no encontrado', 'error')
            return redirect(url_for('facturacion_generar'))
    else:
        fecha_documento = datetime.strptime(fecha_factura, '%Y-%m-%d').date()
        secuencia_ecf = execute_query('''
            SELECT *,
                   GREATEST(ultimo_numero, secuencia_inicial - 1) + 1
                       AS proximo_numero
            FROM ecf_secuencias
            WHERE tenant_id=%s AND tipo_ecf='31' AND activo=1
              AND (fecha_autorizacion IS NULL OR fecha_autorizacion <= %s)
              AND fecha_vencimiento >= %s
              AND GREATEST(ultimo_numero, secuencia_inicial - 1)
                  < secuencia_final
            ORDER BY fecha_vencimiento, id
            LIMIT 1
        ''', (tenant_id, fecha_documento, fecha_documento))
        if not secuencia_ecf:
            flash(
                'Configure una secuencia E31 activa y vigente antes de continuar',
                'warning'
            )
            return redirect(url_for('facturacion_ncf'))
        ncf = {
            'id': '',
            'tipo': 'E31',
            'prefijo': 'E31',
            'fecha_fin': secuencia_ecf['fecha_vencimiento']
        }
    
    # Obtener información de la empresa para determinar tipo
    empresa_info = get_empresa_info(tenant_id)
    tipo_empresa = empresa_info.get('tipo_empresa') if empresa_info else None
    
    # Obtener médico o empresa según tipo
    medico_factura = None
    empresa_factura = None
    if tipo_empresa == 'centro_salud':
        # Si es centro de salud, buscar en empresas
        empresa_factura = execute_query('SELECT * FROM empresas WHERE id = %s', (medico_factura_id,))
        if empresa_factura and empresa_factura.get('id') == tenant_id:
            medico_factura = {
                'id': empresa_factura.get('id'),
                'nombre': empresa_factura.get('razon_social', empresa_factura.get('nombre', 'N/A')),
                'especialidad': 'Centro de Salud',
                'cedula': empresa_factura.get('rnc', '')
            }
        else:
            flash('Empresa no encontrada', 'error')
            return redirect(url_for('facturacion_generar'))
    else:
        # Si es médico, buscar en medicos
        medico_factura = execute_query('SELECT * FROM medicos WHERE id = %s AND tenant_id = %s', (medico_factura_id, tenant_id))
        if not medico_factura:
            flash('Médico no encontrado', 'error')
            return redirect(url_for('facturacion_generar'))
    
    # Obtener pacientes seleccionados exclusivamente dentro del tenant.
    placeholders = ','.join(['%s'] * len(pacientes_ids))
    pacientes_query = f'''
        SELECT pp.*, a.nombre as ars_nombre, m.nombre as medico_nombre
        FROM pacientes_pendientes pp
        LEFT JOIN ars a
          ON pp.ars_id = a.id AND a.tenant_id = pp.tenant_id
        LEFT JOIN medicos m
          ON pp.medico_id = m.id AND m.tenant_id = pp.tenant_id
        WHERE pp.id IN ({placeholders}) AND pp.tenant_id = %s
        ORDER BY pp.fecha_servicio
    '''
    pacientes_raw = execute_query(
        pacientes_query,
        tuple(pacientes_ids) + (tenant_id,),
        fetch='all',
    ) or []
    
    # Procesar pacientes
    pacientes = []
    for p in pacientes_raw:
        servicio_completo = p.get('servicios_realizados', '') or ''
        if ' - Autorización:' in servicio_completo:
            partes = servicio_completo.split(' - Autorización:')
            descripcion_servicio = partes[0].strip()
            autorizacion = partes[1].strip() if len(partes) > 1 else ''
        else:
            descripcion_servicio = servicio_completo.strip()
            autorizacion = ''
        
        p['descripcion_servicio'] = descripcion_servicio
        p['autorizacion'] = autorizacion
        p['paciente_nombre_completo'] = p.get('nombre_paciente', '')
        pacientes.append(p)
    
    # Obtener centro médico del médico (si tiene uno asociado)
    centro_medico = None
    if medico_factura.get('centro_medico_id'):
        centro_medico = execute_query('SELECT * FROM centros_medicos WHERE id = %s AND tenant_id = %s', 
                                     (medico_factura['centro_medico_id'], tenant_id))
    
    # Si no tiene centro médico asociado, obtener el primero del tenant
    if not centro_medico:
        centro_medico = execute_query('SELECT * FROM centros_medicos WHERE tenant_id = %s LIMIT 1', (tenant_id,))
    
    # Si aún no hay centro médico, crear uno por defecto
    if not centro_medico:
        centro_medico = {
            'nombre': 'Centro Médico',
            'direccion': ''
        }
    
    # Calcular subtotal y total
    subtotal = sum(float(p.get('monto_estimado', 0) or 0) for p in pacientes)
    total = subtotal  # Por ahora el total es igual al subtotal (ITBIS es exento)
    
    # La vista previa no reserva el consecutivo; la reserva ocurre al confirmar.
    if tipo_factura == 'ELECTRONICA':
        ncf_completo = build_encf('31', secuencia_ecf['proximo_numero'])
        ncf_tipo_descripcion = 'Factura de Crédito Fiscal Electrónica'
    else:
        proximo_numero = ncf.get('ultimo_numero', 0) + 1
        tamano_secuencia = ncf.get('tamano_secuencia', 8)
        ncf_completo = (
            f"{ncf.get('prefijo', '')}"
            f"{proximo_numero:0{tamano_secuencia}d}"
        )
        ncf_tipos_descripciones = {
            'B01': 'Factura de Crédito Fiscal',
            'B02': 'Factura de Consumo',
            'B14': 'Registro Único de Ingresos',
            'B15': 'GUBERNAMENTAL'
        }
        ncf_tipo_descripcion = ncf_tipos_descripciones.get(
            ncf.get('tipo', ''),
            ncf.get('tipo', '')
        )
    
    return render_template('facturacion/vista_previa_factura.html',
                          pacientes=pacientes,
                          pacientes_ids=','.join(map(str, pacientes_ids)),
                          tipo_factura=tipo_factura,
                          ars=ars,
                          ncf=ncf,
                          ncf_completo=ncf_completo,  # Número completo del NCF
                          ncf_tipo_descripcion=ncf_tipo_descripcion,  # Descripción del tipo de NCF
                          medico=medico_factura,  # Cambiado de medico_factura a medico
                          medico_factura=medico_factura,  # Mantener también por si acaso
                          medico_factura_id=medico_factura_id,
                          fecha_factura=fecha_factura,
                          ars_id=ars_id,
                          ncf_id=ncf_id,
                          centro_medico=centro_medico,
                          subtotal=subtotal,
                          total=total,
                          tipo_empresa=tipo_empresa,
                          empresa_info=empresa_info,
                          idempotency_key=secrets.token_hex(16))

@app.route('/facturacion/generar/final', methods=['POST'])
@login_required
def facturacion_generar_final():
    """Generar factura final en la base de datos"""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos para acceder a esta sección', 'error')
        return redirect(url_for('facturacion_menu'))
    
    tenant_id = get_current_tenant_id()
    
    # Obtener datos del formulario
    tipo_factura = request.form.get('tipo_factura', 'TRADICIONAL').strip().upper()
    pacientes_ids_str = request.form.get('pacientes_ids', '')
    ars_id = request.form.get('ars_id')
    ncf_id = request.form.get('ncf_id')
    medico_factura_id = request.form.get('medico_factura_id')
    fecha_factura = request.form.get('fecha_factura')
    idempotency_key = request.form.get('idempotency_key', '').strip().lower()
    
    if tipo_factura not in ['TRADICIONAL', 'ELECTRONICA']:
        flash('Tipo de factura inválido', 'error')
        return redirect(url_for('facturacion_generar'))
    if (
        tipo_factura == 'ELECTRONICA'
        and not ecf_habilitado_para_tenant(get_current_tenant_id())
    ):
        flash('La cuenta no está habilitada para facturación electrónica', 'error')
        return redirect(url_for('facturacion_generar'))

    if not all([pacientes_ids_str, ars_id, medico_factura_id, fecha_factura]) or (
        tipo_factura == 'TRADICIONAL' and not ncf_id
    ):
        flash('Faltan datos obligatorios', 'error')
        return redirect(url_for('facturacion_generar'))

    if tipo_factura == 'ELECTRONICA':
        if not re.fullmatch(r'[a-f0-9]{32}', idempotency_key):
            flash('La confirmación electrónica expiró. Genere otra vista previa.', 'error')
            return redirect(url_for('facturacion_generar'))
        factura_existente = execute_query('''
            SELECT factura_id
            FROM facturas_ecf
            WHERE tenant_id=%s AND idempotency_key=%s
            LIMIT 1
        ''', (tenant_id, idempotency_key))
        if factura_existente:
            return redirect(url_for(
                'facturacion_ver_factura',
                factura_id=factura_existente['factura_id']
            ))
    
    # Convertir IDs de pacientes
    try:
        pacientes_ids = [int(id) for id in pacientes_ids_str.split(',') if id.strip()]
    except ValueError:
        flash('Error en los IDs de pacientes', 'error')
        return redirect(url_for('facturacion_generar'))
    
    if not pacientes_ids:
        flash('Debe seleccionar al menos un paciente', 'error')
        return redirect(url_for('facturacion_generar'))
    
    # Obtener datos de ARS, NCF y Médico
    ars = execute_query('SELECT * FROM ars WHERE id = %s AND tenant_id = %s', (ars_id, tenant_id))
    if not ars:
        flash('ARS no encontrada', 'error')
        return redirect(url_for('facturacion_generar'))
    
    ncf = None
    if tipo_factura == 'TRADICIONAL':
        ncf = execute_query(
            'SELECT * FROM ncf WHERE id = %s AND tenant_id = %s',
            (ncf_id, tenant_id)
        )
        if not ncf:
            flash('NCF no encontrado', 'error')
            return redirect(url_for('facturacion_generar'))
    
    # Obtener información de la empresa para determinar tipo
    empresa_info = get_empresa_info(tenant_id)
    tipo_empresa = empresa_info.get('tipo_empresa') if empresa_info else None

    if tipo_factura == 'ELECTRONICA':
        rnc_emisor = re.sub(r'\D', '', (empresa_info or {}).get('rnc') or '')
        rnc_comprador = re.sub(r'\D', '', ars.get('rnc') or '')
        if len(rnc_emisor) not in [9, 11]:
            flash('Configure un RNC o cédula válido para el emisor', 'error')
            return redirect(url_for('facturacion_generar'))
        if len(rnc_comprador) not in [9, 11]:
            flash('La ARS debe tener un RNC válido para emitir un E31', 'error')
            return redirect(url_for('facturacion_generar'))
    
    # Obtener médico o empresa según tipo
    medico_factura = None
    empresa_factura = None
    if tipo_empresa == 'centro_salud':
        # Si es centro de salud, buscar en empresas
        empresa_factura = execute_query('SELECT * FROM empresas WHERE id = %s', (medico_factura_id,))
        if empresa_factura and empresa_factura.get('id') == tenant_id:
            medico_factura = {
                'id': empresa_factura.get('id'),
                'nombre': empresa_factura.get('razon_social', empresa_factura.get('nombre', 'N/A')),
                'especialidad': 'Centro de Salud',
                'cedula': empresa_factura.get('rnc', '')
            }
        else:
            flash('Empresa no encontrada', 'error')
            return redirect(url_for('facturacion_generar'))
    else:
        # Si es médico, buscar en medicos
        medico_factura = execute_query('SELECT * FROM medicos WHERE id = %s AND tenant_id = %s', (medico_factura_id, tenant_id))
        if not medico_factura:
            flash('Médico no encontrado', 'error')
            return redirect(url_for('facturacion_generar'))
    
    # Obtener únicamente pacientes pendientes de la empresa actual.
    placeholders = ','.join(['%s'] * len(pacientes_ids))
    pacientes_raw = execute_query(f'''
        SELECT pp.*, a.nombre as ars_nombre, m.nombre as medico_nombre
        FROM pacientes_pendientes pp
        LEFT JOIN ars a
          ON pp.ars_id = a.id AND a.tenant_id = pp.tenant_id
        LEFT JOIN medicos m
          ON pp.medico_id = m.id AND m.tenant_id = pp.tenant_id
        WHERE pp.id IN ({placeholders}) AND pp.tenant_id = %s
          AND pp.estado = 'Pendiente'
        ORDER BY pp.fecha_servicio
    ''', tuple(pacientes_ids) + (tenant_id,), fetch='all') or []
    
    if len(pacientes_raw) != len(set(pacientes_ids)):
        flash(
            'Uno o más pacientes ya fueron facturados o dejaron de estar disponibles',
            'error'
        )
        return redirect(url_for('facturacion_generar'))
    
    # Calcular totales
    subtotal = sum(
        (Decimal(str(p.get('monto_estimado', 0) or 0)) for p in pacientes_raw),
        Decimal('0.00'),
    )
    total = subtotal
    
    conn = None
    cursor = None
    try:
        # Obtener centro médico
        centro_medico_id = None
        centro_medico_nombre = None
        if medico_factura.get('centro_medico_id'):
            centro_medico = execute_query('SELECT * FROM centros_medicos WHERE id = %s AND tenant_id = %s', 
                                         (medico_factura['centro_medico_id'], tenant_id))
            if centro_medico:
                centro_medico_id = centro_medico['id']
                centro_medico_nombre = centro_medico.get('nombre', '')
        
        # Usar el primer paciente como referencia para datos generales
        primer_paciente = pacientes_raw[0]

        # La factura y su consecutivo se confirman o revierten como una unidad.
        conn = get_db_connection()
        conn.begin()
        cursor = conn.cursor()
        fecha_actual = datetime.now()
        reserva_ecf = None
        factura_ecf_id = None
        ecf_build_error = None
        envio_ecf_pendiente = False

        if tipo_factura == 'ELECTRONICA':
            fecha_documento = datetime.strptime(
                fecha_factura,
                '%Y-%m-%d'
            ).date()
            reserva_ecf = reserve_encf(
                cursor,
                tenant_id,
                ecf_type='31',
                issue_date=fecha_documento
            )
            ncf_numero = reserva_ecf.value
            numero_factura = (
                f"FAC-E-{tenant_id}-{fecha_actual.strftime('%Y%m%d')}-"
                f"{reserva_ecf.number:010d}"
            )
        else:
            cursor.execute(
                'SELECT * FROM ncf WHERE id = %s AND tenant_id = %s FOR UPDATE',
                (ncf_id, tenant_id)
            )
            ncf_bloqueado = cursor.fetchone()
            if not ncf_bloqueado or not ncf_bloqueado.get('activo'):
                raise ValueError('La secuencia NCF ya no está disponible')

            proximo_numero = (
                int(ncf_bloqueado.get('ultimo_numero', 0) or 0) + 1
            )
            tamano_secuencia = int(
                ncf_bloqueado.get('tamano_secuencia', 8) or 8
            )
            ncf_numero = (
                f"{ncf_bloqueado['prefijo']}"
                f"{proximo_numero:0{tamano_secuencia}d}"
            )
            numero_factura = (
                f"FAC-{fecha_actual.strftime('%Y%m%d')}-{proximo_numero:04d}"
            )

        cursor.execute(
            'SELECT id FROM facturas WHERE tenant_id = %s AND ncf = %s LIMIT 1',
            (tenant_id, ncf_numero)
        )
        if cursor.fetchone():
            raise ValueError(f'El NCF {ncf_numero} ya fue utilizado')

        cursor.execute('''
            INSERT INTO facturas 
            (tenant_id, numero_factura, tipo_factura, ncf, fecha_emision, paciente_id, nombre_paciente,
             cedula_paciente, nss_paciente, ars_id, nombre_ars, medico_id, nombre_medico,
             centro_medico_id, nombre_centro_medico, subtotal, itbis, total, estado, created_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'Pendiente', %s)
        ''', (tenant_id, numero_factura, tipo_factura, ncf_numero, fecha_factura,
              primer_paciente.get('paciente_id'), primer_paciente.get('nombre_paciente', ''),
              primer_paciente.get('cedula'), primer_paciente.get('nss'),
              ars_id, ars.get('nombre', ''), medico_factura_id, medico_factura.get('nombre', ''),
              centro_medico_id, centro_medico_nombre, subtotal, 0, total, current_user.id))

        factura_id = cursor.lastrowid

        if reserva_ecf:
            cursor.execute('''
                INSERT INTO facturas_ecf
                (tenant_id, factura_id, tipo_ecf, e_ncf, estado,
                 idempotency_key)
                VALUES (%s, %s, %s, %s, 'PENDIENTE_ENVIO', %s)
            ''', (
                tenant_id,
                factura_id,
                reserva_ecf.ecf_type,
                reserva_ecf.value,
                idempotency_key
            ))
            factura_ecf_id = cursor.lastrowid
            cursor.execute('''
                INSERT INTO ecf_eventos
                (tenant_id, factura_ecf_id, estado_anterior, estado_nuevo,
                 evento, detalle, usuario_id)
                VALUES (%s, %s, NULL, 'PENDIENTE_ENVIO',
                        'ENCF_RESERVADO', %s, %s)
            ''', (
                tenant_id,
                factura_ecf_id,
                f'e-NCF {reserva_ecf.value} reservado localmente',
                current_user.id
            ))

        # Crear detalles de factura para cada paciente
        detalles_ecf = []
        for paciente in pacientes_raw:
            servicio_completo = paciente.get('servicios_realizados', '') or ''
            if ' - Autorización:' in servicio_completo:
                descripcion_servicio = servicio_completo.split(' - Autorización:')[0].strip()
            else:
                descripcion_servicio = servicio_completo.strip()
            
            monto = float(paciente.get('monto_estimado', 0) or 0)
            
            cursor.execute('''
                INSERT INTO factura_detalles
                (tenant_id, factura_id, descripcion, cantidad, precio_unitario, subtotal)
                VALUES (%s, %s, %s, 1, %s, %s)
            ''', (tenant_id, factura_id, descripcion_servicio, monto, monto))

            detalles_ecf.append({
                'descripcion': descripcion_servicio,
                'cantidad': 1,
                'precio_unitario': monto,
                'subtotal': monto,
                # Los servicios médicos del flujo actual se registran sin ITBIS.
                'indicador_facturacion': 4,
                'indicador_bien_servicio': 2
            })

        if reserva_ecf:
            cursor.execute('''
                UPDATE facturas_ecf
                SET estado='GENERANDO_XML', ultimo_error=NULL
                WHERE id=%s AND tenant_id=%s
            ''', (factura_ecf_id, tenant_id))
            cursor.execute('''
                INSERT INTO ecf_eventos
                (tenant_id, factura_ecf_id, estado_anterior, estado_nuevo,
                 evento, detalle, usuario_id)
                VALUES (%s, %s, 'PENDIENTE_ENVIO', 'GENERANDO_XML',
                        'GENERACION_XML_INICIADA', %s, %s)
            ''', (
                tenant_id,
                factura_ecf_id,
                'Construcción local del XML E31 iniciada',
                current_user.id
            ))

            try:
                resultado_xml = ECFBuilder().build_e31(
                    invoice={
                        'numero_factura': numero_factura,
                        'fecha_emision': fecha_factura,
                        'total': total
                    },
                    electronic={
                        'tipo_ecf': reserva_ecf.ecf_type,
                        'e_ncf': reserva_ecf.value,
                        # Facturas a ARS: operación ordinaria emitida a crédito.
                        'tipo_ingresos': '01',
                        'tipo_pago': '2'
                    },
                    sequence_expires_at=reserva_ecf.expires_at,
                    issuer=empresa_info or {},
                    buyer=ars,
                    items=detalles_ecf,
                    generated_at=fecha_actual
                )
                cursor.execute('''
                    UPDATE facturas_ecf
                    SET estado='XML_GENERADO', xml_generado=%s,
                        hash_xml_generado=%s, fecha_generacion=%s,
                        ultimo_error=NULL
                    WHERE id=%s AND tenant_id=%s
                ''', (
                    resultado_xml.xml,
                    resultado_xml.sha256,
                    resultado_xml.generated_at,
                    factura_ecf_id,
                    tenant_id
                ))
                cursor.execute('''
                    INSERT INTO ecf_eventos
                    (tenant_id, factura_ecf_id, estado_anterior, estado_nuevo,
                     evento, detalle, usuario_id)
                    VALUES (%s, %s, 'GENERANDO_XML', 'XML_GENERADO',
                            'XML_GENERADO', %s, %s)
                ''', (
                    tenant_id,
                    factura_ecf_id,
                    f'XML E31 generado; SHA-256 {resultado_xml.sha256}',
                    current_user.id
                ))

                resultado_validacion = ECFValidator().validate_unsigned_e31(
                    resultado_xml.xml
                )
                ajustes_xsd = ', '.join(
                    resultado_validacion.compatibility_adjustments
                )
                cursor.execute('''
                    UPDATE facturas_ecf
                    SET estado='XML_VALIDADO', ultimo_error=NULL
                    WHERE id=%s AND tenant_id=%s
                ''', (factura_ecf_id, tenant_id))
                cursor.execute('''
                    INSERT INTO ecf_eventos
                    (tenant_id, factura_ecf_id, estado_anterior, estado_nuevo,
                     evento, detalle, usuario_id)
                    VALUES (%s, %s, 'XML_GENERADO', 'XML_VALIDADO',
                            'XML_VALIDADO_XSD', %s, %s)
                ''', (
                    tenant_id,
                    factura_ecf_id,
                    (
                        'XML E31 validado antes de firma; '
                        f'XSD SHA-256 {resultado_validacion.schema_sha256}; '
                        f'ajustes en memoria: {ajustes_xsd}'
                    ),
                    current_user.id
                ))

                cursor.execute('''
                    INSERT INTO ecf_eventos
                    (tenant_id, factura_ecf_id, estado_anterior, estado_nuevo,
                     evento, detalle, usuario_id)
                    VALUES (%s, %s, 'XML_VALIDADO', 'XML_VALIDADO',
                            'FIRMA_INICIADA', %s, %s)
                ''', (
                    tenant_id,
                    factura_ecf_id,
                    'Firma local XMLDSig RSA-SHA256 iniciada',
                    current_user.id
                ))
                try:
                    certificado_resuelto, certificado_metadata = (
                        TenantCertificateProvider(
                            app.config['ECF_CONFIG']
                        ).inspect(
                            tenant_id,
                            (empresa_info or {}).get('rnc'),
                            obtener_configuracion_ecf_tenant(tenant_id),
                        )
                    )
                    resultado_firma = certificado_resuelto.signer().sign_e31(
                        resultado_xml.xml,
                        expected_signer_id=(empresa_info or {}).get('rnc'),
                        signed_at=datetime.now()
                    )
                    validacion_firmada = ECFValidator().validate_signed_e31(
                        resultado_firma.signed_xml
                    )
                    cursor.execute('''
                        UPDATE facturas_ecf
                        SET estado='FIRMADO', xml_firmado=%s,
                            hash_xml_firmado=%s, fecha_firma=%s,
                            ultimo_error=NULL
                        WHERE id=%s AND tenant_id=%s
                    ''', (
                        resultado_firma.signed_xml,
                        resultado_firma.sha256,
                        resultado_firma.signed_at,
                        factura_ecf_id,
                        tenant_id
                    ))
                    cursor.execute('''
                        UPDATE ecf_configuraciones
                        SET certificado_huella=%s,
                            certificado_vence=%s,
                            certificado_validado_en=NOW()
                        WHERE tenant_id=%s
                    ''', (
                        certificado_metadata.fingerprint,
                        certificado_metadata.valid_until.date(),
                        tenant_id
                    ))
                    cursor.execute('''
                        INSERT INTO ecf_eventos
                        (tenant_id, factura_ecf_id,
                         estado_anterior, estado_nuevo,
                         evento, detalle, usuario_id)
                        VALUES (%s, %s, 'XML_VALIDADO', 'FIRMADO',
                                'XML_FIRMADO', %s, %s)
                    ''', (
                        tenant_id,
                        factura_ecf_id,
                        (
                            'Firma RSA-SHA256 verificada; '
                            f'XML SHA-256 {resultado_firma.sha256}; '
                            'certificado SHA-256 '
                            f'{resultado_firma.certificate_fingerprint}; '
                            'XSD SHA-256 '
                            f'{validacion_firmada.schema_sha256}'
                        ),
                        current_user.id
                    ))
                    cursor.execute('''
                        INSERT INTO ecf_outbox
                        (tenant_id, factura_ecf_id, clave_evento,
                         tipo_evento, estado, payload, proximo_intento)
                        VALUES (%s, %s, %s, 'ENVIAR_ECF',
                                'PENDIENTE', %s, NOW())
                    ''', (
                        tenant_id,
                        factura_ecf_id,
                        f'ENVIAR_ECF:{factura_ecf_id}',
                        json.dumps({
                            'factura_ecf_id': factura_ecf_id,
                            'e_ncf': reserva_ecf.value
                        })
                    ))
                    envio_ecf_pendiente = True
                except (
                    ECFCertificateResolutionError,
                    ECFSigningError,
                    ECFValidationError,
                    ECFSchemaError
                ) as signing_error:
                    ecf_build_error = str(signing_error)
                    cursor.execute('''
                        UPDATE facturas_ecf
                        SET estado='ERROR_FIRMA', ultimo_error=%s
                        WHERE id=%s AND tenant_id=%s
                    ''', (ecf_build_error, factura_ecf_id, tenant_id))
                    cursor.execute('''
                        INSERT INTO ecf_eventos
                        (tenant_id, factura_ecf_id,
                         estado_anterior, estado_nuevo,
                         evento, detalle, usuario_id)
                        VALUES (%s, %s, 'XML_VALIDADO', 'ERROR_FIRMA',
                                'ERROR_FIRMA', %s, %s)
                    ''', (
                        tenant_id,
                        factura_ecf_id,
                        ecf_build_error,
                        current_user.id
                    ))
            except ECFBuildError as build_error:
                ecf_build_error = str(build_error)
                cursor.execute('''
                    UPDATE facturas_ecf
                    SET estado='ERROR_VALIDACION', ultimo_error=%s
                    WHERE id=%s AND tenant_id=%s
                ''', (ecf_build_error, factura_ecf_id, tenant_id))
                cursor.execute('''
                    INSERT INTO ecf_eventos
                    (tenant_id, factura_ecf_id, estado_anterior, estado_nuevo,
                     evento, detalle, usuario_id)
                    VALUES (%s, %s, 'GENERANDO_XML', 'ERROR_VALIDACION',
                            'ERROR_DATOS_XML', %s, %s)
                ''', (
                    tenant_id,
                    factura_ecf_id,
                    ecf_build_error,
                    current_user.id
                ))
            except (ECFValidationError, ECFSchemaError) as validation_error:
                ecf_build_error = str(validation_error)
                cursor.execute('''
                    UPDATE facturas_ecf
                    SET estado='ERROR_VALIDACION', ultimo_error=%s
                    WHERE id=%s AND tenant_id=%s
                ''', (ecf_build_error, factura_ecf_id, tenant_id))
                cursor.execute('''
                    INSERT INTO ecf_eventos
                    (tenant_id, factura_ecf_id, estado_anterior, estado_nuevo,
                     evento, detalle, usuario_id)
                    VALUES (%s, %s, 'XML_GENERADO', 'ERROR_VALIDACION',
                            'ERROR_VALIDACION_XSD', %s, %s)
                ''', (
                    tenant_id,
                    factura_ecf_id,
                    ecf_build_error,
                    current_user.id
                ))
        
        # Actualizar estado de pacientes_pendientes a 'Facturado'
        cursor.execute(f'''
            UPDATE pacientes_pendientes 
            SET estado = 'Facturado' 
            WHERE id IN ({placeholders}) AND tenant_id = %s
              AND estado = 'Pendiente'
        ''', tuple(pacientes_ids) + (tenant_id,))

        if cursor.rowcount != len(set(pacientes_ids)):
            raise RuntimeError(
                'Cambió la disponibilidad de los pacientes durante la generación'
            )

        # El e-NCF ya fue reservado por reserve_encf dentro de esta transacción.
        if tipo_factura == 'TRADICIONAL':
            cursor.execute('''
                UPDATE ncf
                SET ultimo_numero = %s, proximo_numero = %s
                WHERE id = %s AND tenant_id = %s
            ''', (proximo_numero, proximo_numero + 1, ncf_id, tenant_id))

        conn.commit()
        envio_ecf_exitoso = False
        envio_ecf_resultado = ''
        estado_consultado_dgii = None
        mensaje_consultado_dgii = ''
        if tipo_factura == 'ELECTRONICA' and envio_ecf_pendiente:
            try:
                envio_ecf_exitoso, envio_ecf_resultado = (
                    procesar_envio_ecf_dgii(
                        factura_ecf_id,
                        tenant_id,
                        current_user.id
                    )
                )
                if envio_ecf_exitoso:
                    (
                        _,
                        estado_consultado_dgii,
                        mensaje_consultado_dgii
                    ) = consultar_resultado_ecf_dgii(
                        factura_ecf_id,
                        tenant_id,
                        current_user.id
                    )
            except Exception as dispatch_error:
                logger.error(
                    'La factura e-CF %s quedó creada, pero falló el '
                    'procesamiento de salida: %s',
                    factura_ecf_id,
                    dispatch_error,
                    exc_info=True
                )
                envio_ecf_resultado = (
                    'El documento quedó firmado y pendiente de envío'
                )

        if tipo_factura == 'ELECTRONICA':
            if ecf_build_error:
                flash(
                    f'Factura {numero_factura} creada con {ncf_numero}, pero '
                    f'el XML requiere corrección: {ecf_build_error}',
                    'warning'
                )
            elif envio_ecf_exitoso:
                if estado_consultado_dgii == 'ACEPTADO':
                    flash(
                        f'Factura {numero_factura} aceptada por DGII. '
                        f'TrackID: {envio_ecf_resultado}.',
                        'success'
                    )
                elif estado_consultado_dgii == 'RECHAZADO':
                    flash(
                        f'Factura {numero_factura} rechazada por DGII: '
                        f'{mensaje_consultado_dgii}',
                        'error'
                    )
                else:
                    flash(
                        f'Factura {numero_factura} enviada a DGII. '
                        f'TrackID: {envio_ecf_resultado}. '
                        'Pendiente de respuesta de validación.',
                        'success'
                    )
            else:
                flash(
                    f'Factura {numero_factura} creada con {ncf_numero}. '
                    f'{envio_ecf_resultado or "Pendiente de envío a DGII"}.',
                    'warning'
                )
        else:
            flash(f'Factura {numero_factura} generada exitosamente', 'success')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))
        
    except Exception as e:
        if conn:
            conn.rollback()
        import traceback
        error_trace = traceback.format_exc()
        logger.error(f"Error al generar factura: {error_trace}")
        flash(f'Error al generar la factura: {str(e)}', 'error')
        return redirect(url_for('facturacion_generar'))
    finally:
        if cursor:
            cursor.close()

# Rutas alternativas del template base (redirigen al menú principal)
@app.route('/services')
@app.route('/about')
@app.route('/contact')
@app.route('/request-appointment')
def redirects():
    """Rutas alternativas - redirigen al login o menú si está autenticado"""
    if current_user.is_authenticated:
        return redirect(url_for('facturacion_menu'))
    return redirect(url_for('login'))

@app.route('/admin/usuarios')
@login_required
def admin_usuarios():
    """Listar usuarios - Filtra por tenant del usuario actual"""
    if current_user.perfil != 'Administrador':
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_menu'))
    
    # Obtener usuarios del mismo tenant
    tenant_id = get_current_tenant_id()
    usuarios = execute_query('''
        SELECT u.*, e.nombre as empresa_nombre
        FROM usuarios u
        LEFT JOIN empresas e ON u.tenant_id = e.id
        WHERE u.tenant_id = %s 
        ORDER BY u.created_at DESC
    ''', (tenant_id,), fetch='all')
    
    # Obtener info de licencias
    empresa = get_empresa_info()
    
    return render_template('usuarios/lista.html', usuarios=usuarios, empresa=empresa)

@app.route('/admin/usuarios/nuevo', methods=['GET', 'POST'])
@login_required
def admin_usuarios_nuevo():
    """Crear nuevo usuario"""
    if current_user.perfil != 'Administrador':
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_menu'))
    
    if request.method == 'POST':
        nombre = sanitize_input(request.form.get('nombre', ''), 100)
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password_nuevo', '')
        perfil = request.form.get('perfil', '')
        
        if not nombre or not email or not password or not perfil:
            flash('Todos los campos son obligatorios', 'error')
            return redirect(url_for('admin_usuarios_nuevo'))
        
        if not validate_email(email):
            flash('Email inválido', 'error')
            return redirect(url_for('admin_usuarios_nuevo'))
        
        password_errors = validar_password_segura(password)
        if password_errors:
            flash(f'Contraseña no válida: {", ".join(password_errors)}', 'error')
            return redirect(url_for('admin_usuarios_nuevo'))
        
        if perfil not in ['Administrador', 'Nivel 2', 'Registro de Facturas']:
            flash('Perfil inválido', 'error')
            return redirect(url_for('admin_usuarios_nuevo'))
        
        # Obtener tenant_id del usuario actual
        tenant_id = get_current_tenant_id()
        
        # VALIDAR LICENCIAS DISPONIBLES
        licencia_ok, licencias_disponibles, mensaje = check_license_available(tenant_id)
        if not licencia_ok:
            flash(f'No se puede crear usuario: {mensaje}', 'error')
            return redirect(url_for('admin_usuarios_nuevo'))
        
        # Verificar email en el mismo tenant
        existe = execute_query(
            'SELECT id FROM usuarios WHERE email = %s AND tenant_id = %s', 
            (email, tenant_id)
        )
        
        if existe:
            flash('Ya existe un usuario con ese email en tu empresa', 'error')
            return redirect(url_for('admin_usuarios_nuevo'))
        
        password_hash = generate_password_hash(password)
        execute_update('''
            INSERT INTO usuarios (tenant_id, nombre, email, password_hash, perfil, activo, password_temporal)
            VALUES (%s, %s, %s, %s, %s, 1, 1)
        ''', (tenant_id, nombre, email, password_hash, perfil))
        
        flash(f'Usuario {nombre} creado exitosamente ({licencias_disponibles - 1} licencias restantes)', 'success')
        return redirect(url_for('admin_usuarios'))
    
    return render_template('usuarios/form.html', usuario=None)

@app.route('/admin/usuarios/<int:usuario_id>/editar', methods=['GET', 'POST'])
@login_required
def admin_usuarios_editar(usuario_id):
    """Editar usuario"""
    if current_user.perfil != 'Administrador':
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_menu'))

    tenant_id = get_current_tenant_id()
    if tenant_id is None:
        flash(
            'Selecciona una empresa antes de administrar sus usuarios.',
            'error',
        )
        return redirect(url_for('admin_usuarios'))

    usuario = execute_query(
        'SELECT * FROM usuarios WHERE id = %s AND tenant_id = %s',
        (usuario_id, tenant_id),
    )
    
    if not usuario:
        flash('Usuario no encontrado', 'error')
        return redirect(url_for('admin_usuarios'))
    
    if request.method == 'POST':
        nombre = sanitize_input(request.form.get('nombre', ''), 100)
        email = request.form.get('email', '').strip().lower()
        perfil = request.form.get('perfil', '')
        activo = request.form.get('activo') == '1'
        cambiar_password = request.form.get('cambiar_password') == '1'
        password = request.form.get('password', '')
        
        if not nombre or not email or not perfil:
            flash('Nombre, email y perfil son obligatorios', 'error')
            return redirect(url_for('admin_usuarios_editar', usuario_id=usuario_id))
        
        if not validate_email(email):
            flash('Email inválido', 'error')
            return redirect(url_for('admin_usuarios_editar', usuario_id=usuario_id))
        
        if perfil not in ['Administrador', 'Nivel 2', 'Registro de Facturas']:
            flash('Perfil inválido', 'error')
            return redirect(url_for('admin_usuarios_editar', usuario_id=usuario_id))
        
        if usuario_id == current_user.id and not activo:
            flash('No puedes desactivar tu propia cuenta', 'error')
            return redirect(url_for('admin_usuarios_editar', usuario_id=usuario_id))
        
        existe = execute_query(
            '''
            SELECT id FROM usuarios
            WHERE email = %s AND id != %s AND tenant_id = %s
            ''',
            (email, usuario_id, tenant_id),
        )
        
        if existe:
            flash('Ya existe otro usuario con ese email', 'error')
            return redirect(url_for('admin_usuarios_editar', usuario_id=usuario_id))
        
        if cambiar_password and password:
            if len(password) < 8:
                flash('La contraseña debe tener al menos 8 caracteres', 'error')
                return redirect(url_for('admin_usuarios_editar', usuario_id=usuario_id))
            
            password_hash = generate_password_hash(password)
            execute_update('''
                UPDATE usuarios 
                SET nombre = %s, email = %s, password_hash = %s, perfil = %s, activo = %s, password_temporal = 1
                WHERE id = %s AND tenant_id = %s
            ''', (
                nombre,
                email,
                password_hash,
                perfil,
                activo,
                usuario_id,
                tenant_id,
            ))
            
            if usuario_id == current_user.id:
                logout_user()
                flash('Tu contraseña ha sido cambiada.', 'warning')
                return redirect(url_for('login'))
            
            flash(f'Usuario {nombre} actualizado con nueva contraseña', 'success')
        else:
            execute_update('''
                UPDATE usuarios 
                SET nombre = %s, email = %s, perfil = %s, activo = %s
                WHERE id = %s AND tenant_id = %s
            ''', (nombre, email, perfil, activo, usuario_id, tenant_id))
            
            flash(f'Usuario {nombre} actualizado exitosamente', 'success')
        
        return redirect(url_for('admin_usuarios'))
    
    return render_template('usuarios/form.html', usuario=usuario)

@app.route('/admin/usuarios/<int:usuario_id>/eliminar', methods=['POST'])
@login_required
@roles_required('Administrador')
def admin_usuarios_eliminar(usuario_id):
    """Eliminar usuario - DESHABILITADO"""
    flash('Eliminación deshabilitada. Desactiva el usuario en su lugar.', 'warning')
    return redirect(url_for('admin_usuarios'))

@app.route('/perfil/configuracion', methods=['GET', 'POST'])
@login_required
def perfil_configuracion():
    """Configuración del perfil del usuario"""
    TEMAS_VALIDOS = [
        'cyan', 'ocean', 'emerald', 'teal', 'aqua',
        'mint', 'lagoon', 'sky', 'sage'
    ]
    
    if request.method == 'POST':
        tema_color = request.form.get(
            'tema_color', current_user.tema_color or 'cyan'
        )
        fuente_ui = request.form.get(
            'fuente_ui', current_user.fuente_ui or 'arsflow'
        )
        
        if tema_color not in TEMAS_VALIDOS:
            flash('Tema de color inválido', 'error')
            return redirect(url_for('perfil_configuracion'))
        if fuente_ui not in FUENTES_UI:
            flash('Tipografía inválida', 'error')
            return redirect(url_for('perfil_configuracion'))
        
        execute_update(
            '''
            UPDATE usuarios SET tema_color=%s, fuente_ui=%s
            WHERE id=%s AND tenant_id <=> %s
            ''',
            (
                tema_color,
                fuente_ui,
                current_user.id,
                get_current_tenant_id(),
            ),
        )
        
        current_user.tema_color = tema_color
        current_user.fuente_ui = fuente_ui
        
        flash('Apariencia actualizada correctamente', 'success')
        return redirect(url_for('perfil_configuracion'))
    
    ecf_certificado = None
    if current_user.perfil == 'Administrador':
        tenant_id = get_current_tenant_id()
        empresa_actual = get_empresa_info(tenant_id) or {}
        ecf_config = app.config['ECF_CONFIG']
        ecf_certificado = {
            'habilitado_global': ecf_config.enabled,
            'ambiente': ecf_config.environment,
            'configurado': False,
            'valido': False,
            'mensaje': 'La integración e-CF está desactivada en el servidor.',
            'vence': None,
            'huella': None,
            'compatibilidad_global': False,
            'referencia_esperada': (
                f'tenant-{tenant_id}/certificate.p12'
            ),
        }
        if ecf_config.enabled:
            try:
                resolved, metadata = TenantCertificateProvider(
                    ecf_config
                ).inspect(
                    tenant_id,
                    empresa_actual.get('rnc'),
                    obtener_configuracion_ecf_tenant(tenant_id),
                )
                ecf_certificado.update({
                    'configurado': True,
                    'valido': True,
                    'mensaje': (
                        'Certificado válido y correspondiente al RNC de la cuenta.'
                    ),
                    'vence': metadata.valid_until,
                    'huella': metadata.fingerprint,
                    'compatibilidad_global': resolved.legacy_fallback,
                })
            except ECFCertificateResolutionError as error:
                ecf_certificado['mensaje'] = str(error)

    return render_template(
        'perfil/configuracion.html',
        ecf_certificado=ecf_certificado,
    )

if IS_PRODUCTION:
    validate_production_startup()

if __name__ == '__main__':
    if IS_PRODUCTION:
        raise RuntimeError(
            'No uses el servidor de desarrollo en producción. '
            'Inicia la aplicación con Waitress u otro servidor WSGI.'
        )

    port = int(os.getenv('PORT', 5000))
    host = os.getenv('HOST', '127.0.0.1')
    debug = ENVIRONMENT == 'development'
    
    print("\n" + "="*60)
    print(" ARSFLOW GESTION DE FACTRAS MEDICAS")
    print("="*60)
    print(f" Entorno: {'PRODUCCION' if not debug else 'DESARROLLO'}")
    print(f" Host: {host}:{port}")
    print(f" Base de datos: {DATABASE_CONFIG['database']}")
    print("="*60 + "\n")
    
    app.run(host=host, port=port, debug=debug)
