# Sistema de Facturación Médica

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, make_response, send_file, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
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
from collections import defaultdict
from threading import Lock
from functools import wraps

import pymysql
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

app = Flask(__name__)

app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(32))

app.config['SESSION_COOKIE_SECURE'] = os.getenv('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
app.config['SESSION_COOKIE_NAME'] = 'facturacion_session'
app.config['TEMPLATES_AUTO_RELOAD'] = True

@app.after_request
def set_security_headers(response):
    """Agregar headers de seguridad a todas las respuestas"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://www.googletagmanager.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://www.googletagmanager.com; "
        "frame-ancestors 'self';"
    )
    response.headers['Content-Security-Policy'] = csp
    
    if request.path.startswith('/static/'):
        response.headers['Cache-Control'] = 'public, max-age=31536000'
    else:
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    
    return response

from flask import g
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

def get_db_connection():
    """Obtener conexión a la base de datos"""
    config = DATABASE_CONFIG.copy()
    config['cursorclass'] = pymysql.cursors.DictCursor
    conn = pymysql.connect(**config)
    return conn

def execute_query(query, params=None, fetch='one'):
    """Ejecutar query y retornar resultados"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(query, params or ())
        if fetch == 'one':
            result = cursor.fetchone()
        elif fetch == 'all':
            result = cursor.fetchall()
        else:
            result = None
        conn.commit()
        return result
    finally:
        cursor.close()
        conn.close()

def execute_update(query, params=None):
    """Ejecutar UPDATE/INSERT/DELETE"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(query, params or ())
        conn.commit()
        return cursor.lastrowid
    finally:
        cursor.close()
        conn.close()

def sanitize_input(text, max_length=500):
    """Sanitizar entrada de texto"""
    if not text:
        return ""
    text = str(text).strip()
    text = re.sub(r'<[^>]*>', '', text)
    return text[:max_length]

def validate_email(email):
    """Validar formato de email"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

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

# Context processor para temas de color
@app.context_processor
def inject_theme():
    """Inyectar tema de color en todos los templates"""
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
        'coral': {
            'primary': '#FF6B6B',
            'primary_dark': '#EE5A52',
            'primary_light': '#FF8787',
            'background': '#FFF5F5',
            'gradient_start': '#FF6B6B',
            'gradient_end': '#EE5A52',
            'nombre': 'Coral Cálido',
            'categoria': 'Cálido'
        },
        'sunset': {
            'primary': '#F59E0B',
            'primary_dark': '#D97706',
            'primary_light': '#FBBF24',
            'background': '#FFFBEB',
            'gradient_start': '#F59E0B',
            'gradient_end': '#D97706',
            'nombre': 'Naranja Atardecer',
            'categoria': 'Cálido'
        },
        'rose': {
            'primary': '#F43F5E',
            'primary_dark': '#E11D48',
            'primary_light': '#FB7185',
            'background': '#FFF1F2',
            'gradient_start': '#F43F5E',
            'gradient_end': '#E11D48',
            'nombre': 'Rosa Moderno',
            'categoria': 'Cálido'
        },
        'amber': {
            'primary': '#F59E0B',
            'primary_dark': '#D97706',
            'primary_light': '#FCD34D',
            'background': '#FEFCE8',
            'gradient_start': '#F59E0B',
            'gradient_end': '#D97706',
            'nombre': 'Ámbar Dorado',
            'categoria': 'Cálido'
        },
        'indigo': {
            'primary': '#4F46E5',
            'primary_dark': '#4338CA',
            'primary_light': '#6366F1',
            'background': '#EEF2FF',
            'gradient_start': '#4F46E5',
            'gradient_end': '#6366F1',
            'nombre': 'Azul Profesional',
            'categoria': 'Profesional'
        },
        'purple': {
            'primary': '#7C3AED',
            'primary_dark': '#6D28D9',
            'primary_light': '#8B5CF6',
            'background': '#FAF5FF',
            'gradient_start': '#7C3AED',
            'gradient_end': '#8B5CF6',
            'nombre': 'Púrpura Elegante',
            'categoria': 'Profesional'
        },
        'violet': {
            'primary': '#8B5CF6',
            'primary_dark': '#7C3AED',
            'primary_light': '#A78BFA',
            'background': '#F5F3FF',
            'gradient_start': '#8B5CF6',
            'gradient_end': '#7C3AED',
            'nombre': 'Violeta Suave',
            'categoria': 'Profesional'
        },
        'slate': {
            'primary': '#475569',
            'primary_dark': '#334155',
            'primary_light': '#64748B',
            'background': '#F8FAFC',
            'gradient_start': '#475569',
            'gradient_end': '#334155',
            'nombre': 'Gris Elegante',
            'categoria': 'Neutral'
        },
        'navy': {
            'primary': '#1E3A8A',
            'primary_dark': '#1E40AF',
            'primary_light': '#3B82F6',
            'background': '#EFF6FF',
            'gradient_start': '#1E3A8A',
            'gradient_end': '#1E40AF',
            'nombre': 'Azul Marino',
            'categoria': 'Profesional'
        },
        'forest': {
            'primary': '#15803D',
            'primary_dark': '#166534',
            'primary_light': '#22C55E',
            'background': '#F0FDF4',
            'gradient_start': '#15803D',
            'gradient_end': '#166534',
            'nombre': 'Verde Bosque',
            'categoria': 'Natural'
        },
        'wine': {
            'primary': '#BE123C',
            'primary_dark': '#9F1239',
            'primary_light': '#E11D48',
            'background': '#FFF1F2',
            'gradient_start': '#BE123C',
            'gradient_end': '#9F1239',
            'nombre': 'Vino Elegante',
            'categoria': 'Sofisticado'
        },
        'bronze': {
            'primary': '#92400E',
            'primary_dark': '#78350F',
            'primary_light': '#B45309',
            'background': '#FEF3C7',
            'gradient_start': '#92400E',
            'gradient_end': '#78350F',
            'nombre': 'Bronce Cálido',
            'categoria': 'Cálido'
        }
    }
    
    tema_actual = 'cyan'  # Default
    if current_user.is_authenticated:
        tema_actual = current_user.tema_color or 'cyan'
    
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
        'empresa': empresa_info
    }

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = None

class User(UserMixin):
    def __init__(self, id, nombre, email, perfil, tema_color='cyan', tenant_id=1, empresa_nombre=''):
        self.id = id
        self.nombre = nombre
        self.email = email
        self.perfil = perfil
        self.tema_color = tema_color or 'cyan'
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

def get_current_tenant_id():
    """
    Obtener el TenantID del usuario actual de forma segura.
    El TenantID NUNCA viene del cliente, siempre de la sesión.
    """
    if current_user.is_authenticated:
        return current_user.tenant_id
    return None

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

def add_tenant_filter(query, table_alias=''):
    """
    Agregar filtro de TenantID automáticamente a una query.
    
    Uso:
        query = "SELECT * FROM pacientes WHERE activo = 1"
        query = add_tenant_filter(query)
        # Resultado: "SELECT * FROM pacientes WHERE activo = 1 AND tenant_id = %s"
    """
    tenant_id = get_current_tenant_id()
    if not tenant_id:
        return query
    
    table_ref = f"{table_alias}." if table_alias else ""
    
    # Si la query ya tiene WHERE, agregar AND
    if 'WHERE' in query.upper():
        query += f" AND {table_ref}tenant_id = {tenant_id}"
    else:
        query += f" WHERE {table_ref}tenant_id = {tenant_id}"
    
    return query

def validate_tenant_access(table, record_id, id_column='id'):
    """
    Validar que un registro pertenece al Tenant del usuario actual.
    Previene acceso a datos de otras empresas.
    
    Returns: True si el usuario tiene acceso, False si no.
    """
    tenant_id = get_current_tenant_id()
    if not tenant_id:
        return False
    
    result = execute_query(
        f"SELECT COUNT(*) as count FROM {table} WHERE {id_column} = %s AND tenant_id = %s",
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

def execute_query_tenant(query, params=None, fetch='one'):
    """
    Wrapper para execute_query que automáticamente agrega filtro de tenant_id
    Solo para tablas que tienen tenant_id
    
    IMPORTANTE: Esta función agrega el tenant_id automáticamente al final de params
    """
    tenant_id = get_current_tenant_id()
    if not tenant_id:
        return execute_query(query, params, fetch)
    
    # Convertir params a lista si es tupla
    if params is None:
        params = []
    elif isinstance(params, tuple):
        params = list(params)
    elif not isinstance(params, list):
        params = [params]
    
    # Agregar tenant_id a los parámetros
    params.append(tenant_id)
    
    return execute_query(query, tuple(params), fetch)

def execute_update_tenant(query, params=None):
    """
    Wrapper para execute_update que valida tenant_id en UPDATEs/DELETEs
    """
    return execute_update(query, params)

request_counts = defaultdict(list)
rate_limit_lock = Lock()

def rate_limit(max_requests=10, window=60):
    """Decorador para rate limiting"""
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            client_ip = request.remote_addr
            current_time = time.time()
            
            with rate_limit_lock:
                request_counts[client_ip] = [
                    req_time for req_time in request_counts[client_ip]
                    if current_time - req_time < window
                ]
                
                if len(request_counts[client_ip]) >= max_requests:
                    return jsonify({'error': 'Rate limit exceeded'}), 429
                
                request_counts[client_ip].append(current_time)
            
            return f(*args, **kwargs)
        return wrapper
    return decorator


@app.route('/')
def index():
    """Página principal - redirige al login"""
    if current_user.is_authenticated:
        return redirect(url_for('facturacion_menu'))
    return redirect(url_for('login'))

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
                    flash('Debes cambiar tu contraseña temporal', 'warning')
                    return redirect(url_for('cambiar_password_obligatorio'))
                
                user = User(
                    id=user_data['id'],
                    nombre=user_data['nombre'],
                    email=user_data['email'],
                    perfil=user_data['perfil'],
                    tema_color=user_data.get('tema_color', 'cyan'),
                    tenant_id=user_data.get('tenant_id', 1),
                    empresa_nombre=user_data.get('empresa_nombre', '')
                )
                
                session.permanent = True
                session['tenant_id'] = user.tenant_id  # Guardar tenant_id en sesión
                session['empresa_nombre'] = user.empresa_nombre
                login_user(user, remember=True)
                
                execute_update('UPDATE usuarios SET last_login = %s WHERE id = %s',
                           (datetime.now(), user_data['id']))
                
                return redirect(url_for('facturacion_menu'))
            else:
                flash('Contraseña incorrecta', 'error')
        else:
            flash('Usuario no encontrado o inactivo', 'error')
        
        return redirect(url_for('login'))
    
    return render_template('login.html')

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
        password_hash = generate_password_hash(password)
        
        execute_update('''
            UPDATE usuarios 
            SET password_hash = %s, password_temporal = 0
            WHERE id = %s
        ''', (password_hash, user_id))
        
        user_data = execute_query('SELECT * FROM usuarios WHERE id = %s', (user_id,))
        
        # Limpiar sesión temporal
        session.pop('cambio_password_usuario_id', None)
        session.pop('cambio_password_email', None)
        
        # Login automático
        user = User(
            id=user_data['id'],
            nombre=user_data['nombre'],
            email=user_data['email'],
            perfil=user_data['perfil'],
            tema_color=user_data.get('tema_color', 'cyan')
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
                WHERE id = %s
            ''', (token, expiracion, usuario['id']))
            
            # Enviar email si SendGrid está disponible
            if SENDGRID_AVAILABLE:
                try:
                    reset_url = url_for('recuperar_password', token=token, _external=True)
                    
                    message = Mail(
                        from_email=os.getenv('SENDGRID_FROM_EMAIL', 'noreply@facturacion.com'),
                        to_emails=email,
                        subject='Recuperación de Contraseña - Sistema de Facturación',
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
                            <p style="color: #999; font-size: 12px;">Sistema de Facturación Médica</p>
                        </div>
                        '''
                    )
                    
                    sg = SendGridAPIClient(os.getenv('SENDGRID_API_KEY'))
                    sg.send(message)
                    
                    flash('Se ha enviado un email con instrucciones para recuperar tu contraseña', 'success')
                except Exception as e:
                    print(f"Error enviando email: {e}")
                    flash('Error al enviar el email. Contacta al administrador.', 'error')
            else:
                # Si no hay SendGrid, mostrar el token (solo para desarrollo)
                flash(f'Token de recuperación (solo desarrollo): {token}', 'info')
                flash('Usa este enlace para recuperar tu contraseña', 'info')
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
            WHERE id = %s
        ''', (password_hash, usuario['id']))
        
        flash('Contraseña actualizada exitosamente. Ahora puedes iniciar sesión.', 'success')
        return redirect(url_for('login'))
    
    return render_template('recuperar_password.html', token=token)

@app.route('/admin/empresas')
@login_required
def admin_empresas():
    """Listar todas las empresas (Solo Super Admin)"""
    # TODO: Implementar perfil Super Admin
    if current_user.perfil != 'Administrador':
        flash('No tienes permisos para gestionar empresas', 'error')
        return redirect(url_for('facturacion_menu'))
    
    # Verificar y suspender empresas vencidas
    empresas_suspendidas = verificar_suscripciones_vencidas()
    if empresas_suspendidas > 0:
        flash(f'{empresas_suspendidas} empresa(s) suspendida(s) por vencimiento de suscripción', 'warning')
    
    # Super Admin puede ver todas las empresas
    empresas = execute_query('''
        SELECT e.*, 
               COUNT(u.id) as total_usuarios
        FROM empresas e
        LEFT JOIN usuarios u ON e.id = u.tenant_id AND u.activo = 1
        GROUP BY e.id
        ORDER BY e.fecha_creacion DESC
    ''', fetch='all')
    
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
    """Crear nueva empresa"""
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
        licencias_totales = int(request.form.get('licencias_totales', 5))
        plan = request.form.get('plan', 'basico')
        
        if not nombre or not razon_social or not fecha_inicio or not fecha_fin:
            flash('Nombre, Razón Social y fechas son obligatorios', 'error')
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
        
        # Crear empresa
        execute_update('''
            INSERT INTO empresas (
                nombre, razon_social, rnc, telefono, email, direccion,
                fecha_inicio, fecha_fin,
                licencias_totales, licencias_usadas, plan, estado,
                creado_por
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 0, %s, 'activo', %s)
        ''', (nombre, razon_social, rnc, telefono, email, direccion, 
              fecha_inicio, fecha_fin, licencias_totales, plan, current_user.id))
        
        flash(f'Empresa "{nombre}" creada exitosamente', 'success')
        return redirect(url_for('admin_empresas'))
    
    return render_template('admin/empresas/form.html', empresa=None)

@app.route('/admin/empresas/editar/<int:empresa_id>', methods=['GET', 'POST'])
@login_required
def admin_empresas_editar(empresa_id):
    """Editar empresa"""
    if current_user.perfil != 'Administrador':
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_menu'))
    
    empresa = execute_query('SELECT * FROM empresas WHERE id = %s', (empresa_id,))
    
    if not empresa:
        flash('Empresa no encontrada', 'error')
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
        licencias_totales = int(request.form.get('licencias_totales', 5))
        plan = request.form.get('plan', 'basico')
        estado = request.form.get('estado', 'activo')
        
        # Validar fechas
        if fecha_inicio and fecha_fin:
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
        
        # Actualizar empresa
        execute_update('''
            UPDATE empresas SET
                nombre = %s, razon_social = %s, rnc = %s,
                telefono = %s, email = %s, direccion = %s,
                fecha_inicio = %s, fecha_fin = %s,
                licencias_totales = %s, plan = %s, estado = %s
            WHERE id = %s
        ''', (nombre, razon_social, rnc, telefono, email, direccion,
              fecha_inicio, fecha_fin, licencias_totales, plan, estado, empresa_id))
        
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
        tablas_verificar = [
            'usuarios', 'ars', 'medicos', 'codigo_ars', 
            'centros_medicos', 'medico_centro', 'servicios', 'ncf',
            'pacientes', 'facturas'
        ]
        
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
        
        if not nombre_ars:
            flash('El nombre es obligatorio', 'error')
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
        
        if not nombre_ars:
            flash('El nombre es obligatorio', 'error')
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
    medicos_list = execute_query(
        'SELECT * FROM medicos WHERE tenant_id = %s ORDER BY nombre', 
        (tenant_id,), fetch='all'
    ) or []
    return render_template('facturacion/medicos.html', medicos_list=medicos_list)

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
        especialidad = sanitize_input(request.form.get('especialidad', ''), 100)
        telefono = sanitize_input(request.form.get('telefono', ''), 20)
        email = request.form.get('email', '').strip()
        cedula = sanitize_input(request.form.get('cedula', ''), 20)
        factura = 1 if request.form.get('factura') == '1' else 0
        
        if not nombre:
            flash('El nombre es obligatorio', 'error')
            return redirect(url_for('facturacion_medicos_nuevo'))
        
        tenant_id = get_current_tenant_id()
        execute_update('''
            INSERT INTO medicos (tenant_id, nombre, exequatur, especialidad, telefono, email, cedula, activo, factura)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 1, %s)
        ''', (tenant_id, nombre, exequatur, especialidad, telefono, email, cedula, factura))
        
        flash(f'Médico {nombre} creado exitosamente', 'success')
        return redirect(url_for('facturacion_medicos'))
    
    return render_template('facturacion/medicos_form.html', medico=None)

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
        especialidad = sanitize_input(request.form.get('especialidad', ''), 100)
        telefono = sanitize_input(request.form.get('telefono', ''), 20)
        email = request.form.get('email', '').strip()
        cedula = sanitize_input(request.form.get('cedula', ''), 20)
        activo = 1 if request.form.get('activo') == '1' else 0
        factura = 1 if request.form.get('factura') == '1' else 0
        
        if not nombre:
            flash('El nombre es obligatorio', 'error')
            return redirect(url_for('facturacion_medicos_editar', medico_id=medico_id))
        
        tenant_id = get_current_tenant_id()
        execute_update('''
            UPDATE medicos 
            SET nombre = %s, exequatur = %s, especialidad = %s, telefono = %s, email = %s, cedula = %s, activo = %s, factura = %s
            WHERE id = %s AND tenant_id = %s
        ''', (nombre, exequatur, especialidad, telefono, email, cedula, activo, factura, medico_id, tenant_id))
        
        flash(f'Médico {nombre} actualizado exitosamente', 'success')
        return redirect(url_for('facturacion_medicos'))
    
    return render_template('facturacion/medicos_form.html', medico=medico)

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
        
        if not nombre:
            flash('El nombre es obligatorio', 'error')
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
        
        if not nombre:
            flash('El nombre es obligatorio', 'error')
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

@app.route('/facturacion/codigo-ars')
@login_required
def facturacion_codigo_ars():
    """Lista de códigos ARS - Filtrado por tenant"""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos para acceder a esta sección', 'error')
        return redirect(url_for('facturacion_menu'))
    
    tenant_id = get_current_tenant_id()
    codigos_list = execute_query('''
        SELECT ca.*, a.nombre, m.nombre as nombre_medico
        FROM codigo_ars ca 
        JOIN ars a ON ca.ars_id = a.id 
        LEFT JOIN medicos m ON ca.medico_id = m.id
        WHERE ca.tenant_id = %s
        ORDER BY m.nombre, a.nombre, ca.codigo
    ''', (tenant_id,), fetch='all') or []
    return render_template('facturacion/codigo_ars.html', codigos_list=codigos_list)

@app.route('/facturacion/codigo-ars/nuevo', methods=['GET', 'POST'])
@login_required
def facturacion_codigo_ars_nuevo():
    """Crear nuevo código ARS"""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_menu'))
    
    if request.method == 'POST':
        medico_id = request.form.get('medico_id')
        ars_id = request.form.get('ars_id')
        codigo = sanitize_input(request.form.get('codigo_ars', ''), 50)
        descripcion = sanitize_input(request.form.get('descripcion', ''), 500)
        precio = request.form.get('precio', '0')
        activo = 1 if request.form.get('activo') == '1' else 0
        
        if not medico_id or not ars_id or not codigo:
            flash('Médico, ARS y código son obligatorios', 'error')
            return redirect(url_for('facturacion_codigo_ars_nuevo'))
        
        try:
            precio = float(precio) if precio else 0.0
        except:
            precio = 0.0
        
        tenant_id = get_current_tenant_id()
        existe = execute_query('SELECT id FROM codigo_ars WHERE medico_id = %s AND ars_id = %s AND tenant_id = %s', (medico_id, ars_id, tenant_id))
        if existe:
            flash('Ya existe un código para este médico y ARS', 'error')
            return redirect(url_for('facturacion_codigo_ars_nuevo'))
        
        execute_update('''
            INSERT INTO codigo_ars (tenant_id, medico_id, ars_id, codigo, descripcion, precio, activo)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        ''', (tenant_id, medico_id, ars_id, codigo, descripcion or '', precio, activo))
        
        flash(f'Código ARS {codigo} creado exitosamente', 'success')
        return redirect(url_for('facturacion_codigo_ars'))
    
    tenant_id = get_current_tenant_id()
    ars_list = execute_query('SELECT * FROM ars WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    medicos_list = execute_query('SELECT * FROM medicos WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    return render_template('facturacion/codigo_ars_form.html', codigo=None, ars_list=ars_list, medicos=medicos_list)

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
    
    if request.method == 'POST':
        medico_id = request.form.get('medico_id')
        ars_id = request.form.get('ars_id')
        codigo_texto = sanitize_input(request.form.get('codigo_ars', ''), 50)
        descripcion = sanitize_input(request.form.get('descripcion', ''), 500)
        precio = request.form.get('precio', '0')
        activo = 1 if request.form.get('activo') == '1' else 0
        
        if not medico_id or not ars_id or not codigo_texto:
            flash('Médico, ARS y código son obligatorios', 'error')
            return redirect(url_for('facturacion_codigo_ars_editar', codigo_id=codigo_id))
        
        try:
            precio = float(precio) if precio else 0.0
        except:
            precio = 0.0
        
        tenant_id = get_current_tenant_id()
        existe = execute_query('SELECT id FROM codigo_ars WHERE medico_id = %s AND ars_id = %s AND id != %s AND tenant_id = %s', 
                              (medico_id, ars_id, codigo_id, tenant_id))
        if existe:
            flash('Ya existe un código para este médico y ARS', 'error')
            return redirect(url_for('facturacion_codigo_ars_editar', codigo_id=codigo_id))
        
        execute_update('''
            UPDATE codigo_ars 
            SET medico_id = %s, ars_id = %s, codigo = %s, descripcion = %s, precio = %s, activo = %s
            WHERE id = %s AND tenant_id = %s
        ''', (medico_id, ars_id, codigo_texto, descripcion or '', precio, activo, codigo_id, tenant_id))
        
        flash(f'Código ARS actualizado exitosamente', 'success')
        return redirect(url_for('facturacion_codigo_ars'))
    
    tenant_id = get_current_tenant_id()
    ars_list = execute_query('SELECT * FROM ars WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    medicos_list = execute_query('SELECT * FROM medicos WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    return render_template('facturacion/codigo_ars_form.html', codigo=codigo, ars_list=ars_list, medicos=medicos_list)

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
        JOIN medicos m ON mc.medico_id = m.id
        JOIN centros_medicos c ON mc.centro_medico_id = c.id
        WHERE mc.tenant_id = %s
        ORDER BY m.nombre, c.nombre
    ''', (tenant_id,), fetch='all') or []
    return render_template('facturacion/medico_centro.html', relaciones_list=relaciones_list)

@app.route('/facturacion/medico-centro/nuevo', methods=['GET', 'POST'])
@login_required
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

@app.route('/facturacion/ncf')
@login_required
def facturacion_ncf():
    """Lista de NCF - Filtrado por tenant"""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos para acceder a esta sección', 'error')
        return redirect(url_for('facturacion_menu'))
    
    tenant_id = get_current_tenant_id()
    # Incluir registros con el tenant_id actual o sin tenant_id (registros antiguos)
    ncf_list = execute_query('SELECT * FROM ncf WHERE tenant_id = %s OR tenant_id IS NULL ORDER BY tipo, id DESC', (tenant_id,), fetch='all') or []
    return render_template('facturacion/ncf.html', ncf_list=ncf_list)

@app.route('/facturacion/ncf/nuevo', methods=['GET', 'POST'])
@login_required
def facturacion_ncf_nuevo():
    """Crear nuevo NCF"""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_menu'))
    
    if request.method == 'POST':
        tipo = request.form.get('tipo')
        prefijo = sanitize_input(request.form.get('prefijo', ''), 20)
        tamano_secuencia = request.form.get('tamano_secuencia', '8')
        ultimo_numero = request.form.get('ultimo_numero', '0')
        fecha_fin = request.form.get('fecha_fin')
        
        if not all([tipo, prefijo, tamano_secuencia]):
            flash('Tipo, Prefijo y Tamaño son obligatorios', 'error')
            return redirect(url_for('facturacion_ncf_nuevo'))
        
        if tipo not in ['B01', 'B02', 'B14', 'B15']:
            flash('Tipo de NCF inválido', 'error')
            return redirect(url_for('facturacion_ncf_nuevo'))
        
        tenant_id = get_current_tenant_id()
        proximo_numero = int(ultimo_numero or 0) + 1
        execute_update('''
            INSERT INTO ncf (tenant_id, tipo, prefijo, ultimo_numero, proximo_numero, tamano_secuencia, fecha_fin, activo)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 1)
        ''', (tenant_id, tipo, prefijo, int(ultimo_numero or 0), proximo_numero, int(tamano_secuencia or 8), fecha_fin))
        
        flash(f'NCF {tipo} creado exitosamente', 'success')
        return redirect(url_for('facturacion_ncf'))
    
    return render_template('facturacion/ncf_form.html', ncf=None)

@app.route('/facturacion/ncf/<int:ncf_id>/editar', methods=['GET', 'POST'])
@login_required
def facturacion_ncf_editar(ncf_id):
    """Editar NCF"""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_menu'))
    
    tenant_id = get_current_tenant_id()
    # Incluir registros con el tenant_id actual o sin tenant_id (registros antiguos)
    ncf = execute_query('SELECT * FROM ncf WHERE id = %s AND (tenant_id = %s OR tenant_id IS NULL)', (ncf_id, tenant_id))
    if not ncf:
        flash('NCF no encontrado', 'error')
        return redirect(url_for('facturacion_ncf'))
    
    if request.method == 'POST':
        tipo = request.form.get('tipo')
        prefijo = sanitize_input(request.form.get('prefijo', ''), 20)
        tamano_secuencia = request.form.get('tamano_secuencia', '8')
        ultimo_numero = request.form.get('ultimo_numero', '0')
        fecha_fin = request.form.get('fecha_fin')
        activo = 1 if request.form.get('activo') == '1' else 0
        
        if not all([tipo, prefijo, tamano_secuencia]):
            flash('Tipo, Prefijo y Tamaño son obligatorios', 'error')
            return redirect(url_for('facturacion_ncf_editar', ncf_id=ncf_id))
        
        if tipo not in ['B01', 'B02', 'B14', 'B15']:
            flash('Tipo de NCF inválido', 'error')
            return redirect(url_for('facturacion_ncf_editar', ncf_id=ncf_id))
        
        tenant_id = get_current_tenant_id()
        proximo_numero = int(ultimo_numero or 0) + 1
        execute_update('''
            UPDATE ncf 
            SET tipo = %s, prefijo = %s, ultimo_numero = %s, proximo_numero = %s, tamano_secuencia = %s, fecha_fin = %s, activo = %s
            WHERE id = %s AND tenant_id = %s
        ''', (tipo, prefijo, int(ultimo_numero or 0), proximo_numero, int(tamano_secuencia or 8), fecha_fin, activo, ncf_id, tenant_id))
        
        flash(f'NCF actualizado exitosamente', 'success')
        return redirect(url_for('facturacion_ncf'))
    
    return render_template('facturacion/ncf_form.html', ncf=ncf)

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
        LEFT JOIN ars a ON p.ars_id = a.id 
        WHERE p.tenant_id = %s
    '''
    params = [tenant_id]
    
    if search:
        query += ' AND (p.nombre LIKE %s OR p.nss LIKE %s OR p.cedula LIKE %s)'
        search_pattern = f'%{search}%'
        params.extend([search_pattern, search_pattern, search_pattern])
    
    query += ' ORDER BY p.nombre'
    
    pacientes_list = execute_query(query, tuple(params), fetch='all') or []
    return render_template('facturacion/pacientes.html', pacientes_list=pacientes_list, search=search)

@app.route('/facturacion/pacientes/<int:paciente_id>/editar', methods=['GET', 'POST'])
@login_required
def facturacion_pacientes_editar(paciente_id):
    """Editar paciente"""
    tenant_id = get_current_tenant_id()
    paciente = execute_query('''
        SELECT p.*, a.nombre as ars_nombre 
        FROM pacientes p 
        LEFT JOIN ars a ON p.ars_id = a.id 
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
        
        if not nombre:
            flash('El nombre es obligatorio', 'error')
            return redirect(url_for('facturacion_pacientes_editar', paciente_id=paciente_id))
        
        if ars_id:
            ars_id = int(ars_id)
        else:
            ars_id = None
        
        execute_update('''
            UPDATE pacientes 
            SET nombre = %s, cedula = %s, nss = %s, telefono = %s, email = %s, 
                direccion = %s, fecha_nacimiento = %s, sexo = %s, ars_id = %s, tipo_afiliacion = %s
            WHERE id = %s AND tenant_id = %s
        ''', (nombre, cedula or None, nss or None, telefono or None, email or None, 
              direccion or None, fecha_nacimiento, sexo, ars_id, tipo_afiliacion, paciente_id, tenant_id))
        
        flash('Paciente actualizado exitosamente', 'success')
        return redirect(url_for('facturacion_pacientes'))
    
    # Obtener lista de ARS para el dropdown
    ars_list = execute_query('SELECT * FROM ars WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    
    return render_template('facturacion/paciente_form.html', paciente=paciente, ars_list=ars_list)

@app.route('/facturacion/pacientes/<int:paciente_id>/eliminar', methods=['POST'])
@login_required
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

@app.route('/facturacion/reclamaciones')
@login_required
def facturacion_reclamaciones():
    """Lista de reclamaciones - Filtrado por tenant"""
    tenant_id = get_current_tenant_id()
    reclamaciones_list = execute_query('''
        SELECT r.*, f.numero_factura, f.nombre_paciente, f.nombre_ars, f.total as total_factura
        FROM reclamaciones r
        JOIN facturas f ON r.factura_id = f.id
        WHERE r.tenant_id = %s
        ORDER BY r.fecha_reclamacion DESC, r.id DESC
    ''', (tenant_id,), fetch='all') or []
    return render_template('facturacion/reclamaciones.html', reclamaciones_list=reclamaciones_list)

@app.route('/facturacion/reclamaciones/nueva', methods=['GET', 'POST'])
@login_required
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

@app.route('/facturacion/pagos')
@login_required
def facturacion_pagos():
    """Lista de pagos - Filtrado por tenant"""
    tenant_id = get_current_tenant_id()
    pagos_list = execute_query('''
        SELECT p.*, 
               COUNT(pf.id) as cantidad_facturas,
               GROUP_CONCAT(f.numero_factura SEPARATOR ', ') as facturas_numeros
        FROM pagos p
        LEFT JOIN pago_facturas pf ON p.id = pf.pago_id
        LEFT JOIN facturas f ON pf.factura_id = f.id
        WHERE p.tenant_id = %s
        GROUP BY p.id
        ORDER BY p.fecha_pago DESC, p.id DESC
    ''', (tenant_id,), fetch='all') or []
    return render_template('facturacion/pagos.html', pagos_list=pagos_list)

@app.route('/facturacion/pagos/nuevo', methods=['GET', 'POST'])
@login_required
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
        
        # Validar y calcular monto total
        monto_total = 0.0
        facturas_data = []
        for i, factura_id in enumerate(facturas_ids):
            if i < len(montos) and montos[i]:
                try:
                    monto = float(montos[i])
                    if monto > 0:
                        # Verificar que la factura existe y pertenece al tenant
                        factura = execute_query('SELECT id, total FROM facturas WHERE id = %s AND tenant_id = %s', (factura_id, tenant_id))
                        if factura:
                            monto_total += monto
                            facturas_data.append((factura_id, monto))
                except ValueError:
                    continue
        
        if monto_total <= 0:
            flash('El monto total debe ser mayor a cero', 'error')
            return redirect(url_for('facturacion_pagos_nuevo'))
        
        # Generar número de pago
        numero_pago = f"PAGO-{datetime.now().strftime('%Y%m%d')}-{secrets.token_hex(4).upper()}"
        
        # Crear el pago
        pago_id = execute_update('''
            INSERT INTO pagos (numero_pago, monto_total, fecha_pago, metodo_pago, referencia, observaciones, tenant_id, created_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ''', (numero_pago, monto_total, fecha_pago, metodo_pago, referencia or None, observaciones or None, tenant_id, current_user.id))
        
        # Crear relaciones pago-facturas
        for factura_id, monto in facturas_data:
            execute_update('''
                INSERT INTO pago_facturas (pago_id, factura_id, monto_aplicado)
                VALUES (%s, %s, %s)
            ''', (pago_id, factura_id, monto))
            
            # Actualizar estado de la factura a Pagada si el monto aplicado es igual o mayor al total
            factura = execute_query('SELECT total FROM facturas WHERE id = %s', (factura_id,))
            if factura and monto >= float(factura['total']):
                execute_update('UPDATE facturas SET estado = "Pagada" WHERE id = %s', (factura_id,))
        
        flash('Pago registrado exitosamente', 'success')
        return redirect(url_for('facturacion_pagos'))
    
    # Obtener facturas disponibles para pagar
    facturas_list = execute_query('''
        SELECT f.id, f.numero_factura, f.nombre_paciente, f.nombre_ars, f.total, f.fecha_emision, f.estado,
               COALESCE(SUM(pf.monto_aplicado), 0) as monto_pagado
        FROM facturas f
        LEFT JOIN pago_facturas pf ON f.id = pf.factura_id
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
        LEFT JOIN ars a ON p.ars_id = a.id 
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
def facturacion_historico():
    """Histórico de facturas - Filtrado por tenant"""
    tenant_id = get_current_tenant_id()
    facturas = execute_query('''
        SELECT f.*, a.nombre as nombre_ars, m.nombre as medico_nombre
        FROM facturas f 
        LEFT JOIN ars a ON f.ars_id = a.id 
        LEFT JOIN medicos m ON f.medico_id = m.id
        WHERE f.tenant_id = %s
        ORDER BY f.id DESC 
        LIMIT 100
    ''', (tenant_id,), fetch='all') or []
    return render_template('facturacion/historico.html', facturas=facturas)

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
            JOIN ars a ON pp.ars_id = a.id 
            WHERE pp.estado = 'Pendiente'
        ''', fetch='all')
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
            GROUP BY DATE_FORMAT(fecha_emision, '%%Y-%%m')
            ORDER BY mes
        ''', (fecha_desde, fecha_hasta), fetch='all')
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
            JOIN ars a ON f.ars_id = a.id
            WHERE f.fecha_emision BETWEEN %s AND %s
            GROUP BY DATE_FORMAT(f.fecha_emision, '%%Y-%%m'), a.nombre
            ORDER BY mes, a.nombre
        ''', (fecha_desde, fecha_hasta), fetch='all')
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

@app.route('/facturacion/facturas/nueva', methods=['GET', 'POST'])
@login_required
def facturacion_facturas_nueva():
    """Agregar pacientes para facturar"""
    tenant_id = get_current_tenant_id()
    
    if request.method == 'POST':
        # Obtener datos del formulario
        medico_id = request.form.get('medico_id')
        ars_id = request.form.get('ars_id')
        centro_medico_id = request.form.get('centro_medico_id') or None
        lineas_json = request.form.get('lineas_json')
        
        if not medico_id or not ars_id or not lineas_json:
            flash('Faltan datos obligatorios (Médico, ARS o pacientes)', 'error')
            return redirect(url_for('facturacion_facturas_nueva'))
        
        try:
            import json
            lineas = json.loads(lineas_json)
        except json.JSONDecodeError:
            flash('Error al procesar los datos de los pacientes', 'error')
            return redirect(url_for('facturacion_facturas_nueva'))
        
        if not lineas or len(lineas) == 0:
            flash('Debe agregar al menos un paciente', 'error')
            return redirect(url_for('facturacion_facturas_nueva'))
        
        # Procesar cada línea (paciente)
        pacientes_agregados = 0
        for linea in lineas:
            nss = sanitize_input(linea.get('nss', ''), 50)
            nombre = sanitize_input(linea.get('nombre', ''), 200)
            fecha = linea.get('fecha')
            autorizacion = sanitize_input(linea.get('autorizacion', ''), 50)
            servicio = sanitize_input(linea.get('servicio', ''), 200)
            monto = float(linea.get('monto', 0))
            
            if not nss or not nombre:
                continue
            
            # Buscar si el paciente ya existe (por NSS + ARS)
            paciente_existente = execute_query('''
                SELECT id FROM pacientes 
                WHERE nss = %s AND ars_id = %s AND tenant_id = %s
            ''', (nss, ars_id, tenant_id))
            
            paciente_id = None
            if paciente_existente:
                paciente_id = paciente_existente['id']
                # Actualizar datos del paciente si es necesario
                execute_update('''
                    UPDATE pacientes 
                    SET nombre = %s, updated_at = NOW()
                    WHERE id = %s
                ''', (nombre, paciente_id))
            else:
                # Crear nuevo paciente
                paciente_id = execute_update('''
                    INSERT INTO pacientes (tenant_id, nombre, nss, ars_id, created_by)
                    VALUES (%s, %s, %s, %s, %s)
                ''', (tenant_id, nombre, nss, ars_id, current_user.id))
            
            # Crear registro en pacientes_pendientes
            servicios_realizados = f"{servicio} - Autorización: {autorizacion}" if autorizacion else servicio
            
            # Intentar insertar con todas las columnas, si falla intentar sin las opcionales
            try:
                # Intentar insertar con tenant_id y created_by
                execute_update('''
                    INSERT INTO pacientes_pendientes 
                    (tenant_id, paciente_id, nombre_paciente, nss, ars_id, fecha_servicio, 
                     servicios_realizados, monto_estimado, estado, medico_id, centro_medico_id, created_by)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'Pendiente', %s, %s, %s)
                ''', (tenant_id, paciente_id, nombre, nss, ars_id, fecha, servicios_realizados, monto, medico_id, centro_medico_id, current_user.id))
            except Exception as e:
                error_msg = str(e).lower()
                # Si falla por columnas desconocidas, intentar sin ellas
                if 'unknown column' in error_msg:
                    if 'created_by' in error_msg:
                        # Intentar sin created_by
                        try:
                            execute_update('''
                                INSERT INTO pacientes_pendientes 
                                (tenant_id, paciente_id, nombre_paciente, nss, ars_id, fecha_servicio, 
                                 servicios_realizados, monto_estimado, estado, medico_id, centro_medico_id)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'Pendiente', %s, %s)
                            ''', (tenant_id, paciente_id, nombre, nss, ars_id, fecha, servicios_realizados, monto, medico_id, centro_medico_id))
                        except Exception as e2:
                            # Si también falla tenant_id, intentar sin ambos
                            if 'tenant_id' in str(e2).lower():
                                execute_update('''
                                    INSERT INTO pacientes_pendientes 
                                    (paciente_id, nombre_paciente, nss, ars_id, fecha_servicio, 
                                     servicios_realizados, monto_estimado, estado, medico_id, centro_medico_id)
                                    VALUES (%s, %s, %s, %s, %s, %s, %s, 'Pendiente', %s, %s)
                                ''', (paciente_id, nombre, nss, ars_id, fecha, servicios_realizados, monto, medico_id, centro_medico_id))
                            else:
                                raise
                    elif 'tenant_id' in error_msg:
                        # Intentar sin tenant_id
                        execute_update('''
                            INSERT INTO pacientes_pendientes 
                            (paciente_id, nombre_paciente, nss, ars_id, fecha_servicio, 
                             servicios_realizados, monto_estimado, estado, medico_id, centro_medico_id, created_by)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, 'Pendiente', %s, %s, %s)
                        ''', (paciente_id, nombre, nss, ars_id, fecha, servicios_realizados, monto, medico_id, centro_medico_id, current_user.id))
                else:
                    raise  # Re-lanzar si es otro error
            
            pacientes_agregados += 1
        
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
        INNER JOIN centros_medicos cm ON mc.centro_medico_id = cm.id
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
    
    return render_template('facturacion/facturas_form.html', 
                         ars_list=ars_list, 
                         medicos=medicos, 
                         centros_medicos=centros_medicos,
                         servicios_list=servicios_list)

@app.route('/facturacion/pacientes-pendientes')
@login_required
def facturacion_pacientes_pendientes():
    """Estado de facturación - Pacientes pendientes"""
    # Obtener filtros de la query string
    medico_id_filtro = request.args.get('medico_id', '')
    ars_id_filtro = request.args.get('ars_id', '')
    estado_filtro = request.args.get('estado', '')
    
    # Construir query con filtros
    tenant_id = get_current_tenant_id()
    query = '''
        SELECT p.*, a.nombre as nombre_ars
        FROM pacientes p
        LEFT JOIN ars a ON p.ars_id = a.id
        WHERE p.tenant_id = %s
    '''
    params = [tenant_id]
    
    if ars_id_filtro:
        query += ' AND p.ars_id = %s'
        params.append(ars_id_filtro)
    
    query += ' ORDER BY p.id DESC'
    
    pendientes = execute_query(query, tuple(params), fetch='all') or []
    
    # Obtener listas para filtros
    medicos = execute_query('SELECT * FROM medicos WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    ars_list = execute_query('SELECT * FROM ars WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    
    return render_template('facturacion/pacientes_pendientes.html', 
                          pendientes=pendientes,
                          medicos=medicos,
                          ars_list=ars_list,
                          medico_id_filtro=medico_id_filtro,
                          ars_id_filtro=ars_id_filtro,
                          estado_filtro=estado_filtro)

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

@app.route('/facturacion/generar')
@login_required
def facturacion_generar():
    """Generar factura"""
    if current_user.perfil not in ['Administrador', 'Nivel 2']:
        flash('No tienes permisos para acceder a esta sección', 'error')
        return redirect(url_for('facturacion_menu'))
    
    pendientes = execute_query('''
        SELECT pp.*, a.nombre as ars_nombre 
        FROM pacientes_pendientes pp
        LEFT JOIN ars a ON pp.ars_id = a.id
        WHERE pp.estado = 'Pendiente'
        ORDER BY pp.created_at
    ''', fetch='all') or []
    return render_template('facturacion/generar_factura.html', pendientes=pendientes)

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
    
    usuario = execute_query('SELECT * FROM usuarios WHERE id = %s', (usuario_id,))
    
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
        
        existe = execute_query('SELECT id FROM usuarios WHERE email = %s AND id != %s',
                             (email, usuario_id))
        
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
                WHERE id = %s
            ''', (nombre, email, password_hash, perfil, activo, usuario_id))
            
            if usuario_id == current_user.id:
                logout_user()
                flash('Tu contraseña ha sido cambiada.', 'warning')
                return redirect(url_for('login'))
            
            flash(f'Usuario {nombre} actualizado con nueva contraseña', 'success')
        else:
            execute_update('''
                UPDATE usuarios 
                SET nombre = %s, email = %s, perfil = %s, activo = %s
                WHERE id = %s
            ''', (nombre, email, perfil, activo, usuario_id))
            
            flash(f'Usuario {nombre} actualizado exitosamente', 'success')
        
        return redirect(url_for('admin_usuarios'))
    
    return render_template('usuarios/form.html', usuario=usuario)

@app.route('/admin/usuarios/<int:usuario_id>/eliminar', methods=['POST'])
@login_required
def admin_usuarios_eliminar(usuario_id):
    """Eliminar usuario - DESHABILITADO"""
    flash('Eliminación deshabilitada. Desactiva el usuario en su lugar.', 'warning')
    return redirect(url_for('admin_usuarios'))

@app.route('/perfil/configuracion', methods=['GET', 'POST'])
@login_required
def perfil_configuracion():
    """Configuración del perfil del usuario"""
    TEMAS_VALIDOS = ['cyan', 'ocean', 'emerald', 'teal', 'coral', 'sunset', 'rose', 'amber', 
                     'indigo', 'purple', 'violet', 'slate', 'navy', 'forest', 'wine', 'bronze']
    
    if request.method == 'POST':
        tema_color = request.form.get('tema_color')
        
        if tema_color not in TEMAS_VALIDOS:
            flash('Tema de color inválido', 'error')
            return redirect(url_for('perfil_configuracion'))
        
        # Actualizar tema del usuario
        execute_update('UPDATE usuarios SET tema_color = %s WHERE id = %s',
                      (tema_color, current_user.id))
        
        # Actualizar el usuario actual en sesión
        current_user.tema_color = tema_color
        
        flash('Tema de color actualizado exitosamente. Recarga la página para ver los cambios.', 'success')
        return redirect(url_for('perfil_configuracion'))
    
    return render_template('perfil/configuracion.html')

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    host = os.getenv('HOST', '0.0.0.0')
    debug = os.getenv('FLASK_ENV') != 'production'
    
    print("\n" + "="*60)
    print(" SISTEMA DE FACTURACION MEDICA")
    print("="*60)
    print(f" Entorno: {'PRODUCCION' if not debug else 'DESARROLLO'}")
    print(f" Host: {host}:{port}")
    print(f" Base de datos: {DATABASE_CONFIG['database']}")
    print("="*60 + "\n")
    
    app.run(host=host, port=port, debug=debug)