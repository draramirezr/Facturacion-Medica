"""Hooks HTTP de seguridad, CSP y compresión."""

import gzip
import functools
import logging
import secrets
import threading
import time
from collections import defaultdict

from flask import (
    flash,
    g,
    jsonify,
    redirect,
    request,
    url_for,
)
from flask_login import current_user
from flask_wtf.csrf import CSRFError

logger = logging.getLogger(__name__)
request_counts = defaultdict(list)
rate_limit_lock = threading.Lock()


def generate_csp_nonce():
    """Crear un nonce distinto para cada respuesta HTML."""
    g.csp_nonce = secrets.token_urlsafe(18)


def inject_csp_nonce():
    """Permitir que las plantillas autoricen scripts durante la migración CSP."""
    return {'csp_nonce': g.get('csp_nonce', '')}


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
    flash(
        'La sesión de seguridad venció. Recarga la página e inténtalo de nuevo.',
        'error',
    )
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    if request.endpoint == 'cambiar_mi_password':
        return redirect(url_for('cambiar_mi_password'))
    from auth.helpers import destino_inicio_sesion
    return redirect(url_for(destino_inicio_sesion(current_user)))


def set_security_headers(response):
    """Agregar headers de seguridad a todas las respuestas."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = (
        'max-age=31536000; includeSubDomains'
    )
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    nonce = g.get('csp_nonce', '')
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net "
        "https://cdnjs.cloudflare.com https://www.googletagmanager.com; "
        f"script-src-elem 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net "
        "https://cdnjs.cloudflare.com https://www.googletagmanager.com; "
        "script-src-attr 'none'; "
        f"style-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net "
        "https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        f"style-src-elem 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net "
        "https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "style-src-attr 'none'; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://www.googletagmanager.com; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'self';"
    )
    response.headers['Content-Security-Policy-Report-Only'] = (
        "default-src 'self'; "
        f"script-src-elem 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net "
        "https://cdnjs.cloudflare.com https://www.googletagmanager.com; "
        "script-src-attr 'none'; "
        f"style-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net "
        "https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        f"style-src-elem 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net "
        "https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "style-src-attr 'none'; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://www.googletagmanager.com; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'self'; "
        "report-uri /api/csp-report;"
    )
    if request.path.startswith('/static/'):
        response.headers['Cache-Control'] = 'public, max-age=31536000'
    else:
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return response


def compress_response(response):
    """Comprimir respuestas exitosas mayores a 1 KB."""
    if response.status_code < 200 or response.status_code >= 300:
        return response
    if 'gzip' not in request.headers.get('Accept-Encoding', '').lower():
        return response
    if response.direct_passthrough or len(response.get_data()) < 1024:
        return response
    response.set_data(gzip.compress(response.get_data()))
    response.headers['Content-Encoding'] = 'gzip'
    response.headers['Content-Length'] = len(response.get_data())
    response.headers['Vary'] = 'Accept-Encoding'
    return response


def rate_limit(
    max_requests=10,
    window=60,
    methods=('POST', 'PUT', 'PATCH', 'DELETE'),
):
    """Limitar operaciones mutables por cliente y endpoint."""
    limited_methods = frozenset(method.upper() for method in methods)

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if request.method.upper() not in limited_methods:
                return func(*args, **kwargs)

            client_ip = request.remote_addr or 'unknown'
            request_key = f'{client_ip}:{request.endpoint or func.__name__}'
            current_time = time.time()
            with rate_limit_lock:
                request_counts[request_key] = [
                    request_time
                    for request_time in request_counts[request_key]
                    if current_time - request_time < window
                ]
                if len(request_counts[request_key]) >= max_requests:
                    return jsonify({'error': 'Rate limit exceeded'}), 429
                request_counts[request_key].append(current_time)
            return func(*args, **kwargs)

        return wrapper

    return decorator


def init_security(app):
    """Registrar los hooks sin crear endpoints nuevos."""
    app.before_request(generate_csp_nonce)
    app.context_processor(inject_csp_nonce)
    app.register_error_handler(CSRFError, handle_csrf_error)
    app.after_request(set_security_headers)
    app.after_request(compress_response)
