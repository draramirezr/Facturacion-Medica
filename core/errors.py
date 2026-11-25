"""Manejadores HTTP comunes de la aplicación."""

import logging

from flask import flash, jsonify, redirect, render_template, request, url_for

logger = logging.getLogger(__name__)


def not_found(error):
    path = request.path or ''
    if path.startswith('/api/'):
        logger.warning(
            'API POS 404 (no implementado): %s %s query=%s ip=%s ua=%s',
            request.method,
            path,
            (request.query_string or b'').decode('utf-8', errors='replace')[:200],
            request.headers.get('X-Forwarded-For', request.remote_addr),
            (request.headers.get('User-Agent') or '')[:160],
        )
        return jsonify(
            {
                'codigo': 99,
                'mensaje': (
                    f'Ruta API no disponible en ClinicRD: {request.method} {path}. '
                    'Revise logs del servidor o contacte soporte.'
                ),
            }
        ), 404
    return render_template('errors/404.html'), 404


def internal_error(error):
    if request.path.startswith('/api/') or request.is_json:
        return jsonify({
            'error': True,
            'mensaje': 'No se pudo completar la operación. Los datos no se guardaron.',
        }), 500
    return render_template('errors/500.html'), 500


def forbidden(error):
    flash('No tienes permisos para acceder a este recurso', 'error')
    from auth.helpers import destino_inicio_sesion
    from flask_login import current_user
    destino = (
        destino_inicio_sesion(current_user)
        if getattr(current_user, 'is_authenticated', False)
        else 'login'
    )
    return redirect(url_for(destino)), 403


def request_entity_too_large(error):
    if (
        request.path.startswith('/api/')
        or request.path == '/facturacion/procesar-excel'
    ):
        return jsonify({
            'error': True,
            'mensaje': 'El archivo supera el tamaño máximo permitido.',
        }), 413
    flash('El archivo supera el tamaño máximo permitido.', 'error')
    return redirect(url_for('facturacion_menu'))


def init_error_handlers(app):
    app.register_error_handler(404, not_found)
    app.register_error_handler(500, internal_error)
    app.register_error_handler(403, forbidden)
    app.register_error_handler(413, request_entity_too_large)
