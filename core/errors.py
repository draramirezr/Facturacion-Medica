"""Manejadores HTTP comunes de la aplicación."""

from flask import flash, jsonify, redirect, render_template, request, url_for


def not_found(error):
    return render_template('errors/404.html'), 404


def internal_error(error):
    return render_template('errors/500.html'), 500


def forbidden(error):
    flash('No tienes permisos para acceder a este recurso', 'error')
    return redirect(url_for('facturacion_menu')), 403


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
