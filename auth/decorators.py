"""Decoradores de autenticación y autorización."""

import logging
from functools import wraps

from flask import current_app, flash, jsonify, redirect, request, url_for
from flask_login import current_user

from auth.helpers import user_has_permission

logger = logging.getLogger(__name__)


def permission_required(permission):
    """Exigir un permiso RBAC sin confiar en datos enviados por el cliente."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            if not user_has_permission(current_user, permission):
                logger.warning(
                    'Permiso denegado: user_id=%s permission=%s endpoint=%s',
                    current_user.get_id(),
                    permission,
                    request.endpoint,
                )
                if request.path.startswith('/api/'):
                    return jsonify({'error': 'Permiso denegado'}), 403
                flash('No tienes permisos para acceder a esta función', 'error')
                return redirect(url_for('facturacion_menu'))
            return func(*args, **kwargs)

        wrapper.required_permission = permission
        return wrapper

    return decorator


def roles_required(*_legacy_profiles):
    """Compatibilidad segura: resolver el permiso RBAC de la ruta."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            endpoint_view = current_app.view_functions.get(
                request.endpoint or ''
            )
            permission = getattr(endpoint_view, 'required_permission', None)
            if (
                not current_user.is_authenticated
                or not permission
                or not user_has_permission(current_user, permission)
            ):
                flash('No tienes permisos para acceder a esta función', 'error')
                return redirect(url_for('facturacion_menu'))
            return func(*args, **kwargs)

        return wrapper

    return decorator
