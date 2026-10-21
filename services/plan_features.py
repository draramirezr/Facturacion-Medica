"""Funciones disponibles según el plan de suscripción del tenant."""

from functools import wraps

from flask import flash, jsonify, redirect, request, url_for
from flask_login import current_user

PLAN_CENTRO_MEDICO = 'empresarial'

MENSAJE_SOLO_CENTRO_MEDICO = (
    'Esta función está incluida en el plan Centro médico. '
    'Mejore su plan en la configuración de su empresa para activarla.'
)


def tenant_plan_centro_medico(tenant_id=None):
    from core.tenant import get_current_tenant_id
    from services.subscriptions import get_empresa_info

    tid = tenant_id if tenant_id is not None else get_current_tenant_id()
    if not tid:
        return False
    empresa = get_empresa_info(tid) or {}
    return (empresa.get('plan') or '').strip().lower() == PLAN_CENTRO_MEDICO


def requiere_plan_centro_medico(view=None, *, api=False):
    """Decorador: bloquea la vista si el tenant no tiene plan Centro médico."""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if tenant_plan_centro_medico():
                return func(*args, **kwargs)
            es_api = api or (
                request.path.startswith('/api/')
                or (request.accept_mimetypes.best_match(['application/json', 'text/html'])
                    == 'application/json')
            )
            if es_api:
                return jsonify({'error': MENSAJE_SOLO_CENTRO_MEDICO}), 403
            flash(MENSAJE_SOLO_CENTRO_MEDICO, 'warning')
            return redirect(url_for('facturacion_menu'))

        return wrapper

    if view is not None:
        return decorator(view)
    return decorator
