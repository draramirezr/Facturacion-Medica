"""Registro del servicio e-CF externo en la aplicación Flask."""

import logging

from flask import Blueprint

from core.extensions import csrf
from core.security import rate_limit
from integrations.external_ecf_service.config import ExternalECFConfig
from integrations.external_ecf_service.routes.authentication_routes import (
    autenticacion_hka,
)
from integrations.external_ecf_service.routes.health_routes import external_ecf_health
from integrations.external_ecf_service.routes.send_routes import enviar_hka

logger = logging.getLogger(__name__)


def register_external_ecf_service(app):
    """Registrar rutas sin modificar blueprints médicos existentes."""
    try:
        config = ExternalECFConfig.from_env()
    except Exception as error:
        logger.error(
            'Configuración external_ecf_service inválida: %s',
            error,
        )
        raise

    app.config['EXTERNAL_ECF_CONFIG'] = config

    bp = Blueprint('external_ecf_service', __name__)
    rate_decorator = rate_limit(
        max_requests=config.auth_rate_limit_max,
        window=config.auth_rate_limit_window,
        methods=('POST',),
    )
    autenticacion_view = rate_decorator(autenticacion_hka)
    enviar_view = rate_decorator(enviar_hka)
    csrf.exempt(autenticacion_view)
    csrf.exempt(enviar_view)
    app.add_url_rule(
        '/api/Autenticacion',
        endpoint='external_ecf_autenticacion',
        view_func=autenticacion_view,
        methods=['POST'],
    )
    app.add_url_rule(
        '/api/Enviar',
        endpoint='external_ecf_enviar',
        view_func=enviar_view,
        methods=['POST'],
    )
    bp.add_url_rule(
        '/external-ecf/health',
        'external_ecf_health',
        external_ecf_health,
        methods=['GET'],
    )
    app.register_blueprint(bp)

    logger.info(
        'Servicio external_ecf_service registrado (enabled=%s)',
        config.enabled,
    )
