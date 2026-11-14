"""Registro del servicio e-CF externo en la aplicación Flask."""

import logging

from flask import Blueprint

from core.extensions import csrf
from core.security import rate_limit
from integrations.external_ecf_service.config import ExternalECFConfig
from integrations.external_ecf_service.routes.authentication_routes import (
    autenticacion_hka,
)
from integrations.external_ecf_service.request_logging import log_hka_api_request
from integrations.external_ecf_service.routes.health_routes import external_ecf_health
from integrations.external_ecf_service.routes.hka_stub_routes import (
    consulta_rnc_hka,
    estatus_documento_hka,
    estatus_licencia_hka,
    estatus_licencia_lista_hka,
    series_actualizar_serie_hka,
    series_borrar_serie_hka,
    series_crear_serie_hka,
    series_hka,
    series_obtener_sucursales_hka,
)
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

    if not app.config.get('EXTERNAL_ECF_API_LOGGING'):
        app.before_request(log_hka_api_request)
        app.config['EXTERNAL_ECF_API_LOGGING'] = True

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
    for rule, view, endpoint in (
        ('/api/EstatusLicencia', estatus_licencia_hka, 'external_ecf_estatus_licencia'),
        (
            '/api/EstatusLicencia/Lista',
            estatus_licencia_lista_hka,
            'external_ecf_estatus_licencia_lista',
        ),
        ('/api/ConsultaRNC', consulta_rnc_hka, 'external_ecf_consulta_rnc'),
        ('/api/Series', series_hka, 'external_ecf_series'),
        (
            '/api/Series/CrearSerie',
            series_crear_serie_hka,
            'external_ecf_series_crear',
        ),
        (
            '/api/Series/ActualizarSerie',
            series_actualizar_serie_hka,
            'external_ecf_series_actualizar',
        ),
        (
            '/api/Series/BorrarSerie',
            series_borrar_serie_hka,
            'external_ecf_series_borrar',
        ),
        (
            '/api/Series/ObtenerSucursales',
            series_obtener_sucursales_hka,
            'external_ecf_series_sucursales',
        ),
        (
            '/api/EstatusDocumento',
            estatus_documento_hka,
            'external_ecf_estatus_documento',
        ),
    ):
        stub_view = rate_decorator(view)
        csrf.exempt(stub_view)
        app.add_url_rule(
            rule,
            endpoint=endpoint,
            view_func=stub_view,
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
