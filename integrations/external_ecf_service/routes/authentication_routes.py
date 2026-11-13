"""POST /api/Autenticacion — compatibilidad HKA."""

from flask import current_app, jsonify, request

from integrations.external_ecf_service.auth.authentication import (
    AuthFailure,
    AuthSuccess,
)
from integrations.external_ecf_service.services.integration_service import (
    IntegrationService,
)


def _hka_json(payload, status=200):
    return jsonify(payload), status


def autenticacion_hka():
    config = current_app.config.get('EXTERNAL_ECF_CONFIG')
    if config is None:
        return _hka_json(
            {
                'codigo': 99,
                'mensaje': 'Servicio no disponible',
                'token': None,
                'fechaExpiracion': None,
            }
        )

    body = request.get_json(silent=True) or {}
    usuario = body.get('usuario')
    clave = body.get('clave')
    rnc = body.get('rnc')

    service = IntegrationService(config)
    result = service.autenticar(usuario, clave, rnc)

    if isinstance(result, AuthSuccess):
        return _hka_json(
            {
                'codigo': result.codigo,
                'mensaje': result.mensaje,
                'token': result.token,
                'fechaExpiracion': result.fecha_expiracion,
            }
        )

    if isinstance(result, AuthFailure):
        return _hka_json(
            {
                'codigo': result.codigo,
                'mensaje': result.mensaje,
                'token': None,
                'fechaExpiracion': None,
            }
        )

    return _hka_json(
        {
            'codigo': 99,
            'mensaje': 'Error interno',
            'token': None,
            'fechaExpiracion': None,
        }
    )
