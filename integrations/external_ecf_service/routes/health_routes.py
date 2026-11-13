"""GET /external-ecf/health"""

from flask import current_app, jsonify

from integrations.external_ecf_service.services.health_service import (
    build_health_payload,
)


def external_ecf_health():
    config = current_app.config.get('EXTERNAL_ECF_CONFIG')
    if config is None:
        return jsonify(
            {
                'status': 'ok',
                'module': 'external_ecf_service',
                'enabled': False,
            }
        )
    return jsonify(build_health_payload(config))
