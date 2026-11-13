"""POST /api/Enviar — compatibilidad HKA (Fase 2: registro sin DGII)."""

from flask import current_app, jsonify, request

from integrations.external_ecf_service.services.send_service import (
    EnviarFailure,
    EnviarSuccess,
    SendService,
)


def _enviar_json(payload, status=200):
    return jsonify(payload), status


def enviar_hka():
    config = current_app.config.get('EXTERNAL_ECF_CONFIG')
    if config is None:
        return _enviar_json(
            {
                'codigo': 99,
                'mensaje': 'Servicio no disponible',
                'xmlBase64': None,
                'procesado': False,
                'codigoSeguridad': None,
                'fechaFirma': None,
                'fechaEmision': None,
            }
        )

    body = request.get_json(silent=True) or {}
    token = body.get('token')
    documento = body.get('documentoElectronico')

    service = SendService(config)
    result = service.enviar(token, documento)

    if isinstance(result, EnviarSuccess):
        return _enviar_json(
            {
                'codigo': result.codigo,
                'mensaje': result.mensaje,
                'xmlBase64': result.xml_base64,
                'procesado': result.procesado,
                'codigoSeguridad': result.codigo_seguridad,
                'fechaFirma': result.fecha_firma,
                'fechaEmision': result.fecha_emision,
            }
        )

    if isinstance(result, EnviarFailure):
        return _enviar_json(
            {
                'codigo': result.codigo,
                'mensaje': result.mensaje,
                'xmlBase64': result.xml_base64,
                'procesado': result.procesado,
                'codigoSeguridad': result.codigo_seguridad,
                'fechaFirma': result.fecha_firma,
                'fechaEmision': result.fecha_emision,
            }
        )

    return _enviar_json(
        {
            'codigo': 99,
            'mensaje': 'Error interno',
            'xmlBase64': None,
            'procesado': False,
            'codigoSeguridad': None,
            'fechaFirma': None,
            'fechaEmision': None,
        }
    )
