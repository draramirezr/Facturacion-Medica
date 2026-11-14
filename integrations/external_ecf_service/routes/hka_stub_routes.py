"""Stubs compatibles HKA para pruebas de conexión POS (licencia, series, RNC)."""

from __future__ import annotations

from datetime import datetime

from flask import current_app, jsonify, request

from integrations.external_ecf_service.auth.token_authorization import (
    TokenAuthFailure,
    authorize_bearer_token,
)
from integrations.external_ecf_service.repositories.emitter_repository import (
    EmitterRepository,
)
from integrations.external_ecf_service.repositories.integration_repository import (
    IntegrationRepository,
)


def _hka_json(payload, status=200):
    return jsonify(payload), status


def _auth_from_body():
    config = current_app.config.get('EXTERNAL_ECF_CONFIG')
    if config is None or not config.enabled:
        return None, _hka_json({'codigo': 99, 'mensaje': 'Servicio no disponible'}, 503)
    body = request.get_json(silent=True) or {}
    token = body.get('token') or ''
    integration_repo = IntegrationRepository()
    emitter_repo = EmitterRepository()
    auth = authorize_bearer_token(
        token=token,
        config=config,
        get_client=integration_repo.get_client_by_id,
        get_emitter=emitter_repo.get_by_id_for_client,
    )
    if isinstance(auth, TokenAuthFailure):
        return None, _hka_json(
            {'codigo': auth.codigo, 'mensaje': auth.mensaje},
            200,
        )
    return auth, None


def _licencia_demo():
    hoy = datetime.now().strftime('%d-%m-%Y')
    return {
        'id': 1,
        'servicio': 'e-CF',
        'codigoLicencia': 'CLINICRD-PRUEBAS',
        'fechaLicencia': hoy,
        'cadencia': 1,
        'tiempo': 365,
        'etapa': 'PRUEBAS',
        'utilizadosCiclo': 0,
    }


def estatus_licencia_hka():
    auth, err = _auth_from_body()
    if err:
        return err
    # Folios ficticios para pasar prueba de conexión; no son licencias HKA reales.
    lic = _licencia_demo()
    return _hka_json(
        {
            'codigo': 0,
            'mensaje': 'Licencia activa (ClinicRD)',
            'total': 100000,
            'disponible': 100000,
            'licencia': lic,
            'licencias': [lic],
        }
    )


def estatus_licencia_lista_hka():
    return estatus_licencia_hka()


def consulta_rnc_hka():
    auth, err = _auth_from_body()
    if err:
        return err
    body = request.get_json(silent=True) or {}
    rnc = (body.get('rncConsultar') or body.get('rnc') or auth.rnc or '').strip()
    return _hka_json(
        {
            'codigo': 0,
            'mensaje': 'Consulta local ClinicRD',
            'rnc': rnc,
            'razonSocial': None,
            'nombreComercial': None,
            'estado': 'ACTIVO',
            'regimen': None,
        }
    )


def series_hka():
    auth, err = _auth_from_body()
    if err:
        return err
    return _hka_json(
        {
            'codigo': 0,
            'mensaje': 'Series no gestionadas en ClinicRD; use secuencias DGII del tenant',
            'serie': [],
        }
    )


def estatus_documento_hka():
    auth, err = _auth_from_body()
    if err:
        return err
    return _hka_json(
        {
            'codigo': 0,
            'mensaje': 'Consulta no disponible en Fase 2',
            'procesado': False,
            'observaciones': [],
            'codigoSeguridad': None,
            'fechaFirma': None,
            'fechaEmision': None,
        }
    )