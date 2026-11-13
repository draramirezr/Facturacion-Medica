"""Casos de uso del servicio de integración externa."""

import logging

from flask import request

logger = logging.getLogger(__name__)

from integrations.external_ecf_service.auth.authentication import (
    authenticate_hka_request,
)
from integrations.external_ecf_service.repositories.integration_repository import (
    IntegrationRepository,
)
from integrations.external_ecf_service.tenant.resolver import EmitterResolver


class IntegrationService:
    def __init__(
        self,
        config,
        integration_repo: IntegrationRepository | None = None,
        emitter_resolver: EmitterResolver | None = None,
    ):
        self._config = config
        self._integration_repo = integration_repo or IntegrationRepository()
        self._emitter_resolver = emitter_resolver or EmitterResolver()

    def autenticar(self, usuario: str, clave: str, rnc: str):
        result = authenticate_hka_request(
            usuario=usuario,
            clave=clave,
            rnc=rnc,
            config=self._config,
            find_credential=self._integration_repo.find_credential_by_usuario,
            get_client=self._integration_repo.get_client_by_id,
            resolve_emitter=self._resolve_emitter,
        )
        ip = request.remote_addr if request else None
        try:
            if hasattr(result, 'token'):
                self._integration_repo.insert_audit(
                    client_id=result.client_id,
                    emitter_id=result.emitter_id,
                    evento='AUTENTICACION',
                    resultado='OK',
                    ip_origen=ip,
                )
            else:
                self._integration_repo.insert_audit(
                    client_id=None,
                    emitter_id=None,
                    evento='AUTENTICACION',
                    resultado='FALLIDA',
                    ip_origen=ip,
                )
        except Exception:
            logger.warning(
                'No se pudo registrar auditoría de autenticación externa',
                exc_info=True,
            )
        return result

    def _resolve_emitter(self, *, client_id, emitter_id, rnc):
        return self._emitter_resolver.resolve_for_auth(
            client_id=client_id,
            emitter_id=emitter_id,
            rnc=rnc,
        )
