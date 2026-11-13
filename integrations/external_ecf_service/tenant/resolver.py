"""Resolución de emisor autorizado (cliente + RNC + credencial)."""

from __future__ import annotations

import re

from integrations.external_ecf_service.repositories.emitter_repository import (
    EmitterRepository,
)


def normalize_rnc(value: str) -> str:
    return re.sub(r'\D', '', str(value or ''))


class EmitterResolver:
    def __init__(self, repository: EmitterRepository | None = None):
        self._repo = repository or EmitterRepository()

    def resolve_for_auth(
        self,
        *,
        client_id: int,
        emitter_id: int | None,
        rnc: str,
    ) -> dict | None:
        rnc_norm = normalize_rnc(rnc)
        if emitter_id:
            row = self._repo.get_by_id_for_client(int(emitter_id), int(client_id))
            if not row:
                return None
            if normalize_rnc(row.get('rnc')) != rnc_norm:
                return None
            return row
        return self._repo.get_by_client_and_rnc(int(client_id), rnc_norm)
