"""Empresas emisoras vinculadas a clientes externos."""

from core.database import execute_query


class EmitterRepository:
    def get_by_client_and_rnc(self, client_id: int, rnc: str) -> dict | None:
        return execute_query(
            '''
            SELECT id, client_id, tenant_id, rnc, razon_social, ambiente, estado
            FROM ext_integration_emitters
            WHERE client_id = %s AND rnc = %s
            LIMIT 1
            ''',
            (client_id, rnc),
        )

    def get_by_id_for_client(self, emitter_id: int, client_id: int) -> dict | None:
        return execute_query(
            '''
            SELECT id, client_id, tenant_id, rnc, razon_social, ambiente, estado
            FROM ext_integration_emitters
            WHERE id = %s AND client_id = %s
            LIMIT 1
            ''',
            (emitter_id, client_id),
        )
