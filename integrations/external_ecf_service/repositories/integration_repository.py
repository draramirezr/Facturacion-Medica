"""Acceso a clientes y credenciales de integración externa."""

from core.database import execute_query, execute_update


class IntegrationRepository:
    def get_client_by_id(self, client_id: int) -> dict | None:
        return execute_query(
            '''
            SELECT id, nombre, codigo, estado
            FROM ext_integration_clients
            WHERE id = %s
            LIMIT 1
            ''',
            (client_id,),
        )

    def find_credential_by_usuario(self, usuario: str) -> dict | None:
        return execute_query(
            '''
            SELECT id, client_id, emitter_id, usuario, password_hash, estado
            FROM ext_integration_credentials
            WHERE usuario = %s
            LIMIT 1
            ''',
            (usuario.strip(),),
        )

    def insert_audit(
        self,
        *,
        client_id: int | None,
        emitter_id: int | None,
        evento: str,
        resultado: str,
        ip_origen: str | None,
    ) -> None:
        execute_update(
            '''
            INSERT INTO ext_integration_audit
                (client_id, emitter_id, evento, resultado, ip_origen)
            VALUES (%s, %s, %s, %s, %s)
            ''',
            (client_id, emitter_id, evento, resultado, ip_origen),
        )
