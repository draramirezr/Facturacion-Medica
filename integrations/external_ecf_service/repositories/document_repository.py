"""Persistencia de documentos e-CF recibidos de integraciones externas."""

from __future__ import annotations

import json

from core.database import database_transaction, execute_query, execute_update


class DocumentRepository:
    def find_by_emitter_and_hash(
        self, emitter_id: int, payload_hash: str
    ) -> dict | None:
        return execute_query(
            '''
            SELECT id, client_id, emitter_id, tenant_id, external_document_id,
                   tipo_ecf, encf, rnc_emisor, rnc_comprador, fecha_documento,
                   moneda, total, payload_hash, canonical_document, estado,
                   error_codigo, error_mensaje, response_snapshot, created_at
            FROM ext_ecf_documents
            WHERE emitter_id = %s AND payload_hash = %s
            LIMIT 1
            ''',
            (emitter_id, payload_hash),
        )

    def find_by_emitter_and_encf(
        self, emitter_id: int, encf: str
    ) -> dict | None:
        return execute_query(
            '''
            SELECT id, client_id, emitter_id, tenant_id, encf, payload_hash,
                   estado, error_codigo, error_mensaje, response_snapshot
            FROM ext_ecf_documents
            WHERE emitter_id = %s AND encf = %s
            LIMIT 1
            ''',
            (emitter_id, encf),
        )

    def update_response_snapshot(self, document_id: int, snapshot: dict) -> None:
        execute_update(
            '''
            UPDATE ext_ecf_documents
            SET response_snapshot = %s
            WHERE id = %s
            ''',
            (
                json.dumps(snapshot, ensure_ascii=False),
                document_id,
            ),
        )

    def insert_document(
        self,
        *,
        client_id: int,
        emitter_id: int,
        tenant_id: int,
        external_document_id: str | None,
        tipo_ecf: str | None,
        encf: str | None,
        rnc_emisor: str,
        rnc_comprador: str | None,
        fecha_documento,
        moneda: str | None,
        total,
        payload_original: dict,
        payload_hash: str,
        canonical_document: dict,
        estado: str,
        error_codigo: int | None,
        error_mensaje: str | None,
        response_snapshot: dict | None,
    ) -> int:
        with database_transaction():
            return execute_update(
                '''
                INSERT INTO ext_ecf_documents (
                    client_id, emitter_id, tenant_id, external_document_id,
                    tipo_ecf, encf, rnc_emisor, rnc_comprador, fecha_documento,
                    moneda, total, payload_original, payload_hash,
                    canonical_document, estado, error_codigo, error_mensaje,
                    response_snapshot
                ) VALUES (
                    %s, %s, %s, %s,
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    %s
                )
                ''',
                (
                    client_id,
                    emitter_id,
                    tenant_id,
                    external_document_id,
                    tipo_ecf,
                    encf,
                    rnc_emisor,
                    rnc_comprador,
                    fecha_documento,
                    moneda,
                    total,
                    json.dumps(payload_original, ensure_ascii=False),
                    payload_hash,
                    json.dumps(canonical_document, ensure_ascii=False),
                    estado,
                    error_codigo,
                    error_mensaje,
                    json.dumps(response_snapshot, ensure_ascii=False)
                    if response_snapshot
                    else None,
                ),
            )
