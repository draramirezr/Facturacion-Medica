"""Hash estable del documento electrónico para idempotencia."""

from __future__ import annotations

import hashlib
import json


def compute_document_payload_hash(documento: dict) -> str:
    normalized = json.dumps(
        documento,
        ensure_ascii=False,
        sort_keys=True,
        separators=(',', ':'),
        default=str,
    )
    return hashlib.sha256(normalized.encode('utf-8')).hexdigest()
