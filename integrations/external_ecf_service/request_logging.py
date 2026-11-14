"""Registro de peticiones a rutas /api/* (diagnóstico integradores POS)."""

from __future__ import annotations

import logging

from flask import request

logger = logging.getLogger(__name__)


def log_hka_api_request():
    if not request.path.startswith('/api/'):
        return
    logger.info(
        'API POS: %s %s ip=%s ua=%s',
        request.method,
        request.path,
        request.headers.get('X-Forwarded-For', request.remote_addr),
        (request.headers.get('User-Agent') or '')[:160],
    )