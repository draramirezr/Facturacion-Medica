"""Servicio de facturación electrónica para sistemas externos (compatibilidad API)."""

from integrations.external_ecf_service.blueprint import register_external_ecf_service

__all__ = ['register_external_ecf_service']
