"""Estado del módulo de integración externa."""


def build_health_payload(config) -> dict:
    return {
        'status': 'ok',
        'module': 'external_ecf_service',
        'enabled': bool(getattr(config, 'enabled', False)),
        'environment': getattr(config, 'environment', 'PRUEBAS'),
    }
