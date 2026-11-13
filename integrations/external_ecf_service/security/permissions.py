"""Autorización cliente + emisor para integración externa."""


def cliente_habilitado(cliente: dict | None) -> bool:
    if not cliente:
        return False
    return str(cliente.get('estado') or '').lower() == 'activo'


def emisor_habilitado(emisor: dict | None) -> bool:
    if not emisor:
        return False
    if str(emisor.get('estado') or '').lower() != 'activo':
        return False
    if not emisor.get('tenant_id'):
        return False
    return True


def credencial_habilitada(credencial: dict | None) -> bool:
    if not credencial:
        return False
    return str(credencial.get('estado') or '').lower() == 'activa'


def ambiente_coincide(emisor: dict | None, ambiente_config: str) -> bool:
    """El emisor solo opera en el ambiente configurado en el servicio o el suyo."""
    if not emisor:
        return False
    ambiente_emisor = (emisor.get('ambiente') or '').strip().upper()
    if not ambiente_emisor:
        return True
    return ambiente_emisor == ambiente_config.upper()
