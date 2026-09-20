"""Catálogo genérico de ARS para todos los consultorios."""

from core.database import execute_query, execute_update

# Códigos estables. El mismo listado se copia a cada empresa.
ARS_PREDETERMINADAS = (
    ('SENASA', 'SENASA'),
    ('HUMANO', 'ARS Humano'),
    ('UNIVERSAL', 'ARS Universal'),
    ('PRIMERA', 'Primera ARS'),
    ('PALIC', 'ARS Palic'),
    ('MONUMENTAL', 'ARS Monumental'),
    ('GMA', 'ARS GMA'),
    ('SEMMA', 'ARS Semma'),
    ('RESERVAS', 'ARS Reservas'),
    ('FUTURO', 'ARS Futuro'),
    ('RENACER', 'ARS Renacer'),
    ('CMD', 'ARS CMD'),
    ('YUNEN', 'ARS Yunén'),
    ('MAPFRE', 'MAPFRE Salud ARS'),
    ('APS', 'ARS APS'),
    ('PARTICULAR', 'Particular'),
)


def sembrar_ars_tenant(tenant_id):
    """Crear las ARS genéricas que aún no tenga la empresa."""
    if not tenant_id:
        return 0
    try:
        from flask import g, has_app_context
        if has_app_context():
            if getattr(g, '_ars_sembradas_para', None) == tenant_id:
                return 0
            g._ars_sembradas_para = tenant_id
    except RuntimeError:
        pass

    existentes = execute_query(
        'SELECT codigo FROM ars WHERE tenant_id=%s',
        (tenant_id,),
        fetch='all',
    ) or []
    codigos = {fila['codigo'] for fila in existentes}
    creadas = 0
    for codigo, nombre in ARS_PREDETERMINADAS:
        if codigo in codigos:
            continue
        execute_update(
            '''
            INSERT INTO ars (tenant_id, codigo, nombre, activo)
            VALUES (%s, %s, %s, 1)
            ''',
            (tenant_id, codigo, nombre),
        )
        creadas += 1
    return creadas
