"""Datos mínimos que faltan al crear la empresa y se piden en el primer ingreso."""

from flask import g

from core.database import execute_query


def perfil_inicial_pendiente(user):
    """
    'medico' si el consultorio individual aún no tiene la ficha del médico.
    'centro' si el centro de salud no tiene RNC o dirección.
    None si ya puede operar, o si es el dueño del software.
    """
    if getattr(g, '_perfil_inicial_resuelto', False):
        return g._perfil_inicial_pendiente
    g._perfil_inicial_resuelto = True
    g._perfil_inicial_pendiente = None
    tenant_id = getattr(user, 'tenant_id', None)
    if not user or not getattr(user, 'is_authenticated', False) or not tenant_id:
        return None
    empresa = execute_query(
        '''
        SELECT tipo_empresa, rnc, direccion
        FROM empresas WHERE id=%s
        ''',
        (tenant_id,),
    )
    if not empresa:
        return None
    tipo = empresa.get('tipo_empresa') or 'medico'
    if tipo == 'centro_salud':
        rnc = ''.join(ch for ch in str(empresa.get('rnc') or '') if ch.isdigit())
        direccion = (empresa.get('direccion') or '').strip()
        if len(rnc) != 9 or not direccion:
            g._perfil_inicial_pendiente = 'centro'
        return g._perfil_inicial_pendiente
    medico = execute_query(
        '''
        SELECT id FROM medicos
        WHERE tenant_id=%s AND activo=1
          AND cedula IS NOT NULL AND cedula<>''
          AND exequatur IS NOT NULL AND exequatur<>''
          AND especialidad IS NOT NULL AND especialidad<>''
        LIMIT 1
        ''',
        (tenant_id,),
    )
    if not medico:
        g._perfil_inicial_pendiente = 'medico'
    return g._perfil_inicial_pendiente
