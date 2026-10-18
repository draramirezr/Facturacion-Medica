"""Cédula y exequátur únicos por empresa. RNC único en todo ClinicRD."""

import re

from core.database import execute_query


def _digitos(valor):
    return re.sub(r'\D', '', valor or '')


def error_rnc_en_otra_empresa(rnc, empresa_id=None):
    """Un RNC solo puede pertenecer a una empresa."""
    digitos = _digitos(rnc)
    if not digitos:
        return None
    consulta = '''
        SELECT id, nombre FROM empresas
        WHERE REPLACE(REPLACE(REPLACE(IFNULL(rnc,''), '-', ''), ' ', ''), '.', '') = %s
    '''
    params = [digitos]
    if empresa_id:
        consulta += ' AND id<>%s'
        params.append(empresa_id)
    consulta += ' LIMIT 1'
    otra = execute_query(consulta, tuple(params))
    if not otra:
        return None
    nombre = otra.get('nombre') or otra['id']
    if len(digitos) == 11:
        return (
            f'Esa cédula ya está registrada como documento de la empresa "{nombre}". '
            'No puede usarse en otra empresa.'
        )
    return (
        f'Ese RNC ya está registrado en la empresa "{nombre}". '
        'Un RNC no puede pertenecer a dos empresas.'
    )


def error_medico_identificadores(tenant_id, cedula, exequatur, medico_id=None):
    """Cédula y exequátur no se repiten entre los médicos de la misma empresa."""
    if not tenant_id:
        return None
    cedula_digitos = _digitos(cedula)
    if cedula_digitos:
        consulta = '''
            SELECT id, nombre FROM medicos
            WHERE tenant_id=%s
              AND REPLACE(REPLACE(REPLACE(IFNULL(cedula,''), '-', ''), ' ', ''), '.', '') = %s
        '''
        params = [tenant_id, cedula_digitos]
        if medico_id:
            consulta += ' AND id<>%s'
            params.append(medico_id)
        consulta += ' LIMIT 1'
        otro = execute_query(consulta, tuple(params))
        if otro:
            return (
                f'La cédula ya pertenece al médico "{otro.get("nombre") or otro["id"]}" '
                'de esta empresa.'
            )
    licencia = (exequatur or '').strip()
    if licencia:
        consulta = '''
            SELECT id, nombre FROM medicos
            WHERE tenant_id=%s AND LOWER(TRIM(exequatur))=LOWER(%s)
        '''
        params = [tenant_id, licencia]
        if medico_id:
            consulta += ' AND id<>%s'
            params.append(medico_id)
        consulta += ' LIMIT 1'
        otro = execute_query(consulta, tuple(params))
        if otro:
            return (
                f'El exequátur ya pertenece al médico "{otro.get("nombre") or otro["id"]}" '
                'de esta empresa.'
            )
    return None
