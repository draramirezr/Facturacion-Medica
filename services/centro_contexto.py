"""Contexto de trabajo por centro para licencias de médico (no centro médico)."""

from flask import session
from flask_login import current_user

from core.database import execute_query
from services.subscriptions import get_empresa_info

SESSION_DECIDIDO = 'centro_contexto_decidido'
SESSION_CENTRO = 'centro_activo_id'  # 'todos' | int


def limpiar_contexto_centro():
    session.pop(SESSION_DECIDIDO, None)
    session.pop(SESSION_CENTRO, None)


def empresa_es_licencia_medico(tenant_id=None):
    """Solo aplica a tipo_empresa=medico, no a centros de salud."""
    if tenant_id is None:
        tenant_id = getattr(current_user, 'tenant_id', None)
    if not tenant_id:
        return False
    empresa = get_empresa_info(tenant_id) or {}
    return (empresa.get('tipo_empresa') or '') == 'medico'


def centros_del_medico(tenant_id, medico_id):
    if not tenant_id or not medico_id:
        return []
    return execute_query(
        '''
        SELECT c.id, c.nombre, c.codigo,
               COALESCE(mc.es_defecto, 0) AS es_defecto
        FROM medico_centro mc
        JOIN centros_medicos c
          ON c.id = mc.centro_medico_id
         AND c.tenant_id = mc.tenant_id
        WHERE mc.tenant_id = %s
          AND mc.medico_id = %s
          AND c.activo = 1
        ORDER BY COALESCE(mc.es_defecto, 0) DESC, c.nombre, c.id
        ''',
        (tenant_id, medico_id),
        fetch='all',
    ) or []


def requiere_selector_centro(user=None):
    user = user or current_user
    if not user or not getattr(user, 'is_authenticated', False):
        return False
    medico_id = getattr(user, 'medico_id', None)
    tenant_id = getattr(user, 'tenant_id', None)
    if not medico_id or not empresa_es_licencia_medico(tenant_id):
        return False
    return len(centros_del_medico(tenant_id, medico_id)) >= 2


def preparar_contexto_al_login(user):
    """
    Al entrar: si no aplica o hay 0/1 centro, decide solo.
    Si hay 2+, deja pendiente el selector.
    """
    if not user:
        return
    medico_id = getattr(user, 'medico_id', None)
    tenant_id = getattr(user, 'tenant_id', None)
    if not medico_id or not empresa_es_licencia_medico(tenant_id):
        session[SESSION_DECIDIDO] = True
        session[SESSION_CENTRO] = 'todos'
        return

    centros = centros_del_medico(tenant_id, medico_id)
    if len(centros) <= 1:
        session[SESSION_DECIDIDO] = True
        session[SESSION_CENTRO] = (
            int(centros[0]['id']) if centros else 'todos'
        )
        return

    # Ya eligió en esta sesión: no forzar de nuevo
    if session.get(SESSION_DECIDIDO):
        return
    # Pendiente de elegir
    session.pop(SESSION_CENTRO, None)


def debe_elegir_centro(user=None):
    user = user or current_user
    if not requiere_selector_centro(user):
        return False
    return not bool(session.get(SESSION_DECIDIDO))


def set_contexto_centro(centro_id=None):
    """centro_id=None → ver todos; int → trabajar en ese centro."""
    session[SESSION_DECIDIDO] = True
    if centro_id in (None, '', 'todos', 0, '0'):
        session[SESSION_CENTRO] = 'todos'
    else:
        session[SESSION_CENTRO] = int(centro_id)


def get_centro_activo_id():
    """None = todos / sin filtro. Int = centro activo."""
    if not session.get(SESSION_DECIDIDO):
        return None
    valor = session.get(SESSION_CENTRO, 'todos')
    if valor in (None, '', 'todos', 0, '0'):
        return None
    try:
        return int(valor)
    except (TypeError, ValueError):
        return None


def contexto_centro_actual(user=None):
    """Datos para plantillas: etiqueta, centros, si muestra selector."""
    user = user or current_user
    if not user or not getattr(user, 'is_authenticated', False):
        return {
            'aplica': False,
            'mostrar_selector': False,
            'centro_id': None,
            'etiqueta': '',
            'centros': [],
            'viendo_todos': True,
        }
    tenant_id = getattr(user, 'tenant_id', None)
    medico_id = getattr(user, 'medico_id', None)
    aplica = bool(
        medico_id and empresa_es_licencia_medico(tenant_id)
    )
    centros = centros_del_medico(tenant_id, medico_id) if aplica else []
    mostrar = aplica and len(centros) >= 2
    centro_id = get_centro_activo_id() if mostrar else (
        int(centros[0]['id']) if len(centros) == 1 else None
    )
    etiqueta = 'Todos mis pacientes'
    if centro_id:
        for centro in centros:
            if int(centro['id']) == int(centro_id):
                etiqueta = centro['nombre']
                break
    return {
        'aplica': aplica,
        'mostrar_selector': mostrar,
        'centro_id': centro_id,
        'etiqueta': etiqueta,
        'centros': centros,
        'viendo_todos': centro_id is None,
    }


def sql_filtro_paciente_por_centro(alias='p'):
    """
    Fragmento AND + params cuando el médico trabaja en un centro concreto.
    En "Todos" no filtra. Pacientes sin centro solo aparecen en "Todos".
    """
    if not empresa_es_licencia_medico():
        return '', []
    centro_id = get_centro_activo_id()
    if not centro_id:
        return '', []
    return f' AND {alias}.centro_medico_id = %s', [centro_id]


def centro_para_nuevo_registro(form_centro_id=None):
    """
    Centro a guardar al capturar paciente o consulta.
    Prioridad: formulario > centro activo de sesión.
    """
    if form_centro_id not in (None, '', '0', 0):
        try:
            return int(form_centro_id)
        except (TypeError, ValueError):
            pass
    return get_centro_activo_id()
