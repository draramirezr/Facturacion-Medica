"""Resolución y aislamiento del tenant actual."""

import logging
from functools import wraps

from flask import flash, redirect, url_for
from flask_login import current_user

from core.database import execute_query

logger = logging.getLogger(__name__)

ALLOWED_TABLES = {
    'ars', 'auditoria_historia_clinica', 'auditoria_licencias_medicas',
    'centros_medicos', 'citas_medicas', 'codigo_ars',
    'consultas_clinicas', 'conversaciones_internas',
    'ecf_configuraciones', 'ecf_eventos', 'ecf_outbox', 'ecf_secuencias',
    'evoluciones_clinicas', 'factura_detalles', 'facturas', 'facturas_ecf',
    'historias_emergencia', 'hojas_enfermeria', 'licencias_medicas',
    'medico_centro', 'medicos', 'mensajes_internos', 'ncf', 'pacientes',
    'pacientes_pendientes', 'pago_facturas', 'pagos',
    'receta_medicamentos', 'recetas_medicas', 'reclamaciones', 'roles',
    'rol_permisos', 'secuencias_turnos', 'servicios', 'pantallas_turnos',
    'tipos_licencia_medica', 'turnos_atencion', 'turnos_eventos',
    'usuario_medico', 'usuario_roles', 'usuarios',
}
ALLOWED_ID_COLUMNS = {'id', 'paciente_id', 'medico_id', 'ars_id', 'factura_id'}


def get_current_tenant_id():
    """Obtener el tenant exclusivamente del usuario autenticado."""
    if current_user.is_authenticated:
        return current_user.tenant_id
    return None


def require_tenant(func):
    """Exigir un tenant válido antes de ejecutar una vista."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if not getattr(current_user, 'tenant_id', None):
            from auth.helpers import usuario_es_dueno_software
            if usuario_es_dueno_software(current_user):
                flash(
                    'El dueño de ClinicRD administra empresas, no un consultorio.',
                    'info',
                )
                return redirect(url_for('admin_empresas'))
            flash('Error: Usuario sin empresa asignada', 'error')
            return redirect(url_for('logout'))
        return func(*args, **kwargs)

    return wrapper


def validate_tenant_access(table, record_id, id_column='id'):
    """Comprobar mediante una consulta parametrizada que un registro pertenece."""
    if table not in ALLOWED_TABLES:
        logger.warning('Intento de acceso a tabla no permitida: %s', table)
        return False
    if id_column not in ALLOWED_ID_COLUMNS:
        logger.warning(
            'Intento de acceso con columna ID no permitida: %s',
            id_column,
        )
        return False
    try:
        record_id = int(record_id)
    except (ValueError, TypeError):
        logger.warning('record_id inválido: %s', record_id)
        return False

    tenant_id = get_current_tenant_id()
    if not tenant_id:
        return False
    result = execute_query(
        'SELECT COUNT(*) as count FROM {} WHERE {} = %s AND tenant_id = %s'
        .format(table, id_column),
        (record_id, tenant_id),
    )
    return bool(result and result.get('count', 0) > 0)
