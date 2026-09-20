"""Consultas y mantenimiento de suscripciones y licencias de empresa."""

import logging
from datetime import date, datetime

from core.database import execute_query, execute_update
from core.tenant import get_current_tenant_id

logger = logging.getLogger(__name__)


def check_license_available(tenant_id):
    empresa = execute_query(
        """
        SELECT licencias_totales, licencias_usadas,
               (licencias_totales - licencias_usadas) AS disponibles
        FROM empresas WHERE id=%s AND estado='activo'
        """,
        (tenant_id,),
    )
    if not empresa:
        return False, 0, 'Empresa no encontrada o inactiva'
    disponibles = empresa['disponibles']
    if disponibles <= 0:
        return (
            False,
            0,
            f"No hay licencias disponibles "
            f"({empresa['licencias_usadas']}/{empresa['licencias_totales']} en uso)",
        )
    return True, disponibles, f'{disponibles} licencias disponibles'


def get_empresa_info(tenant_id=None):
    tenant_id = get_current_tenant_id() if tenant_id is None else tenant_id
    if not tenant_id:
        return None
    return execute_query('SELECT * FROM empresas WHERE id=%s', (tenant_id,))


def inactivar_demos_vencidos():
    """El demo de 7 días se apaga solo al vencer."""
    try:
        pendientes = execute_query(
            """
            SELECT COUNT(*) AS total FROM empresas
            WHERE es_demo=1 AND estado='activo' AND fecha_fin<CURDATE()
            """
        ) or {}
        total = int(pendientes.get('total') or 0)
        if total:
            execute_update(
                """
                UPDATE empresas SET estado='inactivo'
                WHERE es_demo=1 AND estado='activo' AND fecha_fin<CURDATE()
                """
            )
        return total
    except Exception as error:
        logger.error('Error inactivando demos vencidos: %s', error)
        return 0


def verificar_suscripciones_vencidas():
    try:
        inactivar_demos_vencidos()
        return execute_update(
            """
            UPDATE empresas SET estado='suspendido'
            WHERE fecha_fin<CURDATE() AND estado='activo'
              AND IFNULL(es_demo, 0)=0
            """
        ) or 0
    except Exception as error:
        logger.error('Error verificando suscripciones: %s', error)
        return 0


def get_dias_restantes_suscripcion(tenant_id=None):
    empresa = get_empresa_info(tenant_id)
    if not empresa:
        return 0, 'error', 'Empresa no encontrada'
    if not empresa.get('fecha_fin'):
        return 9999, 'sin_fecha', 'Sin fecha de vencimiento'
    fecha_fin = empresa['fecha_fin']
    if isinstance(fecha_fin, str):
        fecha_fin = datetime.strptime(fecha_fin, '%Y-%m-%d').date()
    dias = (fecha_fin - date.today()).days
    if dias < 0:
        return dias, 'vencida', f'Suscripción vencida hace {abs(dias)} días'
    if dias <= 7:
        return dias, 'urgente', f'Vence en {dias} días - URGENTE'
    if dias <= 30:
        return dias, 'proximo', f'Vence en {dias} días'
    return dias, 'vigente', f'{dias} días restantes'
