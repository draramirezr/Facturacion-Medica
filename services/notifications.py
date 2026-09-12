"""Contexto de notificaciones globales."""

import logging

from flask import url_for
from flask_login import current_user

from core.database import execute_query
from core.tenant import get_current_tenant_id

logger = logging.getLogger(__name__)


def inject_notifications():
    if not current_user.is_authenticated:
        return {'notificaciones': [], 'total_notificaciones': 0}
    tenant_id = get_current_tenant_id()
    notificaciones = []
    try:
        consultas = execute_query(
            """
            SELECT id, nombre_paciente, fecha_servicio
            FROM pacientes_pendientes
            WHERE tenant_id=%s AND estado='Pendiente'
            ORDER BY fecha_servicio DESC, id DESC LIMIT 6
            """,
            (tenant_id,),
            fetch='all',
        ) or []
        for consulta in consultas:
            notificaciones.append({
                'tipo': 'facturacion',
                'titulo': 'Consulta pendiente de facturar',
                'detalle': consulta.get('nombre_paciente') or 'Paciente sin nombre',
                'fecha': consulta.get('fecha_servicio'),
                'url': url_for('facturacion_pacientes_pendientes'),
            })
    except Exception as error:
        logger.warning('No se pudieron cargar consultas pendientes: %s', error)
    if current_user.perfil == 'Registro de Facturas':
        return {
            'notificaciones': notificaciones,
            'total_notificaciones': len(notificaciones),
        }
    try:
        citas = execute_query(
            """
            SELECT c.id, c.fecha, p.id AS paciente_id,
                   p.nombre AS paciente_nombre
            FROM citas_medicas c
            JOIN pacientes p
              ON p.id=c.paciente_id AND p.tenant_id=c.tenant_id
            WHERE c.tenant_id=%s
              AND (c.estado='Vencida' OR (
                c.estado IN ('Programada','Confirmada') AND c.fecha<CURDATE()
              ))
            ORDER BY c.fecha DESC, c.id DESC LIMIT 6
            """,
            (tenant_id,),
            fetch='all',
        ) or []
        for cita in citas:
            notificaciones.append({
                'tipo': 'cita',
                'titulo': 'Paciente con cita vencida',
                'detalle': cita['paciente_nombre'],
                'fecha': cita['fecha'],
                'url': url_for('facturacion_cita_editar', cita_id=cita['id']),
            })
    except Exception as error:
        logger.warning('No se pudieron cargar citas vencidas: %s', error)
    return {
        'notificaciones': notificaciones,
        'total_notificaciones': len(notificaciones),
    }


def init_notifications(app):
    app.context_processor(inject_notifications)
