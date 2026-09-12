"""Contexto de notificaciones globales."""

import logging

from flask import url_for
from flask_login import current_user

from auth import user_has_permission
from core.database import execute_query
from core.tenant import get_current_tenant_id

logger = logging.getLogger(__name__)


def _medico_id_notificaciones():
    """Resolver el alcance personal de alertas para el rol Médico."""
    roles_rbac = set(getattr(current_user, 'rbac_roles', ()))
    es_medico = (
        'Médico' in roles_rbac
        or getattr(current_user, 'perfil', None) == 'Médico'
    )
    es_administrador = (
        'Administrador' in roles_rbac
        or getattr(current_user, 'perfil', None) == 'Administrador'
    )
    medico_id = getattr(current_user, 'medico_id', None)
    return medico_id if medico_id and es_medico and not es_administrador else None


def inject_notifications():
    if not current_user.is_authenticated:
        return {'notificaciones': [], 'total_notificaciones': 0}
    tenant_id = get_current_tenant_id()
    medico_id = _medico_id_notificaciones()
    notificaciones = []
    if user_has_permission(current_user, 'facturacion.ver'):
        try:
            consulta_sql = """
            SELECT id, nombre_paciente, fecha_servicio
            FROM pacientes_pendientes
            WHERE tenant_id=%s AND estado='Pendiente'
            """
            consulta_params = [tenant_id]
            if medico_id:
                consulta_sql += " AND medico_id=%s"
                consulta_params.append(medico_id)
            consulta_sql += """
            ORDER BY fecha_servicio DESC, id DESC LIMIT 6
            """
            consultas = execute_query(
                consulta_sql,
                tuple(consulta_params),
                fetch='all',
            ) or []
            for consulta in consultas:
                notificaciones.append({
                    'tipo': 'facturacion',
                    'titulo': 'Consulta pendiente de facturar',
                    'detalle': (
                        consulta.get('nombre_paciente')
                        or 'Paciente sin nombre'
                    ),
                    'fecha': consulta.get('fecha_servicio'),
                    'url': url_for('facturacion_pacientes_pendientes'),
                })
        except Exception as error:
            logger.warning(
                'No se pudieron cargar consultas pendientes: %s',
                error,
            )
    if not user_has_permission(current_user, 'citas.ver'):
        return {
            'notificaciones': notificaciones,
            'total_notificaciones': len(notificaciones),
        }
    try:
        citas_sql = """
            SELECT c.id, c.fecha, p.id AS paciente_id,
                   p.nombre AS paciente_nombre
            FROM citas_medicas c
            JOIN pacientes p
              ON p.id=c.paciente_id AND p.tenant_id=c.tenant_id
            WHERE c.tenant_id=%s
              AND (c.estado='Vencida' OR (
                c.estado IN ('Programada','Confirmada') AND c.fecha<CURDATE()
              ))
        """
        citas_params = [tenant_id]
        if medico_id:
            citas_sql += " AND c.medico_id=%s"
            citas_params.append(medico_id)
        citas_sql += """
            ORDER BY c.fecha DESC, c.id DESC LIMIT 6
        """
        citas = execute_query(
            citas_sql,
            tuple(citas_params),
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
