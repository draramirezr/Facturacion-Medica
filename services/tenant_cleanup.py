"""Eliminar empresas demo sin uso (registro fallido o prueba del dueño)."""

import logging

from core.config import REQUIRED_TENANT_TABLES
from core.database import database_transaction, execute_query, execute_update

logger = logging.getLogger(__name__)

_TABLAS_SOLO_SEMILLA = frozenset({
    'ars', 'roles', 'rol_permisos', 'usuario_roles',
})
_TABLAS_DATOS = tuple(
    t for t in REQUIRED_TENANT_TABLES
    if t not in _TABLAS_SOLO_SEMILLA and t != 'usuarios'
)
_ORDEN_ELIMINACION = (
    'usuario_roles',
    'usuario_medico',
    'rol_permisos',
    'factura_detalles',
    'pago_facturas',
    'receta_medicamentos',
    'evoluciones_clinicas',
    'consultas_clinicas',
    'citas_medicas',
    'mensajes_internos',
    'conversaciones_internas',
    'turnos_eventos',
    'turnos_atencion',
    'pagos',
    'facturas',
    'facturas_ecf',
    'reclamaciones',
    'recetas_medicas',
    'licencias_medicas',
    'historias_emergencia',
    'hojas_enfermeria',
    'pacientes_pendientes',
    'pacientes',
    'medico_centro',
    'medicos',
    'centros_medicos',
    'servicios',
    'ncf',
    'codigo_ars',
    'ecf_outbox',
    'ecf_eventos',
    'ecf_secuencias',
    'ecf_configuraciones',
    'secuencias_turnos',
    'pantallas_turnos',
    'enlaces_cita_qr',
    'tipos_licencia_medica',
    'auditoria_historia_clinica',
    'auditoria_licencias_medicas',
    'usuarios',
    'roles',
    'ars',
)


def _conteo_tenant(tabla, tenant_id):
    fila = execute_query(
        f'SELECT COUNT(*) AS n FROM `{tabla}` WHERE tenant_id=%s',
        (tenant_id,),
    )
    return int(fila['n']) if fila else 0


def motivo_no_eliminar_demo(empresa_id):
    """Devuelve texto de error si no se puede borrar; None si sí."""
    empresa = execute_query(
        'SELECT id, es_demo FROM empresas WHERE id=%s',
        (empresa_id,),
    )
    if not empresa:
        return 'Empresa no encontrada'
    if empresa_id == 1:
        return 'No se puede eliminar la empresa predeterminada'
    if not empresa.get('es_demo'):
        return 'Solo se pueden eliminar empresas marcadas como demo'
    usuarios = execute_query(
        '''
        SELECT id, email_verificado, last_login
        FROM usuarios WHERE tenant_id=%s
        ''',
        (empresa_id,),
        fetch='all',
    ) or []
    for usuario in usuarios:
        if usuario.get('email_verificado'):
            return (
                'Hay usuarios con correo ya verificado; '
                'no se puede eliminar desde aquí'
            )
        if usuario.get('last_login'):
            return 'Ya hubo inicio de sesión en esta demo'
    for tabla in _TABLAS_DATOS:
        if _conteo_tenant(tabla, empresa_id) > 0:
            return (
                f'La demo tiene datos operativos ({tabla}); '
                'contacte soporte para borrado completo'
            )
    return None


def eliminar_empresa_demo_vacia(empresa_id):
    """
    Borrar empresa demo sin pacientes/facturas/etc.
    Retorna (ok, mensaje).
    """
    motivo = motivo_no_eliminar_demo(empresa_id)
    if motivo:
        return False, motivo
    nombre = execute_query(
        'SELECT nombre FROM empresas WHERE id=%s',
        (empresa_id,),
    )
    etiqueta = (nombre or {}).get('nombre') or f'ID {empresa_id}'
    try:
        with database_transaction():
            orden = [
                t for t in _ORDEN_ELIMINACION if t in REQUIRED_TENANT_TABLES
            ]
            orden += [
                t for t in REQUIRED_TENANT_TABLES if t not in orden
            ]
            for tabla in orden:
                execute_update(
                    f'DELETE FROM `{tabla}` WHERE tenant_id=%s',
                    (empresa_id,),
                )
            execute_update(
                'UPDATE solicitudes_demo SET empresa_id=NULL WHERE empresa_id=%s',
                (empresa_id,),
            )
            execute_update(
                'DELETE FROM facturas_plataforma WHERE empresa_id=%s',
                (empresa_id,),
            )
            execute_update('DELETE FROM empresas WHERE id=%s', (empresa_id,))
        logger.info('Empresa demo eliminada: %s (%s)', etiqueta, empresa_id)
        return True, f'Demo "{etiqueta}" eliminada'
    except Exception as error:
        logger.error(
            'Error eliminando demo %s: %s',
            empresa_id,
            error,
            exc_info=True,
        )
        return False, 'No se pudo eliminar la demo por un error interno'
