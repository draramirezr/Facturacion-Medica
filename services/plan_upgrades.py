"""Mejora de plan por el cliente: acceso inmediato y pago en 7 días."""

import logging
from datetime import date, datetime, timedelta

from core.database import database_transaction, execute_query, execute_update
from core.presentation import SOPORTE_EMAIL_PREDETERMINADO
from services.platform import PLAN_LICENCIAS, crear_factura_plataforma
from services.tipo_cambio import monto_plan_dop

logger = logging.getLogger(__name__)

UPGRADE_GRACIA_DIAS = 7

PLAN_ORDEN = ('basico', 'profesional', 'empresarial')

PLAN_ETIQUETAS = {
    'basico': 'Independiente (1 usuario)',
    'profesional': 'Consultorio (hasta 2 usuarios)',
    'empresarial': 'Centro médico (hasta 5 usuarios)',
}


def asegurar_tabla_upgrades():
    execute_update(
        '''
        CREATE TABLE IF NOT EXISTS solicitudes_upgrade_plan (
            id INT AUTO_INCREMENT PRIMARY KEY,
            empresa_id INT NOT NULL,
            usuario_id INT NULL,
            plan_anterior ENUM('basico','profesional','empresarial') NOT NULL,
            plan_nuevo ENUM('basico','profesional','empresarial') NOT NULL,
            licencias_anterior INT NOT NULL,
            licencias_nuevo INT NOT NULL,
            factura_id INT NULL,
            monto DECIMAL(12,2) NOT NULL,
            estado ENUM('pendiente_pago','pagado','vencido','anulado') NOT NULL DEFAULT 'pendiente_pago',
            vence_pago DATE NOT NULL,
            creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            pagado_en DATETIME NULL,
            INDEX idx_upgrade_empresa (empresa_id),
            INDEX idx_upgrade_estado (estado),
            INDEX idx_upgrade_vence (vence_pago)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        '''
    )


def _indice_plan(plan):
    try:
        return PLAN_ORDEN.index(plan)
    except ValueError:
        return -1


def planes_superiores(plan_actual):
    idx = _indice_plan(plan_actual or 'basico')
    if idx < 0:
        return list(PLAN_ORDEN)
    return list(PLAN_ORDEN[idx + 1:])


def upgrade_pendiente_empresa(empresa_id):
    asegurar_tabla_upgrades()
    return execute_query(
        '''
        SELECT s.*, f.numero AS factura_numero
        FROM solicitudes_upgrade_plan s
        LEFT JOIN facturas_plataforma f ON f.id=s.factura_id
        WHERE s.empresa_id=%s AND s.estado='pendiente_pago'
        ORDER BY s.id DESC LIMIT 1
        ''',
        (empresa_id,),
    )


def contar_upgrades_pendientes():
    asegurar_tabla_upgrades()
    fila = execute_query(
        "SELECT COUNT(*) AS total FROM solicitudes_upgrade_plan WHERE estado='pendiente_pago'"
    ) or {}
    return int(fila.get('total') or 0)


def listar_upgrades_pendientes(limite=50):
    asegurar_tabla_upgrades()
    return execute_query(
        '''
        SELECT s.*, e.nombre AS empresa_nombre, e.email AS empresa_email,
               e.plan AS plan_actual, f.numero AS factura_numero,
               DATEDIFF(s.vence_pago, CURDATE()) AS dias_para_pagar
        FROM solicitudes_upgrade_plan s
        JOIN empresas e ON e.id=s.empresa_id
        LEFT JOIN facturas_plataforma f ON f.id=s.factura_id
        WHERE s.estado='pendiente_pago'
        ORDER BY s.vence_pago ASC, s.id ASC
        LIMIT %s
        ''',
        (limite,),
        fetch='all',
    ) or []


def _notificar_soporte_upgrade(empresa, solicitud_id, plan_nuevo, monto, vence_pago):
    from services.email_content import correo_upgrade_plan_soporte
    from services.platform_mail import enviar_correo_plataforma
    import os

    destino = (
        os.getenv('SOPORTE_EMAIL', '').strip() or SOPORTE_EMAIL_PREDETERMINADO
    )
    asunto, texto, html = correo_upgrade_plan_soporte(
        empresa, solicitud_id, plan_nuevo, monto, vence_pago,
    )
    ok, detalle = enviar_correo_plataforma(destino, asunto, html, texto=texto)
    if not ok:
        logger.warning('No se pudo avisar a soporte del upgrade %s: %s', solicitud_id, detalle)


def solicitar_upgrade_plan(empresa_id, plan_nuevo, usuario_id=None):
    """
    Aplica el plan de inmediato, genera factura pendiente y plazo de pago.
    Retorna (ok, mensaje, solicitud_id).
    """
    asegurar_tabla_upgrades()
    if plan_nuevo not in PLAN_ORDEN:
        return False, 'Plan inválido.', None
    empresa = execute_query('SELECT * FROM empresas WHERE id=%s', (empresa_id,))
    if not empresa:
        return False, 'Empresa no encontrada.', None
    if empresa.get('es_demo'):
        return (
            False,
            'Las cuentas demo no pueden cambiar de plan aquí. '
            'Contacte a soporte para contratar.',
            None,
        )
    if empresa.get('estado') != 'activo':
        return False, 'La empresa debe estar activa para mejorar el plan.', None
    plan_actual = empresa.get('plan') or 'basico'
    if _indice_plan(plan_nuevo) <= _indice_plan(plan_actual):
        return False, 'Solo puede subir a un plan superior al actual.', None
    if upgrade_pendiente_empresa(empresa_id):
        return (
            False,
            'Ya tiene una mejora de plan pendiente de pago. '
            'Espere el plazo o contacte a soporte.',
            None,
        )
    monto = monto_plan_dop(plan_nuevo, 1)
    if monto is None:
        return False, 'No se pudo calcular el monto. Intente más tarde.', None

    licencias_anterior = int(empresa.get('licencias_totales') or 1)
    licencias_nuevo = PLAN_LICENCIAS.get(plan_nuevo, licencias_anterior)
    hoy = date.today()
    vence = hoy + timedelta(days=UPGRADE_GRACIA_DIAS)
    periodo_fin = hoy + timedelta(days=30)

    solicitud_id = None
    with database_transaction():
        execute_update(
            '''
            UPDATE empresas
            SET plan=%s, licencias_totales=%s
            WHERE id=%s
            ''',
            (plan_nuevo, licencias_nuevo, empresa_id),
        )
        factura_id = crear_factura_plataforma(
            {
                'empresa_id': empresa_id,
                'fecha': hoy.isoformat(),
                'periodo_inicio': hoy.isoformat(),
                'periodo_fin': periodo_fin.isoformat(),
                'plan': plan_nuevo,
                'licencias': licencias_nuevo,
                'monto': round(float(monto), 2),
                'notas': (
                    f'Upgrade {PLAN_ETIQUETAS.get(plan_anterior, plan_actual)} → '
                    f'{PLAN_ETIQUETAS.get(plan_nuevo, plan_nuevo)}. '
                    f'Pago antes del {vence.isoformat()}.'
                ),
            },
            creado_por=usuario_id,
        )
        solicitud_id = execute_update(
            '''
            INSERT INTO solicitudes_upgrade_plan (
                empresa_id, usuario_id, plan_anterior, plan_nuevo,
                licencias_anterior, licencias_nuevo, factura_id, monto,
                vence_pago
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ''',
            (
                empresa_id, usuario_id, plan_actual, plan_nuevo,
                licencias_anterior, licencias_nuevo, factura_id,
                round(float(monto), 2), vence.isoformat(),
            ),
        )

    _notificar_soporte_upgrade(empresa, solicitud_id, plan_nuevo, monto, vence)
    etiqueta = PLAN_ETIQUETAS.get(plan_nuevo, plan_nuevo)
    return (
        True,
        f'Plan actualizado a {etiqueta}. Tiene {UPGRADE_GRACIA_DIAS} días para '
        f'completar el pago (antes del {vence.strftime("%d/%m/%Y")}). '
        'Soporte recibió la solicitud.',
        solicitud_id,
    )


def marcar_upgrade_pagado_por_factura(factura_id):
    asegurar_tabla_upgrades()
    solicitud = execute_query(
        '''
        SELECT * FROM solicitudes_upgrade_plan
        WHERE factura_id=%s AND estado='pendiente_pago'
        LIMIT 1
        ''',
        (factura_id,),
    )
    if not solicitud:
        return
    hoy = date.today()
    execute_update(
        '''
        UPDATE solicitudes_upgrade_plan
        SET estado='pagado', pagado_en=%s
        WHERE id=%s
        ''',
        (datetime.now(), solicitud['id']),
    )
    empresa = execute_query(
        'SELECT fecha_fin FROM empresas WHERE id=%s',
        (solicitud['empresa_id'],),
    )
    fecha_fin = empresa.get('fecha_fin') if empresa else None
    if isinstance(fecha_fin, str):
        try:
            fecha_fin = datetime.strptime(fecha_fin[:10], '%Y-%m-%d').date()
        except ValueError:
            fecha_fin = hoy
    elif not fecha_fin:
        fecha_fin = hoy
    if fecha_fin < hoy:
        fecha_fin = hoy
    nueva_fin = fecha_fin + timedelta(days=30)
    execute_update(
        'UPDATE empresas SET estado=%s, fecha_fin=%s WHERE id=%s',
        ('activo', nueva_fin.isoformat(), solicitud['empresa_id']),
    )


def _revertir_upgrade(solicitud):
    execute_update(
        '''
        UPDATE empresas
        SET plan=%s, licencias_totales=%s, estado='suspendido'
        WHERE id=%s
        ''',
        (
            solicitud['plan_anterior'],
            solicitud['licencias_anterior'],
            solicitud['empresa_id'],
        ),
    )
    if solicitud.get('factura_id'):
        execute_update(
            "UPDATE facturas_plataforma SET estado='anulada' WHERE id=%s AND estado='pendiente'",
            (solicitud['factura_id'],),
        )
    execute_update(
        "UPDATE solicitudes_upgrade_plan SET estado='vencido' WHERE id=%s",
        (solicitud['id'],),
    )


def vencer_upgrades_sin_pago():
    """Suspende y revierte el plan si no se registró el pago a tiempo."""
    asegurar_tabla_upgrades()
    vencidas = execute_query(
        '''
        SELECT * FROM solicitudes_upgrade_plan
        WHERE estado='pendiente_pago' AND vence_pago < CURDATE()
        ''',
        fetch='all',
    ) or []
    for solicitud in vencidas:
        try:
            _revertir_upgrade(solicitud)
        except Exception as error:
            logger.error('Error revirtiendo upgrade %s: %s', solicitud.get('id'), error)
    return len(vencidas)
