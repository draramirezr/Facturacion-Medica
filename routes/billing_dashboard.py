"""Dashboard de facturación."""
from flask import render_template, request
from flask_login import current_user, login_required
from auth import permission_required, user_has_permission
from core.database import execute_query
from core.tenant import get_current_tenant_id


def _render_dashboard_medico(tenant_id, medico_id, fecha_desde, fecha_hasta):
    """Mostrar exclusivamente la actividad asociada al médico autenticado."""
    alcance = (tenant_id, medico_id, fecha_desde, fecha_hasta)
    consultas = execute_query('''
        SELECT COUNT(*) AS total,
               COUNT(DISTINCT paciente_id) AS pacientes,
               COALESCE(SUM(fecha = CURDATE()), 0) AS hoy
        FROM consultas_clinicas
        WHERE tenant_id=%s AND medico_id=%s
          AND fecha BETWEEN %s AND %s
    ''', alcance) or {}
    citas = execute_query('''
        SELECT COUNT(*) AS total,
               COALESCE(SUM(
                   estado = 'Programada'
                   AND TIMESTAMP(fecha, hora) >= NOW()
               ), 0) AS proximas
        FROM citas_medicas
        WHERE tenant_id=%s AND medico_id=%s
          AND fecha BETWEEN %s AND %s
    ''', alcance) or {}
    recetas = execute_query('''
        SELECT COUNT(*) AS total
        FROM recetas_medicas
        WHERE tenant_id=%s AND medico_id=%s
          AND fecha BETWEEN %s AND %s
    ''', alcance) or {}
    turnos = execute_query('''
        SELECT COUNT(*) AS total
        FROM turnos_atencion
        WHERE tenant_id=%s AND medico_id=%s
          AND fecha BETWEEN %s AND %s
          AND estado='Finalizado'
    ''', alcance) or {}
    actividad_reciente = execute_query('''
        SELECT c.id, c.paciente_id, c.fecha, c.hora,
               c.motivo_consulta, c.diagnostico_principal,
               p.nombre AS paciente_nombre
        FROM consultas_clinicas c
        JOIN pacientes p
          ON p.id=c.paciente_id AND p.tenant_id=c.tenant_id
        WHERE c.tenant_id=%s AND c.medico_id=%s
          AND c.fecha BETWEEN %s AND %s
        ORDER BY c.fecha DESC, c.hora DESC, c.id DESC
        LIMIT 10
    ''', alcance, fetch='all') or []
    medico = execute_query(
        'SELECT nombre, especialidad FROM medicos '
        'WHERE id=%s AND tenant_id=%s',
        (medico_id, tenant_id),
    ) or {}
    return render_template(
        'facturacion/dashboard_medico.html',
        medico=medico,
        consultas=consultas,
        citas=citas,
        recetas=recetas,
        turnos=turnos,
        actividad_reciente=actividad_reciente,
        fecha_desde=fecha_desde,
        fecha_hasta=fecha_hasta,
    )


PRESETS_PERIODO = (
    ('mes', 'Este mes'),
    ('mes_anterior', 'Mes anterior'),
    ('trimestre', 'Últimos 3 meses'),
    ('anio', 'Este año'),
)


def rango_preset(preset, hoy=None):
    """(desde, hasta) para los atajos de periodo del dashboard."""
    from datetime import date, timedelta

    hoy = hoy or date.today()
    inicio_mes = hoy.replace(day=1)
    if preset == 'mes_anterior':
        fin = inicio_mes - timedelta(days=1)
        return fin.replace(day=1), fin
    if preset == 'trimestre':
        mes = hoy.month - 2
        anio = hoy.year
        if mes <= 0:
            mes += 12
            anio -= 1
        return date(anio, mes, 1), hoy
    if preset == 'anio':
        return date(hoy.year, 1, 1), hoy
    return inicio_mes, hoy


def _fecha_param(nombre):
    from datetime import datetime

    valor = (request.args.get(nombre) or '').strip()[:10]
    try:
        return datetime.strptime(valor, '%Y-%m-%d').date()
    except ValueError:
        return None


@login_required
@permission_required('dashboard.ver')
def facturacion_dashboard():
    """Dashboard de facturación: indicadores del periodo y situación al día."""

    from routes.production_report import agrupacion_por_defecto, consultar_produccion
    from routes.support import validate_int
    from services.dashboard import resumen_dashboard
    from services.subscriptions import get_empresa_info

    tenant_id = get_current_tenant_id()
    preset = request.args.get('periodo') or ''
    desde, hasta = _fecha_param('fecha_desde'), _fecha_param('fecha_hasta')
    if preset or not (desde and hasta):
        preset = preset or 'mes'
        desde, hasta = rango_preset(preset)
    if desde > hasta:
        desde, hasta = hasta, desde

    medico_id = getattr(current_user, 'medico_id', None)
    roles_rbac = set(getattr(current_user, 'rbac_roles', ()))
    es_medico = (
        'Médico' in roles_rbac
        or getattr(current_user, 'perfil', None) == 'Médico'
    )
    es_administrador = (
        'Administrador' in roles_rbac
        or getattr(current_user, 'perfil', None) == 'Administrador'
    )
    if medico_id and es_medico and not es_administrador:
        return _render_dashboard_medico(
            tenant_id, medico_id, desde.isoformat(), hasta.isoformat(),
        )

    ars_id = validate_int(request.args.get('ars_id'), min_value=1, default=None)
    datos = resumen_dashboard(tenant_id, desde, hasta, ars_id)
    empresa = get_empresa_info(tenant_id) or {}
    agrupar = agrupacion_por_defecto(empresa.get('tipo_empresa'))
    produccion, _ = consultar_produccion(tenant_id, agrupar, desde, hasta, ars_id)

    graficas = {
        'meses': [m['mes'] for m in datos['serie_mensual']],
        'facturado': [float(m['facturado']) for m in datos['serie_mensual']],
        'cobrado': [float(m['cobrado']) for m in datos['serie_mensual']],
        'ars': [a['ars'] for a in datos['por_ars']],
        'ars_facturado': [float(a['facturado']) for a in datos['por_ars']],
        'ars_saldo': [float(a['saldo']) for a in datos['por_ars']],
        'antiguedad': list(datos['antiguedad'].keys()),
        'antiguedad_montos': [float(v) for v in datos['antiguedad'].values()],
    }
    ars_list = execute_query(
        'SELECT id, nombre FROM ars WHERE activo = 1 AND tenant_id = %s ORDER BY nombre',
        (tenant_id,),
        fetch='all',
    ) or []
    return render_template(
        'facturacion/dashboard.html',
        d=datos,
        produccion=produccion[:8],
        agrupar=agrupar,
        graficas=graficas,
        desde=desde.isoformat(),
        hasta=hasta.isoformat(),
        preset=preset,
        presets=PRESETS_PERIODO,
        ars_id=ars_id,
        ars_list=ars_list,
        puede_generar=user_has_permission(current_user, 'facturacion.crear'),
    )
