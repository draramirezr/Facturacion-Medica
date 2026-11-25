"""Reporte de producción: servicios y montos por médico o por centro.

- Centro de salud: por defecto agrupa por médico (qué produjo cada uno).
- Médico: por defecto agrupa por centro donde trabaja.

Fuente: pacientes_pendientes, donde queda el médico que atendió, el centro,
la ARS, la fecha del servicio y si ya se facturó.
"""

import csv
from datetime import date, datetime
from decimal import Decimal
from io import StringIO

from flask import Response, render_template, request
from flask_login import login_required

from auth import permission_required
from core.database import execute_query
from core.tenant import get_current_tenant_id
from routes.support import validate_int
from services.subscriptions import get_empresa_info

AGRUPACIONES = {
    'medico': {
        'join': 'LEFT JOIN medicos ent ON ent.id = pp.medico_id AND ent.tenant_id = pp.tenant_id',
        'id': 'pp.medico_id',
        'sin': 'Sin médico asignado',
        'titulo': 'Médico',
    },
    'centro': {
        'join': (
            'LEFT JOIN centros_medicos ent '
            'ON ent.id = pp.centro_medico_id AND ent.tenant_id = pp.tenant_id'
        ),
        'id': 'pp.centro_medico_id',
        'sin': 'Sin centro asignado',
        'titulo': 'Centro',
    },
}

CERO = Decimal('0.00')


def agrupacion_por_defecto(tipo_empresa):
    return 'medico' if tipo_empresa == 'centro_salud' else 'centro'


def _fecha(valor, defecto):
    try:
        return datetime.strptime((valor or '').strip()[:10], '%Y-%m-%d').date()
    except ValueError:
        return defecto


def rango_por_defecto(hoy=None):
    hoy = hoy or date.today()
    return hoy.replace(day=1), hoy


def consultar_produccion(tenant_id, agrupar, desde, hasta, ars_id=None):
    """Filas por entidad y totales. `agrupar` debe ser 'medico' o 'centro'."""
    config = AGRUPACIONES[agrupar]
    query = f'''
        SELECT {config['id']} AS entidad_id,
               ent.nombre AS entidad,
               COUNT(*) AS servicios,
               COUNT(DISTINCT COALESCE(
                   CAST(pp.paciente_id AS CHAR), pp.nss, pp.nombre_paciente
               )) AS pacientes,
               COALESCE(SUM(pp.monto_estimado), 0) AS total,
               COALESCE(SUM(CASE WHEN pp.estado = 'Facturado'
                                 THEN pp.monto_estimado ELSE 0 END), 0) AS facturado,
               COALESCE(SUM(CASE WHEN pp.estado <> 'Facturado'
                                 THEN pp.monto_estimado ELSE 0 END), 0) AS por_facturar
        FROM pacientes_pendientes pp
        {config['join']}
        WHERE pp.tenant_id = %s
          AND pp.fecha_servicio BETWEEN %s AND %s
    '''
    params = [tenant_id, desde, hasta]
    if ars_id:
        query += ' AND pp.ars_id = %s'
        params.append(ars_id)
    query += f' GROUP BY {config["id"]}, ent.nombre ORDER BY total DESC, entidad'
    filas = execute_query(query, tuple(params), fetch='all') or []
    resultado = []
    totales = {'servicios': 0, 'pacientes': 0, 'total': CERO, 'facturado': CERO, 'por_facturar': CERO}
    for fila in filas:
        item = {
            'entidad_id': fila.get('entidad_id'),
            'entidad': fila.get('entidad') or config['sin'],
            'servicios': int(fila.get('servicios') or 0),
            'pacientes': int(fila.get('pacientes') or 0),
            'total': Decimal(str(fila.get('total') or 0)),
            'facturado': Decimal(str(fila.get('facturado') or 0)),
            'por_facturar': Decimal(str(fila.get('por_facturar') or 0)),
        }
        resultado.append(item)
        for clave in ('servicios', 'total', 'facturado', 'por_facturar'):
            totales[clave] += item[clave]
    for item in resultado:
        item['porcentaje'] = (
            (item['total'] * 100 / totales['total']).quantize(Decimal('0.1'))
            if totales['total'] > 0 else Decimal('0.0')
        )
    # Pacientes distintos del periodo completo (no la suma por entidad).
    totales['pacientes'] = _pacientes_distintos(tenant_id, desde, hasta, ars_id)
    return resultado, totales


def _pacientes_distintos(tenant_id, desde, hasta, ars_id=None):
    query = '''
        SELECT COUNT(DISTINCT COALESCE(
            CAST(paciente_id AS CHAR), nss, nombre_paciente
        )) AS n
        FROM pacientes_pendientes
        WHERE tenant_id = %s AND fecha_servicio BETWEEN %s AND %s
    '''
    params = [tenant_id, desde, hasta]
    if ars_id:
        query += ' AND ars_id = %s'
        params.append(ars_id)
    fila = execute_query(query, tuple(params)) or {}
    return int(fila.get('n') or 0)


def _csv(filas, totales, titulo):
    salida = StringIO()
    escritor = csv.writer(salida)
    escritor.writerow([titulo, 'Servicios', 'Pacientes', 'Total', 'Facturado', 'Por facturar', '% del total'])
    for fila in filas:
        escritor.writerow([
            fila['entidad'], fila['servicios'], fila['pacientes'],
            fila['total'], fila['facturado'], fila['por_facturar'], fila['porcentaje'],
        ])
    escritor.writerow([
        'TOTAL', totales['servicios'], totales['pacientes'],
        totales['total'], totales['facturado'], totales['por_facturar'], '100.0',
    ])
    # BOM para que Excel abra bien los acentos.
    return '﻿' + salida.getvalue()


@login_required
@permission_required('reportes.ver')
def facturacion_reporte_produccion():
    tenant_id = get_current_tenant_id()
    empresa = get_empresa_info(tenant_id) or {}
    tipo_empresa = empresa.get('tipo_empresa') or 'medico'
    agrupar = request.args.get('por') or agrupacion_por_defecto(tipo_empresa)
    if agrupar not in AGRUPACIONES:
        agrupar = agrupacion_por_defecto(tipo_empresa)
    desde_def, hasta_def = rango_por_defecto()
    desde = _fecha(request.args.get('desde'), desde_def)
    hasta = _fecha(request.args.get('hasta'), hasta_def)
    if desde > hasta:
        desde, hasta = hasta, desde
    ars_id = validate_int(request.args.get('ars_id'), min_value=1, default=None)

    filas, totales = consultar_produccion(tenant_id, agrupar, desde, hasta, ars_id)
    titulo = AGRUPACIONES[agrupar]['titulo']

    if request.args.get('formato') == 'csv':
        nombre = f'produccion_por_{agrupar}_{desde.isoformat()}_{hasta.isoformat()}.csv'
        return Response(
            _csv(filas, totales, titulo),
            mimetype='text/csv; charset=utf-8',
            headers={'Content-Disposition': f'attachment; filename="{nombre}"'},
        )

    ars_list = execute_query(
        'SELECT id, nombre FROM ars WHERE activo = 1 AND tenant_id = %s ORDER BY nombre',
        (tenant_id,),
        fetch='all',
    ) or []
    return render_template(
        'facturacion/reporte_produccion.html',
        filas=filas,
        totales=totales,
        agrupar=agrupar,
        titulo_entidad=titulo,
        desde=desde.isoformat(),
        hasta=hasta.isoformat(),
        ars_id=ars_id,
        ars_list=ars_list,
    )


def register_production_report_routes(app):
    app.add_url_rule(
        '/facturacion/reportes/produccion',
        endpoint='facturacion_reporte_produccion',
        view_func=facturacion_reporte_produccion,
    )
