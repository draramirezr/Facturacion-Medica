"""Indicadores del dashboard de facturación.

Todo se filtra por empresa (tenant_id) y excluye facturas anuladas.
- Periodo: facturado, cobrado, facturas emitidas y su evolución mensual.
- Foto al día de hoy: cuentas por cobrar (con antigüedad), pendiente por
  facturar y reclamaciones abiertas, que no dependen del rango elegido.
"""

from datetime import date, timedelta
from decimal import Decimal

from core.database import execute_query

CERO = Decimal('0.00')
TRAMOS_ANTIGUEDAD = (
    ('0-30', 0, 30),
    ('31-60', 31, 60),
    ('61-90', 61, 90),
    ('+90', 91, None),
)


def _dec(valor):
    return Decimal(str(valor or 0))


def _variacion(actual, anterior):
    if not anterior:
        return None
    return ((actual - anterior) * 100 / anterior).quantize(Decimal('0.1'))


def periodo_anterior(desde, hasta):
    """Periodo inmediatamente anterior con la misma cantidad de días."""
    dias = (hasta - desde).days + 1
    return desde - timedelta(days=dias), desde - timedelta(days=1)


def _filtro_ars(alias, ars_id, params):
    if ars_id:
        params.append(ars_id)
        return f' AND {alias}.ars_id = %s'
    return ''


def facturado_en(tenant_id, desde, hasta, ars_id=None):
    params = [tenant_id, desde, hasta]
    fila = execute_query(
        '''
        SELECT COUNT(*) AS facturas, COALESCE(SUM(f.total), 0) AS monto
        FROM facturas f
        WHERE f.tenant_id = %s AND f.estado <> 'Anulada'
          AND f.fecha_emision BETWEEN %s AND %s
        ''' + _filtro_ars('f', ars_id, params),
        tuple(params),
    ) or {}
    return int(fila.get('facturas') or 0), _dec(fila.get('monto'))


def cobrado_pacientes_en(tenant_id, desde, hasta):
    fila = execute_query(
        '''
        SELECT COALESCE(SUM(f.total), 0) AS monto
        FROM facturas f
        WHERE f.tenant_id = %s AND f.estado <> 'Anulada'
          AND f.destinatario = 'PACIENTE'
          AND f.fecha_emision BETWEEN %s AND %s
        ''',
        (tenant_id, desde, hasta),
    ) or {}
    return _dec(fila.get('monto'))


def cobrado_en(tenant_id, desde, hasta, ars_id=None):
    # Con filtro de ARS solo cuentan los pagos de esa ARS.
    pacientes = CERO if ars_id else cobrado_pacientes_en(tenant_id, desde, hasta)
    params = [tenant_id, desde, hasta]
    fila = execute_query(
        '''
        SELECT COALESCE(SUM(pf.monto_aplicado), 0) AS monto
        FROM pago_facturas pf
        JOIN pagos p ON p.id = pf.pago_id AND p.tenant_id = pf.tenant_id
        JOIN facturas f ON f.id = pf.factura_id AND f.tenant_id = pf.tenant_id
        WHERE pf.tenant_id = %s AND f.estado <> 'Anulada'
          AND p.fecha_pago BETWEEN %s AND %s
        ''' + _filtro_ars('f', ars_id, params),
        tuple(params),
    ) or {}
    return _dec(fila.get('monto')) + pacientes


def cuentas_por_cobrar(tenant_id, hoy, ars_id=None):
    """Saldo de facturas no anuladas, total y por antigüedad desde la emisión."""
    params = [tenant_id]
    filas = execute_query(
        '''
        SELECT f.fecha_emision,
               f.total - COALESCE(ap.aplicado, 0) AS saldo
        FROM facturas f
        LEFT JOIN (
            SELECT factura_id, SUM(monto_aplicado) AS aplicado
            FROM pago_facturas WHERE tenant_id = %s
            GROUP BY factura_id
        ) ap ON ap.factura_id = f.id
        WHERE f.tenant_id = %s AND f.estado <> 'Anulada'
          AND f.destinatario = 'ARS'
        ''' + _filtro_ars('f', ars_id, params) + '''
        HAVING saldo > 0
        ''',
        (tenant_id, *params),
        fetch='all',
    ) or []
    tramos = {nombre: CERO for nombre, _, _ in TRAMOS_ANTIGUEDAD}
    total = CERO
    for fila in filas:
        saldo = _dec(fila.get('saldo'))
        emision = fila.get('fecha_emision')
        dias = (hoy - emision).days if hasattr(emision, 'year') else 0
        for nombre, minimo, maximo in TRAMOS_ANTIGUEDAD:
            if dias >= minimo and (maximo is None or dias <= maximo):
                tramos[nombre] += saldo
                break
        total += saldo
    return total, tramos, len(filas)


def pendiente_por_facturar(tenant_id, ars_id=None):
    """Servicios registrados aún sin factura, agrupados por ARS."""
    params = [tenant_id]
    filas = execute_query(
        '''
        SELECT pp.ars_id, a.nombre AS ars,
               COUNT(*) AS servicios,
               COALESCE(SUM(pp.monto_estimado), 0) AS monto,
               MIN(pp.fecha_servicio) AS desde
        FROM pacientes_pendientes pp
        LEFT JOIN ars a ON a.id = pp.ars_id AND a.tenant_id = pp.tenant_id
        WHERE pp.tenant_id = %s AND pp.estado = 'Pendiente'
        ''' + _filtro_ars('pp', ars_id, params) + '''
        GROUP BY pp.ars_id, a.nombre
        ORDER BY monto DESC
        ''',
        tuple(params),
        fetch='all',
    ) or []
    por_ars = [
        {
            'ars_id': fila.get('ars_id'),
            'ars': fila.get('ars') or 'Sin ARS',
            'servicios': int(fila.get('servicios') or 0),
            'monto': _dec(fila.get('monto')),
            'desde': fila.get('desde'),
        }
        for fila in filas
    ]
    return (
        sum((x['monto'] for x in por_ars), CERO),
        sum(x['servicios'] for x in por_ars),
        por_ars,
    )


def reclamaciones_abiertas(tenant_id, ars_id=None):
    params = [tenant_id]
    fila = execute_query(
        '''
        SELECT COUNT(*) AS n, COALESCE(SUM(r.monto_reclamado), 0) AS monto
        FROM reclamaciones r
        JOIN facturas f ON f.id = r.factura_id AND f.tenant_id = r.tenant_id
        WHERE r.tenant_id = %s AND r.estado = 'Pendiente'
        ''' + _filtro_ars('f', ars_id, params),
        tuple(params),
    ) or {}
    return int(fila.get('n') or 0), _dec(fila.get('monto'))


def serie_mensual(tenant_id, desde, hasta, ars_id=None):
    """Facturado y cobrado por mes (AAAA-MM) dentro del rango."""
    params_f = [tenant_id, desde, hasta]
    facturado = execute_query(
        '''
        SELECT DATE_FORMAT(f.fecha_emision, '%%Y-%%m') AS mes,
               COALESCE(SUM(f.total), 0) AS monto
        FROM facturas f
        WHERE f.tenant_id = %s AND f.estado <> 'Anulada'
          AND f.fecha_emision BETWEEN %s AND %s
        ''' + _filtro_ars('f', ars_id, params_f) + ' GROUP BY mes ORDER BY mes',
        tuple(params_f),
        fetch='all',
    ) or []
    params_c = [tenant_id, desde, hasta]
    cobrado = execute_query(
        '''
        SELECT DATE_FORMAT(p.fecha_pago, '%%Y-%%m') AS mes,
               COALESCE(SUM(pf.monto_aplicado), 0) AS monto
        FROM pago_facturas pf
        JOIN pagos p ON p.id = pf.pago_id AND p.tenant_id = pf.tenant_id
        JOIN facturas f ON f.id = pf.factura_id AND f.tenant_id = pf.tenant_id
        WHERE pf.tenant_id = %s AND f.estado <> 'Anulada'
          AND p.fecha_pago BETWEEN %s AND %s
        ''' + _filtro_ars('f', ars_id, params_c) + ' GROUP BY mes ORDER BY mes',
        tuple(params_c),
        fetch='all',
    ) or []
    meses = []
    cursor = date(desde.year, desde.month, 1)
    while cursor <= hasta:
        meses.append(cursor.strftime('%Y-%m'))
        cursor = date(cursor.year + (cursor.month == 12), cursor.month % 12 + 1, 1)
    if not ars_id:
        cobrado = list(cobrado) + (execute_query(
            '''
            SELECT DATE_FORMAT(f.fecha_emision, '%%Y-%%m') AS mes,
                   COALESCE(SUM(f.total), 0) AS monto
            FROM facturas f
            WHERE f.tenant_id = %s AND f.estado <> 'Anulada'
              AND f.destinatario = 'PACIENTE'
              AND f.fecha_emision BETWEEN %s AND %s
            GROUP BY mes ORDER BY mes
            ''',
            (tenant_id, desde, hasta),
            fetch='all',
        ) or [])
    f_map = {r['mes']: _dec(r['monto']) for r in facturado}
    c_map = {}
    for r in cobrado:
        c_map[r['mes']] = c_map.get(r['mes'], CERO) + _dec(r['monto'])
    return [
        {'mes': mes, 'facturado': f_map.get(mes, CERO), 'cobrado': c_map.get(mes, CERO)}
        for mes in meses
    ]


def por_ars(tenant_id, desde, hasta, limite=8):
    """Facturado en el periodo y saldo pendiente por ARS."""
    filas = execute_query(
        '''
        SELECT a.id AS ars_id, a.nombre AS ars,
               COUNT(*) AS facturas,
               COALESCE(SUM(f.total), 0) AS facturado,
               COALESCE(SUM(f.total - COALESCE(ap.aplicado, 0)), 0) AS saldo
        FROM facturas f
        JOIN ars a ON a.id = f.ars_id AND a.tenant_id = f.tenant_id
        LEFT JOIN (
            SELECT factura_id, SUM(monto_aplicado) AS aplicado
            FROM pago_facturas WHERE tenant_id = %s
            GROUP BY factura_id
        ) ap ON ap.factura_id = f.id
        WHERE f.tenant_id = %s AND f.estado <> 'Anulada'
          AND f.destinatario = 'ARS'
          AND f.fecha_emision BETWEEN %s AND %s
        GROUP BY a.id, a.nombre
        ORDER BY facturado DESC
        LIMIT %s
        ''',
        (tenant_id, tenant_id, desde, hasta, limite),
        fetch='all',
    ) or []
    return [
        {
            'ars_id': f['ars_id'],
            'ars': f['ars'],
            'facturas': int(f.get('facturas') or 0),
            'facturado': _dec(f.get('facturado')),
            'saldo': _dec(f.get('saldo')),
        }
        for f in filas
    ]


def alertas(tenant_id, hoy, dias_aviso=30):
    """Secuencias NCF o e-CF vencidas o próximas a vencer."""
    avisos = []
    limite = hoy + timedelta(days=dias_aviso)
    ncf = execute_query(
        '''
        SELECT tipo, fecha_fin FROM ncf
        WHERE tenant_id = %s AND activo = 1
          AND fecha_fin IS NOT NULL AND fecha_fin <= %s
        ORDER BY fecha_fin
        ''',
        (tenant_id, limite),
        fetch='all',
    ) or []
    for fila in ncf:
        vence = fila['fecha_fin']
        avisos.append({
            'nivel': 'danger' if vence < hoy else 'warning',
            'texto': (
                f"La secuencia NCF {fila['tipo']} "
                + ('venció' if vence < hoy else 'vence')
                + f" el {vence.strftime('%d/%m/%Y')}."
            ),
            'endpoint': 'facturacion_ncf',
        })
    try:
        ecf = execute_query(
            '''
            SELECT tipo_ecf, fecha_vencimiento FROM ecf_secuencias
            WHERE tenant_id = %s AND activo = 1
              AND fecha_vencimiento IS NOT NULL AND fecha_vencimiento <= %s
            ''',
            (tenant_id, limite),
            fetch='all',
        ) or []
    except Exception:  # Empresas sin módulo e-CF instalado.
        ecf = []
    for fila in ecf:
        vence = fila['fecha_vencimiento']
        avisos.append({
            'nivel': 'danger' if vence < hoy else 'warning',
            'texto': (
                f"La secuencia e-CF E{fila['tipo_ecf']} "
                + ('venció' if vence < hoy else 'vence')
                + f" el {vence.strftime('%d/%m/%Y')}."
            ),
            'endpoint': 'facturacion_ncf',
        })
    return avisos


def resumen_dashboard(tenant_id, desde, hasta, ars_id=None, hoy=None):
    hoy = hoy or date.today()
    facturas, facturado = facturado_en(tenant_id, desde, hasta, ars_id)
    ant_desde, ant_hasta = periodo_anterior(desde, hasta)
    _, facturado_ant = facturado_en(tenant_id, ant_desde, ant_hasta, ars_id)
    cobrado = cobrado_en(tenant_id, desde, hasta, ars_id)
    cobrado_ant = cobrado_en(tenant_id, ant_desde, ant_hasta, ars_id)
    por_cobrar, antiguedad, facturas_abiertas = cuentas_por_cobrar(tenant_id, hoy, ars_id)
    pendiente, servicios_pendientes, pendiente_ars = pendiente_por_facturar(tenant_id, ars_id)
    reclamos, monto_reclamos = reclamaciones_abiertas(tenant_id, ars_id)
    return {
        'facturado': facturado,
        'facturado_variacion': _variacion(facturado, facturado_ant),
        'facturas': facturas,
        'ticket_promedio': (facturado / facturas).quantize(Decimal('0.01')) if facturas else CERO,
        'cobrado': cobrado,
        'cobrado_variacion': _variacion(cobrado, cobrado_ant),
        'tasa_cobro': (
            (cobrado * 100 / facturado).quantize(Decimal('0.1')) if facturado else None
        ),
        'por_cobrar': por_cobrar,
        'facturas_abiertas': facturas_abiertas,
        'antiguedad': antiguedad,
        'pendiente_facturar': pendiente,
        'servicios_pendientes': servicios_pendientes,
        'pendiente_por_ars': pendiente_ars,
        'reclamaciones': reclamos,
        'monto_reclamaciones': monto_reclamos,
        'serie_mensual': serie_mensual(tenant_id, desde, hasta, ars_id),
        'por_ars': por_ars(tenant_id, desde, hasta),
        'alertas': alertas(tenant_id, hoy),
        'periodo_anterior': (ant_desde, ant_hasta),
    }
