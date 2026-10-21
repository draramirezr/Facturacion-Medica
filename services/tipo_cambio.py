"""Precio fijo en dólares y conversión con la tasa de compra del Banco Central."""

import logging
import re
import threading
from datetime import datetime, timedelta
from decimal import Decimal, ROUND_HALF_UP
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

PLAN_USD = {
    'basico': Decimal('20'),
    'profesional': Decimal('30'),
    'empresarial': Decimal('60'),
}
USUARIO_ADICIONAL_USD = Decimal('7')
DESCUENTO_ANUAL = Decimal('0.85')
_URL_BCRD = 'https://www.bancentral.gov.do/'
_PATRON_COMPRA = re.compile(
    r"Tipo de cambio.*?text-bolder-gb'>(?P<fecha>[^<]+)</span>"
    r".*?<!-- Compra -->.*?<h5>\s*(?P<compra>\d+\.\d+)\s*</h5>",
    re.S,
)
_CACHE_HORAS = 6
_lock = threading.Lock()
_cache = {'compra': None, 'fecha': None, 'obtenido': None}


def _cuantizar(valor):
    return Decimal(valor).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)


def formato_usd(valor):
    cantidad = _cuantizar(valor)
    if cantidad == cantidad.to_integral_value():
        return f'US$ {int(cantidad):,}'
    return f'US$ {cantidad:,.2f}'


def formato_dop(valor):
    return f'RD$ {_cuantizar(valor):,.2f}'


def _leer_bcrd():
    solicitud = Request(_URL_BCRD, headers={'User-Agent': 'ClinicRD/1.0'})
    html = urlopen(solicitud, timeout=8).read().decode('utf-8', 'replace')
    encontrado = _PATRON_COMPRA.search(html)
    if not encontrado:
        raise ValueError('El Banco Central no publicó la tasa de compra')
    compra = Decimal(encontrado.group('compra'))
    if not Decimal('20') <= compra <= Decimal('200'):
        raise ValueError('La tasa de compra está fuera de rango')
    return {
        'compra': compra,
        'fecha': encontrado.group('fecha').strip(),
    }


def _guardar(tasa):
    from core.database import execute_update
    execute_update(
        '''
        CREATE TABLE IF NOT EXISTS tipo_cambio_bcrd (
            id TINYINT NOT NULL PRIMARY KEY,
            fecha_texto VARCHAR(40) NOT NULL,
            compra DECIMAL(10,4) NOT NULL,
            obtenido_en DATETIME NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        '''
    )
    execute_update(
        '''
        INSERT INTO tipo_cambio_bcrd (id, fecha_texto, compra, obtenido_en)
        VALUES (1, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            fecha_texto=VALUES(fecha_texto),
            compra=VALUES(compra),
            obtenido_en=VALUES(obtenido_en)
        ''',
        (tasa['fecha'][:40], str(tasa['compra']), datetime.now()),
    )


def _leer_guardada():
    from core.database import execute_query
    fila = execute_query(
        'SELECT fecha_texto, compra FROM tipo_cambio_bcrd WHERE id=1'
    )
    if not fila or fila.get('compra') is None:
        return None
    return {
        'compra': Decimal(str(fila['compra'])),
        'fecha': fila.get('fecha_texto') or '',
    }


def obtener_tasa_compra():
    """Tasa de compra USD publicada por el Banco Central. Se relee cada 6 horas."""
    ahora = datetime.now()
    with _lock:
        vigente = (
            _cache['compra'] is not None
            and _cache['obtenido'] is not None
            and ahora - _cache['obtenido'] < timedelta(hours=_CACHE_HORAS)
        )
        if vigente:
            return {'compra': _cache['compra'], 'fecha': _cache['fecha']}
    try:
        fresca = _leer_bcrd()
    except Exception:
        logger.warning('No se pudo leer la tasa del Banco Central', exc_info=True)
        fresca = None
    if fresca:
        with _lock:
            _cache['compra'] = fresca['compra']
            _cache['fecha'] = fresca['fecha']
            _cache['obtenido'] = ahora
        try:
            _guardar(fresca)
        except Exception:
            logger.warning('No se guardó la tasa de compra', exc_info=True)
        return fresca
    with _lock:
        if _cache['compra'] is not None:
            return {'compra': _cache['compra'], 'fecha': _cache['fecha']}
    try:
        guardada = _leer_guardada()
    except Exception:
        logger.warning('No se leyó la tasa guardada', exc_info=True)
        guardada = None
    if not guardada:
        return None
    with _lock:
        _cache['compra'] = guardada['compra']
        _cache['fecha'] = guardada['fecha']
        _cache['obtenido'] = ahora
    return guardada


def monto_dop(dolares, tasa=None):
    if tasa is None:
        tasa = obtener_tasa_compra()
    if not tasa:
        return None
    return _cuantizar(Decimal(dolares) * tasa['compra'])


def monto_plan_dop(plan, meses=1, tasa=None):
    if plan not in PLAN_USD:
        return None
    dolares = PLAN_USD[plan]
    if int(meses or 1) >= 12:
        dolares = dolares * DESCUENTO_ANUAL * 12
    return monto_dop(dolares, tasa)


def catalogo_precios(tasa=None):
    """Textos de la página de precios y del cobro, en dólares y en pesos."""
    if tasa is None:
        tasa = obtener_tasa_compra()
    planes = {}
    for clave, dolares in PLAN_USD.items():
        dolares_mes_anual = dolares * DESCUENTO_ANUAL
        dolares_anio = dolares_mes_anual * 12
        pesos_mes = monto_dop(dolares, tasa) if tasa else None
        pesos_mes_anual = monto_dop(dolares_mes_anual, tasa) if tasa else None
        pesos_anio = monto_dop(dolares_anio, tasa) if tasa else None
        planes[clave] = {
            'usd': dolares,
            'dop': pesos_mes,
            'mensual_dop': formato_dop(pesos_mes) if pesos_mes is not None else 'RD$ —',
            'anual_dop': formato_dop(pesos_mes_anual) if pesos_mes_anual is not None else 'RD$ —',
            'detalle_dop': (
                f'{formato_dop(pesos_anio)} facturados anualmente'
                if pesos_anio is not None else 'Tasa no disponible'
            ),
            'mensual_usd': formato_usd(dolares),
            'anual_usd': formato_usd(dolares_mes_anual),
            'detalle_usd': f'{formato_usd(dolares_anio)} facturados anualmente',
        }
    pesos_usuario = monto_dop(USUARIO_ADICIONAL_USD, tasa) if tasa else None
    return {
        'tasa': tasa,
        'compra_texto': f'{tasa["compra"]:.4f}' if tasa else None,
        'planes': planes,
        'usuario_dop': formato_dop(pesos_usuario) if pesos_usuario is not None else 'RD$ —',
        'usuario_usd': formato_usd(USUARIO_ADICIONAL_USD),
    }
