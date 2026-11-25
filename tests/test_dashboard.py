"""Indicadores del dashboard de facturación."""

import unittest
from datetime import date
from decimal import Decimal as D
from unittest.mock import patch

import services.dashboard as sd
from routes.billing_dashboard import rango_preset


def _consultas_falsas(registro):
    def fake(sql, params=None, fetch='one'):
        registro.append((sql, params))
        if 'GROUP BY a.id' in sql:
            return [{'ars_id': 3, 'ars': 'ARS Humano', 'facturas': 4,
                     'facturado': D('5100'), 'saldo': D('3100')}]
        if 'GROUP BY mes' in sql:
            return [{'mes': '2026-11', 'monto': D('5100')}]
        if 'COUNT(*) AS facturas' in sql:
            return {'facturas': 4, 'monto': D('5100')}
        if 'HAVING saldo > 0' in sql:
            return [{'fecha_emision': date(2026, 11, 2), 'saldo': D('1000')},
                    {'fecha_emision': date(2026, 7, 1), 'saldo': D('2100')}]
        if 'SUM(pf.monto_aplicado), 0) AS monto' in sql:
            return {'monto': D('2000')}
        if "pp.estado = 'Pendiente'" in sql:
            return [{'ars_id': 3, 'ars': 'ARS Humano', 'servicios': 2,
                     'monto': D('900'), 'desde': date(2026, 11, 10)}]
        if 'reclamaciones' in sql:
            return {'n': 1, 'monto': D('300')}
        if 'FROM ncf' in sql:
            return [{'tipo': 'B01', 'fecha_fin': date(2026, 11, 1)}]
        return []
    return fake


class DashboardTests(unittest.TestCase):
    def _resumen(self):
        consultas = []
        with patch.object(sd, 'execute_query', side_effect=_consultas_falsas(consultas)):
            datos = sd.resumen_dashboard(
                16, date(2026, 11, 1), date(2026, 11, 24), hoy=date(2026, 11, 24),
            )
        return datos, consultas

    def test_indicadores(self):
        d, _ = self._resumen()
        self.assertEqual(d['facturado'], D('5100'))
        self.assertEqual(d['cobrado'], D('2000'))
        self.assertEqual(d['tasa_cobro'], D('39.2'))
        self.assertEqual(d['ticket_promedio'], D('1275.00'))
        self.assertEqual(d['por_cobrar'], D('3100'))
        self.assertEqual(d['antiguedad']['0-30'], D('1000'))
        self.assertEqual(d['antiguedad']['+90'], D('2100'))
        self.assertEqual(d['pendiente_facturar'], D('900'))
        self.assertEqual(d['reclamaciones'], 1)
        self.assertIn('venció', d['alertas'][0]['texto'])

    def test_todas_las_consultas_filtran_por_empresa_y_excluyen_anuladas(self):
        _, consultas = self._resumen()
        for sql, params in consultas:
            self.assertIn('tenant_id = %s', sql)
            self.assertEqual(params[0], 16)
            if 'FROM facturas' in sql:
                self.assertIn("estado <> 'Anulada'", sql)

    def test_periodo_anterior_misma_duracion(self):
        self.assertEqual(
            sd.periodo_anterior(date(2026, 11, 1), date(2026, 11, 30)),
            (date(2026, 10, 2), date(2026, 10, 31)),
        )

    def test_serie_mensual_rellena_meses_sin_datos(self):
        with patch.object(sd, 'execute_query', return_value=[]):
            serie = sd.serie_mensual(1, date(2026, 11, 15), date(2027, 2, 3))
        self.assertEqual([m['mes'] for m in serie], ['2026-11', '2026-12', '2027-01', '2027-02'])

    def test_presets_de_periodo(self):
        hoy = date(2026, 1, 15)
        self.assertEqual(rango_preset('mes', hoy), (date(2026, 1, 1), hoy))
        self.assertEqual(rango_preset('mes_anterior', hoy), (date(2025, 12, 1), date(2025, 12, 31)))
        self.assertEqual(rango_preset('trimestre', hoy), (date(2025, 11, 1), hoy))
        self.assertEqual(rango_preset('anio', hoy), (date(2026, 1, 1), hoy))


if __name__ == '__main__':
    unittest.main()
