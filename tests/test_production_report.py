"""Reporte de producción por médico / por centro."""

import unittest
from datetime import date
from decimal import Decimal
from unittest.mock import patch

import app as app_module
import routes.production_report as report


class ProduccionTests(unittest.TestCase):
    def test_agrupacion_por_defecto_segun_tipo(self):
        self.assertEqual(report.agrupacion_por_defecto('centro_salud'), 'medico')
        self.assertEqual(report.agrupacion_por_defecto('medico'), 'centro')

    def test_rango_por_defecto_es_el_mes_actual(self):
        self.assertEqual(
            report.rango_por_defecto(date(2026, 11, 24)),
            (date(2026, 11, 1), date(2026, 11, 24)),
        )

    def test_consulta_filtra_por_empresa_y_calcula_totales(self):
        filas = [
            {'entidad_id': 1, 'entidad': 'Dra. Ana', 'servicios': 3, 'pacientes': 2,
             'total': Decimal('3000'), 'facturado': Decimal('2000'), 'por_facturar': Decimal('1000')},
            {'entidad_id': None, 'entidad': None, 'servicios': 1, 'pacientes': 1,
             'total': Decimal('1000'), 'facturado': Decimal('0'), 'por_facturar': Decimal('1000')},
        ]
        llamadas = []

        def fake_query(sql, params=None, fetch='one'):
            llamadas.append((sql, params))
            return filas if fetch == 'all' else {'n': 3}

        with patch.object(report, 'execute_query', side_effect=fake_query):
            resultado, totales = report.consultar_produccion(
                12, 'medico', date(2026, 11, 1), date(2026, 11, 30), ars_id=4,
            )

        sql, params = llamadas[0]
        self.assertIn('pp.tenant_id = %s', sql)
        self.assertIn('ent.tenant_id = pp.tenant_id', sql)
        self.assertIn('pp.ars_id = %s', sql)
        self.assertEqual(params, (12, date(2026, 11, 1), date(2026, 11, 30), 4))
        self.assertEqual(resultado[1]['entidad'], 'Sin médico asignado')
        self.assertEqual(resultado[0]['porcentaje'], Decimal('75.0'))
        self.assertEqual(totales['total'], Decimal('4000'))
        self.assertEqual(totales['por_facturar'], Decimal('2000'))
        self.assertEqual(totales['pacientes'], 3)

    def test_csv_incluye_total_y_bom(self):
        resultado = [{'entidad': 'Centro A', 'servicios': 2, 'pacientes': 2,
                      'total': Decimal('10'), 'facturado': Decimal('10'),
                      'por_facturar': Decimal('0'), 'porcentaje': Decimal('100.0')}]
        totales = {'servicios': 2, 'pacientes': 2, 'total': Decimal('10'),
                   'facturado': Decimal('10'), 'por_facturar': Decimal('0')}
        texto = report._csv(resultado, totales, 'Centro')
        self.assertTrue(texto.startswith('\ufeff'))
        self.assertIn('Centro A', texto)
        self.assertIn('TOTAL', texto)

    def test_ruta_registrada_y_protegida(self):
        vista = app_module.app.view_functions['facturacion_reporte_produccion']
        self.assertEqual(getattr(vista, 'required_permission', None), 'reportes.ver')


if __name__ == '__main__':
    unittest.main()
