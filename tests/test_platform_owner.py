import unittest
from datetime import date, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import app as app_module
from auth.helpers import usuario_es_dueno_software
from services import platform as platform_service


class PlatformOwnerTests(unittest.TestCase):
    def test_owner_nav_exposes_platform_modules(self):
        plantilla = (
            Path(app_module.__file__).resolve().parent
            / 'templates'
            / 'base.html'
        ).read_text(encoding='utf-8')
        self.assertIn("url_for('plataforma_alertas')", plantilla)
        self.assertIn("url_for('plataforma_facturas')", plantilla)
        self.assertIn("url_for('plataforma_reportes')", plantilla)
        self.assertIn("url_for('plataforma_demos')", plantilla)

    def test_public_home_does_not_show_demo_request_form(self):
        plantilla = (
            Path(app_module.__file__).resolve().parent
            / 'templates'
            / 'inicio.html'
        ).read_text(encoding='utf-8')
        self.assertNotIn("url_for('solicitar_demo')", plantilla)
        self.assertNotIn('Solicita o activa tu prueba', plantilla)

    def test_public_signup_is_seven_day_demo(self):
        source = (
            Path(app_module.__file__).resolve().parent
            / 'auth'
            / 'routes.py'
        ).read_text(encoding='utf-8')
        self.assertIn('timedelta(days=7)', source)
        self.assertNotIn('timedelta(days=30)', source)

    def test_pending_payment_companies_query_groups_by_empresa(self):
        with patch.object(platform_service, 'execute_query', return_value=[
            {'id': 1, 'razon_social': 'Dra. Shirley Ramírez', 'monto_pendiente': 20, 'facturas_pendientes': 1},
        ]) as query:
            filas = platform_service.empresas_pendientes_pago()
        self.assertEqual(filas[0]['razon_social'], 'Dra. Shirley Ramírez')
        self.assertIn("f.estado='pendiente'", query.call_args.args[0])
        self.assertIn('GROUP BY', query.call_args.args[0])

    def test_resumen_separates_paid_and_pending(self):
        filas = [
            {'monto': 40, 'estado': 'pagada'},
            {'monto': 20, 'estado': 'pendiente'},
            {'monto': 100, 'estado': 'anulada'},
        ]
        with patch.object(platform_service, 'listar_facturas_plataforma', return_value=filas):
            _facturas, resumen = platform_service.resumen_facturacion_plataforma()
        self.assertEqual(resumen['pagada'], 40)
        self.assertEqual(resumen['pendiente'], 20)
        self.assertEqual(resumen['anulada'], 100)
        self.assertEqual(resumen['cantidad_pagada'], 1)

    def test_owner_can_enable_seven_day_demo(self):
        hoy = date.today()
        with (
            patch.object(platform_service, 'execute_query', return_value={'id': 9}),
            patch.object(platform_service, 'execute_update') as update,
        ):
            self.assertTrue(platform_service.habilitar_demo_empresa(9))
        self.assertEqual(update.call_args.args[1][1], hoy + timedelta(days=7))

    def test_expired_demo_is_inactivated(self):
        from services import subscriptions as subscriptions_service
        with (
            patch.object(
                subscriptions_service, 'execute_query',
                return_value={'total': 2},
            ),
            patch.object(subscriptions_service, 'execute_update') as update,
        ):
            self.assertEqual(subscriptions_service.inactivar_demos_vencidos(), 2)
        self.assertIn("estado='inactivo'", update.call_args.args[0])
        self.assertIn('es_demo=1', update.call_args.args[0])

    def test_owner_can_upgrade_demo_to_paid_client(self):
        hoy = date.today()
        with (
            patch.object(
                platform_service, 'execute_query',
                return_value={'id': 9, 'licencias_totales': 2},
            ),
            patch.object(platform_service, 'execute_update'),
            patch.object(platform_service, 'crear_factura_plataforma', return_value=44) as factura,
        ):
            resultado = platform_service.dar_de_alta_empresa(9, plan='profesional', meses=1)
        self.assertEqual(resultado['plan'], 'profesional')
        self.assertEqual(resultado['fecha_fin'], hoy + timedelta(days=30))
        self.assertEqual(resultado['factura_id'], 44)
        factura.assert_called_once()

    def test_platform_invoice_pdf_contains_number(self):
        factura = {
            'id': 1,
            'numero': 'FP-2026-0001',
            'fecha': date.today(),
            'empresa_nombre': 'Dra. Shirley Ramírez',
            'empresa_email': 'cliente@example.com',
            'empresa_telefono': '8090000000',
            'plan': 'basico',
            'licencias': 1,
            'periodo_inicio': date.today(),
            'periodo_fin': date.today(),
            'estado': 'pendiente',
            'notas': '',
            'monto': 20,
        }
        pdf = platform_service.generar_pdf_factura_plataforma(factura)
        contenido = pdf.getvalue()
        self.assertTrue(contenido.startswith(b'%PDF'))
        self.assertGreater(len(contenido), 200)

    def test_email_requires_company_address(self):
        ok, detalle = platform_service.enviar_factura_plataforma_por_correo(
            {'numero': 'FP-2026-0001', 'empresa_email': ''},
        )
        self.assertFalse(ok)
        self.assertIn('correo', detalle.lower())

    def test_tenant_admin_is_not_owner(self):
        admin = SimpleNamespace(tenant_id=1, perfil='Administrador')
        owner = SimpleNamespace(tenant_id=None, perfil='Administrador')
        self.assertFalse(usuario_es_dueno_software(admin))
        self.assertTrue(usuario_es_dueno_software(owner))


if __name__ == '__main__':
    unittest.main()
