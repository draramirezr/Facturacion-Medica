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
        self.assertIn("url_for('enviar_contacto')", plantilla)
        self.assertIn('soporte.telefono', plantilla)
        self.assertIn('id="contacto"', plantilla)
        self.assertIn('application/ld+json', plantilla)
        self.assertIn('og:title', plantilla)
        self.assertIn('seo.canonical', plantilla)

    def test_public_seo_files_and_legacy_urls(self):
        import routes.public as public_routes

        with app_module.app.test_request_context('/robots.txt'):
            robots = public_routes.robots_txt()
        with app_module.app.test_request_context('/sitemap.xml'):
            mapa = public_routes.sitemap_xml()
        with app_module.app.test_request_context('/contact'):
            contacto = public_routes.redirects()

        self.assertIn('Disallow: /facturacion', robots.get_data(as_text=True))
        self.assertIn('sitemap.xml', robots.get_data(as_text=True))
        self.assertIn('<loc>', mapa.get_data(as_text=True))
        self.assertEqual(contacto.status_code, 301)
        self.assertTrue(contacto.location.endswith('/#contacto'))

        base = (
            Path(app_module.__file__).resolve().parent
            / 'templates'
            / 'base.html'
        ).read_text(encoding='utf-8')
        self.assertNotIn('draramirez.com', base)
        self.assertIn('noindex, nofollow', base)

    def test_public_contact_requires_message_fields(self):
        import routes.public as public_routes

        with app_module.app.test_request_context(
            '/contacto',
            method='POST',
            data={'nombre': '', 'email': 'invalido', 'mensaje': ''},
        ):
            with patch.object(public_routes, 'flash') as avisos:
                redireccion = public_routes.enviar_contacto()
        self.assertEqual(redireccion.status_code, 302)
        self.assertTrue(redireccion.location.endswith('#contacto'))
        avisos.assert_called()

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

    def test_tenant_admin_cannot_change_subscription_fields(self):
        import routes.admin_companies as companies

        admin = app_module.User(
            4, 'Admin', 'admin@facturacion.com', 'Administrador', tenant_id=5,
        )
        empresa = {
            'id': 5,
            'nombre': 'Clinica',
            'razon_social': 'Clinica SRL',
            'rnc': '00100000001',
            'telefono': '8095550101',
            'email': 'clinica@example.com',
            'direccion': 'Santo Domingo',
            'fecha_inicio': date(2026, 9, 20),
            'fecha_fin': date(2026, 11, 30),
            'licencias_totales': 10,
            'plan': 'profesional',
            'estado': 'activo',
            'tipo_empresa': 'medico',
        }
        captured = {}

        def fake_update(query, params=None):
            captured['params'] = params

        with app_module.app.test_request_context(
            '/admin/empresas/5/editar',
            method='POST',
            data={
                'nombre': 'Clinica',
                'razon_social': 'Clinica SRL',
                'rnc': '00100000001',
                'telefono': '8095550101',
                'email': 'clinica@example.com',
                'direccion': 'Santo Domingo',
                'tipo_empresa': 'medico',
                'fecha_inicio': '2020-01-01',
                'fecha_fin': '2099-12-31',
                'licencias_totales': '999',
                'plan': 'empresarial',
                'estado': 'inactivo',
            },
        ):
            with (
                patch.object(companies, 'current_user', admin),
                patch.object(companies, 'get_current_tenant_id', return_value=5),
                patch.object(companies, 'execute_query', return_value=empresa),
                patch.object(companies, 'execute_update', side_effect=fake_update),
                patch.object(companies, 'flash'),
            ):
                companies.admin_empresas_editar.__wrapped__(5)

        self.assertEqual(captured['params'][6], '2026-09-20')
        self.assertEqual(captured['params'][7], '2026-11-30')
        self.assertEqual(captured['params'][8], 10)
        self.assertEqual(captured['params'][9], 'profesional')
        self.assertEqual(captured['params'][10], 'activo')

        plantilla = (
            Path(app_module.__file__).resolve().parent
            / 'templates'
            / 'admin'
            / 'empresas'
            / 'form.html'
        ).read_text(encoding='utf-8')
        self.assertIn('puede_editar_suscripcion', plantilla)
        self.assertIn('Solo el dueño de ClinicRD', plantilla)


if __name__ == '__main__':
    unittest.main()
