import unittest
import re
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import app as app_module
import auth.decorators as auth_decorators
import auth.routes as auth_routes
import core.database as database_module
import core.tenant as tenant_module
import routes.admin_companies as company_routes
import routes.billing as billing_routes
import routes.catalogs as catalog_routes
import routes.clinical_history as clinical_history_routes
import routes.patients as patient_routes
import routes.search as search_routes
import routes.support as route_support
import routes.users_roles as user_routes
from rbac_catalog import PERMISOS_ROLES_SISTEMA


@contextmanager
def patch_current_user(user):
    with (
        patch.object(auth_decorators, 'current_user', user),
        patch.object(auth_routes, 'current_user', user),
        patch.object(tenant_module, 'current_user', user),
        patch.object(company_routes, 'current_user', user),
        patch.object(billing_routes, 'current_user', user),
        patch.object(search_routes, 'current_user', user),
        patch.object(user_routes, 'current_user', user),
    ):
        yield


class _FakeCursor:
    def __init__(self, table_names):
        self.table_names = table_names

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def execute(self, query, params):
        self.query = query
        self.params = params

    def fetchall(self):
        return [{'TABLE_NAME': name} for name in self.table_names]


class _FakeConnection:
    def __init__(self, table_names):
        self.table_names = table_names
        self.closed = False

    def cursor(self):
        return _FakeCursor(self.table_names)

    def close(self):
        self.closed = True


class _DatabaseCursor:
    def __init__(self, result=None, fail=False):
        self.result = result
        self.fail = fail
        self.lastrowid = 1

    def execute(self, query, params=()):
        if self.fail:
            raise RuntimeError('forced database error')

    def fetchone(self):
        return self.result

    def fetchall(self):
        return self.result or []

    def close(self):
        pass


class _DatabaseConnection:
    def __init__(self, result=None):
        self.cursor_instance = _DatabaseCursor(result=result)
        self.begin_count = 0
        self.commit_count = 0
        self.rollback_count = 0

    def cursor(self):
        return self.cursor_instance

    def begin(self):
        self.begin_count += 1

    def commit(self):
        self.commit_count += 1

    def rollback(self):
        self.rollback_count += 1


class PhaseZeroSecurityTests(unittest.TestCase):
    def setUp(self):
        self.flask_app = app_module.app
        self.flask_app.config.update(TESTING=True, SECRET_KEY='phase-zero-test')
        self.user = SimpleNamespace(
            id=10,
            perfil='Administrador',
            tenant_id=22,
            is_authenticated=True,
        )

    def test_company_admin_list_keeps_tenant_filter(self):
        queries = []

        def fake_query(query, params=None, fetch='one'):
            queries.append((query, params, fetch))
            return []

        with self.flask_app.test_request_context('/admin/empresas'):
            with (
                patch_current_user(self.user),
                patch.object(company_routes, 'execute_query', side_effect=fake_query),
                patch.object(
                    company_routes,
                    'verificar_suscripciones_vencidas',
                    return_value=0,
                ),
                patch.object(
                    company_routes,
                    'render_template',
                    side_effect=lambda template, **context: context,
                ),
            ):
                company_routes.admin_empresas.__wrapped__()

        self.assertEqual(len(queries), 1)
        self.assertIn('WHERE e.id = %s', queries[0][0])
        self.assertEqual(queries[0][1], (22,))

    def test_user_list_is_scoped_to_current_tenant(self):
        from routes.users_roles import listar_usuarios_del_tenant

        self.assertEqual(listar_usuarios_del_tenant(None), [])
        with patch.object(
            user_routes,
            'execute_query',
            return_value=[{'id': 1, 'nombre': 'Mio'}],
        ) as query:
            filas = listar_usuarios_del_tenant(22)

        self.assertEqual(filas[0]['nombre'], 'Mio')
        sql, params = query.call_args.args[:2]
        self.assertIn('u.tenant_id = %s', sql)
        self.assertNotIn('u.*', sql)
        self.assertEqual(params, (22,))

        with self.flask_app.test_request_context('/admin/usuarios'):
            with (
                patch_current_user(SimpleNamespace(
                    id=10,
                    perfil='Administrador',
                    tenant_id=None,
                    is_authenticated=True,
                )),
                patch.object(user_routes, 'execute_query') as list_query,
            ):
                respuesta = user_routes.admin_usuarios.__wrapped__()

        self.assertEqual(respuesta.status_code, 302)
        list_query.assert_not_called()

    def test_tenant_admin_cannot_see_other_tenants_user_counts(self):
        with self.flask_app.test_request_context('/admin/verificar-multitenant'):
            with (
                patch_current_user(self.user),
                patch.object(company_routes, 'current_user', self.user),
                patch.object(company_routes, 'execute_query') as query,
            ):
                respuesta = company_routes.verificar_multitenant.__wrapped__()

        estado = (
            respuesta[1]
            if isinstance(respuesta, tuple)
            else respuesta.status_code
        )
        self.assertEqual(estado, 403)
        query.assert_not_called()

    def test_dashboard_financial_queries_are_tenant_scoped(self):
        queries = []

        def fake_query(query, params=None, fetch='one'):
            queries.append((query, params, fetch))
            if fetch == 'all':
                return []
            return {'total': 0}

        with self.flask_app.test_request_context('/facturacion/dashboard'):
            with (
                patch_current_user(self.user),
                patch.object(billing_routes, 'execute_query', side_effect=fake_query),
                patch.object(
                    billing_routes,
                    'render_template',
                    side_effect=lambda template, **context: context,
                ),
            ):
                billing_routes.facturacion_dashboard.__wrapped__()

        protected_queries = [
            (query, params)
            for query, params, _fetch in queries
            if (
                'FROM facturas' in query
                or 'FROM pacientes_pendientes' in query
                or 'FROM facturas f' in query
            )
        ]
        self.assertTrue(protected_queries)
        for query, params in protected_queries:
            self.assertIn('tenant_id = %s', query)
            self.assertIn(22, params)

    def test_doctor_dashboard_queries_are_scoped_to_linked_doctor(self):
        queries = []

        def fake_query(query, params=None, fetch='one'):
            queries.append((query, params, fetch))
            return [] if fetch == 'all' else {}

        with (
            patch.object(
                billing_routes,
                'execute_query',
                side_effect=fake_query,
            ),
            patch.object(
                billing_routes,
                'render_template',
                side_effect=lambda template, **context: (template, context),
            ),
        ):
            template, _context = billing_routes._render_dashboard_medico(
                22,
                77,
                '2026-08-01',
                '2026-08-31',
            )

        self.assertEqual(template, 'facturacion/dashboard_medico.html')
        activity_queries = [
            (query, params)
            for query, params, _fetch in queries
            if 'consultas_clinicas' in query
            or 'citas_medicas' in query
            or 'recetas_medicas' in query
            or 'turnos_atencion' in query
        ]
        self.assertTrue(activity_queries)
        for query, params in activity_queries:
            self.assertRegex(
                query,
                r'(?:\w+\.)?tenant_id=%s AND (?:\w+\.)?medico_id=%s',
            )
            self.assertEqual(params[:2], (22, 77))

    def test_user_edit_rejects_record_from_another_tenant(self):
        update = Mock()
        with self.flask_app.test_request_context('/admin/usuarios/99/editar'):
            with (
                patch_current_user(self.user),
                patch.object(user_routes, 'execute_query', return_value=None) as query,
                patch.object(user_routes, 'execute_update', update),
            ):
                response = user_routes.admin_usuarios_editar.__wrapped__(99)

        sql, params = query.call_args.args
        self.assertIn('tenant_id = %s', sql)
        self.assertEqual(params, (99, 22))
        self.assertEqual(response.status_code, 302)
        update.assert_not_called()

    def test_user_update_includes_tenant_in_every_user_query(self):
        stored_user = {
            'id': 99,
            'tenant_id': 22,
            'nombre': 'Usuario',
            'email': 'usuario@example.com',
            'perfil': 'Nivel 2',
            'activo': 1,
        }
        queries = []
        updates = []

        def fake_query(query, params=None, fetch='one'):
            queries.append((query, params))
            return stored_user if len(queries) == 1 else None

        def fake_update(query, params=None):
            updates.append((query, params))
            return 99

        form = {
            'nombre': 'Usuario Actualizado',
            'email': 'actualizado@example.com',
            'perfil': 'Nivel 2',
            'activo': '1',
        }
        with self.flask_app.test_request_context(
            '/admin/usuarios/99/editar',
            method='POST',
            data=form,
        ):
            with (
                patch_current_user(self.user),
                patch.object(user_routes, 'execute_query', side_effect=fake_query),
                patch.object(user_routes, 'execute_update', side_effect=fake_update),
            ):
                response = user_routes.admin_usuarios_editar.__wrapped__(99)

        self.assertEqual(response.status_code, 302)
        for query, params in queries + updates:
            if 'usuarios' in query:
                self.assertIn('tenant_id = %s', query)
                self.assertIn(22, params)

    def test_schema_validation_fails_when_tenant_column_is_missing(self):
        present = app_module.REQUIRED_TENANT_TABLES[:-1]
        connection = _FakeConnection(present)

        with self.assertRaisesRegex(RuntimeError, 'usuarios'):
            app_module.validate_required_tenant_schema(
                lambda **config: connection
            )
        self.assertTrue(connection.closed)

    def test_required_schema_covers_every_tenant_data_table(self):
        expected_tables = {
            'ars',
            'auditoria_historia_clinica',
            'auditoria_licencias_medicas',
            'centros_medicos',
            'citas_medicas',
            'codigo_ars',
            'consultas_clinicas',
            'conversaciones_internas',
            'ecf_configuraciones',
            'ecf_eventos',
            'ecf_outbox',
            'ecf_secuencias',
            'evoluciones_clinicas',
            'factura_detalles',
            'facturas',
            'facturas_ecf',
            'historias_emergencia',
            'hojas_enfermeria',
            'licencias_medicas',
            'medico_centro',
            'medicos',
            'mensajes_internos',
            'ncf',
            'pacientes',
            'pacientes_pendientes',
            'pago_facturas',
            'pagos',
            'receta_medicamentos',
            'recetas_medicas',
            'reclamaciones',
            'roles',
            'rol_permisos',
            'secuencias_turnos',
            'servicios',
            'pantallas_turnos',
            'tipos_licencia_medica',
            'turnos_atencion',
            'turnos_eventos',
            'usuario_medico',
            'usuario_roles',
            'usuarios',
        }
        self.assertEqual(set(app_module.REQUIRED_TENANT_TABLES), expected_tables)
        self.assertTrue(expected_tables.issubset(app_module._ALLOWED_TABLES))

    def test_relational_catalog_access_uses_tenant_whitelist(self):
        with self.flask_app.test_request_context('/'):
            with (
                patch.object(tenant_module, 'current_user', self.user),
                patch.object(
                    tenant_module,
                    'execute_query',
                    return_value={'count': 1},
                ) as query,
            ):
                self.assertTrue(
                    app_module.validate_tenant_access('codigo_ars', 7)
                )
                self.assertTrue(
                    app_module.validate_tenant_access('medico_centro', 8)
                )

        for call in query.call_args_list:
            sql, params = call.args
            self.assertIn('tenant_id = %s', sql)
            self.assertEqual(params[-1], 22)

    def test_medico_centro_new_rejects_cross_tenant_relations(self):
        queries = []
        update = Mock()

        def fake_query(query, params=None, fetch='one'):
            queries.append((query, params))
            if 'FROM medicos' in query:
                return None
            if 'FROM centros_medicos' in query:
                return {'id': 8}
            return None

        handler = catalog_routes.facturacion_medico_centro_nuevo
        while hasattr(handler, '__wrapped__'):
            handler = handler.__wrapped__

        with self.flask_app.test_request_context(
            '/facturacion/medico-centro/nuevo',
            method='POST',
            data={
                'medico_id': '7',
                'centro_medico_id': '8',
            },
        ):
            with (
                patch_current_user(self.user),
                patch.object(
                    catalog_routes,
                    'execute_query',
                    side_effect=fake_query,
                ),
                patch.object(catalog_routes, 'execute_update', update),
            ):
                response = handler()

        self.assertEqual(response.status_code, 302)
        self.assertEqual(len(queries), 2)
        for sql, params in queries:
            self.assertIn('tenant_id = %s', sql)
            self.assertEqual(params[-1], 22)
        update.assert_not_called()

    def test_pending_patient_delete_never_falls_back_without_tenant(self):
        updates = Mock()
        with self.flask_app.test_request_context(
            '/facturacion/pacientes-pendientes/91/eliminar',
            method='POST',
        ):
            with (
                patch_current_user(self.user),
                patch.object(
                    patient_routes,
                    'execute_query',
                    return_value={'id': 91},
                ) as query,
                patch.object(patient_routes, 'execute_update', updates),
            ):
                response = (
                    patient_routes.facturacion_pacientes_pendientes_eliminar
                    .__wrapped__(91)
                )

        self.assertEqual(response.status_code, 302)
        self.assertIn('tenant_id = %s', query.call_args.args[0])
        self.assertEqual(query.call_args.args[1], (91, 22))
        self.assertIn('tenant_id = %s', updates.call_args.args[0])
        self.assertEqual(updates.call_args.args[1], (91, 22))

    def test_pending_patient_get_is_tenant_scoped(self):
        stored_patient = {
            'id': 91,
            'nombre_paciente': 'Paciente',
            'fecha_servicio': '2026-09-12',
            'monto_estimado': 0,
        }
        with self.flask_app.test_request_context(
            '/api/facturacion/pacientes-pendientes/91'
        ):
            with (
                patch_current_user(self.user),
                patch.object(
                    patient_routes,
                    'execute_query',
                    return_value=stored_patient,
                ) as query,
            ):
                response = (
                    patient_routes.api_facturacion_pacientes_pendientes_get
                    .__wrapped__(91)
                )

        self.assertEqual(response.status_code, 200)
        sql, params = query.call_args.args
        self.assertIn('pp.tenant_id = %s', sql)
        self.assertIn('a.tenant_id = pp.tenant_id', sql)
        self.assertIn('m.tenant_id = pp.tenant_id', sql)
        self.assertEqual(params, (91, 22))

    def test_pending_patient_update_rejects_another_tenant(self):
        update = Mock()
        payload = {
            'nombre_paciente': 'Paciente',
            'fecha_servicio': '2026-09-12',
            'servicio': 'Consulta',
        }
        with self.flask_app.test_request_context(
            '/api/facturacion/pacientes-pendientes/91',
            method='PUT',
            json=payload,
        ):
            with (
                patch_current_user(self.user),
                patch.object(
                    patient_routes,
                    'execute_query',
                    return_value=None,
                ) as query,
                patch.object(patient_routes, 'execute_update', update),
            ):
                response, status = (
                    patient_routes.api_facturacion_pacientes_pendientes_update
                    .__wrapped__(91)
                )

        self.assertEqual(status, 404)
        self.assertIn('tenant_id = %s', query.call_args.args[0])
        self.assertEqual(query.call_args.args[1], (91, 22))
        update.assert_not_called()

    def test_runtime_code_has_no_tenant_column_fallbacks(self):
        source = Path(billing_routes.__file__).read_text(encoding='utf-8')
        self.assertNotIn('tiene_tenant_id', source)
        self.assertNotIn('OR tenant_id IS NULL', source)
        self.assertNotIn('def add_tenant_filter(', source)
        self.assertNotIn('def execute_query_tenant(', source)
        self.assertNotIn('def execute_update_tenant(', source)
        normalized = ' '.join(source.split())
        self.assertRegex(
            normalized,
            r'INSERT INTO pago_facturas\s*'
            r'\(pago_id, factura_id, monto_aplicado, tenant_id\)',
        )

    def test_pdf_download_rejects_invoice_outside_tenant(self):
        generator = Mock()
        handler = billing_routes.facturacion_descargar_pdf
        while hasattr(handler, '__wrapped__'):
            handler = handler.__wrapped__

        with self.flask_app.test_request_context(
            '/facturacion/facturas/91/pdf'
        ):
            with (
                patch_current_user(self.user),
                patch.object(
                    auth_decorators,
                    'user_has_permission',
                    return_value=True,
                ),
                patch.object(billing_routes, 'REPORTLAB_AVAILABLE', True),
                patch.object(
                    tenant_module,
                    'execute_query',
                    return_value=None,
                ) as query,
                patch.object(
                    billing_routes,
                    'generar_pdf_factura_vista_previa',
                    generator,
                ),
            ):
                response = handler(91)

        self.assertEqual(response.status_code, 302)
        sql, params = query.call_args.args
        self.assertIn('tenant_id = %s', sql)
        self.assertEqual(params, (91, 22))
        generator.assert_not_called()

    def test_base_schema_defines_tenant_scope_for_core_tables(self):
        schema = (
            Path(app_module.__file__).resolve().parent
            / 'database_schema.sql'
        ).read_text(encoding='utf-8')
        core_tables = {
            'usuarios',
            'ars',
            'centros_medicos',
            'medicos',
            'medico_centro',
            'codigo_ars',
            'servicios',
            'ncf',
            'pacientes',
            'pacientes_pendientes',
            'facturas',
            'factura_detalles',
            'pagos',
        }
        for table in core_tables:
            with self.subTest(table=table):
                match = re.search(
                    rf'CREATE TABLE IF NOT EXISTS {table}\s*\((.*?)\)'
                    r'\s*ENGINE=',
                    schema,
                    re.DOTALL,
                )
                self.assertIsNotNone(match)
                self.assertRegex(match.group(1), r'\btenant_id\s+INT\b')

    def test_login_template_contains_no_fixed_credentials(self):
        template = (
            Path(app_module.__file__).resolve().parent
            / 'templates'
            / 'login.html'
        ).read_text(encoding='utf-8')

        self.assertNotIn('admin@facturacion.com', template)
        self.assertNotIn('Entrar2026!', template)

    def test_safe_return_url_rejects_login_and_keeps_app_page(self):
        with self.flask_app.test_request_context(
            '/mi-cuenta/cambiar-password',
            query_string={'volver': '/login'},
        ):
            self.assertEqual(
                auth_routes.url_retorno_segura(),
                '/facturacion',
            )

        with self.flask_app.test_request_context(
            '/mi-cuenta/cambiar-password',
            query_string={'volver': '/facturacion/historia-clinica'},
        ):
            self.assertEqual(
                auth_routes.url_retorno_segura(),
                '/facturacion/historia-clinica',
            )

    def test_change_password_template_returns_to_previous_page(self):
        template = (
            Path(app_module.__file__).resolve().parent
            / 'templates'
            / 'cambiar_mi_password.html'
        ).read_text(encoding='utf-8')

        self.assertIn('href="{{ volver_url }}"', template)
        self.assertNotIn("url_for('facturacion_menu')", template)

    def test_dark_mode_stylesheets_use_theme_tokens(self):
        static_css = Path(app_module.__file__).resolve().parent / 'static' / 'css'
        dark_mode = (static_css / 'dark-mode.css').read_text(encoding='utf-8')
        public_theme = (static_css / 'public-theme.css').read_text(encoding='utf-8')
        layout = (static_css / 'layout-design.css').read_text(encoding='utf-8')

        self.assertIn('--ars-shell-surface', dark_mode)
        self.assertIn(':not(i):not(.fa):not(.fas)', dark_mode)
        self.assertIn('.btn [class*="fa-"]', dark_mode)
        self.assertIn('html[data-color-mode="dark"]', public_theme)
        self.assertIn('var(--ars-shell-surface', layout)
        self.assertNotIn('.card {\n    background-color: white !important;', layout)

    def test_typography_preference_uses_data_font_tokens(self):
        root = Path(app_module.__file__).resolve().parent
        typography = (root / 'static' / 'css' / 'typography.css').read_text(encoding='utf-8')
        shell = (root / 'static' / 'css' / 'app-shell.css').read_text(encoding='utf-8')
        base = (root / 'templates' / 'base.html').read_text(encoding='utf-8')

        self.assertIn('html[data-font="manrope"]', typography)
        self.assertIn('html[data-font] body.ars-app-body', typography)
        self.assertIn('var(--font-body', shell)
        self.assertIn('fonts.googleapis.com/css2', base)
        self.assertIn('data-font="{{ fuente_nombre|default(\'arsflow\') }}"', base)

    def test_spellcheck_uses_browser_language_on_text_fields(self):
        root = Path(app_module.__file__).resolve().parent
        script = (root / 'static' / 'js' / 'spellcheck-ui.js').read_text(encoding='utf-8')
        base = (root / 'templates' / 'base.html').read_text(encoding='utf-8')

        self.assertIn("setAttribute('spellcheck'", script)
        self.assertIn("setAttribute('lang'", script)
        self.assertIn('spellcheck-ui.js', base)
        self.assertIn("idioma_correccion == 'none'", base)

    def test_theme_context_includes_support_center(self):
        import core.presentation as presentation

        with self.flask_app.test_request_context('/facturacion'):
            contexto = presentation.inject_theme()

        self.assertIn('email', contexto['soporte'])
        self.assertIn('manual_url', contexto['soporte'])

        base = (
            Path(app_module.__file__).resolve().parent
            / 'templates'
            / 'base.html'
        ).read_text(encoding='utf-8')
        self.assertIn("url_for('centro_ayuda')", base)
        self.assertIn('Manual de usuario en línea', base)
        self.assertNotIn("mailto:' ~ centro_ayuda.email", base)

    def test_help_center_opens_manual_or_placeholder(self):
        import routes.public as public_routes

        usuario = SimpleNamespace(
            is_authenticated=True,
            is_active=True,
            is_anonymous=False,
            get_id=lambda: '1',
        )
        with self.flask_app.test_request_context('/ayuda'):
            with patch('flask_login.utils._get_user', return_value=usuario):
                with patch.object(
                    public_routes,
                    'obtener_soporte',
                    return_value={'manual_url': '', 'email': 'soporte@arsflow.com'},
                ), patch.object(
                    public_routes,
                    'render_template',
                    return_value='Manual de usuario',
                ) as render:
                    pagina = public_routes.centro_ayuda()
                with patch.object(
                    public_routes,
                    'obtener_soporte',
                    return_value={
                        'manual_url': 'https://manual.arsflow.com',
                        'email': 'soporte@arsflow.com',
                    },
                ):
                    redireccion = public_routes.centro_ayuda()

        render.assert_called_once_with('ayuda.html')
        self.assertEqual(pagina, 'Manual de usuario')
        self.assertEqual(redireccion.status_code, 302)
        self.assertEqual(redireccion.location, 'https://manual.arsflow.com')

    def test_owner_is_redirected_away_from_clinic_manual(self):
        import routes.public as public_routes

        dueno = SimpleNamespace(
            is_authenticated=True,
            is_active=True,
            is_anonymous=False,
            tenant_id=None,
            perfil='Administrador',
            get_id=lambda: '1',
        )
        with self.flask_app.test_request_context('/ayuda'):
            with patch('flask_login.utils._get_user', return_value=dueno):
                with patch.object(
                    public_routes,
                    'usuario_es_dueno_software',
                    return_value=True,
                ):
                    redireccion = public_routes.centro_ayuda()

        self.assertEqual(redireccion.status_code, 302)
        self.assertTrue(redireccion.location.endswith('/admin/empresas'))

    def test_clinic_manual_covers_daily_work_not_platform(self):
        ayuda = (
            Path(app_module.__file__).resolve().parent
            / 'templates'
            / 'ayuda.html'
        ).read_text(encoding='utf-8')
        self.assertIn('Manual de ClinicRD', ayuda)
        self.assertIn('Generar factura', ayuda)
        self.assertIn('e-CF', ayuda)
        self.assertIn('Reclamaciones', ayuda)
        self.assertNotIn('El manual en línea se publicará aquí', ayuda)
        self.assertNotIn('plataforma_alertas', ayuda)
        self.assertNotIn('Dar de alta', ayuda)
        self.assertNotIn('Dueño de ClinicRD', ayuda)

    def test_production_entrypoint_binds_waitress_on_all_interfaces(self):
        fuente = (
            Path(app_module.__file__).resolve().parent / 'app.py'
        ).read_text(encoding='utf-8')
        self.assertIn("from waitress import serve", fuente)
        self.assertIn("host='0.0.0.0'", fuente)
        self.assertNotIn(
            'No uses el servidor de desarrollo en producción',
            fuente,
        )

    def test_public_base_url_falls_back_to_railway_domain(self):
        import core.config as config

        with patch.dict(
            'os.environ',
            {'APP_BASE_URL': '', 'RAILWAY_PUBLIC_DOMAIN': 'www.clinicrd.com'},
            clear=False,
        ):
            self.assertEqual(config.url_publica_base(), 'https://www.clinicrd.com')

    def test_theme_context_includes_health_center_name(self):
        import core.presentation as presentation

        usuario = SimpleNamespace(
            is_authenticated=True,
            tenant_id=7,
            empresa_nombre='Fallback',
        )
        with (
            patch.object(presentation, 'current_user', usuario),
            patch(
                'services.subscriptions.get_empresa_info',
                return_value={
                    'nombre': 'Centro Médico del Este',
                    'tipo_empresa': 'centro_salud',
                },
            ),
            self.flask_app.test_request_context('/facturacion/dashboard'),
        ):
            contexto = presentation.inject_theme()

        self.assertEqual(
            contexto['empresa']['empresa_nombre'],
            'Centro Médico del Este',
        )
        self.assertEqual(contexto['empresa']['tipo_empresa'], 'centro_salud')

    def test_claims_list_is_invoice_scoped(self):
        lista = (
            Path(app_module.__file__).resolve().parent
            / 'templates'
            / 'facturacion'
            / 'reclamaciones.html'
        ).read_text(encoding='utf-8')
        formulario = (
            Path(app_module.__file__).resolve().parent
            / 'templates'
            / 'facturacion'
            / 'reclamacion_form.html'
        ).read_text(encoding='utf-8')

        self.assertNotIn('nombre_paciente', lista)
        self.assertNotIn('>Paciente</th>', lista)
        self.assertIn('Observación', lista)
        self.assertIn("url_for('facturacion_reclamacion_detalle'", lista)
        self.assertIn("url_for('facturacion_reclamacion_editar'", lista)
        self.assertNotIn('nombre_paciente', formulario)
        self.assertNotIn('data-paciente', formulario)

    def test_payments_list_has_view_and_edit_actions(self):
        lista = (
            Path(app_module.__file__).resolve().parent
            / 'templates'
            / 'facturacion'
            / 'pagos.html'
        ).read_text(encoding='utf-8')

        self.assertNotIn('href="#"', lista)
        self.assertIn("url_for('facturacion_pago_detalle'", lista)
        self.assertIn("url_for('facturacion_pago_editar'", lista)

    def test_historico_covers_clinical_and_billing_sections(self):
        import routes.reports as reports_module

        plantilla = (
            Path(app_module.__file__).resolve().parent
            / 'templates'
            / 'facturacion'
            / 'historico.html'
        ).read_text(encoding='utf-8')
        ids = {seccion['id'] for seccion in reports_module.SECCIONES_HISTORICO}

        self.assertTrue(
            {'facturas', 'consultas', 'emergencias', 'licencias', 'citas'}.issubset(ids)
        )
        self.assertIn('name="tipo"', plantilla)
        self.assertIn('historico-tab', plantilla)
        self.assertIn('filtros_visibles', plantilla)

        with self.flask_app.test_request_context('/facturacion/historico'):
            with patch.object(
                reports_module,
                'execute_paginated_query',
                return_value=([], {'total': 0}),
            ) as consulta:
                reports_module._consultar_facturas(22, {
                    'ars_id': 4,
                    'medico_id': 8,
                    'ncf': 'B01',
                    'estado': 'Pendiente',
                    'fecha_desde': '2026-01-01',
                    'fecha_hasta': '2026-01-31',
                    'buscar': '',
                    'numero': '',
                    'metodo_pago': '',
                })

        sql, params = consulta.call_args.args[:2]
        self.assertIn('f.ars_id=%s', sql)
        self.assertIn('f.medico_id=%s', sql)
        self.assertIn('f.ncf LIKE %s', sql)
        self.assertIn('f.fecha_emision >= %s', sql)
        self.assertEqual(params[1], 4)

    def test_payment_form_requires_ars_before_invoices(self):
        formulario = (
            Path(app_module.__file__).resolve().parent
            / 'templates'
            / 'facturacion'
            / 'pago_form.html'
        ).read_text(encoding='utf-8')

        self.assertIn('ARS que realizó el pago', formulario)
        self.assertIn('name="ars_id"', formulario)
        self.assertIn('name="numero"', formulario)
        self.assertIn('5 facturas más antiguas', formulario)
        self.assertIn("url_for('facturacion_pagos_nuevo')", formulario)

    def test_available_payment_invoices_stay_empty_without_ars(self):
        from routes.billing import _facturas_disponibles_pago

        with patch.object(billing_routes, 'execute_query') as query:
            resultado = _facturas_disponibles_pago(22)

        query.assert_not_called()
        self.assertEqual(resultado, [])

    def test_available_payment_invoices_limit_oldest_unpaid(self):
        from routes.billing import FACTURAS_ANTIGUAS_PAGO, _facturas_disponibles_pago

        with patch.object(
            billing_routes,
            'execute_query',
            return_value=[{'id': 1, 'numero_factura': 'FAC-1'}],
        ) as query:
            resultado = _facturas_disponibles_pago(22, ars_id=9)

        self.assertEqual(len(resultado), 1)
        sql, params = query.call_args.args[:2]
        self.assertIn('f.ars_id = %s', sql)
        self.assertIn('f.fecha_emision ASC', sql)
        self.assertEqual(params[-1], FACTURAS_ANTIGUAS_PAGO)
        self.assertEqual(FACTURAS_ANTIGUAS_PAGO, 5)

    def test_calendar_day_opens_new_appointment(self):
        from routes.appointments import fecha_prellenada_agenda

        agenda = (
            Path(app_module.__file__).resolve().parent
            / 'templates'
            / 'facturacion'
            / 'citas.html'
        ).read_text(encoding='utf-8')

        self.assertEqual(fecha_prellenada_agenda('2026-09-20'), '2026-09-20')
        self.assertEqual(fecha_prellenada_agenda('20/09/2026'), '')
        self.assertIn('calendar-day-hit', agenda)
        self.assertIn("url_for('facturacion_citas_nueva'", agenda)
        self.assertIn('fecha=dia.isoformat()', agenda)

    def test_dashboard_shows_health_center_name(self):
        dashboard = (
            Path(app_module.__file__).resolve().parent
            / 'templates'
            / 'facturacion'
            / 'dashboard.html'
        ).read_text(encoding='utf-8')
        medico = (
            Path(app_module.__file__).resolve().parent
            / 'templates'
            / 'facturacion'
            / 'dashboard_medico.html'
        ).read_text(encoding='utf-8')

        self.assertIn('dashboard-center', dashboard)
        self.assertIn('Centro de salud', dashboard)
        self.assertIn('empresa.empresa_nombre', dashboard)
        self.assertIn('Centro de salud', medico)
        self.assertIn('empresa.empresa_nombre', medico)

    def test_csrf_rejects_unsafe_request_without_token(self):
        client = self.flask_app.test_client()
        response = client.put(
            '/api/facturacion/pacientes-pendientes/1',
            json={'nombre': 'Intento sin token'},
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn('seguridad', response.get_json()['mensaje'])

    def test_csrf_accepts_token_rendered_by_login(self):
        client = self.flask_app.test_client()
        page = client.get('/login')
        match = re.search(
            rb'<meta name="csrf-token" content="([^"]+)">',
            page.data,
        )
        self.assertIsNotNone(match)

        app_module.request_counts.clear()
        with patch.object(
            auth_routes,
            'verificar_suscripciones_vencidas',
            return_value=0,
        ):
            response = client.post(
                '/login',
                data={
                    'csrf_token': match.group(1).decode('utf-8'),
                    'email': '',
                    'password': '',
                },
            )

        self.assertEqual(response.status_code, 302)

    def test_clinical_role_rejects_billing_only_profile(self):
        billing_user = SimpleNamespace(
            id=30,
            perfil='Registro de Facturas',
            tenant_id=22,
            is_authenticated=True,
            get_id=lambda: '30',
        )
        protected = app_module.roles_required(
            'Administrador',
            'Nivel 2',
        )(lambda: 'allowed')

        with self.flask_app.test_request_context('/facturacion/historia-clinica'):
            with patch.object(auth_decorators, 'current_user', billing_user):
                response = protected()

        self.assertEqual(response.status_code, 302)

    def test_billing_role_uses_rbac_for_financial_routes(self):
        billing_user = app_module.User(
            30,
            'Facturación',
            'facturacion@example.test',
            'Registro de Facturas',
            tenant_id=22,
            permissions=PERMISOS_ROLES_SISTEMA['Registro de Facturas'],
            rbac_roles={'Registro de Facturas'},
            rbac_role_count=1,
        )
        endpoints = {
            'facturacion_reclamaciones': True,
            'facturacion_reclamaciones_nueva': True,
            'facturacion_reclamacion_editar': True,
            'facturacion_pagos': True,
            'facturacion_pagos_nuevo': True,
            'facturacion_pago_editar': True,
            'facturacion_pacientes_exportar_excel': True,
            'facturacion_historico': True,
            'facturacion_ver_xml_ecf': True,
            'facturacion_qr_ecf': True,
            'facturacion_representacion_impresa_ecf': True,
            'facturacion_editar_factura': True,
            'facturacion_enviar_email': True,
            'facturacion_pacientes_eliminar': False,
            'admin_usuarios_eliminar': False,
        }

        for endpoint, expected in endpoints.items():
            with self.subTest(endpoint=endpoint):
                view = self.flask_app.view_functions[endpoint]
                permission = getattr(view, 'required_permission', None)
                self.assertIsNotNone(permission)
                self.assertEqual(
                    app_module.user_has_permission(billing_user, permission),
                    expected,
                )

    def test_billing_global_search_does_not_query_clinical_tables(self):
        billing_user = SimpleNamespace(
            id=30,
            perfil='Registro de Facturas',
            tenant_id=22,
            is_authenticated=True,
            get_id=lambda: '30',
        )
        queries = []

        def fake_query(query, params=None, fetch='one'):
            queries.append(query)
            return []

        with self.flask_app.test_request_context('/api/busqueda-global?q=ana'):
            with (
                patch_current_user(billing_user),
                patch.object(search_routes, 'execute_query', side_effect=fake_query),
            ):
                response = search_routes.api_busqueda_global.__wrapped__()

        self.assertEqual(response.status_code, 200)
        combined = ' '.join(queries)
        self.assertIn('FROM pacientes', combined)
        self.assertIn('FROM facturas', combined)
        self.assertNotIn('consultas_clinicas', combined)
        self.assertNotIn('licencias_medicas', combined)
        self.assertNotIn('recetas_medicas', combined)

    def test_patient_picker_search_is_tenant_scoped_and_limited(self):
        captured = {}

        def fake_query(query, params=None, fetch='one'):
            captured.update(query=query, params=params, fetch=fetch)
            return [{
                'id': 8,
                'nombre': 'Ana Pérez',
                'cedula': '00112345678',
                'nss': '123',
                'telefono': '8095550101',
                'fecha_nacimiento': None,
                'sexo': 'F',
                'direccion': '',
                'ars_nombre': 'ARS Demo',
                'nombre_pariente': '',
                'telefono_pariente': '',
            }]

        with self.flask_app.test_request_context(
            '/api/pacientes/buscar?q=ana'
        ):
            with (
                patch.object(
                    search_routes, 'get_current_tenant_id', return_value=22
                ),
                patch.object(
                    search_routes, 'execute_query', side_effect=fake_query
                ),
            ):
                response = (
                    search_routes.api_buscar_pacientes
                    .__wrapped__.__wrapped__()
                )

        self.assertEqual(response.status_code, 200)
        self.assertIn('p.tenant_id=%s', captured['query'])
        self.assertIn('LIMIT 10', captured['query'])
        self.assertEqual(captured['params'][0], 22)
        self.assertEqual(response.get_json()['resultados'][0]['id'], 8)

    def test_patient_picker_lookup_by_id_is_tenant_scoped(self):
        captured = {}

        def fake_query(query, params=None, fetch='one'):
            captured.update(query=query, params=params, fetch=fetch)
            return []

        with self.flask_app.test_request_context(
            '/api/pacientes/buscar?id=91'
        ):
            with (
                patch.object(
                    search_routes, 'get_current_tenant_id', return_value=22
                ),
                patch.object(
                    search_routes, 'execute_query', side_effect=fake_query
                ),
            ):
                (
                    search_routes.api_buscar_pacientes
                    .__wrapped__.__wrapped__()
                )

        self.assertIn('p.id=%s', captured['query'])
        self.assertEqual(captured['params'], (22, 91))

    def test_doctor_can_see_full_patient_360_clinical_details(self):
        queries = []

        def fake_query(query, params=None, fetch='one'):
            queries.append(query)
            if 'SELECT p.*' in query:
                return {'id': 3, 'nombre': 'Paciente', 'fecha_nacimiento': None}
            if 'FROM consultas_clinicas c' in query:
                return [{
                    'id': 10, 'medico_id': 8, 'fecha': '2026-01-01',
                    'motivo_consulta': 'Dato reservado',
                    'diagnostico_principal': 'Dato reservado',
                    'plan_tratamiento': '{}',
                    'nota_evolucion_inicial': 'Dato reservado',
                    'proxima_cita': None, 'medico_nombre': 'Dra. Externa',
                }]
            if 'FROM licencias_medicas l' in query:
                return [{
                    'id': 20, 'medico_id': 8,
                    'medico_nombre': 'Dra. Externa',
                    'diagnostico': 'Dato reservado',
                    'fecha_inicio': '2026-01-01',
                    'fecha_termino': '2026-01-02',
                    'cantidad_dias': 2, 'codigo': 'L-20',
                }]
            if 'FROM historias_emergencia' in query:
                return [{
                    'id': 30, 'medico_id': 8,
                    'medico_nombre': 'Dra. Externa',
                    'motivo_emergencia': 'Dato reservado',
                    'diagnostico_impresion': 'Dato reservado',
                    'estatus_paciente': 'Estable',
                }]
            if 'FROM pacientes_pendientes pp' in query:
                return []
            if 'FROM citas_medicas c' in query:
                return []
            if 'FROM recetas_medicas r' in query:
                return [{
                    'id': 40, 'medico_id': 8,
                    'medico_nombre': 'Dra. Externa',
                    'codigo': 'R-40', 'diagnostico': 'Dato reservado',
                }]
            return []

        with self.flask_app.test_request_context(
            '/facturacion/historia-clinica/paciente/3'
        ):
            with (
                patch.object(
                    clinical_history_routes,
                    'get_current_tenant_id',
                    return_value=22,
                ),
                patch.object(
                    clinical_history_routes,
                    'medico_id_historias_restringido',
                    return_value=7,
                ),
                patch.object(
                    clinical_history_routes,
                    'execute_query',
                    side_effect=fake_query,
                ),
                patch.object(
                    clinical_history_routes,
                    'actualizar_licencias_vencidas',
                ),
                patch.object(
                    clinical_history_routes,
                    'actualizar_citas_vencidas',
                ),
                patch.object(
                    clinical_history_routes,
                    'render_template',
                    side_effect=lambda _template, **context: context,
                ),
            ):
                context = (
                    clinical_history_routes
                    .facturacion_historia_clinica_expediente
                    .__wrapped__.__wrapped__(3)
                )

        self.assertTrue(context['vista_restringida'])
        self.assertEqual(context['resumen']['consultas_clinicas'], 1)
        self.assertEqual(context['resumen']['recetas'], 1)
        self.assertEqual(context['consultas'][0]['diagnostico_principal'], 'Dato reservado')
        self.assertEqual(context['recetas'][0]['diagnostico'], 'Dato reservado')
        self.assertEqual(context['licencias'][0]['diagnostico'], 'Dato reservado')
        self.assertEqual(
            context['actividad_por_medico'][0]['medico_nombre'],
            'Dra. Externa',
        )
        self.assertFalse(any('(%s IS NULL OR' in query for query in queries))

    def test_select_does_not_commit(self):
        connection = _DatabaseConnection(result={'value': 1})
        with self.flask_app.app_context():
            with patch.object(
                database_module,
                'get_db_connection',
                return_value=connection,
            ):
                result = app_module.execute_query('SELECT 1 AS value')

        self.assertEqual(result, {'value': 1})
        self.assertEqual(connection.commit_count, 0)

    def test_database_transaction_commits_once(self):
        connection = _DatabaseConnection()
        with self.flask_app.app_context():
            with patch.object(
                database_module,
                'get_db_connection',
                return_value=connection,
            ):
                with app_module.database_transaction():
                    pass

        self.assertEqual(connection.begin_count, 1)
        self.assertEqual(connection.commit_count, 1)
        self.assertEqual(connection.rollback_count, 0)

    def test_database_transaction_rolls_back_on_error(self):
        connection = _DatabaseConnection()
        with self.flask_app.app_context():
            with patch.object(
                database_module,
                'get_db_connection',
                return_value=connection,
            ):
                with self.assertRaisesRegex(RuntimeError, 'forced'):
                    with app_module.database_transaction():
                        raise RuntimeError('forced')

        self.assertEqual(connection.commit_count, 0)
        self.assertEqual(connection.rollback_count, 1)

    def test_transactional_post_rolls_back_complete_workflow(self):
        connection = _DatabaseConnection()

        @app_module.transactional_methods('POST')
        def workflow():
            app_module.execute_update('INSERT INTO documento VALUES (1)')
            raise RuntimeError('forced workflow failure')

        with self.flask_app.test_request_context('/workflow', method='POST'):
            with patch.object(
                database_module,
                'get_db_connection',
                return_value=connection,
            ):
                with self.assertRaisesRegex(RuntimeError, 'forced workflow'):
                    workflow()

        self.assertEqual(connection.begin_count, 1)
        self.assertEqual(connection.commit_count, 0)
        self.assertEqual(connection.rollback_count, 1)

    def test_multiwrite_clinical_workflows_are_transactional(self):
        endpoint_names = (
            'facturacion_historia_clinica_nueva',
            'facturacion_historia_clinica_editar',
            'facturacion_recetas_medicas_nueva',
            'facturacion_licencias_medicas_nueva',
            'facturacion_licencia_medica_editar',
            'facturacion_licencia_medica_anular',
            'facturacion_medico_centro_nuevo',
            'facturacion_medico_centro_editar',
        )

        for endpoint_name in endpoint_names:
            with self.subTest(endpoint=endpoint_name):
                wrapped = self.flask_app.view_functions[endpoint_name]
                while wrapped and not hasattr(wrapped, 'transactional_methods'):
                    wrapped = getattr(wrapped, '__wrapped__', None)
                self.assertIsNotNone(wrapped)
                self.assertEqual(
                    wrapped.transactional_methods,
                    frozenset({'POST'}),
                )

    def test_paginated_query_preserves_filters(self):
        calls = []

        def fake_query(query, params=None, fetch='one'):
            calls.append((query, params, fetch))
            if 'COUNT(*)' in query:
                return {'total': 61}
            return [{'id': 26}]

        with self.flask_app.test_request_context(
            '/facturacion/pacientes?search=ana&page=2&per_page=25'
        ):
            with patch.object(
                route_support,
                'execute_query',
                side_effect=fake_query,
            ):
                rows, pagination = route_support.execute_paginated_query(
                    'SELECT id FROM pacientes WHERE tenant_id=%s',
                    (22,),
                    'id',
                )

        self.assertEqual(rows, [{'id': 26}])
        self.assertEqual(calls[1][1], (22, 25, 25))
        self.assertEqual(pagination['total_pages'], 3)
        self.assertIn('search=ana', pagination['next_url'])


if __name__ == '__main__':
    unittest.main()
