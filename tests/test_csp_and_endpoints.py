import re
import unittest
from contextlib import contextmanager, nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import app as app_module
import auth.decorators as auth_decorators
import auth.routes as auth_routes
import core.tenant as tenant_module
import routes.billing as billing_routes


@contextmanager
def patch_current_user(user):
    with (
        patch.object(auth_decorators, 'current_user', user),
        patch.object(auth_routes, 'current_user', user),
        patch.object(tenant_module, 'current_user', user),
    ):
        yield


URL_FOR_PATTERN = re.compile(r"""url_for\(\s*['"]([^'"]+)['"]""")
INLINE_EVENT_PATTERN = re.compile(
    r'\son[a-z]+\s*=',
    re.IGNORECASE,
)
SCRIPT_TAG_PATTERN = re.compile(r'<script\b([^>]*)>', re.IGNORECASE)
STYLE_TAG_PATTERN = re.compile(r'<style\b([^>]*)>', re.IGNORECASE)
STYLE_ATTRIBUTE_PATTERN = re.compile(r'\sstyle\s*=', re.IGNORECASE)
STYLE_MUTATION_PATTERN = re.compile(
    r'style\.cssText|setAttribute\(\s*["\']style',
)
JAVASCRIPT_URL_PATTERN = re.compile(
    r'(?:href|src)\s*=\s*["\']javascript:',
    re.IGNORECASE,
)


class CSPAndEndpointTests(unittest.TestCase):
    def setUp(self):
        self.flask_app = app_module.app
        self.flask_app.config.update(TESTING=True)
        self.client = self.flask_app.test_client()

    def test_all_literal_template_endpoints_exist(self):
        templates_dir = Path(app_module.__file__).resolve().parent / 'templates'
        known_endpoints = {
            rule.endpoint for rule in self.flask_app.url_map.iter_rules()
        }
        missing = {}

        for template in templates_dir.rglob('*.html'):
            source = template.read_text(encoding='utf-8')
            for endpoint in URL_FOR_PATTERN.findall(source):
                if endpoint not in known_endpoints:
                    missing.setdefault(endpoint, []).append(
                        str(template.relative_to(templates_dir))
                    )

        self.assertEqual(missing, {})

    def test_route_rule_signatures_are_unique(self):
        signatures = [
            (
                rule.rule,
                tuple(sorted(rule.methods - {'HEAD', 'OPTIONS'})),
            )
            for rule in self.flask_app.url_map.iter_rules()
        ]
        self.assertEqual(len(signatures), len(set(signatures)))

    def test_templates_have_no_inline_event_attributes(self):
        templates_dir = Path(app_module.__file__).resolve().parent / 'templates'
        offenders = {}
        for template in templates_dir.rglob('*.html'):
            source = template.read_text(encoding='utf-8')
            matches = INLINE_EVENT_PATTERN.findall(source)
            if matches:
                offenders[str(template.relative_to(templates_dir))] = len(matches)
        self.assertEqual(offenders, {})

    def test_templates_have_no_javascript_urls(self):
        templates_dir = Path(app_module.__file__).resolve().parent / 'templates'
        offenders = []
        for template in templates_dir.rglob('*.html'):
            source = template.read_text(encoding='utf-8')
            if JAVASCRIPT_URL_PATTERN.search(source):
                offenders.append(str(template.relative_to(templates_dir)))
        self.assertEqual(offenders, [])

    def test_inline_script_blocks_have_a_nonce(self):
        templates_dir = Path(app_module.__file__).resolve().parent / 'templates'
        offenders = {}
        for template in templates_dir.rglob('*.html'):
            source = template.read_text(encoding='utf-8')
            for attributes in SCRIPT_TAG_PATTERN.findall(source):
                if 'src=' not in attributes and 'nonce=' not in attributes:
                    relative_path = str(template.relative_to(templates_dir))
                    offenders[relative_path] = offenders.get(relative_path, 0) + 1
        self.assertEqual(offenders, {})

    def test_inline_style_blocks_have_a_nonce(self):
        templates_dir = Path(app_module.__file__).resolve().parent / 'templates'
        offenders = {}
        for template in templates_dir.rglob('*.html'):
            source = template.read_text(encoding='utf-8')
            for attributes in STYLE_TAG_PATTERN.findall(source):
                if 'nonce=' not in attributes:
                    relative_path = str(template.relative_to(templates_dir))
                    offenders[relative_path] = offenders.get(relative_path, 0) + 1
        self.assertEqual(offenders, {})

    def test_templates_have_no_style_attributes(self):
        templates_dir = Path(app_module.__file__).resolve().parent / 'templates'
        offenders = {}
        for template in templates_dir.rglob('*.html'):
            source = template.read_text(encoding='utf-8')
            matches = STYLE_ATTRIBUTE_PATTERN.findall(source)
            if matches:
                offenders[str(template.relative_to(templates_dir))] = len(matches)
        self.assertEqual(offenders, {})

    def test_frontend_does_not_mutate_inline_styles(self):
        project_dir = Path(app_module.__file__).resolve().parent
        offenders = []
        paths = list((project_dir / 'templates').rglob('*.html'))
        paths.extend((project_dir / 'static' / 'js').rglob('*.js'))
        for path in paths:
            source = path.read_text(encoding='utf-8')
            if STYLE_MUTATION_PATTERN.search(source):
                offenders.append(str(path.relative_to(project_dir)))
        self.assertEqual(offenders, [])

    def test_report_only_csp_uses_per_request_nonce(self):
        first = self.client.get('/login')
        second = self.client.get('/login')
        first_policy = first.headers['Content-Security-Policy-Report-Only']
        second_policy = second.headers['Content-Security-Policy-Report-Only']
        enforced_policy = first.headers['Content-Security-Policy']

        nonce_pattern = re.compile(r"'nonce-([^']+)'")
        first_nonce = nonce_pattern.search(first_policy)
        second_nonce = nonce_pattern.search(second_policy)

        self.assertIsNotNone(first_nonce)
        self.assertIsNotNone(second_nonce)
        self.assertNotEqual(first_nonce.group(1), second_nonce.group(1))
        self.assertIn(
            f'nonce="{first_nonce.group(1)}"'.encode(),
            first.data,
        )
        self.assertIn(
            f'<style nonce="{first_nonce.group(1)}"'.encode(),
            first.data,
        )
        self.assertNotIn("'unsafe-eval'", enforced_policy)
        script_directives = [
            directive.strip()
            for directive in enforced_policy.split(';')
            if directive.strip().startswith('script-src')
        ]
        self.assertTrue(script_directives)
        for directive in script_directives:
            self.assertNotIn("'unsafe-inline'", directive)
        self.assertIn("script-src-attr 'none'", enforced_policy)
        style_directives = [
            directive.strip()
            for directive in enforced_policy.split(';')
            if directive.strip().startswith('style-src')
        ]
        self.assertTrue(style_directives)
        for directive in style_directives:
            self.assertNotIn("'unsafe-inline'", directive)
        self.assertIn("style-src-attr 'none'", enforced_policy)
        self.assertNotIn("'unsafe-eval'", first_policy)
        self.assertIn("script-src-attr 'none'", first_policy)
        self.assertIn("style-src-attr 'none'", first_policy)
        self.assertIn("report-uri /api/csp-report", first_policy)

    def test_csp_report_endpoint_accepts_browser_payload(self):
        response = self.client.post(
            '/api/csp-report',
            json={
                'csp-report': {
                    'effective-directive': 'script-src-attr',
                    'blocked-uri': 'inline',
                    'document-uri': 'https://example.test/login',
                }
            },
        )

        self.assertEqual(response.status_code, 204)

    def test_recovery_page_get_is_not_rate_limited(self):
        app_module.request_counts.clear()
        responses = [
            self.client.get('/solicitar-recuperacion')
            for _ in range(5)
        ]
        self.assertTrue(all(response.status_code == 200 for response in responses))

    def test_csp_reports_do_not_consume_recovery_rate_limit(self):
        app_module.request_counts.clear()
        for _ in range(4):
            response = self.client.post('/api/csp-report', json={})
            self.assertEqual(response.status_code, 204)

        page = self.client.get('/solicitar-recuperacion')
        csrf_token = re.search(
            rb'name="csrf_token" value="([^"]+)"',
            page.data,
        ).group(1).decode('utf-8')
        response = self.client.post(
            '/solicitar-recuperacion',
            data={
                'csrf_token': csrf_token,
                'email': 'correo-invalido',
            },
        )
        self.assertEqual(response.status_code, 302)

    def test_reclamation_detail_is_tenant_scoped(self):
        user = SimpleNamespace(
            id=10,
            perfil='Administrador',
            tenant_id=22,
            is_authenticated=True,
        )
        handler = billing_routes.facturacion_reclamacion_detalle
        while hasattr(handler, '__wrapped__'):
            handler = handler.__wrapped__

        with self.flask_app.test_request_context(
            '/facturacion/reclamaciones/91'
        ):
            with (
                patch_current_user(user),
                patch.object(
                    billing_routes,
                    'execute_query',
                    return_value=None,
                ) as query,
            ):
                response = handler(91)

        self.assertEqual(response.status_code, 302)
        self.assertIn('r.tenant_id = %s', query.call_args.args[0])
        self.assertEqual(query.call_args.args[1], (91, 22))

    def test_reclamation_status_rejects_another_tenant(self):
        user = SimpleNamespace(
            id=10,
            perfil='Administrador',
            tenant_id=22,
            is_authenticated=True,
        )
        update = Mock()
        handler = billing_routes.facturacion_reclamacion_cambiar_estado
        while hasattr(handler, '__wrapped__'):
            handler = handler.__wrapped__

        with self.flask_app.test_request_context(
            '/facturacion/reclamaciones/91/estado',
            method='POST',
            data={'estado': 'Procesada'},
        ):
            with (
                patch_current_user(user),
                patch.object(
                    billing_routes,
                    'execute_query',
                    return_value=None,
                ) as query,
                patch.object(billing_routes, 'execute_update', update),
            ):
                response = handler(91)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(query.call_args.args[1], (91, 22))
        update.assert_not_called()

    def test_public_registration_requires_ten_digit_phone(self):
        handler = auth_routes.registro
        while hasattr(handler, '__wrapped__'):
            handler = handler.__wrapped__

        with self.flask_app.test_request_context(
            '/registro',
            method='POST',
            data={
                'nombre_empresa': 'Consultorio Prueba',
                'tipo_empresa': 'medico',
                'nombre': 'Usuario Prueba',
                'email': 'usuario@example.com',
                'telefono': '809-555-1234',
                'password': 'Segura123!',
                'password_confirm': 'Segura123!',
            },
        ):
            with (
                patch.object(
                    auth_routes,
                    'current_user',
                    SimpleNamespace(is_authenticated=False),
                ),
                patch.object(auth_routes, 'execute_query') as query,
                patch.object(auth_routes, 'render_template', return_value='form'),
            ):
                response = handler()

        self.assertEqual(response, 'form')
        query.assert_not_called()

    def test_public_registration_stores_company_phone(self):
        handler = auth_routes.registro
        while hasattr(handler, '__wrapped__'):
            handler = handler.__wrapped__
        updates = Mock(side_effect=[12, 34])

        with self.flask_app.test_request_context(
            '/registro',
            method='POST',
            data={
                'nombre_empresa': 'Consultorio Prueba',
                'tipo_empresa': 'medico',
                'nombre': 'Usuario Prueba',
                'email': 'usuario@example.com',
                'telefono': '8095551234',
                'password': 'Segura123!',
                'password_confirm': 'Segura123!',
            },
        ):
            with (
                patch.object(
                    auth_routes,
                    'current_user',
                    SimpleNamespace(is_authenticated=False),
                ),
                patch.object(auth_routes, 'execute_query', return_value=None),
                patch.object(auth_routes, 'execute_update', updates),
                patch.object(
                    auth_routes,
                    'database_transaction',
                    return_value=nullcontext(),
                ),
            ):
                response = handler()

        self.assertEqual(response.status_code, 302)
        company_insert, company_params = updates.call_args_list[0].args
        self.assertIn('telefono', company_insert)
        self.assertIn('8095551234', company_params)


if __name__ == '__main__':
    unittest.main()
