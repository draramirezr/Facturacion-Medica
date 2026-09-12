import re
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import app as app_module


URL_FOR_PATTERN = re.compile(r"""url_for\(\s*['"]([^'"]+)['"]""")


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
        self.assertNotIn("'unsafe-eval'", enforced_policy)
        self.assertNotIn("'unsafe-eval'", first_policy)
        self.assertIn("script-src-attr 'none'", first_policy)
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

    def test_reclamation_detail_is_tenant_scoped(self):
        user = SimpleNamespace(
            id=10,
            perfil='Administrador',
            tenant_id=22,
            is_authenticated=True,
        )
        handler = app_module.facturacion_reclamacion_detalle
        while hasattr(handler, '__wrapped__'):
            handler = handler.__wrapped__

        with self.flask_app.test_request_context(
            '/facturacion/reclamaciones/91'
        ):
            with (
                patch.object(app_module, 'current_user', user),
                patch.object(
                    app_module,
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
        handler = app_module.facturacion_reclamacion_cambiar_estado
        while hasattr(handler, '__wrapped__'):
            handler = handler.__wrapped__

        with self.flask_app.test_request_context(
            '/facturacion/reclamaciones/91/estado',
            method='POST',
            data={'estado': 'Procesada'},
        ):
            with (
                patch.object(app_module, 'current_user', user),
                patch.object(
                    app_module,
                    'execute_query',
                    return_value=None,
                ) as query,
                patch.object(app_module, 'execute_update', update),
            ):
                response = handler(91)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(query.call_args.args[1], (91, 22))
        update.assert_not_called()


if __name__ == '__main__':
    unittest.main()
