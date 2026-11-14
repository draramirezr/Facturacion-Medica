import unittest
from unittest.mock import patch

from integrations.external_ecf_service.auth.token_authorization import (
    AuthorizedIntegrationContext,
)
from integrations.external_ecf_service.config import ExternalECFConfig


class ExternalECFStubRouteTests(unittest.TestCase):
    def setUp(self):
        import app as app_module

        self.app = app_module.app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        self.app.config['EXTERNAL_ECF_CONFIG'] = ExternalECFConfig(
            enabled=True,
            jwt_secret='e' * 32,
            token_ttl_seconds=3600,
            environment='PRUEBAS',
            auth_rate_limit_max=30,
            auth_rate_limit_window=300,
        )

    def test_api_404_devuelve_json(self):
        response = self.client.post('/api/RutaInexistenteDemo')
        self.assertEqual(response.status_code, 404)
        data = response.get_json()
        self.assertEqual(data['codigo'], 99)
        self.assertIn('Ruta API no disponible', data['mensaje'])

    @patch(
        'integrations.external_ecf_service.routes.hka_stub_routes.authorize_bearer_token'
    )
    def test_estatus_licencia_stub(self, auth_mock):
        auth_mock.return_value = AuthorizedIntegrationContext(
            client_id=1,
            emitter_id=3,
            tenant_id=16,
            rnc='01400204101',
            environment='PRUEBAS',
        )
        response = self.client.post(
            '/api/EstatusLicencia',
            json={'token': 'jwt', 'rnc': '01400204101'},
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['codigo'], 0)
        self.assertGreaterEqual(data['disponible'], 1)
        self.assertIn('licencia', data)


if __name__ == '__main__':
    unittest.main()