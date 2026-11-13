import unittest
from unittest.mock import patch

import jwt

from integrations.external_ecf_service.auth.authentication import (
    AuthFailure,
    AuthSuccess,
    authenticate_hka_request,
)
from integrations.external_ecf_service.auth.token_service import (
    decode_token,
    issue_token,
)
from integrations.external_ecf_service.config import ExternalECFConfig
from integrations.external_ecf_service.security.credentials import (
    hash_integration_password,
)


class ExternalECFAuthLogicTests(unittest.TestCase):
    def setUp(self):
        self.config = ExternalECFConfig(
            enabled=True,
            jwt_secret='a' * 32,
            token_ttl_seconds=3600,
            environment='PRUEBAS',
            auth_rate_limit_max=30,
            auth_rate_limit_window=300,
        )
        self.password_hash = hash_integration_password('clave-segura')
        self.client = {
            'id': 1,
            'estado': 'activo',
            'codigo': 'ricohotdog',
        }
        self.emitter = {
            'id': 10,
            'client_id': 1,
            'tenant_id': 99,
            'rnc': '131793916',
            'estado': 'activo',
            'ambiente': 'PRUEBAS',
        }
        self.credential = {
            'id': 5,
            'client_id': 1,
            'emitter_id': 10,
            'usuario': 'api-rico',
            'password_hash': self.password_hash,
            'estado': 'activa',
        }

    def test_autenticacion_correcta(self):
        result = authenticate_hka_request(
            usuario='api-rico',
            clave='clave-segura',
            rnc='131-793-916',
            config=self.config,
            find_credential=lambda u: self.credential if u == 'api-rico' else None,
            get_client=lambda cid: self.client,
            resolve_emitter=lambda **kw: self.emitter,
        )
        self.assertTrue(hasattr(result, 'token'))
        self.assertEqual(result.codigo, 0)
        payload = decode_token(result.token, secret=self.config.jwt_secret)
        self.assertEqual(payload['client_id'], 1)
        self.assertEqual(payload['emitter_id'], 10)
        self.assertEqual(payload['tenant_id'], 99)
        self.assertEqual(payload['rnc'], '131793916')

    def test_credenciales_invalidas(self):
        result = authenticate_hka_request(
            usuario='api-rico',
            clave='mala',
            rnc='131793916',
            config=self.config,
            find_credential=lambda u: self.credential,
            get_client=lambda cid: self.client,
            resolve_emitter=lambda **kw: self.emitter,
        )
        self.assertIsInstance(result, AuthFailure)
        self.assertEqual(result.codigo, 1)

    def test_rnc_no_autorizado(self):
        other_emitter = dict(self.emitter, rnc='999999999')
        result = authenticate_hka_request(
            usuario='api-rico',
            clave='clave-segura',
            rnc='131793916',
            config=self.config,
            find_credential=lambda u: self.credential,
            get_client=lambda cid: self.client,
            resolve_emitter=lambda **kw: other_emitter,
        )
        self.assertIsInstance(result, AuthFailure)

    def test_servicio_desactivado(self):
        disabled = ExternalECFConfig(
            enabled=False,
            jwt_secret='',
            token_ttl_seconds=3600,
            environment='PRUEBAS',
            auth_rate_limit_max=30,
            auth_rate_limit_window=300,
        )
        result = authenticate_hka_request(
            usuario='api-rico',
            clave='clave-segura',
            rnc='131793916',
            config=disabled,
            find_credential=lambda u: self.credential,
            get_client=lambda cid: self.client,
            resolve_emitter=lambda **kw: self.emitter,
        )
        self.assertIsInstance(result, AuthFailure)
        self.assertEqual(result.codigo, 99)

    def test_token_expiracion_configurable(self):
        token, expires = issue_token(
            secret=self.config.jwt_secret,
            ttl_seconds=120,
            client_id=1,
            emitter_id=10,
            tenant_id=99,
            rnc='131793916',
            environment='PRUEBAS',
        )
        payload = jwt.decode(token, self.config.jwt_secret, algorithms=['HS256'])
        self.assertEqual(payload['exp'] - payload['iat'], 120)
        self.assertIsNotNone(expires)


class ExternalECFAuthRouteTests(unittest.TestCase):
    def setUp(self):
        import app as app_module

        self.app = app_module.app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        self.app.config['EXTERNAL_ECF_CONFIG'] = ExternalECFConfig(
            enabled=True,
            jwt_secret='b' * 32,
            token_ttl_seconds=3600,
            environment='PRUEBAS',
            auth_rate_limit_max=30,
            auth_rate_limit_window=300,
        )

    @patch(
        'integrations.external_ecf_service.routes.authentication_routes.IntegrationService'
    )
    def test_endpoint_autenticacion_formato_hka(self, service_mock):
        success = AuthSuccess(
            codigo=0,
            mensaje='Autenticación exitosa',
            token='jwt-token',
            fecha_expiracion='2026-12-31T23:59:59',
            client_id=1,
            emitter_id=10,
            tenant_id=99,
        )
        service_mock.return_value.autenticar.return_value = success
        self.assertTrue(self.app.config['EXTERNAL_ECF_CONFIG'].enabled)
        response = self.client.post(
            '/api/Autenticacion',
            json={
                'usuario': 'u',
                'clave': 'p',
                'rnc': '131793916',
            },
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['codigo'], 0)
        self.assertEqual(data['token'], 'jwt-token')
        self.assertIn('fechaExpiracion', data)

    def test_health_endpoint(self):
        response = self.client.get('/external-ecf/health')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['module'], 'external_ecf_service')
        self.assertIn('enabled', data)


if __name__ == '__main__':
    unittest.main()
