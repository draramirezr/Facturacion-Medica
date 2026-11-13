import json
import unittest
from decimal import Decimal
from unittest.mock import MagicMock, patch

from integrations.external_ecf_service.adapters.hka.mapper import (
    HkaMapperError,
    map_hka_documento_electronico,
)
from integrations.external_ecf_service.auth.token_service import issue_token
from integrations.external_ecf_service.config import ExternalECFConfig
from integrations.external_ecf_service.services.payload_hash import (
    compute_document_payload_hash,
)
from integrations.external_ecf_service.services.send_service import SendService


def _sample_documento_e31_exento():
    return {
        'encabezado': {
            'identificacionDocumento': {
                'tipoDocumento': 'E31',
                'ncf': 'E310000000001',
                'tipoIngresos': '01',
                'tipoPago': '1',
                'tablaFormasPago': [{'forma': '1', 'monto': '118.00'}],
            },
            'emisor': {
                'rnc': '131793916',
                'razonSocial': 'Emisor Demo',
                'fechaEmision': '13-11-2026',
                'sucursal': 'Principal',
                'numeroFacturaInterna': 'FAC-1001',
            },
            'comprador': {
                'rncComprador': '401007557',
                'razonSocialComprador': 'Cliente Demo',
            },
            'totales': {
                'montoExento': '118.00',
                'montoTotal': '118.00',
            },
        },
        'detallesItems': [
            {
                'numeroLinea': '1',
                'indicadorFacturacion': '4',
                'nombre': 'Producto',
                'cantidad': '1',
                'precioUnitario': '118.00',
                'montoItem': '118.00',
            }
        ],
        'serialDevice': 'POS-1',
    }


class HkaMapperTests(unittest.TestCase):
    def test_map_e31_exento(self):
        doc = _sample_documento_e31_exento()
        mapped = map_hka_documento_electronico(doc, authorized_rnc='131793916')
        self.assertEqual(mapped.tipo_ecf, 'E31')
        self.assertEqual(mapped.rnc_emisor, '131793916')
        self.assertEqual(mapped.total, Decimal('118.00'))
        self.assertTrue(mapped.canonical.dgii_motor_ready)

    def test_rechaza_rnc_distinto(self):
        doc = _sample_documento_e31_exento()
        with self.assertRaises(HkaMapperError):
            map_hka_documento_electronico(doc, authorized_rnc='999999999')

    def test_e32_marca_motor_no_listo(self):
        doc = _sample_documento_e31_exento()
        doc['encabezado']['identificacionDocumento']['tipoDocumento'] = 'E32'
        mapped = map_hka_documento_electronico(doc, authorized_rnc='131793916')
        self.assertFalse(mapped.canonical.dgii_motor_ready)


class SendServiceTests(unittest.TestCase):
    def setUp(self):
        self.config = ExternalECFConfig(
            enabled=True,
            jwt_secret='c' * 32,
            token_ttl_seconds=3600,
            environment='PRUEBAS',
            auth_rate_limit_max=30,
            auth_rate_limit_window=300,
        )
        self.client = {'id': 1, 'estado': 'activo'}
        self.emitter = {
            'id': 10,
            'client_id': 1,
            'tenant_id': 99,
            'rnc': '131793916',
            'estado': 'activo',
            'ambiente': 'PRUEBAS',
        }
        token, _ = issue_token(
            secret=self.config.jwt_secret,
            ttl_seconds=3600,
            client_id=1,
            emitter_id=10,
            tenant_id=99,
            rnc='131793916',
            environment='PRUEBAS',
        )
        self.token = token
        self.documento = _sample_documento_e31_exento()

    def test_enviar_registra_documento(self):
        integration_repo = MagicMock()
        integration_repo.get_client_by_id.return_value = self.client
        emitter_repo = MagicMock()
        emitter_repo.get_by_id_for_client.return_value = self.emitter
        document_repo = MagicMock()
        document_repo.find_by_emitter_and_hash.return_value = None
        document_repo.find_by_emitter_and_encf.return_value = None
        document_repo.insert_document.return_value = 501
        document_repo.update_response_snapshot = MagicMock()

        service = SendService(
            self.config,
            integration_repo=integration_repo,
            emitter_repo=emitter_repo,
            document_repo=document_repo,
        )
        result = service.enviar(self.token, self.documento)
        self.assertEqual(result.codigo, 0)
        self.assertFalse(result.procesado)
        self.assertIsNone(result.xml_base64)
        document_repo.insert_document.assert_called_once()
        document_repo.update_response_snapshot.assert_called_once()

    def test_idempotencia_mismo_hash(self):
        snapshot = {
            'codigo': 0,
            'mensaje': 'Documento recibido y registrado',
            'xmlBase64': None,
            'procesado': False,
            'codigoSeguridad': None,
            'fechaFirma': None,
            'fechaEmision': '2026-11-13',
            'document_id': 55,
        }
        integration_repo = MagicMock()
        integration_repo.get_client_by_id.return_value = self.client
        emitter_repo = MagicMock()
        emitter_repo.get_by_id_for_client.return_value = self.emitter
        document_repo = MagicMock()
        document_repo.find_by_emitter_and_hash.return_value = {
            'id': 55,
            'response_snapshot': snapshot,
        }

        service = SendService(
            self.config,
            integration_repo=integration_repo,
            emitter_repo=emitter_repo,
            document_repo=document_repo,
        )
        result = service.enviar(self.token, self.documento)
        self.assertTrue(result.idempotent_replay)
        document_repo.insert_document.assert_not_called()


class EnviarRouteTests(unittest.TestCase):
    def setUp(self):
        import app as app_module

        self.app = app_module.app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        self.app.config['EXTERNAL_ECF_CONFIG'] = ExternalECFConfig(
            enabled=True,
            jwt_secret='d' * 32,
            token_ttl_seconds=3600,
            environment='PRUEBAS',
            auth_rate_limit_max=30,
            auth_rate_limit_window=300,
        )

    @patch('integrations.external_ecf_service.routes.send_routes.SendService')
    def test_endpoint_formato_hka(self, service_mock):
        from integrations.external_ecf_service.services.send_service import EnviarSuccess

        service_mock.return_value.enviar.return_value = EnviarSuccess(
            codigo=0,
            mensaje='Documento recibido y registrado',
            xml_base64=None,
            procesado=True,
            codigo_seguridad=None,
            fecha_firma=None,
            fecha_emision='2026-11-13',
        )
        response = self.client.post(
            '/api/Enviar',
            json={
                'token': 'jwt',
                'documentoElectronico': _sample_documento_e31_exento(),
            },
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['codigo'], 0)
        self.assertIn('procesado', data)
        self.assertIn('xmlBase64', data)


class PayloadHashTests(unittest.TestCase):
    def test_hash_estable(self):
        doc = _sample_documento_e31_exento()
        h1 = compute_document_payload_hash(doc)
        h2 = compute_document_payload_hash(json.loads(json.dumps(doc)))
        self.assertEqual(h1, h2)

    def test_hash_independiente_del_orden(self):
        doc = _sample_documento_e31_exento()
        reordered = {
            'serialDevice': doc['serialDevice'],
            'detallesItems': doc['detallesItems'],
            'encabezado': doc['encabezado'],
        }
        self.assertEqual(
            compute_document_payload_hash(doc),
            compute_document_payload_hash(reordered),
        )

    def test_numero_interno_diferencia_hash(self):
        a = _sample_documento_e31_exento()
        b = _sample_documento_e31_exento()
        b['encabezado']['emisor']['numeroFacturaInterna'] = 'FAC-1002'
        self.assertNotEqual(
            compute_document_payload_hash(a),
            compute_document_payload_hash(b),
        )


class SendServiceErrorTests(unittest.TestCase):
    def setUp(self):
        self.config = ExternalECFConfig(
            enabled=True,
            jwt_secret='e' * 32,
            token_ttl_seconds=3600,
            environment='PRUEBAS',
            auth_rate_limit_max=30,
            auth_rate_limit_window=300,
        )
        self.documento = _sample_documento_e31_exento()

    def test_encf_duplicado_distinto_contenido(self):
        token, _ = issue_token(
            secret=self.config.jwt_secret,
            ttl_seconds=3600,
            client_id=1,
            emitter_id=10,
            tenant_id=99,
            rnc='131793916',
            environment='PRUEBAS',
        )
        integration_repo = MagicMock()
        integration_repo.get_client_by_id.return_value = {
            'id': 1,
            'estado': 'activo',
        }
        emitter_repo = MagicMock()
        emitter_repo.get_by_id_for_client.return_value = {
            'id': 10,
            'client_id': 1,
            'tenant_id': 99,
            'rnc': '131793916',
            'estado': 'activo',
            'ambiente': 'PRUEBAS',
        }
        document_repo = MagicMock()
        document_repo.find_by_emitter_and_hash.return_value = None
        document_repo.find_by_emitter_and_encf.return_value = {
            'payload_hash': 'otro-hash',
            'encf': 'E310000000001',
        }

        service = SendService(
            self.config,
            integration_repo=integration_repo,
            emitter_repo=emitter_repo,
            document_repo=document_repo,
        )
        result = service.enviar(token, self.documento)
        self.assertEqual(result.codigo, 2)

    def test_integrity_error_relee_registro(self):
        import pymysql

        token, _ = issue_token(
            secret=self.config.jwt_secret,
            ttl_seconds=3600,
            client_id=1,
            emitter_id=10,
            tenant_id=99,
            rnc='131793916',
            environment='PRUEBAS',
        )
        integration_repo = MagicMock()
        integration_repo.get_client_by_id.return_value = {
            'id': 1,
            'estado': 'activo',
        }
        emitter_repo = MagicMock()
        emitter_repo.get_by_id_for_client.return_value = {
            'id': 10,
            'client_id': 1,
            'tenant_id': 99,
            'rnc': '131793916',
            'estado': 'activo',
            'ambiente': 'PRUEBAS',
        }
        snapshot = {
            'codigo': 0,
            'mensaje': 'Documento recibido; emisión fiscal pendiente',
            'xmlBase64': None,
            'procesado': False,
            'codigoSeguridad': None,
            'fechaFirma': None,
            'fechaEmision': '2026-11-13',
            'document_id': 88,
        }
        document_repo = MagicMock()
        document_repo.find_by_emitter_and_hash.side_effect = [
            None,
            {'id': 88, 'response_snapshot': snapshot},
        ]
        document_repo.find_by_emitter_and_encf.return_value = None
        document_repo.insert_document.side_effect = pymysql.IntegrityError(
            1062, 'Duplicate'
        )

        service = SendService(
            self.config,
            integration_repo=integration_repo,
            emitter_repo=emitter_repo,
            document_repo=document_repo,
        )
        result = service.enviar(token, self.documento)
        self.assertTrue(result.idempotent_replay)
        self.assertEqual(result.document_id, 88)

    def test_persistencia_falla_codigo_99(self):
        token, _ = issue_token(
            secret=self.config.jwt_secret,
            ttl_seconds=3600,
            client_id=1,
            emitter_id=10,
            tenant_id=99,
            rnc='131793916',
            environment='PRUEBAS',
        )
        integration_repo = MagicMock()
        integration_repo.get_client_by_id.return_value = {
            'id': 1,
            'estado': 'activo',
        }
        emitter_repo = MagicMock()
        emitter_repo.get_by_id_for_client.return_value = {
            'id': 10,
            'client_id': 1,
            'tenant_id': 99,
            'rnc': '131793916',
            'estado': 'activo',
            'ambiente': 'PRUEBAS',
        }
        document_repo = MagicMock()
        document_repo.find_by_emitter_and_hash.return_value = None
        document_repo.find_by_emitter_and_encf.return_value = None
        document_repo.insert_document.side_effect = RuntimeError('db down')

        service = SendService(
            self.config,
            integration_repo=integration_repo,
            emitter_repo=emitter_repo,
            document_repo=document_repo,
        )
        result = service.enviar(token, self.documento)
        self.assertEqual(result.codigo, 99)


class TokenIsolationTests(unittest.TestCase):
    def test_token_no_autoriza_emisor_ajeno(self):
        config = ExternalECFConfig(
            enabled=True,
            jwt_secret='f' * 32,
            token_ttl_seconds=3600,
            environment='PRUEBAS',
            auth_rate_limit_max=30,
            auth_rate_limit_window=300,
        )
        token, _ = issue_token(
            secret=config.jwt_secret,
            ttl_seconds=3600,
            client_id=1,
            emitter_id=10,
            tenant_id=99,
            rnc='131793916',
            environment='PRUEBAS',
        )
        integration_repo = MagicMock()
        integration_repo.get_client_by_id.return_value = {
            'id': 1,
            'estado': 'activo',
        }
        emitter_repo = MagicMock()
        emitter_repo.get_by_id_for_client.return_value = None

        service = SendService(
            config,
            integration_repo=integration_repo,
            emitter_repo=emitter_repo,
            document_repo=MagicMock(),
        )
        result = service.enviar(token, _sample_documento_e31_exento())
        self.assertEqual(result.codigo, 1)


if __name__ == '__main__':
    unittest.main()
