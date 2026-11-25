"""Una configuración e-CF inválida apaga el e-CF, no la aplicación."""

import unittest

from flask import Flask

from core.config import cargar_config_ecf


class ArranqueConfigEcfTests(unittest.TestCase):
    def test_allow_production_sin_produccion_no_tumba_la_app(self):
        app = Flask(__name__)
        config = cargar_config_ecf(app, {
            'ECF_ENABLED': 'true',
            'ECF_ENVIRONMENT': 'PRUEBAS',
            'ECF_ALLOW_PRODUCTION': 'true',
        })
        self.assertFalse(config.enabled)
        self.assertIn('ECF_ALLOW_PRODUCTION', app.config['ECF_CONFIG_ERROR'])

    def test_produccion_con_urls_de_prueba_queda_apagado(self):
        base = 'https://ecf.dgii.gov.do/testecf'
        app = Flask(__name__)
        config = cargar_config_ecf(app, {
            'ECF_ENABLED': 'true',
            'ECF_ENVIRONMENT': 'PRODUCCION',
            'ECF_ALLOW_PRODUCTION': 'true',
            'FLASK_ENV': 'production',
            'ECF_TENANT_SECRETS_ROOT': '',
            'ECF_AUTHENTICATION_URL': f'{base}/autenticacion',
            'ECF_RECEPTION_URL': f'{base}/recepcion',
            'ECF_RESULT_URL': f'{base}/consultaresultado',
            'ECF_TRACK_URL': f'{base}/consultatrackids',
            'ECF_STAMP_URL': f'{base}/consultatimbre',
        })
        self.assertFalse(config.enabled)
        self.assertTrue(app.config['ECF_CONFIG_ERROR'])

    def test_ambiente_desconocido_cae_a_pruebas_apagado(self):
        config = cargar_config_ecf(None, {'ECF_ENVIRONMENT': 'OTRO'})
        self.assertFalse(config.enabled)
        self.assertEqual(config.environment, 'PRUEBAS')

    def test_configuracion_valida_no_registra_error(self):
        app = Flask(__name__)
        config = cargar_config_ecf(app, {'ECF_ENABLED': 'false'})
        self.assertFalse(config.enabled)
        self.assertIsNone(app.config['ECF_CONFIG_ERROR'])


if __name__ == '__main__':
    unittest.main()
