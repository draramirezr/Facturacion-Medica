import unittest

from services.external_ecf_pos_config import (
    _normalizar_usuario_api,
    _slug_desde_empresa,
    _usuario_api_por_defecto,
)


class ExternalECFPosConfigTests(unittest.TestCase):
    def test_slug_desde_empresa(self):
        self.assertEqual(
            _slug_desde_empresa({'nombre': 'LEV BARUJ'}),
            'levbaruj',
        )
        self.assertEqual(
            _slug_desde_empresa({
                'razon_social': 'SHIRLEY SCARLETT RAMIREZ MONTERO',
            }),
            'shirleyscarlettramir',
        )

    def test_usuario_por_defecto(self):
        self.assertEqual(
            _usuario_api_por_defecto(16, empresa_slug='levbaruj'),
            'api-t16-levbaruj',
        )
        self.assertEqual(
            _usuario_api_por_defecto(
                16,
                empresa_slug='levbaruj',
                client_codigo='otro-pos',
                multiples_integradores=True,
            ),
            'api-t16-levbaruj-otropos',
        )

    def test_normalizar_usuario_api(self):
        self.assertEqual(
            _normalizar_usuario_api('api-custom', 16, empresa_slug='x'),
            'api-custom',
        )
        self.assertEqual(
            _normalizar_usuario_api('  ', 16, empresa_slug='levbaruj'),
            'api-t16-levbaruj',
        )


if __name__ == '__main__':
    unittest.main()