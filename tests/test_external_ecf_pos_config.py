import unittest

from services.external_ecf_pos_config import (
    _normalizar_usuario_api,
    _usuario_api_por_defecto,
)


class ExternalECFPosConfigTests(unittest.TestCase):
    def test_usuario_por_defecto(self):
        self.assertEqual(_usuario_api_por_defecto(16), 'api-t16')
        self.assertEqual(_usuario_api_por_defecto(16, 'otro-pos'), 'api-t16-otropos')

    def test_normalizar_usuario_api(self):
        self.assertEqual(_normalizar_usuario_api('api-custom', 16, 'x'), 'api-custom')
        self.assertEqual(_normalizar_usuario_api('  ', 16, 'ricohotdog'), 'api-t16-ricohotdog')
        self.assertEqual(_normalizar_usuario_api('bad@user', 3, None), 'baduser')


if __name__ == '__main__':
    unittest.main()