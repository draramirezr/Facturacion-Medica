import unittest

from services.external_ecf_pos_config import (
    _normalizar_usuario_api,
    _usuario_api_por_defecto,
)


class ExternalECFPosConfigTests(unittest.TestCase):
    def test_usuario_por_defecto(self):
        self.assertEqual(_usuario_api_por_defecto(16), 'api-t16')

    def test_normalizar_usuario_api(self):
        self.assertEqual(_normalizar_usuario_api('api-ricohotdog', 16), 'api-ricohotdog')
        self.assertEqual(_normalizar_usuario_api('  ', 16), 'api-t16')
        self.assertEqual(_normalizar_usuario_api('bad@user', 3), 'baduser')


if __name__ == '__main__':
    unittest.main()