"""Los logos deben sobrevivir a los despliegues (volumen de Railway)."""

import unittest
from pathlib import Path
from unittest.mock import patch

import services.stationery as stationery


class PapeleriaVolumenTests(unittest.TestCase):
    def test_con_volumen_usa_el_volumen(self):
        with patch.dict('os.environ', {'RAILWAY_VOLUME_MOUNT_PATH': '/data'}):
            self.assertEqual(stationery._raiz_papeleria(), (Path('/data') / 'papeleria').resolve())

    def test_sin_volumen_usa_instance_local(self):
        with patch.dict('os.environ', {'RAILWAY_VOLUME_MOUNT_PATH': ''}):
            self.assertTrue(str(stationery._raiz_papeleria()).endswith(str(Path('instance') / 'papeleria')))


if __name__ == '__main__':
    unittest.main()
