import unittest

from services.stationery import MAX_LOGO_BYTES, _carpeta_tenant, detectar_imagen


class StationerySafetyTests(unittest.TestCase):
    def test_rejects_svg_and_html(self):
        self.assertIsNone(detectar_imagen(b'<svg xmlns="http://www.w3.org/2000/svg"></svg>'))
        self.assertIsNone(detectar_imagen(b'<html><img src=x onerror=alert(1)>'))
        self.assertIsNone(detectar_imagen(b'{not-an-image}'))

    def test_rejects_oversized_payload(self):
        png = b'\x89PNG\r\n\x1a\n' + (b'x' * MAX_LOGO_BYTES)
        self.assertIsNone(detectar_imagen(png))

    def test_accepts_png_jpeg_webp(self):
        self.assertEqual(detectar_imagen(b'\x89PNG\r\n\x1a\nrest')[0], 'png')
        self.assertEqual(detectar_imagen(b'\xff\xd8\xff\xdbdata')[0], 'jpg')
        webp = b'RIFF' + b'\x10\x00\x00\x00' + b'WEBP' + b'xxxx'
        self.assertEqual(detectar_imagen(webp)[0], 'webp')

    def test_tenant_folder_rejects_invalid_ids(self):
        with self.assertRaises(ValueError):
            _carpeta_tenant(0)
        with self.assertRaises(ValueError):
            _carpeta_tenant(-3)
        carpeta = _carpeta_tenant(12)
        self.assertEqual(carpeta.name, '12')
        self.assertTrue(str(carpeta).replace('\\', '/').endswith('instance/papeleria/12'))


if __name__ == '__main__':
    unittest.main()
