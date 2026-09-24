import hashlib
import unittest

from routes.appointments import _datetime_cita, hashear_token_cita


class AppointmentConfirmationTests(unittest.TestCase):
    def test_confirmation_token_is_hashed(self):
        token = 'abc123token-de-prueba-seguro'
        digest = hashear_token_cita(token)
        self.assertEqual(len(digest), 64)
        self.assertNotEqual(digest, token)
        self.assertEqual(digest, hashlib.sha256(token.encode('utf-8')).hexdigest())

    def test_expiration_parses_mysql_datetime_strings(self):
        parsed = _datetime_cita('2026-09-25 09:30:00')
        self.assertEqual(parsed.year, 2026)
        self.assertEqual(parsed.minute, 30)
