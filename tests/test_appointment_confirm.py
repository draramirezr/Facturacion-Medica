import hashlib
import unittest

from datetime import date, datetime, time

from routes.appointments import _datetime_cita, calcular_huecos, hashear_token_cita


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

    def test_slots_skip_occupied_and_past_hours(self):
        huecos = calcular_huecos(
            date(2026, 9, 25),
            30,
            time(8, 0),
            time(10, 0),
            [{'hora': time(8, 30), 'duracion_minutos': 30}],
            ahora=datetime(2026, 9, 25, 8, 10),
        )
        self.assertEqual(huecos, ['09:00', '09:30'])
