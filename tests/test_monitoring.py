"""El monitoreo no debe enviar datos de pacientes a Sentry."""

import unittest
from unittest.mock import patch

from flask import Flask

from core.monitoring import _sin_datos_sensibles, init_monitoring


class MonitoringTests(unittest.TestCase):
    def test_sin_dsn_no_se_activa(self):
        with patch.dict('os.environ', {'SENTRY_DSN': ''}):
            self.assertFalse(init_monitoring(Flask(__name__)))

    def test_evento_queda_sin_datos_sensibles(self):
        evento = {
            'request': {
                'url': 'https://clinicrd.com/pacientes?cedula=00100000009',
                'method': 'POST',
                'data': {'nombre_paciente': 'Juan Pérez', 'nss': '123'},
                'cookies': {'session': 'abc'},
                'headers': {'Authorization': 'Bearer x'},
                'query_string': 'cedula=00100000009',
            },
            'user': {'id': '5', 'email': 'medico@example.com', 'ip_address': '1.2.3.4'},
            'exception': {'values': [{'stacktrace': {'frames': [
                {'function': 'guardar', 'vars': {'paciente': {'nombre': 'Juan'}}},
            ]}}]},
            'breadcrumbs': {'values': [{'message': 'SELECT * FROM pacientes'}]},
        }
        limpio = _sin_datos_sensibles(evento, {})
        self.assertEqual(
            limpio['request'],
            {'url': 'https://clinicrd.com/pacientes', 'method': 'POST'},
        )
        self.assertEqual(limpio['user'], {'id': '5'})
        frame = limpio['exception']['values'][0]['stacktrace']['frames'][0]
        self.assertNotIn('vars', frame)
        self.assertNotIn('breadcrumbs', limpio)
        self.assertNotIn('Juan', repr(limpio))
        self.assertNotIn('00100000009', repr(limpio))


if __name__ == '__main__':
    unittest.main()
