import unittest

import pymysql

from auth.helpers import (
    mensaje_error_registro_publico,
    registro_sugerir_login_tras_error,
)


class RegistrationErrorMessagesTests(unittest.TestCase):
    def test_integrity_email_sugiere_login(self):
        error = pymysql.err.IntegrityError(1062, 'Duplicate entry email')
        mensaje = mensaje_error_registro_publico(error)
        self.assertIn('correo', mensaje.lower())
        self.assertTrue(registro_sugerir_login_tras_error(error))

    def test_integrity_nombre_empresa(self):
        error = pymysql.err.IntegrityError(1062, 'empresas.nombre')
        mensaje = mensaje_error_registro_publico(error)
        self.assertIn('nombre', mensaje.lower())

    def test_runtime_error_usuario_muestra_texto(self):
        error = RuntimeError(
            'No pudimos crear su usuario. Si el correo ya@x.com ya está '
            'registrado, use Iniciar sesión.'
        )
        self.assertIn('Iniciar sesión', mensaje_error_registro_publico(error))


if __name__ == '__main__':
    unittest.main()
