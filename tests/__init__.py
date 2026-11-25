"""Aislamiento de la suite de tests.

core/config.py llama a load_dotenv(), y el .env local apunta a la base de
Railway. load_dotenv() no sobrescribe variables ya definidas, así que aquí
se fijan antes de importar la app: cualquier consulta que un test olvide
simular falla contra un puerto local cerrado en vez de tocar datos reales.

Ejecutar desde la raíz del proyecto:
    py -m pytest
    py -m unittest discover -s tests -t .
"""

import os

_BD_INALCANZABLE = 'mysql://tests:tests@127.0.0.1:1/clinicrd_tests'

for _clave in ('MYSQL_URL', 'DATABASE_URL'):
    os.environ[_clave] = _BD_INALCANZABLE
for _clave, _valor in (
    ('MYSQL_HOST', '127.0.0.1'),
    ('MYSQLHOST', '127.0.0.1'),
    ('MYSQL_PORT', '1'),
    ('MYSQLPORT', '1'),
    ('MYSQL_USER', 'tests'),
    ('MYSQL_PASSWORD', 'tests'),
    ('MYSQL_DATABASE', 'clinicrd_tests'),
    ('SECRET_KEY', 'clave-solo-para-tests'),
    ('EXTERNAL_ECF_JWT_SECRET', 'jwt-solo-para-tests-0123456789abcdef'),
):
    os.environ[_clave] = _valor
# Sin credenciales de correo reales: ningún test debe poder enviar emails.
for _clave in (
    'ZOHO_SMTP_USER', 'ZOHO_SMTP_PASSWORD', 'SENDGRID_API_KEY',
):
    os.environ[_clave] = ''


# Bloqueo duro: ningún test abre conexiones MySQL reales. Falla al instante
# (un puerto cerrado en Windows tarda ~2 s por intento).
import pymysql  # noqa: E402


class ConexionBloqueadaEnTests(pymysql.err.OperationalError):
    pass


def _conexion_bloqueada(*args, **kwargs):
    raise ConexionBloqueadaEnTests(
        2003, 'Los tests no pueden conectarse a MySQL; simule la consulta.'
    )


pymysql.connect = _conexion_bloqueada
pymysql.Connect = _conexion_bloqueada
pymysql.connections.Connection.__init__ = (
    lambda self, *a, **k: _conexion_bloqueada()
)
