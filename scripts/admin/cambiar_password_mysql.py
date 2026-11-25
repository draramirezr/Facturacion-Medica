"""Cambia la contraseña del usuario MySQL que usa la app (según el .env).

Uso, desde la raíz del proyecto:
    py scripts/admin/cambiar_password_mysql.py

1. Lee la conexión actual del .env.
2. Genera una contraseña nueva y la aplica con ALTER USER CURRENT_USER().
3. Comprueba que la nueva contraseña conecta.
4. Actualiza MYSQL_PASSWORD y MYSQL_URL en el .env local.
5. Muestra la contraseña nueva para copiarla en las variables de Railway.

Desde el paso 2, la app en Railway no conecta hasta que actualice sus
variables. Hágalo en un momento de poco uso.
"""

import secrets
import sys
from pathlib import Path
from urllib.parse import quote, urlparse, urlunparse

import pymysql
from dotenv import dotenv_values

RAIZ = Path(__file__).resolve().parents[2]
ENV_PATH = RAIZ / '.env'


def _conexion_desde_env(valores):
    url = valores.get('MYSQL_URL') or ''
    if url:
        p = urlparse(url)
        return {
            'host': p.hostname,
            'port': p.port or 3306,
            'user': p.username,
            'password': p.password or '',
            'database': (p.path or '/').lstrip('/') or None,
        }
    return {
        'host': valores.get('MYSQL_HOST'),
        'port': int(valores.get('MYSQL_PORT') or 3306),
        'user': valores.get('MYSQL_USER'),
        'password': valores.get('MYSQL_PASSWORD') or '',
        'database': valores.get('MYSQL_DATABASE'),
    }


def _actualizar_env(nueva):
    lineas = ENV_PATH.read_text(encoding='utf-8').splitlines(keepends=True)
    salida = []
    for linea in lineas:
        clave = linea.split('=', 1)[0].strip()
        if clave == 'MYSQL_PASSWORD':
            linea = f'MYSQL_PASSWORD={nueva}\n'
        elif clave == 'MYSQL_URL':
            url = urlparse(linea.split('=', 1)[1].strip())
            netloc = f'{url.username}:{quote(nueva, safe="")}@{url.hostname}'
            if url.port:
                netloc += f':{url.port}'
            linea = f'MYSQL_URL={urlunparse(url._replace(netloc=netloc))}\n'
        salida.append(linea)
    ENV_PATH.write_text(''.join(salida), encoding='utf-8')


def main():
    conf = _conexion_desde_env(dotenv_values(ENV_PATH))
    print(f"Servidor: {conf['host']}:{conf['port']}  usuario: {conf['user']}")
    if input('Escriba CAMBIAR para continuar: ').strip() != 'CAMBIAR':
        print('Cancelado. No se cambió nada.')
        return 1

    # Solo letras y números: evita problemas de escape en URLs y en Railway.
    nueva = secrets.token_hex(20)

    conn = pymysql.connect(**conf, connect_timeout=15)
    try:
        with conn.cursor() as cur:
            cur.execute('ALTER USER CURRENT_USER() IDENTIFIED BY %s', (nueva,))
        conn.commit()
    finally:
        conn.close()
    print('Contraseña cambiada en MySQL.')

    prueba = dict(conf, password=nueva)
    pymysql.connect(**prueba, connect_timeout=15).close()
    print('Verificado: la contraseña nueva conecta.')

    _actualizar_env(nueva)
    print('.env local actualizado.')
    print('\n' + '=' * 60)
    print('CONTRASEÑA NUEVA (cópiela ahora en Railway):')
    print(nueva)
    print('=' * 60)
    return 0


if __name__ == '__main__':
    sys.exit(main())
