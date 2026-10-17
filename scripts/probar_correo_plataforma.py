#!/usr/bin/env python3
"""
Prueba el correo de plataforma (ZeptoMail API / SMTP) sin commit ni deploy.

Uso:
  py scripts/probar_correo_plataforma.py tu@correo.com
  py scripts/probar_correo_plataforma.py --solo-config

Variables en .env (raíz del proyecto):
  ZEPTOMAIL_API_KEY, ZOHO_FROM_EMAIL, APP_BASE_URL (para prueba de activación)
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

load_dotenv(ROOT / '.env')


def _mostrar_config():
    from services.platform_mail import (
        _config_zoho,
        _preferir_api,
        _zeptomail_api_url,
        _zeptomail_token,
        plataforma_correo_configurado,
    )

    cfg = _config_zoho()
    token = _zeptomail_token()
    print('--- Configuración correo plataforma ---')
    print('Listo para enviar:', plataforma_correo_configurado())
    print('Modo preferido:', 'API' if _preferir_api() else 'SMTP')
    print('API URL:', _zeptomail_api_url())
    print('Zepto token:', 'sí' if token else 'no')
    print('From:', cfg.get('remitente') or '(vacío)')
    print('SMTP host:', cfg.get('host'), 'puerto:', cfg.get('port'))
    print('SMTP user:', cfg.get('usuario') or '(vacío)')
    print('SMTP password:', 'sí' if cfg.get('password') else 'no')
    print('APP_BASE_URL:', os.getenv('APP_BASE_URL', '') or '(no definida)')


def _enviar_prueba(destino):
    from services.platform_mail import enviar_correo_plataforma

    ok, detalle = enviar_correo_plataforma(
        destino,
        'Prueba ClinicRD (script local)',
        (
            '<p>Si ves este mensaje, ZeptoMail / SMTP de plataforma funciona.</p>'
            '<p>Puedes hacer commit y deploy con confianza.</p>'
        ),
    )
    return ok, detalle


def _probar_enlace_activacion():
    os.environ.setdefault('SECRET_KEY', 'solo-prueba-local-no-produccion')
    from app import create_app

    app = create_app()
    with app.app_context():
        from services.account_activation import (
            enviar_correo_activacion_demo,
            url_activacion_cuenta,
        )

        token = 'token-de-prueba-no-valido-en-bd'
        try:
            enlace = url_activacion_cuenta(token)
        except Exception as error:
            print('Enlace activación: ERROR —', error)
            return False
        print('Enlace activación (muestra):', enlace)
        dest = os.getenv('TEST_EMAIL', '').strip()
        if not dest:
            print('Defina TEST_EMAIL en .env para enviar correo de activación demo.')
            return True
        ok, detalle = enviar_correo_activacion_demo(
            'Usuario prueba', dest, 'token-de-prueba-no-valido',
        )
        print('Envío activación demo:', 'OK' if ok else 'FALLO', detalle)
        return ok


def main():
    if '--solo-config' in sys.argv:
        _mostrar_config()
        return 0

    if '--activacion' in sys.argv:
        _mostrar_config()
        print()
        return 0 if _probar_enlace_activacion() else 1

    destino = ''
    for arg in sys.argv[1:]:
        if arg.startswith('-'):
            continue
        destino = arg.strip()
        break
    destino = destino or os.getenv('TEST_EMAIL', '').strip()
    if not destino:
        print(__doc__)
        return 1

    _mostrar_config()
    print()
    ok, detalle = _enviar_prueba(destino)
    print('Resultado:', 'OK' if ok else 'FALLO')
    print(detalle)
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
