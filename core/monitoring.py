"""Monitoreo de errores con Sentry (opcional).

Solo se activa si existe la variable SENTRY_DSN. La app maneja datos
clínicos y fiscales, así que a Sentry solo viaja el error técnico:
sin cuerpo de formularios, cookies, cabeceras, query string ni datos del
usuario más allá de su id interno y el id de la empresa.
"""

import logging
import os

logger = logging.getLogger(__name__)

_CAMPOS_REQUEST_PERMITIDOS = ('url', 'method')


def _sin_datos_sensibles(event, _hint):
    request = event.get('request')
    if isinstance(request, dict):
        # La URL sin query string (puede llevar cédulas, NSS o tokens).
        url = (request.get('url') or '').split('?', 1)[0]
        event['request'] = {
            clave: (url if clave == 'url' else request.get(clave))
            for clave in _CAMPOS_REQUEST_PERMITIDOS
            if request.get(clave) is not None
        }
    usuario = event.get('user')
    if isinstance(usuario, dict):
        event['user'] = {'id': usuario.get('id')} if usuario.get('id') else {}
    # Variables locales de cada frame: pueden contener datos de pacientes.
    for excepcion in (event.get('exception') or {}).get('values') or []:
        for frame in (excepcion.get('stacktrace') or {}).get('frames') or []:
            frame.pop('vars', None)
    event.pop('breadcrumbs', None)
    return event


def _etiquetar_usuario():
    try:
        import sentry_sdk
        from flask_login import current_user

        if getattr(current_user, 'is_authenticated', False):
            sentry_sdk.set_user({'id': str(current_user.get_id())})
            sentry_sdk.set_tag('tenant_id', str(getattr(current_user, 'tenant_id', '') or ''))
    except Exception:  # El monitoreo nunca debe romper una petición.
        pass


def init_monitoring(flask_app):
    dsn = (os.getenv('SENTRY_DSN') or '').strip()
    if not dsn:
        return False
    try:
        import sentry_sdk
        from sentry_sdk.integrations.flask import FlaskIntegration
    except ImportError:
        logger.warning('SENTRY_DSN definido pero sentry-sdk no está instalado')
        return False
    sentry_sdk.init(
        dsn=dsn,
        integrations=[FlaskIntegration()],
        environment=os.getenv('SENTRY_ENVIRONMENT')
        or os.getenv('RAILWAY_ENVIRONMENT_NAME')
        or os.getenv('FLASK_ENV', 'production'),
        release=os.getenv('RAILWAY_GIT_COMMIT_SHA') or None,
        send_default_pii=False,
        include_local_variables=False,
        max_request_body_size='never',
        traces_sample_rate=0.0,
        before_send=_sin_datos_sensibles,
    )
    flask_app.before_request(_etiquetar_usuario)
    logger.info('Monitoreo de errores (Sentry) activo')
    return True
