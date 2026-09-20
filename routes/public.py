"""Landing, reporte CSP y redirecciones públicas."""

import logging
from datetime import datetime

from flask import jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from core.extensions import csrf
from auth.helpers import usuario_es_dueno_software
from core.presentation import obtener_soporte
from core.security import rate_limit

logger = logging.getLogger(__name__)


@csrf.exempt
@rate_limit(max_requests=120, window=60)
def receive_csp_report():
    payload = request.get_json(silent=True) or {}
    report = payload.get('csp-report', payload)
    if isinstance(report, dict):
        logger.warning(
            'CSP report: directive=%s blocked=%s document=%s',
            report.get('effective-directive') or report.get('violated-directive'),
            report.get('blocked-uri'),
            report.get('document-uri'),
        )
    return '', 204


def index():
    return render_template('inicio.html', current_year=datetime.now().year)


def redirects():
    if current_user.is_authenticated:
        return redirect(url_for('facturacion_menu'))
    return redirect(url_for('login'))


@login_required
def centro_ayuda():
    """Manual del consultorio. El dueño del software no lo necesita."""
    if usuario_es_dueno_software(current_user):
        return redirect(url_for('admin_empresas'))
    destino = (obtener_soporte() or {}).get('manual_url') or ''
    if destino:
        return redirect(destino)
    return render_template('ayuda.html')


def register_public_routes(app):
    app.add_url_rule(
        '/api/csp-report',
        'receive_csp_report',
        receive_csp_report,
        methods=['POST'],
    )
    app.add_url_rule('/', 'index', index)
    app.add_url_rule('/ayuda', 'centro_ayuda', centro_ayuda)
    for path in ('/services', '/about', '/contact', '/request-appointment'):
        app.add_url_rule(path, 'redirects', redirects)
