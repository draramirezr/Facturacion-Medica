"""Landing, reporte CSP y redirecciones públicas."""

import logging
import os
from datetime import datetime

from flask import Response, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from markupsafe import escape

from core.extensions import csrf
from auth.helpers import usuario_es_dueno_software
from core.config import url_publica_base
from core.presentation import obtener_soporte
from core.security import rate_limit
from routes.support import sanitize_input, validate_email
from services.platform import registrar_vista_pagina

logger = logging.getLogger(__name__)

try:
    from sendgrid import SendGridAPIClient
    from sendgrid.helpers.mail import Mail

    SENDGRID_AVAILABLE = True
except ImportError:
    SENDGRID_AVAILABLE = False


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
    registrar_vista_pagina('index')
    return render_template('inicio.html', current_year=datetime.now().year)


def redirects():
    destinos = {
        '/contact': '/#contacto',
        '/about': '/#beneficios',
        '/services': '/#beneficios',
        '/request-appointment': '/#contacto',
    }
    return redirect(destinos.get(request.path, '/'), code=301)


def robots_txt():
    base = (url_publica_base() or 'https://www.clinicrd.com').rstrip('/')
    cuerpo = (
        'User-agent: *\n'
        'Allow: /\n'
        'Disallow: /login\n'
        'Disallow: /registro\n'
        'Disallow: /recuperar-password\n'
        'Disallow: /solicitar-recuperacion\n'
        'Disallow: /facturacion\n'
        'Disallow: /admin\n'
        'Disallow: /ayuda\n'
        'Disallow: /api/\n'
        'Disallow: /mi-cuenta\n'
        'Disallow: /perfil\n'
        'Disallow: /turnos\n'
        f'\nSitemap: {base}/sitemap.xml\n'
    )
    return Response(cuerpo, mimetype='text/plain; charset=utf-8')


def sitemap_xml():
    base = (url_publica_base() or 'https://www.clinicrd.com').rstrip('/')
    hoy = datetime.now().date().isoformat()
    cuerpo = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        '  <url>\n'
        f'    <loc>{base}/</loc>\n'
        f'    <lastmod>{hoy}</lastmod>\n'
        '    <changefreq>weekly</changefreq>\n'
        '    <priority>1.0</priority>\n'
        '  </url>\n'
        '</urlset>\n'
    )
    return Response(cuerpo, mimetype='application/xml; charset=utf-8')


@rate_limit(max_requests=5, window=300)
def enviar_contacto():
    """Recibir un mensaje público y enviarlo al correo de soporte."""
    if request.method == 'GET':
        return redirect(url_for('index', _anchor='contacto'))
    nombre = sanitize_input(request.form.get('nombre', ''), 100)
    email = (request.form.get('email') or '').strip().lower()
    mensaje = sanitize_input(request.form.get('mensaje', ''), 2000)
    if not all((nombre, email, mensaje)):
        flash('Completa nombre, correo y mensaje para escribirnos.', 'error')
        return redirect(url_for('index', _anchor='contacto'))
    if not validate_email(email):
        flash('Ingresa un correo electrónico válido.', 'error')
        return redirect(url_for('index', _anchor='contacto'))
    soporte = obtener_soporte()
    if not SENDGRID_AVAILABLE or not os.getenv('SENDGRID_API_KEY', '').strip():
        logger.warning('Contacto de %s no enviado: falta SendGrid', email)
        flash(
            f'Ahora mismo no se pudo enviar el correo. Escríbenos a '
            f'{soporte["email"]} o llama al {soporte["telefono"]}.',
            'error',
        )
        return redirect(url_for('index', _anchor='contacto'))
    try:
        cuerpo = (
            f'<p><strong>Nombre:</strong> {escape(nombre)}</p>'
            f'<p><strong>Correo:</strong> {escape(email)}</p>'
            f'<p><strong>Mensaje:</strong></p>'
            f'<p>{escape(mensaje).replace(chr(10), "<br>")}</p>'
        )
        correo = Mail(
            from_email=os.getenv('SENDGRID_FROM_EMAIL', 'noreply@clinicrd.com'),
            to_emails=soporte['email'],
            subject=f'Contacto ClinicRD · {nombre}',
            html_content=cuerpo,
        )
        correo.reply_to = email
        SendGridAPIClient(os.getenv('SENDGRID_API_KEY')).send(correo)
        flash('Recibimos tu mensaje. Te escribimos pronto.', 'success')
    except Exception as error:
        logger.error('Error enviando contacto: %s', error)
        flash(
            f'No se pudo enviar el mensaje. Escríbenos a {soporte["email"]} '
            f'o llama al {soporte["telefono"]}.',
            'error',
        )
    return redirect(url_for('index', _anchor='contacto'))


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
    app.add_url_rule('/robots.txt', 'robots_txt', robots_txt)
    app.add_url_rule('/sitemap.xml', 'sitemap_xml', sitemap_xml)
    app.add_url_rule(
        '/contacto',
        'enviar_contacto',
        enviar_contacto,
        methods=['GET', 'POST'],
    )
    app.add_url_rule('/ayuda', 'centro_ayuda', centro_ayuda)
    for path in ('/services', '/about', '/contact', '/request-appointment'):
        app.add_url_rule(path, 'redirects', redirects)
