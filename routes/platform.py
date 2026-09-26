"""Rutas del dueño de ClinicRD: demos, facturas y alertas."""

from datetime import date, timedelta
from functools import wraps

from flask import flash, redirect, render_template, request, send_file, url_for
from flask_login import current_user, login_required

from auth.helpers import usuario_es_dueno_software
from core.security import rate_limit
from routes.support import sanitize_input, validate_digits, validate_email
from services.platform import (
    DEMO_DIAS,
    PLAN_LICENCIAS,
    PLAN_PRECIOS,
    activar_demo_solicitud,
    alertas_licencias,
    asegurar_tablas_plataforma,
    cambiar_estado_factura_plataforma,
    crear_factura_plataforma,
    dar_de_alta_empresa,
    descartar_solicitud_demo,
    empresas_pendientes_pago,
    enviar_factura_plataforma_por_correo,
    generar_pdf_factura_plataforma,
    habilitar_demo_empresa,
    obtener_factura_plataforma,
    listar_empresas_activas,
    listar_solicitudes_demo,
    registrar_solicitud_demo,
    resumen_facturacion_plataforma,
    resumen_visitas_pagina,
)


def _solo_dueno(func):
    @wraps(func)
    @login_required
    def wrapper(*args, **kwargs):
        if not usuario_es_dueno_software(current_user):
            flash('Solo el dueño de ClinicRD puede usar esta función.', 'error')
            return redirect(url_for('admin_empresas'))
        asegurar_tablas_plataforma()
        return func(*args, **kwargs)

    return wrapper


@rate_limit(max_requests=5, window=300)
def solicitar_demo():
    if request.method == 'GET':
        return redirect(url_for('index', _anchor='contacto'))
    asegurar_tablas_plataforma()
    nombre = sanitize_input(request.form.get('nombre', ''), 100)
    email = request.form.get('email', '').strip().lower()
    telefono = sanitize_input(request.form.get('telefono', ''), 20)
    nombre_empresa = sanitize_input(request.form.get('nombre_empresa', ''), 255)
    tipo_empresa = request.form.get('tipo_empresa', 'medico').strip()
    mensaje = sanitize_input(request.form.get('mensaje', ''), 1000)
    if not all((nombre, email, telefono, nombre_empresa)):
        flash('Completa nombre, correo, teléfono y empresa para solicitar el demo.', 'error')
        return redirect(url_for('index', _anchor='contacto'))
    if not validate_email(email):
        flash('Ingresa un correo electrónico válido.', 'error')
        return redirect(url_for('index', _anchor='contacto'))
    if not validate_digits(telefono, 10):
        flash('El teléfono debe tener 10 números.', 'error')
        return redirect(url_for('index', _anchor='contacto'))
    if tipo_empresa not in ('medico', 'centro_salud'):
        tipo_empresa = 'medico'
    registrar_solicitud_demo({
        'nombre': nombre,
        'email': email,
        'telefono': telefono,
        'nombre_empresa': nombre_empresa,
        'tipo_empresa': tipo_empresa,
        'mensaje': mensaje,
    })
    flash(
        'Recibimos tu solicitud de demo. Te contactamos para activar 7 días.',
        'success',
    )
    return redirect(url_for('index', _anchor='contacto'))


@_solo_dueno
def plataforma_alertas():
    return render_template(
        'admin/plataforma/alertas.html',
        alertas=alertas_licencias(),
        demo_dias=DEMO_DIAS,
    )


@_solo_dueno
def plataforma_demos():
    estado = request.args.get('estado', '').strip()
    return render_template(
        'admin/plataforma/demos.html',
        solicitudes=listar_solicitudes_demo(estado or None),
        estado=estado,
        demo_dias=DEMO_DIAS,
    )


@_solo_dueno
def plataforma_demo_activar(solicitud_id):
    try:
        resultado = activar_demo_solicitud(solicitud_id)
    except Exception:
        flash('No se pudo activar el demo. Revisa si el correo o la empresa ya existen.', 'error')
        return redirect(url_for('plataforma_demos'))
    if not resultado:
        flash('Esa solicitud ya no está pendiente.', 'error')
        return redirect(url_for('plataforma_demos'))
    if resultado.get('clave'):
        flash(
            f"Demo de {DEMO_DIAS} días activo. Usuario {resultado['email']} "
            f"clave temporal {resultado['clave']}",
            'success',
        )
    else:
        flash(
            f"Demo de {DEMO_DIAS} días reactivado para {resultado['email']}.",
            'success',
        )
    return redirect(url_for('plataforma_demos'))


@_solo_dueno
def plataforma_demo_descartar(solicitud_id):
    descartar_solicitud_demo(solicitud_id)
    flash('Solicitud descartada.', 'info')
    return redirect(url_for('plataforma_demos'))


@_solo_dueno
def plataforma_empresa_demo(empresa_id):
    if habilitar_demo_empresa(empresa_id):
        flash(f'Demo de {DEMO_DIAS} días habilitado para esa empresa.', 'success')
    else:
        flash('Empresa no encontrada.', 'error')
    return redirect(request.referrer or url_for('admin_empresas'))


@_solo_dueno
def plataforma_empresa_alta(empresa_id):
    from core.database import execute_query
    empresa = execute_query('SELECT * FROM empresas WHERE id=%s', (empresa_id,))
    if not empresa:
        flash('Empresa no encontrada.', 'error')
        return redirect(url_for('admin_empresas'))
    if request.method == 'GET':
        return render_template(
            'admin/plataforma/alta.html',
            empresa=empresa,
            precios=PLAN_PRECIOS,
            licencias=PLAN_LICENCIAS,
        )
    plan = request.form.get('plan', empresa.get('plan') or 'basico').strip()
    meses = 12 if request.form.get('meses') == '12' else 1
    crear_factura = request.form.get('crear_factura') == '1'
    resultado = dar_de_alta_empresa(
        empresa_id,
        plan=plan,
        meses=meses,
        crear_factura=crear_factura,
        creado_por=current_user.id,
    )
    if not resultado:
        flash('No se pudo dar de alta a esa empresa.', 'error')
        return redirect(url_for('admin_empresas'))
    flash(
        f"{empresa['nombre']} quedó de alta hasta {resultado['fecha_fin']}.",
        'success',
    )
    if resultado.get('factura_id'):
        return redirect(url_for('plataforma_facturas'))
    return redirect(url_for('admin_empresas'))


@_solo_dueno
def plataforma_facturas():
    filtros = {
        'estado': request.args.get('estado', '').strip(),
        'desde': request.args.get('desde', '').strip(),
        'hasta': request.args.get('hasta', '').strip(),
        'empresa_id': request.args.get('empresa_id', type=int),
    }
    facturas, resumen = resumen_facturacion_plataforma({
        key: value for key, value in filtros.items() if value
    })
    return render_template(
        'admin/plataforma/facturas.html',
        facturas=facturas,
        resumen=resumen,
        filtros=filtros,
        precios=PLAN_PRECIOS,
    )


@_solo_dueno
def plataforma_factura_nueva():
    empresas = listar_empresas_activas()
    if request.method == 'GET':
        empresa_id = request.args.get('empresa_id', type=int)
        empresa = next((item for item in empresas if item['id'] == empresa_id), None)
        plan = (empresa or {}).get('plan') or 'basico'
        hoy = date.today()
        return render_template(
            'admin/plataforma/factura_form.html',
            empresas=empresas,
            empresa_id=empresa_id,
            valores={
                'fecha': hoy.isoformat(),
                'periodo_inicio': hoy.replace(day=1).isoformat(),
                'periodo_fin': hoy.isoformat(),
                'plan': plan,
                'licencias': PLAN_LICENCIAS.get(plan, 1),
                'monto': PLAN_PRECIOS.get(plan, 995),
                'notas': '',
            },
            precios=PLAN_PRECIOS,
        )
    empresa_id = request.form.get('empresa_id', type=int)
    plan = request.form.get('plan', 'basico').strip()
    if plan not in PLAN_PRECIOS or not empresa_id:
        flash('Selecciona una empresa y un plan válidos.', 'error')
        return redirect(url_for('plataforma_factura_nueva'))
    try:
        monto = float(request.form.get('monto') or PLAN_PRECIOS[plan])
        licencias = int(request.form.get('licencias') or PLAN_LICENCIAS[plan])
    except (TypeError, ValueError):
        flash('Monto o licencias inválidos.', 'error')
        return redirect(url_for('plataforma_factura_nueva'))
    crear_factura_plataforma(
        {
            'empresa_id': empresa_id,
            'fecha': request.form.get('fecha') or date.today().isoformat(),
            'periodo_inicio': request.form.get('periodo_inicio') or date.today().isoformat(),
            'periodo_fin': request.form.get('periodo_fin') or date.today().isoformat(),
            'plan': plan,
            'licencias': max(licencias, 1),
            'monto': monto,
            'notas': sanitize_input(request.form.get('notas', ''), 500),
        },
        creado_por=current_user.id,
    )
    flash('Factura de cliente creada.', 'success')
    return redirect(url_for('plataforma_facturas'))


@_solo_dueno
def plataforma_factura_estado(factura_id, estado):
    if cambiar_estado_factura_plataforma(factura_id, estado):
        flash(f'Factura marcada como {estado}.', 'success')
    else:
        flash('No se pudo actualizar la factura.', 'error')
    return redirect(url_for('plataforma_facturas'))


@_solo_dueno
def plataforma_factura_pdf(factura_id):
    factura = obtener_factura_plataforma(factura_id)
    if not factura:
        flash('Factura no encontrada.', 'error')
        return redirect(url_for('plataforma_facturas'))
    try:
        pdf = generar_pdf_factura_plataforma(factura)
    except Exception:
        flash('No se pudo generar el PDF de la factura.', 'error')
        return redirect(url_for('plataforma_facturas'))
    nombre = f"{factura.get('numero') or factura_id}.pdf"
    return send_file(
        pdf,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=nombre,
    )


@_solo_dueno
def plataforma_factura_enviar(factura_id):
    factura = obtener_factura_plataforma(factura_id)
    if not factura:
        flash('Factura no encontrada.', 'error')
        return redirect(url_for('plataforma_facturas'))
    correo = sanitize_input(
        request.form.get('correo', factura.get('empresa_email') or ''),
        100,
    ).strip().lower()
    ok, detalle = enviar_factura_plataforma_por_correo(factura, correo)
    if ok:
        flash(f'Factura enviada a {detalle}.', 'success')
    else:
        flash(detalle, 'error')
    return redirect(url_for('plataforma_facturas'))


@_solo_dueno
def plataforma_reportes():
    hoy = date.today()
    filtros = {
        'desde': request.args.get('desde', (hoy - timedelta(days=30)).isoformat()),
        'hasta': request.args.get('hasta', hoy.isoformat()),
        'estado': request.args.get('estado', '').strip(),
    }
    facturas, resumen = resumen_facturacion_plataforma({
        key: value for key, value in filtros.items() if value
    })
    deudoras = empresas_pendientes_pago()
    resumen['empresas_deudoras'] = len(deudoras)
    resumen['monto_deudoras'] = sum(
        float(item.get('monto_pendiente') or 0) for item in deudoras
    )
    visitas = resumen_visitas_pagina(30)
    return render_template(
        'admin/plataforma/reportes.html',
        facturas=facturas,
        resumen=resumen,
        filtros=filtros,
        deudoras=deudoras,
        visitas=visitas,
    )


def register_platform_routes(app):
    app.add_url_rule(
        '/solicitar-demo', 'solicitar_demo', solicitar_demo,
        methods=['GET', 'POST'],
    )
    app.add_url_rule(
        '/admin/plataforma/alertas', 'plataforma_alertas', plataforma_alertas,
    )
    app.add_url_rule(
        '/admin/plataforma/demos', 'plataforma_demos', plataforma_demos,
    )
    app.add_url_rule(
        '/admin/plataforma/demos/<int:solicitud_id>/activar',
        'plataforma_demo_activar', plataforma_demo_activar,
        methods=['POST'],
    )
    app.add_url_rule(
        '/admin/plataforma/demos/<int:solicitud_id>/descartar',
        'plataforma_demo_descartar', plataforma_demo_descartar,
        methods=['POST'],
    )
    app.add_url_rule(
        '/admin/empresas/<int:empresa_id>/demo-7',
        'plataforma_empresa_demo', plataforma_empresa_demo,
        methods=['POST'],
    )
    app.add_url_rule(
        '/admin/empresas/<int:empresa_id>/alta',
        'plataforma_empresa_alta', plataforma_empresa_alta,
        methods=['GET', 'POST'],
    )
    app.add_url_rule(
        '/admin/plataforma/facturas', 'plataforma_facturas', plataforma_facturas,
    )
    app.add_url_rule(
        '/admin/plataforma/facturas/nueva', 'plataforma_factura_nueva',
        plataforma_factura_nueva, methods=['GET', 'POST'],
    )
    app.add_url_rule(
        '/admin/plataforma/facturas/<int:factura_id>/pdf',
        'plataforma_factura_pdf', plataforma_factura_pdf,
    )
    app.add_url_rule(
        '/admin/plataforma/facturas/<int:factura_id>/enviar',
        'plataforma_factura_enviar', plataforma_factura_enviar,
        methods=['POST'],
    )
    app.add_url_rule(
        '/admin/plataforma/facturas/<int:factura_id>/<any(pagada, anulada, pendiente):estado>',
        'plataforma_factura_estado', plataforma_factura_estado,
        methods=['POST'],
    )
    app.add_url_rule(
        '/admin/plataforma/reportes', 'plataforma_reportes', plataforma_reportes,
    )
