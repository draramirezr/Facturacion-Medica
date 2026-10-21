"""Primer ingreso: completar médico o empresa antes de operar."""

import re

from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from core.database import execute_query, execute_update
from core.tenant import get_current_tenant_id
from routes.support import (
    ESPECIALIDADES_MEDICAS,
    get_especialidad_form,
    sanitize_input,
    error_cedula,
    error_rnc,
    validate_digits,
    validate_email,
)
from services.onboarding import perfil_inicial_pendiente
from services.subscriptions import check_medico_catalog_limit

_ENDPOINTS_LIBRES = frozenset({
    'completar_perfil_inicial',
    'logout',
    'login',
    'registro',
    'static',
    'index',
    'cambiar_password_obligatorio',
    'cambiar_mi_password',
    'activar_cuenta',
    'solicitar_recuperacion',
    'recuperar_password',
    'confirmar_cambio_password',
    'confirmar_correo_empresa',
})


def _empresa_actual():
    tenant_id = get_current_tenant_id()
    if not tenant_id:
        return None
    return execute_query('SELECT * FROM empresas WHERE id=%s', (tenant_id,))


def _vincular_usuario(tenant_id, usuario_id, medico_id):
    execute_update(
        'DELETE FROM usuario_medico WHERE tenant_id=%s AND usuario_id=%s',
        (tenant_id, usuario_id),
    )
    execute_update(
        '''
        INSERT INTO usuario_medico (tenant_id, usuario_id, medico_id)
        VALUES (%s, %s, %s)
        ''',
        (tenant_id, usuario_id, medico_id),
    )


@login_required
def completar_perfil_inicial():
    pendiente = perfil_inicial_pendiente(current_user)
    if not pendiente:
        return redirect(url_for('facturacion_menu'))
    empresa = _empresa_actual()
    if not empresa:
        return redirect(url_for('facturacion_menu'))
    if request.method == 'GET':
        return render_template(
            'onboarding_perfil.html',
            empresa=empresa,
            pendiente=pendiente,
            especialidades=ESPECIALIDADES_MEDICAS,
            nombre_usuario=getattr(current_user, 'nombre', '') or '',
            email_usuario=getattr(current_user, 'email', '') or '',
        )
    tenant_id = empresa['id']
    if pendiente == 'medico':
        return _guardar_medico(tenant_id)
    return _guardar_centro(tenant_id)


def _guardar_medico(tenant_id):
    nombre = sanitize_input(request.form.get('nombre', ''), 200)
    especialidad = get_especialidad_form(request.form)
    cedula = re.sub(r'\D', '', request.form.get('cedula', '') or '')
    exequatur = sanitize_input(request.form.get('exequatur', ''), 10)
    telefono = re.sub(r'\D', '', request.form.get('telefono', '') or '')
    email = (getattr(current_user, 'email', '') or '').strip().lower()
    if not all((nombre, especialidad, cedula, exequatur, telefono, email)):
        flash('Complete todos los datos del médico para empezar.', 'error')
        return redirect(url_for('completar_perfil_inicial'))
    if len(exequatur) > 10:
        flash('El exequátur puede tener como máximo 10 caracteres.', 'error')
        return redirect(url_for('completar_perfil_inicial'))
    if not validate_digits(cedula, 11):
        flash('La cédula debe tener 11 números.', 'error')
        return redirect(url_for('completar_perfil_inicial'))
    if error_cedula(cedula):
        flash(error_cedula(cedula), 'error')
        return redirect(url_for('completar_perfil_inicial'))
    if not validate_digits(telefono, 10):
        flash('El teléfono debe tener 10 números.', 'error')
        return redirect(url_for('completar_perfil_inicial'))
    if not validate_email(email):
        flash('El correo del usuario no es válido.', 'error')
        return redirect(url_for('completar_perfil_inicial'))
    from services.identificadores import (
        error_medico_identificadores,
        error_rnc_en_otra_empresa,
    )
    repetido = (
        error_medico_identificadores(tenant_id, cedula, exequatur)
        or error_rnc_en_otra_empresa(cedula, tenant_id)
    )
    if repetido:
        flash(repetido, 'error')
        return redirect(url_for('completar_perfil_inicial'))
    ok_medico, _, _, msg_medico = check_medico_catalog_limit(tenant_id)
    if not ok_medico:
        flash(msg_medico, 'error')
        return redirect(url_for('completar_perfil_inicial'))
    medico_id = execute_update(
        '''
        INSERT INTO medicos (
            tenant_id, nombre, exequatur, especialidad, telefono, email,
            cedula, activo, factura
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, 1, 1)
        ''',
        (tenant_id, nombre, exequatur, especialidad, telefono, email, cedula),
    )
    if not medico_id:
        flash('No se pudo guardar el médico. Intente de nuevo.', 'error')
        return redirect(url_for('completar_perfil_inicial'))
    _vincular_usuario(tenant_id, current_user.id, medico_id)
    execute_update(
        '''
        UPDATE empresas
        SET rnc=%s, telefono=%s, email=%s
        WHERE id=%s
        ''',
        (cedula, telefono, email, tenant_id),
    )
    flash(
        'Médico registrado y vinculado a su usuario. Ya puede operar.',
        'success',
    )
    return redirect(url_for('facturacion_menu'))


def _guardar_centro(tenant_id):
    razon = sanitize_input(request.form.get('razon_social', ''), 255)
    rnc = re.sub(r'\D', '', request.form.get('rnc', '') or '')
    telefono = re.sub(r'\D', '', request.form.get('telefono', '') or '')
    direccion = sanitize_input(request.form.get('direccion', ''), 500)
    if not all((razon, rnc, telefono, direccion)):
        flash('Complete los datos del centro para empezar.', 'error')
        return redirect(url_for('completar_perfil_inicial'))
    if not validate_digits(rnc, 9):
        flash('El RNC debe tener 9 números, sin guiones.', 'error')
        return redirect(url_for('completar_perfil_inicial'))
    if error_rnc(rnc):
        flash(error_rnc(rnc), 'error')
        return redirect(url_for('completar_perfil_inicial'))
    if not validate_digits(telefono, 10):
        flash('El teléfono debe tener 10 números.', 'error')
        return redirect(url_for('completar_perfil_inicial'))
    from services.identificadores import error_rnc_en_otra_empresa
    repetido = error_rnc_en_otra_empresa(rnc, tenant_id)
    if repetido:
        flash(repetido, 'error')
        return redirect(url_for('completar_perfil_inicial'))
    execute_update(
        '''
        UPDATE empresas
        SET razon_social=%s, nombre=%s, rnc=%s, telefono=%s, direccion=%s
        WHERE id=%s
        ''',
        (razon, razon, rnc, telefono, direccion, tenant_id),
    )
    flash('Datos del centro guardados. Ya puede operar.', 'success')
    return redirect(url_for('facturacion_menu'))


def register_onboarding_routes(app):
    @app.before_request
    def _exigir_perfil_inicial():
        if not getattr(current_user, 'is_authenticated', False):
            return None
        endpoint = request.endpoint or ''
        if endpoint in _ENDPOINTS_LIBRES or endpoint.startswith('static'):
            return None
        if perfil_inicial_pendiente(current_user):
            return redirect(url_for('completar_perfil_inicial'))
        return None

    app.add_url_rule(
        '/empezar',
        'completar_perfil_inicial',
        completar_perfil_inicial,
        methods=['GET', 'POST'],
    )
