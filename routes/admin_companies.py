"""Administración de empresas y diagnóstico multiempresa."""

import logging
from datetime import date, datetime

from flask import flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from core.config import REQUIRED_TENANT_TABLES
from core.database import execute_query, execute_update
from core.tenant import get_current_tenant_id
from routes.support import sanitize_input, validate_digits, validate_email, validate_int
from services.subscriptions import verificar_suscripciones_vencidas

logger = logging.getLogger(__name__)


@login_required
def admin_empresas():
    if current_user.perfil != 'Administrador':
        flash('No tienes permisos para gestionar empresas', 'error')
        return redirect(url_for('facturacion_menu'))
    tenant_id = get_current_tenant_id()
    if tenant_id is None:
        empresas = execute_query(
            """
            SELECT e.*, COUNT(u.id) AS total_usuarios
            FROM empresas e
            LEFT JOIN usuarios u ON e.id=u.tenant_id AND u.activo=1
            GROUP BY e.id ORDER BY e.fecha_creacion DESC
            """,
            fetch='all',
        )
    else:
        empresas = execute_query(
            """
            SELECT e.*, COUNT(u.id) AS total_usuarios
            FROM empresas e
            LEFT JOIN usuarios u ON e.id=u.tenant_id AND u.activo=1
            WHERE e.id = %s GROUP BY e.id ORDER BY e.fecha_creacion DESC
            """,
            (tenant_id,),
            fetch='all',
        ) or []
    suspendidas = verificar_suscripciones_vencidas()
    if suspendidas > 0:
        flash(
            f'{suspendidas} empresa(s) suspendida(s) por vencimiento '
            'de suscripción',
            'warning',
        )
    for empresa in empresas:
        _decorate_subscription(empresa)
    return render_template('admin/empresas/lista.html', empresas=empresas)


def _decorate_subscription(empresa):
    fecha_fin = empresa.get('fecha_fin')
    if not fecha_fin:
        empresa.update(
            dias_restantes=None,
            estado_suscripcion='sin_fecha',
            estado_texto='Sin fecha',
            estado_clase='secondary',
            estado_icono='calendar',
        )
        return
    try:
        if isinstance(fecha_fin, str):
            fecha_fin = datetime.strptime(fecha_fin, '%Y-%m-%d').date()
        dias = (fecha_fin - date.today()).days
        empresa['dias_restantes'] = dias
        if dias < 0:
            values = ('vencida', 'VENCIDA', 'danger', 'exclamation-circle')
        elif dias <= 7:
            values = ('urgente', f'{dias}d - URGENTE', 'danger', 'exclamation-triangle')
        elif dias <= 30:
            values = ('proximo', f'{dias} días', 'warning', 'clock')
        else:
            values = ('vigente', f'{dias} días', 'success', 'check-circle')
        (
            empresa['estado_suscripcion'],
            empresa['estado_texto'],
            empresa['estado_clase'],
            empresa['estado_icono'],
        ) = values
    except (TypeError, ValueError):
        empresa.update(
            dias_restantes=None,
            estado_suscripcion='error',
            estado_texto='Error',
            estado_clase='secondary',
            estado_icono='question',
        )


def _company_form_values():
    return {
        'nombre': sanitize_input(request.form.get('nombre', ''), 255),
        'razon_social': sanitize_input(request.form.get('razon_social', ''), 255),
        'rnc': sanitize_input(request.form.get('rnc', ''), 20),
        'telefono': sanitize_input(request.form.get('telefono', ''), 20),
        'email': request.form.get('email', '').strip().lower(),
        'direccion': sanitize_input(request.form.get('direccion', ''), 500),
        'fecha_inicio': request.form.get('fecha_inicio'),
        'fecha_fin': request.form.get('fecha_fin'),
        'licencias_totales': validate_int(
            request.form.get('licencias_totales', '').strip(),
            min_value=1,
            max_value=1000,
            default=None,
        ),
        'plan': request.form.get('plan', '').strip(),
        'tipo_empresa': request.form.get('tipo_empresa', '').strip(),
        'estado': request.form.get('estado', '').strip(),
    }


def _validate_company(values, editing=False):
    if values['tipo_empresa'] not in ('medico', 'centro_salud'):
        return 'Tipo de empresa inválido'
    required = (
        'nombre', 'razon_social', 'rnc', 'telefono', 'email', 'direccion',
        'fecha_inicio', 'fecha_fin', 'licencias_totales', 'plan',
    )
    if editing:
        required += ('estado',)
    if any(values[key] in (None, '') for key in required):
        return 'Todos los campos son obligatorios'
    document_length = 11 if values['tipo_empresa'] == 'medico' else 9
    if not validate_digits(values['rnc'], document_length):
        name = 'cédula' if document_length == 11 else 'RNC'
        return f'La {name} debe contener exactamente {document_length} números'
    if not validate_digits(values['telefono'], 10):
        return 'El teléfono debe contener exactamente 10 números'
    if not validate_email(values['email']):
        return 'Debe introducir un email válido'
    if values['plan'] not in ('basico', 'profesional', 'empresarial'):
        return 'Debe seleccionar un plan válido'
    if editing and values['estado'] not in ('activo', 'suspendido', 'inactivo'):
        return 'Debe seleccionar un estado válido'
    try:
        start = datetime.strptime(values['fecha_inicio'], '%Y-%m-%d').date()
        end = datetime.strptime(values['fecha_fin'], '%Y-%m-%d').date()
        if end <= start:
            return 'La fecha de fin debe ser posterior a la fecha de inicio'
        if editing and end < date.today() and values['estado'] == 'activo':
            values['estado'] = 'suspendido'
            flash(
                'La fecha de fin ya venció. El estado se cambió a '
                '"suspendido" automáticamente.',
                'warning',
            )
    except ValueError:
        return 'Fechas inválidas'
    return None


@login_required
def admin_empresas_nueva():
    if get_current_tenant_id() is not None:
        flash(
            'No tienes permisos para crear empresas. Solo Super '
            'Administradores pueden crear nuevas empresas.',
            'error',
        )
        return redirect(url_for('admin_empresas'))
    if current_user.perfil != 'Administrador':
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_menu'))
    if request.method == 'GET':
        return render_template('admin/empresas/form.html', empresa=None)
    values = _company_form_values()
    error = _validate_company(values)
    if error:
        flash(error, 'error')
        return redirect(url_for('admin_empresas_nueva'))
    if execute_query('SELECT id FROM empresas WHERE nombre=%s', (values['nombre'],)):
        flash('Ya existe una empresa con ese nombre', 'error')
        return redirect(url_for('admin_empresas_nueva'))
    execute_update(
        """
        INSERT INTO empresas (
            nombre, razon_social, rnc, telefono, email, direccion,
            fecha_inicio, fecha_fin, licencias_totales, licencias_usadas,
            plan, estado, tipo_empresa, creado_por
        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,0,%s,'activo',%s,%s)
        """,
        (
            values['nombre'], values['razon_social'], values['rnc'],
            values['telefono'], values['email'], values['direccion'],
            values['fecha_inicio'], values['fecha_fin'],
            values['licencias_totales'], values['plan'],
            values['tipo_empresa'], current_user.id,
        ),
    )
    flash(f'Empresa "{values["nombre"]}" creada exitosamente', 'success')
    return redirect(url_for('admin_empresas'))


@login_required
def admin_empresas_editar(empresa_id):
    if current_user.perfil != 'Administrador':
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_menu'))
    tenant_id = get_current_tenant_id()
    empresa = execute_query('SELECT * FROM empresas WHERE id=%s', (empresa_id,))
    if not empresa:
        flash('Empresa no encontrada', 'error')
        return redirect(url_for('admin_empresas'))
    if tenant_id is not None and empresa['id'] != tenant_id:
        flash(
            'No tienes permisos para editar esta empresa. Solo puedes editar '
            'tu propia empresa.',
            'error',
        )
        return redirect(url_for('admin_empresas'))
    if request.method == 'GET':
        return render_template('admin/empresas/form.html', empresa=empresa)
    values = _company_form_values()
    error = _validate_company(values, editing=True)
    if error:
        flash(error, 'error')
        return redirect(url_for('admin_empresas_editar', empresa_id=empresa_id))
    execute_update(
        """
        UPDATE empresas SET nombre=%s, razon_social=%s, rnc=%s,
            telefono=%s, email=%s, direccion=%s, fecha_inicio=%s,
            fecha_fin=%s, licencias_totales=%s, plan=%s, estado=%s,
            tipo_empresa=%s WHERE id=%s
        """,
        (
            values['nombre'], values['razon_social'], values['rnc'],
            values['telefono'], values['email'], values['direccion'],
            values['fecha_inicio'], values['fecha_fin'],
            values['licencias_totales'], values['plan'], values['estado'],
            values['tipo_empresa'], empresa_id,
        ),
    )
    flash(f'Empresa "{values["nombre"]}" actualizada exitosamente', 'success')
    return redirect(url_for('admin_empresas'))


@login_required
def verificar_multitenant():
    if current_user.perfil != 'Administrador':
        return jsonify({'error': 'No tienes permisos'}), 403
    result = {
        'titulo': 'VERIFICACIÓN SISTEMA MULTI-TENANT',
        'fecha': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'estado_general': 'OK',
        'errores': [],
        'advertencias': [],
        'detalles': {},
    }
    try:
        empresas = execute_query('SELECT COUNT(*) AS total FROM empresas')
        result['detalles']['tabla_empresas'] = {
            'existe': True,
            'total_empresas': empresas['total'],
        }
        default = execute_query('SELECT * FROM empresas WHERE id=1')
        if default:
            result['detalles']['empresa_default'] = {
                'existe': True,
                'nombre': default['nombre'],
                'licencias_totales': default['licencias_totales'],
                'licencias_usadas': default['licencias_usadas'],
                'licencias_disponibles': (
                    default['licencias_totales'] - default['licencias_usadas']
                ),
                'plan': default['plan'],
                'estado': default['estado'],
            }
        else:
            result['advertencias'].append(
                'No existe empresa con ID=1 (empresa por defecto)',
            )
        ok, missing = [], []
        for table in REQUIRED_TENANT_TABLES:
            try:
                if execute_query(f"SHOW COLUMNS FROM {table} LIKE 'tenant_id'"):
                    ok.append(table)
                else:
                    missing.append(table)
                    result['errores'].append(
                        f'Tabla {table} NO tiene columna tenant_id',
                    )
            except Exception as error:
                missing.append(table)
                result['errores'].append(
                    f'Error verificando tabla {table}: {error}',
                )
        result['detalles']['columnas_tenant_id'] = {
            'total_tablas': len(REQUIRED_TENANT_TABLES),
            'tablas_ok': len(ok),
            'tablas_faltantes': len(missing),
            'lista_ok': ok,
            'lista_faltantes': missing,
        }
        without_tenant = execute_query(
            'SELECT COUNT(*) AS total FROM usuarios '
            'WHERE tenant_id IS NULL OR tenant_id=0',
        )
        if without_tenant and without_tenant['total'] > 0:
            result['advertencias'].append(
                f'{without_tenant["total"]} usuarios sin tenant_id asignado',
            )
        users = execute_query(
            'SELECT tenant_id, COUNT(*) AS total FROM usuarios '
            'WHERE activo=1 GROUP BY tenant_id',
            fetch='all',
        ) or []
        result['detalles']['usuarios_por_tenant'] = [
            {'tenant_id': user['tenant_id'], 'total': user['total']}
            for user in users
        ]
        triggers = execute_query(
            "SHOW TRIGGERS WHERE `Trigger` LIKE 'trg_usuarios_%'",
            fetch='all',
        ) or []
        result['detalles']['triggers'] = {
            'total': len(triggers),
            'esperados': 3,
            'ok': len(triggers) == 3,
            'lista': [trigger['Trigger'] for trigger in triggers],
        }
        if len(triggers) < 3:
            result['advertencias'].append(
                f'Solo {len(triggers)}/3 triggers encontrados',
            )
        indexes = execute_query(
            """
            SELECT TABLE_NAME, INDEX_NAME FROM information_schema.STATISTICS
            WHERE TABLE_SCHEMA=DATABASE() AND INDEX_NAME LIKE '%tenant%'
            """,
            fetch='all',
        ) or []
        result['detalles']['indices'] = {
            'total': len(indexes),
            'lista': [
                {'tabla': index['TABLE_NAME'], 'indice': index['INDEX_NAME']}
                for index in indexes
            ],
        }
        result['detalles']['usuario_actual'] = {
            'nombre': current_user.nombre,
            'email': current_user.email,
            'tenant_id': getattr(current_user, 'tenant_id', 'NO DISPONIBLE'),
            'empresa_nombre': getattr(
                current_user, 'empresa_nombre', 'NO DISPONIBLE',
            ),
        }
        if result['errores']:
            result['estado_general'] = 'ERROR'
        elif result['advertencias']:
            result['estado_general'] = 'ADVERTENCIAS'
        else:
            result['estado_general'] = 'PERFECTO ✅'
    except Exception as error:
        result['estado_general'] = 'ERROR CRÍTICO'
        result['errores'].append(f'Error durante verificación: {error}')
    return jsonify(result)


@login_required
def verificar_multitenant_visual():
    if current_user.perfil != 'Administrador':
        flash('No tienes permisos', 'error')
        return redirect(url_for('facturacion_menu'))
    return render_template('admin/empresas/verificar.html')


@login_required
def admin():
    return redirect(url_for('facturacion_menu'))


def register_admin_company_routes(app):
    app.add_url_rule('/admin/empresas', 'admin_empresas', admin_empresas)
    app.add_url_rule(
        '/admin/empresas/nueva', 'admin_empresas_nueva',
        admin_empresas_nueva, methods=['GET', 'POST'],
    )
    app.add_url_rule(
        '/admin/empresas/editar/<int:empresa_id>', 'admin_empresas_editar',
        admin_empresas_editar, methods=['GET', 'POST'],
    )
    app.add_url_rule(
        '/admin/verificar-multitenant', 'verificar_multitenant',
        verificar_multitenant,
    )
    app.add_url_rule(
        '/admin/verificar-multitenant-visual',
        'verificar_multitenant_visual',
        verificar_multitenant_visual,
    )
    app.add_url_rule('/admin', 'admin', admin)
