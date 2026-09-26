"""Administraci?n de roles, usuarios y perfil."""

import json
import logging

from flask import (
    Response, current_app, flash, jsonify, redirect, render_template, request,
    send_file, stream_with_context, url_for,
)
from flask_login import current_user, login_required, logout_user
from werkzeug.security import generate_password_hash

from auth import permission_required, user_has_permission
from auth.helpers import usuario_es_dueno_software
from core.database import execute_query, execute_update, transactional_methods
from core.presentation import FUENTES_UI
from core.tenant import get_current_tenant_id
from ecf import ECFCertificateResolutionError, TenantCertificateProvider
from rbac_catalog import PERMISOS_POR_GRUPO, TODOS_LOS_PERMISOS
from routes.support import (
    sanitize_input, validar_password_segura, validate_email, validate_int,
)
from services.ecf_operations import obtener_configuracion_ecf_tenant
from services.subscriptions import check_license_available, get_empresa_info
from services.tenant_mail import resumen_correo_empresa

logger = logging.getLogger(__name__)
_MODO_COLOR_LISTO = False


def asegurar_columna_modo_color():
    """Preferencia clara/oscura por usuario."""
    global _MODO_COLOR_LISTO
    if _MODO_COLOR_LISTO:
        return
    try:
        if not execute_query("SHOW COLUMNS FROM usuarios LIKE 'modo_color'"):
            execute_update(
                '''
                ALTER TABLE usuarios
                ADD COLUMN modo_color VARCHAR(10) NOT NULL DEFAULT 'light'
                AFTER idioma_correccion
                '''
            )
        _MODO_COLOR_LISTO = True
    except Exception as error:
        logger.warning('No se pudo preparar modo_color: %s', error)


def obtener_rol_tenant(rol_id, tenant_id):
    return execute_query(
        'SELECT * FROM roles WHERE id=%s AND tenant_id=%s AND activo=1',
        (rol_id, tenant_id)
    )

def rol_tiene_permisos(rol_id, tenant_id, codigos):
    if not codigos:
        return True
    placeholders = ','.join(['%s'] * len(codigos))
    resultado = execute_query(
        f'''
        SELECT COUNT(DISTINCT p.codigo) AS total
        FROM rol_permisos rp
        JOIN permisos p ON p.id=rp.permiso_id AND p.activo=1
        WHERE rp.tenant_id=%s AND rp.rol_id=%s
          AND p.codigo IN ({placeholders})
        ''',
        (tenant_id, rol_id, *codigos)
    ) or {'total': 0}
    return int(resultado.get('total') or 0) == len(set(codigos))

def guardar_permisos_rol(rol_id, tenant_id, codigos):
    execute_update(
        'DELETE FROM rol_permisos WHERE rol_id=%s AND tenant_id=%s',
        (rol_id, tenant_id)
    )
    for codigo in sorted(set(codigos)):
        execute_update('''
            INSERT INTO rol_permisos (tenant_id, rol_id, permiso_id)
            SELECT %s, %s, id FROM permisos
            WHERE codigo=%s AND activo=1
        ''', (tenant_id, rol_id, codigo))

@login_required
@permission_required('roles.ver')
def admin_roles():
    tenant_id = get_current_tenant_id()
    roles = execute_query('''
        SELECT r.*, COUNT(DISTINCT rp.permiso_id) AS total_permisos,
               COUNT(DISTINCT ur.usuario_id) AS total_usuarios
        FROM roles r
        LEFT JOIN rol_permisos rp
          ON rp.rol_id=r.id AND rp.tenant_id=r.tenant_id
        LEFT JOIN usuario_roles ur
          ON ur.rol_id=r.id AND ur.tenant_id=r.tenant_id
        WHERE r.tenant_id=%s AND r.activo=1
        GROUP BY r.id
        ORDER BY r.es_sistema DESC, r.nombre
    ''', (tenant_id,), fetch='all') or []
    return render_template('roles/lista.html', roles=roles)

@login_required
@permission_required('roles.crear')
@transactional_methods('POST')
def admin_roles_nuevo():
    tenant_id = get_current_tenant_id()
    if request.method == 'POST':
        nombre = sanitize_input(request.form.get('nombre', ''), 100)
        descripcion = sanitize_input(request.form.get('descripcion', ''), 500)
        codigos = request.form.getlist('permisos')
        if not nombre or not codigos:
            flash('Indica un nombre y al menos un permiso', 'error')
            return redirect(url_for('admin_roles_nuevo'))
        if not set(codigos).issubset(TODOS_LOS_PERMISOS):
            flash('La selección contiene permisos no válidos', 'error')
            return redirect(url_for('admin_roles_nuevo'))
        existente = execute_query(
            'SELECT id FROM roles WHERE tenant_id=%s AND nombre=%s',
            (tenant_id, nombre)
        )
        if existente:
            flash('Ya existe un rol con ese nombre', 'error')
            return redirect(url_for('admin_roles_nuevo'))
        rol_id = execute_update('''
            INSERT INTO roles (
                tenant_id, nombre, descripcion, es_sistema, activo
            ) VALUES (%s,%s,%s,0,1)
        ''', (tenant_id, nombre, descripcion or None))
        guardar_permisos_rol(rol_id, tenant_id, codigos)
        flash('Rol creado correctamente', 'success')
        return redirect(url_for('admin_roles'))
    return render_template(
        'roles/form.html',
        rol=None,
        permisos_por_grupo=PERMISOS_POR_GRUPO,
        seleccionados=set(),
    )

@login_required
@permission_required('roles.editar')
@transactional_methods('POST')
def admin_roles_editar(rol_id):
    tenant_id = get_current_tenant_id()
    rol = obtener_rol_tenant(rol_id, tenant_id)
    if not rol:
        flash('Rol no encontrado', 'error')
        return redirect(url_for('admin_roles'))
    if request.method == 'POST':
        nombre = sanitize_input(request.form.get('nombre', ''), 100)
        descripcion = sanitize_input(request.form.get('descripcion', ''), 500)
        codigos = request.form.getlist('permisos')
        if rol.get('es_sistema'):
            nombre = rol['nombre']
        if not nombre or not codigos or not set(codigos).issubset(TODOS_LOS_PERMISOS):
            flash('Nombre o permisos no válidos', 'error')
            return redirect(url_for('admin_roles_editar', rol_id=rol_id))
        duplicado = execute_query(
            'SELECT id FROM roles '
            'WHERE tenant_id=%s AND nombre=%s AND id<>%s',
            (tenant_id, nombre, rol_id)
        )
        if duplicado:
            flash('Ya existe otro rol con ese nombre', 'error')
            return redirect(url_for('admin_roles_editar', rol_id=rol_id))
        if rol.get('es_sistema'):
            execute_update(
                'UPDATE roles SET descripcion=%s '
                'WHERE id=%s AND tenant_id=%s',
                (descripcion or None, rol_id, tenant_id)
            )
        else:
            execute_update(
                'UPDATE roles SET nombre=%s, descripcion=%s '
                'WHERE id=%s AND tenant_id=%s AND es_sistema=0',
                (nombre, descripcion or None, rol_id, tenant_id)
            )
        guardar_permisos_rol(rol_id, tenant_id, codigos)
        flash('Rol actualizado correctamente', 'success')
        return redirect(url_for('admin_roles'))
    seleccionados = execute_query('''
        SELECT p.codigo FROM rol_permisos rp
        JOIN permisos p ON p.id=rp.permiso_id
        WHERE rp.rol_id=%s AND rp.tenant_id=%s
    ''', (rol_id, tenant_id), fetch='all') or []
    return render_template(
        'roles/form.html',
        rol=rol,
        permisos_por_grupo=PERMISOS_POR_GRUPO,
        seleccionados={item['codigo'] for item in seleccionados},
    )

@login_required
@permission_required('roles.crear')
@transactional_methods('POST')
def admin_roles_clonar(rol_id):
    tenant_id = get_current_tenant_id()
    rol = obtener_rol_tenant(rol_id, tenant_id)
    nombre = sanitize_input(request.form.get('nombre', ''), 100)
    if not rol or not nombre:
        flash('Indica un nombre para la copia', 'error')
        return redirect(url_for('admin_roles'))
    if execute_query(
        'SELECT id FROM roles WHERE tenant_id=%s AND nombre=%s',
        (tenant_id, nombre)
    ):
        flash('Ya existe un rol con ese nombre', 'error')
        return redirect(url_for('admin_roles'))
    nuevo_id = execute_update('''
        INSERT INTO roles (
            tenant_id, nombre, descripcion, es_sistema, activo
        ) VALUES (%s,%s,%s,0,1)
    ''', (tenant_id, nombre, f"Copia de {rol['nombre']}"))
    execute_update('''
        INSERT INTO rol_permisos (tenant_id, rol_id, permiso_id)
        SELECT tenant_id, %s, permiso_id
        FROM rol_permisos WHERE tenant_id=%s AND rol_id=%s
    ''', (nuevo_id, tenant_id, rol_id))
    flash('Rol clonado correctamente', 'success')
    return redirect(url_for('admin_roles_editar', rol_id=nuevo_id))

@login_required
@permission_required('roles.eliminar')
@transactional_methods('POST')
def admin_roles_eliminar(rol_id):
    tenant_id = get_current_tenant_id()
    rol = obtener_rol_tenant(rol_id, tenant_id)
    if not rol or rol.get('es_sistema'):
        flash('El rol no puede eliminarse', 'error')
        return redirect(url_for('admin_roles'))
    asignaciones = execute_query(
        'SELECT COUNT(*) AS total FROM usuario_roles '
        'WHERE tenant_id=%s AND rol_id=%s',
        (tenant_id, rol_id)
    ) or {'total': 0}
    if asignaciones.get('total'):
        flash('No puedes eliminar un rol asignado a usuarios', 'error')
        return redirect(url_for('admin_roles'))
    execute_update(
        'DELETE FROM roles WHERE id=%s AND tenant_id=%s AND es_sistema=0',
        (rol_id, tenant_id)
    )
    flash('Rol eliminado correctamente', 'success')
    return redirect(url_for('admin_roles'))

def listar_usuarios_del_tenant(tenant_id):
    """Usuarios de una sola empresa; nunca listar sin tenant."""
    if not tenant_id:
        return []
    return execute_query(
        '''
        SELECT u.id, u.nombre, u.email, u.perfil, u.activo, u.last_login,
               u.created_at, e.nombre AS empresa_nombre,
               GROUP_CONCAT(DISTINCT r.nombre ORDER BY r.nombre SEPARATOR ', ')
                   AS roles_nombres
        FROM usuarios u
        LEFT JOIN empresas e ON e.id = u.tenant_id
        LEFT JOIN usuario_roles ur
          ON ur.usuario_id=u.id AND ur.tenant_id=u.tenant_id
        LEFT JOIN roles r
          ON r.id=ur.rol_id AND r.tenant_id=ur.tenant_id AND r.activo=1
        WHERE u.tenant_id = %s
        GROUP BY u.id
        ORDER BY u.nombre, u.id
        ''',
        (tenant_id,),
        fetch='all',
    ) or []


def listar_usuarios_plataforma():
    """Equipo del dueño: cuentas sin consultorio (tenant_id nulo)."""
    return execute_query(
        '''
        SELECT u.id, u.nombre, u.email, u.perfil, u.activo, u.last_login,
               u.created_at, NULL AS empresa_nombre,
               'Equipo ClinicRD' AS roles_nombres
        FROM usuarios u
        WHERE u.tenant_id IS NULL
        ORDER BY u.nombre, u.id
        ''',
        fetch='all',
    ) or []


def _obtener_usuario_plataforma(usuario_id):
    return execute_query(
        'SELECT * FROM usuarios WHERE id=%s AND tenant_id IS NULL',
        (usuario_id,),
    )


def _email_ya_usado(email, usuario_id=None):
    if usuario_id:
        return execute_query(
            'SELECT id FROM usuarios WHERE email=%s AND id<>%s',
            (email, usuario_id),
        )
    return execute_query('SELECT id FROM usuarios WHERE email=%s', (email,))


def _conteo_equipo_plataforma_activo(excluir_id=None):
    if excluir_id:
        fila = execute_query(
            '''
            SELECT COUNT(*) AS total FROM usuarios
            WHERE tenant_id IS NULL AND activo=1 AND id<>%s
            ''',
            (excluir_id,),
        ) or {'total': 0}
    else:
        fila = execute_query(
            '''
            SELECT COUNT(*) AS total FROM usuarios
            WHERE tenant_id IS NULL AND activo=1
            '''
        ) or {'total': 0}
    return int(fila.get('total') or 0)


@login_required
@permission_required('usuarios.ver')
def admin_usuarios():
    """Listar usuarios del consultorio o del equipo ClinicRD."""
    if usuario_es_dueno_software(current_user):
        return render_template(
            'usuarios/lista.html',
            usuarios=listar_usuarios_plataforma(),
            empresa=None,
            equipo_plataforma=True,
        )
    tenant_id = get_current_tenant_id()
    if not tenant_id:
        flash(
            'Selecciona una empresa antes de administrar sus usuarios.',
            'error',
        )
        return redirect(url_for('admin_empresas'))
    return render_template(
        'usuarios/lista.html',
        usuarios=listar_usuarios_del_tenant(tenant_id),
        empresa=get_empresa_info(),
        equipo_plataforma=False,
    )

def obtener_contexto_usuario_form(tenant_id, usuario_id=None):
    roles = execute_query(
        '''
        SELECT r.id, r.nombre, r.descripcion,
               EXISTS(
                   SELECT 1 FROM rol_permisos rp
                   JOIN permisos p ON p.id=rp.permiso_id
                   WHERE rp.tenant_id=r.tenant_id AND rp.rol_id=r.id
                     AND p.codigo='turnos.cola_propia'
               ) AS requiere_medico
        FROM roles r
        WHERE r.tenant_id=%s AND r.activo=1
        ORDER BY r.es_sistema DESC, r.nombre
        ''',
        (tenant_id,),
        fetch='all'
    ) or []
    medicos = execute_query(
        'SELECT id, nombre, especialidad FROM medicos '
        'WHERE tenant_id=%s ORDER BY nombre',
        (tenant_id,),
        fetch='all'
    ) or []
    rol_seleccionado = None
    medico_seleccionado = None
    if usuario_id:
        asignacion = execute_query(
            'SELECT rol_id FROM usuario_roles '
            'WHERE tenant_id=%s AND usuario_id=%s ORDER BY created_at LIMIT 1',
            (tenant_id, usuario_id)
        )
        vinculacion = execute_query(
            'SELECT medico_id FROM usuario_medico '
            'WHERE tenant_id=%s AND usuario_id=%s',
            (tenant_id, usuario_id)
        )
        rol_seleccionado = asignacion.get('rol_id') if asignacion else None
        medico_seleccionado = (
            vinculacion.get('medico_id') if vinculacion else None
        )
    return roles, medicos, rol_seleccionado, medico_seleccionado

def perfil_legacy_para_rol(nombre_rol):
    if nombre_rol in {
        'Administrador',
        'Nivel 2',
        'Registro de Facturas',
    }:
        return nombre_rol
    return 'Registro de Facturas'

def asignar_rol_y_medico(usuario_id, tenant_id, rol_id, medico_id=None):
    execute_update(
        'DELETE FROM usuario_roles WHERE tenant_id=%s AND usuario_id=%s',
        (tenant_id, usuario_id)
    )
    execute_update(
        'INSERT INTO usuario_roles (tenant_id, usuario_id, rol_id) '
        'VALUES (%s,%s,%s)',
        (tenant_id, usuario_id, rol_id)
    )
    execute_update(
        'DELETE FROM usuario_medico WHERE tenant_id=%s AND usuario_id=%s',
        (tenant_id, usuario_id)
    )
    if medico_id:
        execute_update(
            'INSERT INTO usuario_medico (tenant_id, usuario_id, medico_id) '
            'VALUES (%s,%s,%s)',
            (tenant_id, usuario_id, medico_id)
        )

def usuario_tiene_permiso_db(usuario_id, tenant_id, codigo):
    return bool(execute_query('''
        SELECT 1 FROM usuario_roles ur
        JOIN roles r
          ON r.id=ur.rol_id AND r.tenant_id=ur.tenant_id AND r.activo=1
        JOIN rol_permisos rp
          ON rp.rol_id=ur.rol_id AND rp.tenant_id=ur.tenant_id
        JOIN permisos p ON p.id=rp.permiso_id AND p.activo=1
        WHERE ur.tenant_id=%s AND ur.usuario_id=%s AND p.codigo=%s
        LIMIT 1
    ''', (tenant_id, usuario_id, codigo)))

@login_required
@permission_required('usuarios.crear')
@transactional_methods('POST')
def admin_usuarios_nuevo():
    """Crear nuevo usuario"""
    if usuario_es_dueno_software(current_user):
        return _admin_usuarios_plataforma_nuevo()
    if request.method == 'POST':
        nombre = sanitize_input(request.form.get('nombre', ''), 100)
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password_nuevo', '')
        rol_id = request.form.get('rol_id', type=int)
        medico_id = request.form.get('medico_id', type=int)
        
        if not nombre or not email or not password or not rol_id:
            flash('Todos los campos son obligatorios', 'error')
            return redirect(url_for('admin_usuarios_nuevo'))
        
        if not validate_email(email):
            flash('Email inválido', 'error')
            return redirect(url_for('admin_usuarios_nuevo'))
        
        password_errors = validar_password_segura(password)
        if password_errors:
            flash(f'Contraseña no válida: {", ".join(password_errors)}', 'error')
            return redirect(url_for('admin_usuarios_nuevo'))
        
        tenant_id = get_current_tenant_id()
        if not tenant_id:
            flash(
                'Selecciona una empresa antes de crear usuarios.',
                'error',
            )
            return redirect(url_for('admin_usuarios'))
        rol = obtener_rol_tenant(rol_id, tenant_id)
        if not rol:
            flash('Rol inválido', 'error')
            return redirect(url_for('admin_usuarios_nuevo'))
        requiere_medico = rol_tiene_permisos(
            rol_id,
            tenant_id,
            {'turnos.cola_propia'},
        )
        if requiere_medico and not medico_id:
            flash('El rol seleccionado requiere vincular un médico', 'error')
            return redirect(url_for('admin_usuarios_nuevo'))
        if medico_id and not execute_query(
            'SELECT id FROM medicos WHERE id=%s AND tenant_id=%s',
            (medico_id, tenant_id)
        ):
            flash('Médico inválido', 'error')
            return redirect(url_for('admin_usuarios_nuevo'))
        perfil = perfil_legacy_para_rol(rol['nombre'])
        
        # VALIDAR LICENCIAS DISPONIBLES
        licencia_ok, licencias_disponibles, mensaje = check_license_available(tenant_id)
        if not licencia_ok:
            flash(f'No se puede crear usuario: {mensaje}', 'error')
            return redirect(url_for('admin_usuarios_nuevo'))
        
        # Verificar email en el mismo tenant
        existe = execute_query(
            'SELECT id FROM usuarios WHERE email = %s AND tenant_id = %s', 
            (email, tenant_id)
        )
        
        if existe:
            flash('Ya existe un usuario con ese email en tu empresa', 'error')
            return redirect(url_for('admin_usuarios_nuevo'))
        
        password_hash = generate_password_hash(password)
        usuario_id = execute_update('''
            INSERT INTO usuarios (tenant_id, nombre, email, password_hash, perfil, activo, password_temporal)
            VALUES (%s, %s, %s, %s, %s, 1, 1)
        ''', (tenant_id, nombre, email, password_hash, perfil))
        asignar_rol_y_medico(
            usuario_id,
            tenant_id,
            rol_id,
            medico_id if requiere_medico else None,
        )
        
        flash(f'Usuario {nombre} creado exitosamente ({licencias_disponibles - 1} licencias restantes)', 'success')
        return redirect(url_for('admin_usuarios'))
    
    tenant_id = get_current_tenant_id()
    if not tenant_id:
        flash(
            'Selecciona una empresa antes de crear usuarios.',
            'error',
        )
        return redirect(url_for('admin_usuarios'))
    roles, medicos, rol_seleccionado, medico_seleccionado = (
        obtener_contexto_usuario_form(tenant_id)
    )
    return render_template(
        'usuarios/form.html',
        usuario=None,
        roles=roles,
        medicos=medicos,
        rol_seleccionado=rol_seleccionado,
        medico_seleccionado=medico_seleccionado,
        equipo_plataforma=False,
    )


def _admin_usuarios_plataforma_nuevo():
    if request.method == 'POST':
        nombre = sanitize_input(request.form.get('nombre', ''), 100)
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password_nuevo', '')
        if not nombre or not email or not password:
            flash('Nombre, correo y contraseña son obligatorios', 'error')
            return redirect(url_for('admin_usuarios_nuevo'))
        if not validate_email(email):
            flash('Email inválido', 'error')
            return redirect(url_for('admin_usuarios_nuevo'))
        password_errors = validar_password_segura(password)
        if password_errors:
            flash(f'Contraseña no válida: {", ".join(password_errors)}', 'error')
            return redirect(url_for('admin_usuarios_nuevo'))
        if _email_ya_usado(email):
            flash('Ya existe un usuario con ese correo', 'error')
            return redirect(url_for('admin_usuarios_nuevo'))
        password_hash = generate_password_hash(password)
        execute_update(
            '''
            INSERT INTO usuarios (
                tenant_id, nombre, email, password_hash, perfil, activo,
                password_temporal
            ) VALUES (NULL, %s, %s, %s, %s, 1, 1)
            ''',
            (nombre, email, password_hash, 'Administrador'),
        )
        flash(
            f'{nombre} ya puede entrar al panel de ClinicRD. '
            'Entrégarle la contraseña de forma segura.',
            'success',
        )
        return redirect(url_for('admin_usuarios'))
    return render_template(
        'usuarios/form.html',
        usuario=None,
        roles=[],
        medicos=[],
        rol_seleccionado=None,
        medico_seleccionado=None,
        equipo_plataforma=True,
    )


def _admin_usuarios_plataforma_editar(usuario_id):
    usuario = _obtener_usuario_plataforma(usuario_id)
    if not usuario:
        flash('Usuario no encontrado', 'error')
        return redirect(url_for('admin_usuarios'))
    if request.method == 'POST':
        nombre = sanitize_input(request.form.get('nombre', ''), 100)
        email = request.form.get('email', '').strip().lower()
        activo = request.form.get('activo') == '1'
        cambiar_password = request.form.get('cambiar_password') == '1'
        password = request.form.get('password', '')
        if not nombre or not email:
            flash('Nombre y correo son obligatorios', 'error')
            return redirect(url_for('admin_usuarios_editar', usuario_id=usuario_id))
        if not validate_email(email):
            flash('Email inválido', 'error')
            return redirect(url_for('admin_usuarios_editar', usuario_id=usuario_id))
        if usuario_id == current_user.id and not activo:
            flash('No puedes desactivar tu propia cuenta', 'error')
            return redirect(url_for('admin_usuarios_editar', usuario_id=usuario_id))
        if not activo and _conteo_equipo_plataforma_activo(usuario_id) < 1:
            flash('Debe quedar al menos una cuenta activa del equipo ClinicRD', 'error')
            return redirect(url_for('admin_usuarios_editar', usuario_id=usuario_id))
        if _email_ya_usado(email, usuario_id):
            flash('Ya existe un usuario con ese correo', 'error')
            return redirect(url_for('admin_usuarios_editar', usuario_id=usuario_id))
        if cambiar_password and password:
            password_errors = validar_password_segura(password)
            if password_errors:
                flash(
                    f'Contraseña no válida: {", ".join(password_errors)}',
                    'error',
                )
                return redirect(
                    url_for('admin_usuarios_editar', usuario_id=usuario_id)
                )
            execute_update(
                '''
                UPDATE usuarios
                SET nombre=%s, email=%s, password_hash=%s, activo=%s,
                    password_temporal=1
                WHERE id=%s AND tenant_id IS NULL
                ''',
                (
                    nombre, email, generate_password_hash(password),
                    activo, usuario_id,
                ),
            )
            if usuario_id == current_user.id:
                logout_user()
                flash('Tu contraseña ha sido cambiada.', 'warning')
                return redirect(url_for('login'))
            flash(f'Usuario {nombre} actualizado con nueva contraseña', 'success')
        else:
            execute_update(
                '''
                UPDATE usuarios
                SET nombre=%s, email=%s, activo=%s
                WHERE id=%s AND tenant_id IS NULL
                ''',
                (nombre, email, activo, usuario_id),
            )
            flash(f'Usuario {nombre} actualizado exitosamente', 'success')
        return redirect(url_for('admin_usuarios'))
    return render_template(
        'usuarios/form.html',
        usuario=usuario,
        roles=[],
        medicos=[],
        rol_seleccionado=None,
        medico_seleccionado=None,
        equipo_plataforma=True,
    )


@login_required
@permission_required('usuarios.editar')
@transactional_methods('POST')
def admin_usuarios_editar(usuario_id):
    """Editar usuario"""
    if usuario_es_dueno_software(current_user):
        return _admin_usuarios_plataforma_editar(usuario_id)
    tenant_id = get_current_tenant_id()
    if tenant_id is None:
        flash(
            'Selecciona una empresa antes de administrar sus usuarios.',
            'error',
        )
        return redirect(url_for('admin_usuarios'))

    usuario = execute_query(
        'SELECT * FROM usuarios WHERE id = %s AND tenant_id = %s',
        (usuario_id, tenant_id),
    )
    
    if not usuario:
        flash('Usuario no encontrado', 'error')
        return redirect(url_for('admin_usuarios'))
    
    if request.method == 'POST':
        nombre = sanitize_input(request.form.get('nombre', ''), 100)
        email = request.form.get('email', '').strip().lower()
        rol_id = request.form.get('rol_id', type=int)
        medico_id = request.form.get('medico_id', type=int)
        activo = request.form.get('activo') == '1'
        cambiar_password = request.form.get('cambiar_password') == '1'
        password = request.form.get('password', '')
        
        if not nombre or not email or not rol_id:
            flash('Nombre, email y rol son obligatorios', 'error')
            return redirect(url_for('admin_usuarios_editar', usuario_id=usuario_id))
        
        if not validate_email(email):
            flash('Email inválido', 'error')
            return redirect(url_for('admin_usuarios_editar', usuario_id=usuario_id))
        
        rol = obtener_rol_tenant(rol_id, tenant_id)
        if not rol:
            flash('Rol inválido', 'error')
            return redirect(url_for('admin_usuarios_editar', usuario_id=usuario_id))
        requiere_medico = rol_tiene_permisos(
            rol_id,
            tenant_id,
            {'turnos.cola_propia'},
        )
        if requiere_medico and not medico_id:
            flash('El rol seleccionado requiere vincular un médico', 'error')
            return redirect(url_for('admin_usuarios_editar', usuario_id=usuario_id))
        if medico_id and not execute_query(
            'SELECT id FROM medicos WHERE id=%s AND tenant_id=%s',
            (medico_id, tenant_id)
        ):
            flash('Médico inválido', 'error')
            return redirect(url_for('admin_usuarios_editar', usuario_id=usuario_id))
        perfil = perfil_legacy_para_rol(rol['nombre'])
        
        if usuario_id == current_user.id and not activo:
            flash('No puedes desactivar tu propia cuenta', 'error')
            return redirect(url_for('admin_usuarios_editar', usuario_id=usuario_id))

        nuevos_permisos_gestion = rol_tiene_permisos(
            rol_id,
            tenant_id,
            {'usuarios.editar', 'roles.editar'},
        )
        if usuario_id == current_user.id and not nuevos_permisos_gestion:
            flash('No puedes quitarte tus propios permisos administrativos', 'error')
            return redirect(url_for('admin_usuarios_editar', usuario_id=usuario_id))
        if (
            usuario_tiene_permiso_db(usuario_id, tenant_id, 'roles.editar')
            and not nuevos_permisos_gestion
        ):
            administradores = execute_query('''
                SELECT COUNT(DISTINCT ur.usuario_id) AS total
                FROM usuario_roles ur
                JOIN roles r
                  ON r.id=ur.rol_id AND r.tenant_id=ur.tenant_id
                 AND r.activo=1
                JOIN rol_permisos rp
                  ON rp.rol_id=ur.rol_id AND rp.tenant_id=ur.tenant_id
                JOIN permisos p ON p.id=rp.permiso_id
                JOIN usuarios u
                  ON u.id=ur.usuario_id AND u.tenant_id=ur.tenant_id
                 AND u.activo=1
                WHERE ur.tenant_id=%s AND p.codigo='roles.editar'
            ''', (tenant_id,)) or {'total': 0}
            if int(administradores.get('total') or 0) <= 1:
                flash('Debe permanecer al menos un administrador activo', 'error')
                return redirect(url_for(
                    'admin_usuarios_editar',
                    usuario_id=usuario_id,
                ))
        
        existe = execute_query(
            '''
            SELECT id FROM usuarios
            WHERE email = %s AND id != %s AND tenant_id = %s
            ''',
            (email, usuario_id, tenant_id),
        )
        
        if existe:
            flash('Ya existe otro usuario con ese email', 'error')
            return redirect(url_for('admin_usuarios_editar', usuario_id=usuario_id))
        
        if cambiar_password and password:
            if len(password) < 8:
                flash('La contraseña debe tener al menos 8 caracteres', 'error')
                return redirect(url_for('admin_usuarios_editar', usuario_id=usuario_id))
            
            password_hash = generate_password_hash(password)
            execute_update('''
                UPDATE usuarios 
                SET nombre = %s, email = %s, password_hash = %s, perfil = %s, activo = %s, password_temporal = 1
                WHERE id = %s AND tenant_id = %s
            ''', (
                nombre,
                email,
                password_hash,
                perfil,
                activo,
                usuario_id,
                tenant_id,
            ))
            asignar_rol_y_medico(
                usuario_id,
                tenant_id,
                rol_id,
                medico_id if requiere_medico else None,
            )
            
            if usuario_id == current_user.id:
                logout_user()
                flash('Tu contraseña ha sido cambiada.', 'warning')
                return redirect(url_for('login'))
            
            flash(f'Usuario {nombre} actualizado con nueva contraseña', 'success')
        else:
            execute_update('''
                UPDATE usuarios 
                SET nombre = %s, email = %s, perfil = %s, activo = %s
                WHERE id = %s AND tenant_id = %s
            ''', (nombre, email, perfil, activo, usuario_id, tenant_id))
            asignar_rol_y_medico(
                usuario_id,
                tenant_id,
                rol_id,
                medico_id if requiere_medico else None,
            )
            
            flash(f'Usuario {nombre} actualizado exitosamente', 'success')
        
        return redirect(url_for('admin_usuarios'))
    
    roles, medicos, rol_seleccionado, medico_seleccionado = (
        obtener_contexto_usuario_form(tenant_id, usuario_id)
    )
    return render_template(
        'usuarios/form.html',
        usuario=usuario,
        roles=roles,
        medicos=medicos,
        rol_seleccionado=rol_seleccionado,
        medico_seleccionado=medico_seleccionado,
        equipo_plataforma=False,
    )

@login_required
@permission_required('usuarios.eliminar')
def admin_usuarios_eliminar(usuario_id):
    """Eliminar usuario - DESHABILITADO"""
    flash('Eliminación deshabilitada. Desactiva el usuario en su lugar.', 'warning')
    return redirect(url_for('admin_usuarios'))

@login_required
@permission_required('configuracion.ver')
def perfil_configuracion():
    """Configuración del perfil del usuario"""
    TEMAS_VALIDOS = [
        'cyan', 'ocean', 'emerald', 'teal', 'aqua',
        'mint', 'lagoon', 'sky', 'sage'
    ]
    
    if request.method == 'POST':
        if request.form.get('accion') == 'correo_smtp':
            if not user_has_permission(current_user, 'configuracion.editar'):
                flash('No tienes permiso para configurar el correo', 'error')
                return redirect(url_for('perfil_configuracion'))
            tenant_id = get_current_tenant_id()
            if not tenant_id:
                flash('No hay una empresa asociada a tu usuario.', 'error')
                return redirect(url_for('perfil_configuracion'))
            from services.tenant_mail import (
                enviar_correo_consultorio, guardar_correo_empresa,
            )
            puerto = validate_int(
                request.form.get('smtp_port'), min_value=1,
                max_value=65535, default=587,
            )
            remitente = sanitize_input(request.form.get('smtp_remitente', ''), 255)
            if remitente and not validate_email(remitente):
                flash('El correo remitente no es válido', 'error')
                return redirect(url_for('perfil_configuracion'))
            guardar_correo_empresa(
                tenant_id,
                {
                    'smtp_host': sanitize_input(request.form.get('smtp_host', ''), 255),
                    'smtp_port': puerto,
                    'smtp_usuario': sanitize_input(request.form.get('smtp_usuario', ''), 255),
                    'smtp_remitente': remitente,
                    'smtp_nombre_remitente': sanitize_input(
                        request.form.get('smtp_nombre_remitente', ''), 150
                    ),
                    'smtp_usar_tls': request.form.get('smtp_usar_tls') == '1',
                },
                password_nueva=request.form.get('smtp_password') or None,
            )
            if request.form.get('enviar_prueba') == '1' and current_user.email:
                ok, detalle = enviar_correo_consultorio(
                    tenant_id,
                    current_user.email,
                    'Prueba de correo ClinicRD',
                    '<p>Si lees esto, el correo del consultorio ya envía mensajes.</p>',
                    fallback_plataforma=False,
                )
                flash(
                    'Correo de prueba enviado a tu usuario.' if ok else detalle,
                    'success' if ok else 'error',
                )
            else:
                flash('Correo del consultorio guardado', 'success')
            return redirect(url_for('perfil_configuracion'))

        if request.form.get('accion') == 'certificado_ecf':
            if not user_has_permission(current_user, 'configuracion.editar'):
                flash('No tienes permiso para cargar el certificado e-CF', 'error')
                return redirect(url_for('perfil_configuracion'))
            tenant_id = get_current_tenant_id()
            if not tenant_id:
                flash('No hay una empresa asociada a tu usuario.', 'error')
                return redirect(url_for('perfil_configuracion'))
            archivo = request.files.get('certificado_p12')
            password = request.form.get('certificado_password', '')
            nombre = (archivo.filename or '').lower() if archivo else ''
            if not archivo or not nombre.endswith(('.p12', '.pfx')):
                flash('Sube un certificado PKCS#12 (.p12 o .pfx).', 'error')
                return redirect(url_for('perfil_configuracion'))
            empresa_actual = get_empresa_info(tenant_id) or {}
            rnc = str(empresa_actual.get('rnc') or '').strip()
            if not rnc:
                flash(
                    'Registra el RNC de la empresa antes de cargar el certificado.',
                    'error',
                )
                return redirect(url_for('perfil_configuracion'))
            try:
                TenantCertificateProvider(
                    current_app.config['ECF_CONFIG']
                ).store(tenant_id, archivo.read(), password, rnc)
            except ECFCertificateResolutionError as error:
                flash(str(error), 'error')
                return redirect(url_for('perfil_configuracion'))
            flash('Certificado e-CF de la cuenta guardado correctamente.', 'success')
            return redirect(url_for('perfil_configuracion'))

        if request.form.get('accion') == 'papeleria':
            if not user_has_permission(current_user, 'configuracion.editar'):
                flash('No tienes permiso para editar la papelería', 'error')
                return redirect(url_for('perfil_configuracion'))
            tenant_id = get_current_tenant_id()
            if not tenant_id:
                flash('La papelería es del consultorio, no de la plataforma.', 'error')
                return redirect(url_for('perfil_configuracion'))
            from services.stationery import MAX_LOGO_BYTES, guardar_papeleria
            archivo = request.files.get('logo_papeleria')
            logo_bytes = None
            if archivo and archivo.filename:
                logo_bytes = archivo.read(MAX_LOGO_BYTES + 1)
                if len(logo_bytes) > MAX_LOGO_BYTES:
                    flash('El logo no puede superar 512 KB.', 'error')
                    return redirect(url_for('perfil_configuracion'))
            try:
                guardar_papeleria(
                    tenant_id,
                    {
                        'encabezado': request.form.get('encabezado', ''),
                        'subtitulo': request.form.get('subtitulo', ''),
                        'pie_pagina': request.form.get('pie_pagina', ''),
                    },
                    logo_bytes=logo_bytes,
                    quitar_logo=request.form.get('quitar_logo') == '1',
                )
            except ValueError as error:
                flash(str(error), 'error')
                return redirect(url_for('perfil_configuracion'))
            flash('Papelería del consultorio actualizada.', 'success')
            return redirect(url_for('perfil_configuracion'))

        tema_color = request.form.get(
            'tema_color', current_user.tema_color or 'cyan'
        )
        fuente_ui = request.form.get(
            'fuente_ui', current_user.fuente_ui or 'arsflow'
        )
        mostrar_chat = request.form.get('mostrar_chat') == '1'
        idioma_correccion = request.form.get(
            'idioma_correccion',
            getattr(current_user, 'idioma_correccion', 'es'),
        )
        modo_color = request.form.get(
            'modo_color',
            getattr(current_user, 'modo_color', 'light'),
        )
        
        if tema_color not in TEMAS_VALIDOS:
            flash('Tema de color inválido', 'error')
            return redirect(url_for('perfil_configuracion'))
        if fuente_ui not in FUENTES_UI:
            flash('Tipografía inválida', 'error')
            return redirect(url_for('perfil_configuracion'))
        if idioma_correccion not in {'es', 'en', 'fr', 'none'}:
            flash('Idioma de corrección inválido', 'error')
            return redirect(url_for('perfil_configuracion'))
        if modo_color not in {'light', 'dark'}:
            flash('Modo de pantalla inválido', 'error')
            return redirect(url_for('perfil_configuracion'))
        
        asegurar_columna_modo_color()
        execute_update(
            '''
            UPDATE usuarios
            SET tema_color=%s, fuente_ui=%s, mostrar_chat=%s,
                idioma_correccion=%s, modo_color=%s
            WHERE id=%s AND tenant_id <=> %s
            ''',
            (
                tema_color,
                fuente_ui,
                1 if mostrar_chat else 0,
                idioma_correccion,
                modo_color,
                current_user.id,
                get_current_tenant_id(),
            ),
        )
        
        current_user.tema_color = tema_color
        current_user.fuente_ui = fuente_ui
        current_user.mostrar_chat = mostrar_chat
        current_user.idioma_correccion = idioma_correccion
        current_user.modo_color = modo_color
        
        flash('Preferencias actualizadas correctamente', 'success')
        return redirect(url_for('perfil_configuracion'))
    
    ecf_certificado = None
    if user_has_permission(current_user, 'configuracion.editar'):
        tenant_id = get_current_tenant_id()
        empresa_actual = get_empresa_info(tenant_id) or {}
        ecf_config = current_app.config['ECF_CONFIG']
        ecf_certificado = {
            'habilitado_global': ecf_config.enabled,
            'almacen_disponible': bool(ecf_config.tenant_secrets_root),
            'ambiente': ecf_config.environment,
            'configurado': False,
            'valido': False,
            'mensaje': (
                'La integración e-CF está desactivada en el servidor. '
                'Aun así puede cargar el certificado de esta cuenta.'
                if not ecf_config.enabled else
                'La cuenta no tiene un certificado PKCS#12 configurado'
            ),
            'vence': None,
            'huella': None,
            'compatibilidad_global': False,
            'referencia_esperada': (
                f'tenant-{tenant_id}/certificate.p12'
            ),
        }
        if tenant_id and (ecf_config.enabled or ecf_config.tenant_secrets_root):
            try:
                resolved, metadata = TenantCertificateProvider(
                    ecf_config
                ).inspect(
                    tenant_id,
                    empresa_actual.get('rnc'),
                    obtener_configuracion_ecf_tenant(tenant_id),
                )
                ecf_certificado.update({
                    'configurado': True,
                    'valido': True,
                    'mensaje': (
                        'Certificado válido y correspondiente al RNC de la cuenta.'
                    ),
                    'vence': metadata.valid_until,
                    'huella': metadata.fingerprint,
                    'compatibilidad_global': resolved.legacy_fallback,
                })
            except ECFCertificateResolutionError as error:
                ecf_certificado['mensaje'] = str(error)

    correo_smtp = {'configurado': False}
    if user_has_permission(current_user, 'configuracion.editar'):
        try:
            correo_smtp = resumen_correo_empresa(get_empresa_info())
        except Exception:
            correo_smtp = resumen_correo_empresa(None)

    papeleria = None
    tenant_id = get_current_tenant_id()
    if tenant_id and user_has_permission(current_user, 'configuracion.editar'):
        from services.stationery import obtener_papeleria
        papeleria = obtener_papeleria(tenant_id)

    return render_template(
        'perfil/configuracion.html',
        ecf_certificado=ecf_certificado,
        correo_smtp=correo_smtp,
        papeleria=papeleria,
    )


@login_required
@permission_required('configuracion.backup')
def perfil_descargar_backup():
    """Descargar un Excel con los datos de la empresa, una hoja por módulo."""
    tenant_id = get_current_tenant_id()
    if not tenant_id:
        flash('No hay una empresa asociada a tu usuario.', 'error')
        return redirect(url_for('perfil_configuracion'))
    if request.args.get('progreso') == '1':
        def stream():
            for evento in generar_backup_eventos(tenant_id):
                contenido = evento.pop('contenido', None)
                yield (json.dumps(evento, ensure_ascii=False) + '\n').encode('utf-8')
                if contenido is not None:
                    yield b'\x1e'
                    yield contenido
        return Response(
            stream_with_context(stream()),
            mimetype='application/octet-stream',
            headers={
                'Cache-Control': 'no-store',
                'X-Accel-Buffering': 'no',
            },
        )
    archivo = generar_backup_excel(tenant_id)
    return send_file(
        archivo,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=nombre_archivo_backup(tenant_id),
    )


@login_required
def perfil_modo_color():
    """Guardar claro/oscuro solo para la cuenta que está en sesión."""
    asegurar_columna_modo_color()
    payload = request.get_json(silent=True) or request.form
    modo = (payload.get('modo') or payload.get('modo_color') or '').strip()
    if modo not in {'light', 'dark'}:
        return jsonify({'ok': False, 'error': 'Modo inválido'}), 400
    execute_update(
        '''
        UPDATE usuarios SET modo_color=%s
        WHERE id=%s AND tenant_id <=> %s
        ''',
        (modo, current_user.id, get_current_tenant_id()),
    )
    current_user.modo_color = modo
    return jsonify({'ok': True, 'modo': modo})


@login_required
def papeleria_logo():
    """Servir el logo de papelería solo de la empresa en sesión."""
    from flask import abort, send_file
    from services.stationery import obtener_papeleria, ruta_logo

    tenant_id = get_current_tenant_id()
    if not tenant_id:
        abort(404)
    datos = obtener_papeleria(tenant_id) or {}
    archivo = ruta_logo(tenant_id, datos.get('logo_ext'))
    if not archivo or not archivo.is_file():
        abort(404)
    return send_file(
        archivo,
        mimetype=datos.get('logo_mime') or 'application/octet-stream',
        max_age=300,
        as_attachment=False,
        download_name=archivo.name,
    )


def register_user_role_routes(app):
    app.add_url_rule('/admin/roles', endpoint='admin_roles', view_func=admin_roles)
    app.add_url_rule('/admin/roles/nuevo', endpoint='admin_roles_nuevo', view_func=admin_roles_nuevo, methods=['GET', 'POST'])
    app.add_url_rule('/admin/roles/<int:rol_id>/editar', endpoint='admin_roles_editar', view_func=admin_roles_editar, methods=['GET', 'POST'])
    app.add_url_rule('/admin/roles/<int:rol_id>/clonar', endpoint='admin_roles_clonar', view_func=admin_roles_clonar, methods=['POST'])
    app.add_url_rule('/admin/roles/<int:rol_id>/eliminar', endpoint='admin_roles_eliminar', view_func=admin_roles_eliminar, methods=['POST'])
    app.add_url_rule('/admin/usuarios', endpoint='admin_usuarios', view_func=admin_usuarios)
    app.add_url_rule('/admin/usuarios/nuevo', endpoint='admin_usuarios_nuevo', view_func=admin_usuarios_nuevo, methods=['GET', 'POST'])
    app.add_url_rule('/admin/usuarios/<int:usuario_id>/editar', endpoint='admin_usuarios_editar', view_func=admin_usuarios_editar, methods=['GET', 'POST'])
    app.add_url_rule('/admin/usuarios/<int:usuario_id>/eliminar', endpoint='admin_usuarios_eliminar', view_func=admin_usuarios_eliminar, methods=['POST'])
    app.add_url_rule('/perfil/configuracion', endpoint='perfil_configuracion', view_func=perfil_configuracion, methods=['GET', 'POST'])
    app.add_url_rule(
        '/perfil/modo-color',
        endpoint='perfil_modo_color',
        view_func=perfil_modo_color,
        methods=['POST'],
    )
    app.add_url_rule(
        '/perfil/papeleria/logo',
        endpoint='papeleria_logo',
        view_func=papeleria_logo,
    )
    app.add_url_rule(
        '/perfil/configuracion/backup',
        endpoint='perfil_descargar_backup',
        view_func=perfil_descargar_backup,
    )

    @app.before_request
    def _asegurar_preferencia_modo_color():
        if request.endpoint in (None, 'static'):
            return None
        asegurar_columna_modo_color()
        return None
