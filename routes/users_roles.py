"""Administraci?n de roles, usuarios y perfil."""

from flask import current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, logout_user
from werkzeug.security import generate_password_hash

from auth import permission_required, user_has_permission
from core.database import execute_query, execute_update, transactional_methods
from core.presentation import FUENTES_UI
from core.tenant import get_current_tenant_id
from ecf import ECFCertificateResolutionError, TenantCertificateProvider
from rbac_catalog import PERMISOS_POR_GRUPO, TODOS_LOS_PERMISOS
from routes.support import (
    sanitize_input, validar_password_segura, validate_email,
)
from services.ecf_operations import obtener_configuracion_ecf_tenant
from services.subscriptions import check_license_available, get_empresa_info

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
    if rol.get('es_sistema'):
        flash('Los roles del sistema no se pueden modificar', 'warning')
        return redirect(url_for('admin_roles'))
    if request.method == 'POST':
        nombre = sanitize_input(request.form.get('nombre', ''), 100)
        descripcion = sanitize_input(request.form.get('descripcion', ''), 500)
        codigos = request.form.getlist('permisos')
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

@login_required
@permission_required('usuarios.ver')
def admin_usuarios():
    """Listar usuarios - Filtra por tenant del usuario actual"""
    # Obtener usuarios del mismo tenant
    tenant_id = get_current_tenant_id()
    usuarios = execute_query('''
        SELECT u.*, e.nombre as empresa_nombre,
               GROUP_CONCAT(DISTINCT r.nombre ORDER BY r.nombre SEPARATOR ', ')
                   AS roles_nombres
        FROM usuarios u
        LEFT JOIN empresas e ON u.tenant_id = e.id
        LEFT JOIN usuario_roles ur
          ON ur.usuario_id=u.id AND ur.tenant_id=u.tenant_id
        LEFT JOIN roles r
          ON r.id=ur.rol_id AND r.tenant_id=ur.tenant_id AND r.activo=1
        WHERE u.tenant_id = %s
        GROUP BY u.id
        ORDER BY u.created_at DESC
    ''', (tenant_id,), fetch='all')
    
    # Obtener info de licencias
    empresa = get_empresa_info()
    
    return render_template('usuarios/lista.html', usuarios=usuarios, empresa=empresa)

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
        
        # Obtener tenant_id del usuario actual
        tenant_id = get_current_tenant_id()
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
    )

@login_required
@permission_required('usuarios.editar')
@transactional_methods('POST')
def admin_usuarios_editar(usuario_id):
    """Editar usuario"""
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
    )

@login_required
@permission_required('usuarios.eliminar')
def admin_usuarios_eliminar(usuario_id):
    """Eliminar usuario - DESHABILITADO"""
    flash('Eliminación deshabilitada. Desactiva el usuario en su lugar.', 'warning')
    return redirect(url_for('admin_usuarios'))

@login_required
def perfil_configuracion():
    """Configuración del perfil del usuario"""
    TEMAS_VALIDOS = [
        'cyan', 'ocean', 'emerald', 'teal', 'aqua',
        'mint', 'lagoon', 'sky', 'sage'
    ]
    
    if request.method == 'POST':
        tema_color = request.form.get(
            'tema_color', current_user.tema_color or 'cyan'
        )
        fuente_ui = request.form.get(
            'fuente_ui', current_user.fuente_ui or 'arsflow'
        )
        mostrar_chat = request.form.get('mostrar_chat') == '1'
        
        if tema_color not in TEMAS_VALIDOS:
            flash('Tema de color inválido', 'error')
            return redirect(url_for('perfil_configuracion'))
        if fuente_ui not in FUENTES_UI:
            flash('Tipografía inválida', 'error')
            return redirect(url_for('perfil_configuracion'))
        
        execute_update(
            '''
            UPDATE usuarios
            SET tema_color=%s, fuente_ui=%s, mostrar_chat=%s
            WHERE id=%s AND tenant_id <=> %s
            ''',
            (
                tema_color,
                fuente_ui,
                1 if mostrar_chat else 0,
                current_user.id,
                get_current_tenant_id(),
            ),
        )
        
        current_user.tema_color = tema_color
        current_user.fuente_ui = fuente_ui
        current_user.mostrar_chat = mostrar_chat
        
        flash('Apariencia actualizada correctamente', 'success')
        return redirect(url_for('perfil_configuracion'))
    
    ecf_certificado = None
    if user_has_permission(current_user, 'configuracion.editar'):
        tenant_id = get_current_tenant_id()
        empresa_actual = get_empresa_info(tenant_id) or {}
        ecf_config = current_app.config['ECF_CONFIG']
        ecf_certificado = {
            'habilitado_global': ecf_config.enabled,
            'ambiente': ecf_config.environment,
            'configurado': False,
            'valido': False,
            'mensaje': 'La integración e-CF está desactivada en el servidor.',
            'vence': None,
            'huella': None,
            'compatibilidad_global': False,
            'referencia_esperada': (
                f'tenant-{tenant_id}/certificate.p12'
            ),
        }
        if ecf_config.enabled:
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

    return render_template(
        'perfil/configuracion.html',
        ecf_certificado=ecf_certificado,
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
