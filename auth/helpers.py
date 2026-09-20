"""Carga de usuarios y helpers de autorización."""

from auth.models import User
from core.database import execute_query
from rbac_catalog import PERMISOS_ROLES_SISTEMA


def usuario_es_administrador(user):
    """Administrador de empresa: rol RBAC o perfil legacy sin roles asignados."""
    if not user:
        return False
    roles = set(getattr(user, 'rbac_roles', ()) or ())
    if 'Administrador' in roles:
        return True
    return (
        getattr(user, 'perfil', None) == 'Administrador'
        and not getattr(user, 'rbac_role_count', 0)
    )


def usuario_es_medico_operativo(user):
    """Médico de cola: no aplica a quien administra usuarios o la empresa."""
    if not user or usuario_es_administrador(user):
        return False
    if user_has_permission(user, 'usuarios.ver'):
        return False
    return bool(
        getattr(user, 'medico_id', None)
        and user_has_permission(user, 'turnos.cola_propia')
    )


def user_has_permission(user, codigo):
    """Consultar permisos con compatibilidad para usuarios legacy y de pruebas."""
    checker = getattr(user, 'has_permission', None)
    if callable(checker):
        return checker(codigo)
    if usuario_es_administrador(user):
        return True
    if (
        getattr(user, 'tenant_id', 1) is None
        and getattr(user, 'perfil', None) == 'Administrador'
    ):
        return True
    return codigo in PERMISOS_ROLES_SISTEMA.get(
        getattr(user, 'perfil', None),
        frozenset(),
    )


def load_user(user_id):
    """Cargar usuario activo con empresa, roles, permisos y médico asociado."""
    user_data = execute_query(
        '''
        SELECT u.*, e.nombre as empresa_nombre,
               (
                   SELECT GROUP_CONCAT(DISTINCT p.codigo SEPARATOR ',')
                   FROM usuario_roles ur
                   JOIN rol_permisos rp
                     ON rp.tenant_id=ur.tenant_id AND rp.rol_id=ur.rol_id
                   JOIN permisos p ON p.id=rp.permiso_id AND p.activo=1
                   JOIN roles r
                     ON r.id=ur.rol_id AND r.tenant_id=ur.tenant_id
                    AND r.activo=1
                   WHERE ur.usuario_id=u.id AND ur.tenant_id=u.tenant_id
               ) AS permisos_rbac,
               (
                   SELECT GROUP_CONCAT(DISTINCT r.nombre SEPARATOR ',')
                   FROM usuario_roles ur
                   JOIN roles r
                     ON r.id=ur.rol_id AND r.tenant_id=ur.tenant_id
                    AND r.activo=1
                   WHERE ur.usuario_id=u.id AND ur.tenant_id=u.tenant_id
               ) AS roles_rbac,
               (
                   SELECT COUNT(DISTINCT ur.rol_id)
                   FROM usuario_roles ur
                   JOIN roles r
                     ON r.id=ur.rol_id AND r.tenant_id=ur.tenant_id
                    AND r.activo=1
                   WHERE ur.usuario_id=u.id AND ur.tenant_id=u.tenant_id
               ) AS cantidad_roles_rbac,
               (
                   SELECT um.medico_id
                   FROM usuario_medico um
                   WHERE um.usuario_id=u.id AND um.tenant_id=u.tenant_id
                   LIMIT 1
               ) AS medico_id
        FROM usuarios u
        LEFT JOIN empresas e ON u.tenant_id = e.id
        WHERE u.id = %s AND u.activo = 1
        ''',
        (user_id,),
    )
    if not user_data:
        return None
    return User(
        id=user_data['id'],
        nombre=user_data['nombre'],
        email=user_data['email'],
        perfil=user_data['perfil'],
        tema_color=user_data.get('tema_color', 'cyan'),
        fuente_ui=user_data.get('fuente_ui', 'arsflow'),
        tenant_id=user_data.get('tenant_id', 1),
        empresa_nombre=user_data.get('empresa_nombre', ''),
        mostrar_chat=user_data.get('mostrar_chat', 1),
        idioma_correccion=user_data.get('idioma_correccion', 'es'),
        permissions=(
            user_data.get('permisos_rbac', '').split(',')
            if user_data.get('permisos_rbac') else ()
        ),
        rbac_roles=(
            user_data.get('roles_rbac', '').split(',')
            if user_data.get('roles_rbac') else ()
        ),
        rbac_role_count=user_data.get('cantidad_roles_rbac', 0),
        medico_id=user_data.get('medico_id'),
    )
