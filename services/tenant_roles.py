"""Roles de sistema iguales para cada empresa, más el administrador inicial."""

from core.database import execute_query, execute_update
from rbac_catalog import DESCRIPCIONES_ROLES_SISTEMA, PERMISOS_ROLES_SISTEMA


def sembrar_roles_sistema(tenant_id):
    """Crear los roles de sistema que falten. No toca roles creados por la empresa."""
    if not tenant_id:
        return
    for nombre, codigos in PERMISOS_ROLES_SISTEMA.items():
        existente = execute_query(
            'SELECT id FROM roles WHERE tenant_id=%s AND nombre=%s',
            (tenant_id, nombre),
        )
        if existente:
            continue
        rol_id = execute_update(
            '''
            INSERT INTO roles (
                tenant_id, nombre, descripcion, es_sistema, activo
            ) VALUES (%s, %s, %s, 1, 1)
            ''',
            (tenant_id, nombre, DESCRIPCIONES_ROLES_SISTEMA[nombre]),
        )
        if not rol_id:
            continue
        for codigo in sorted(codigos):
            execute_update(
                '''
                INSERT IGNORE INTO rol_permisos (tenant_id, rol_id, permiso_id)
                SELECT %s, %s, id FROM permisos WHERE codigo=%s
                ''',
                (tenant_id, rol_id, codigo),
            )


def _rol_administrador(tenant_id):
    return execute_query(
        '''
        SELECT id FROM roles
        WHERE tenant_id=%s AND nombre='Administrador' AND activo=1
        ''',
        (tenant_id,),
    )


def asignar_rol_administrador(usuario_id, tenant_id):
    """Da el rol Administrador si el usuario todavía no tiene ninguno."""
    if not usuario_id or not tenant_id:
        return
    sembrar_roles_sistema(tenant_id)
    ya_tiene = execute_query(
        '''
        SELECT 1 AS ok FROM usuario_roles
        WHERE tenant_id=%s AND usuario_id=%s
        LIMIT 1
        ''',
        (tenant_id, usuario_id),
    )
    if ya_tiene:
        return
    rol = _rol_administrador(tenant_id)
    if not rol:
        return
    execute_update(
        '''
        INSERT IGNORE INTO usuario_roles (tenant_id, usuario_id, rol_id)
        VALUES (%s, %s, %s)
        ''',
        (tenant_id, usuario_id, rol['id']),
    )


def asegurar_roles_del_tenant(tenant_id):
    """Roles de sistema y administrador para quien creó la empresa y aún no tiene rol."""
    if not tenant_id:
        return
    sembrar_roles_sistema(tenant_id)
    rol = _rol_administrador(tenant_id)
    if not rol:
        return
    execute_update(
        '''
        INSERT IGNORE INTO usuario_roles (tenant_id, usuario_id, rol_id)
        SELECT u.tenant_id, u.id, %s
        FROM usuarios u
        WHERE u.tenant_id=%s
          AND u.perfil='Administrador'
          AND NOT EXISTS (
              SELECT 1 FROM usuario_roles ur
              WHERE ur.tenant_id=u.tenant_id AND ur.usuario_id=u.id
          )
        ''',
        (rol['id'], tenant_id),
    )
