"""Crea y puebla el almacenamiento RBAC sin modificar el perfil legacy."""

from app import app
from core.database import database_transaction, execute_query, execute_update
from rbac_catalog import (
    DESCRIPCIONES_ROLES_SISTEMA,
    PERMISOS,
    PERMISOS_ROLES_SISTEMA,
)


DDL_TABLAS = (
    """
    CREATE TABLE IF NOT EXISTS permisos (
        id INT NOT NULL AUTO_INCREMENT,
        codigo VARCHAR(100) NOT NULL,
        grupo VARCHAR(50) NOT NULL,
        nombre VARCHAR(150) NOT NULL,
        descripcion VARCHAR(500) NULL,
        activo TINYINT(1) NOT NULL DEFAULT 1,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY uq_permisos_codigo (codigo),
        INDEX idx_permisos_grupo_activo (grupo, activo)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    """
    CREATE TABLE IF NOT EXISTS roles (
        id INT NOT NULL AUTO_INCREMENT,
        tenant_id INT NOT NULL,
        nombre VARCHAR(100) NOT NULL,
        descripcion VARCHAR(500) NULL,
        es_sistema TINYINT(1) NOT NULL DEFAULT 0,
        activo TINYINT(1) NOT NULL DEFAULT 1,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY uq_roles_tenant_nombre (tenant_id, nombre),
        UNIQUE KEY uq_roles_tenant_id (tenant_id, id),
        INDEX idx_roles_tenant_activo (tenant_id, activo),
        CONSTRAINT fk_roles_empresa
            FOREIGN KEY (tenant_id) REFERENCES empresas (id)
            ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    """
    CREATE TABLE IF NOT EXISTS rol_permisos (
        tenant_id INT NOT NULL,
        rol_id INT NOT NULL,
        permiso_id INT NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (tenant_id, rol_id, permiso_id),
        INDEX idx_rol_permisos_permiso (permiso_id, tenant_id),
        CONSTRAINT fk_rol_permisos_empresa
            FOREIGN KEY (tenant_id) REFERENCES empresas (id)
            ON DELETE CASCADE,
        CONSTRAINT fk_rol_permisos_rol
            FOREIGN KEY (tenant_id, rol_id) REFERENCES roles (tenant_id, id)
            ON DELETE CASCADE,
        CONSTRAINT fk_rol_permisos_permiso
            FOREIGN KEY (permiso_id) REFERENCES permisos (id)
            ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    """
    CREATE TABLE IF NOT EXISTS usuario_roles (
        tenant_id INT NOT NULL,
        usuario_id INT NOT NULL,
        rol_id INT NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (tenant_id, usuario_id, rol_id),
        INDEX idx_usuario_roles_rol (tenant_id, rol_id, usuario_id),
        CONSTRAINT fk_usuario_roles_empresa
            FOREIGN KEY (tenant_id) REFERENCES empresas (id)
            ON DELETE CASCADE,
        CONSTRAINT fk_usuario_roles_usuario
            FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
            ON DELETE CASCADE,
        CONSTRAINT fk_usuario_roles_rol
            FOREIGN KEY (tenant_id, rol_id) REFERENCES roles (tenant_id, id)
            ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    """
    CREATE TABLE IF NOT EXISTS usuario_medico (
        tenant_id INT NOT NULL,
        usuario_id INT NOT NULL,
        medico_id INT NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (tenant_id, usuario_id, medico_id),
        UNIQUE KEY uq_usuario_medico_usuario (tenant_id, usuario_id),
        UNIQUE KEY uq_usuario_medico_medico (tenant_id, medico_id),
        INDEX idx_usuario_medico_medico (medico_id, tenant_id),
        CONSTRAINT fk_usuario_medico_empresa
            FOREIGN KEY (tenant_id) REFERENCES empresas (id)
            ON DELETE CASCADE,
        CONSTRAINT fk_usuario_medico_usuario
            FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
            ON DELETE CASCADE,
        CONSTRAINT fk_usuario_medico_medico
            FOREIGN KEY (medico_id) REFERENCES medicos (id)
            ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
)


def _crear_tablas():
    for ddl in DDL_TABLAS:
        execute_update(ddl)


def _sembrar_permisos():
    for permiso in PERMISOS:
        execute_update(
            """
            INSERT INTO permisos (codigo, grupo, nombre, descripcion, activo)
            VALUES (%s, %s, %s, %s, 1)
            ON DUPLICATE KEY UPDATE
                grupo = VALUES(grupo),
                nombre = VALUES(nombre),
                descripcion = VALUES(descripcion),
                activo = 1
            """,
            (
                permiso["codigo"],
                permiso["grupo"],
                permiso["nombre"],
                permiso["descripcion"],
            ),
        )


def _sembrar_roles():
    empresas = execute_query("SELECT id FROM empresas ORDER BY id", fetch="all") or []
    for empresa in empresas:
        tenant_id = empresa["id"]
        for nombre, codigos in PERMISOS_ROLES_SISTEMA.items():
            execute_update(
                """
                INSERT INTO roles (
                    tenant_id, nombre, descripcion, es_sistema, activo
                )
                VALUES (%s, %s, %s, 1, 1)
                ON DUPLICATE KEY UPDATE
                    descripcion = VALUES(descripcion),
                    es_sistema = 1,
                    activo = 1
                """,
                (
                    tenant_id,
                    nombre,
                    DESCRIPCIONES_ROLES_SISTEMA[nombre],
                ),
            )

            for codigo in sorted(codigos):
                execute_update(
                    """
                    INSERT IGNORE INTO rol_permisos (
                        tenant_id, rol_id, permiso_id
                    )
                    SELECT %s, r.id, p.id
                    FROM roles AS r
                    INNER JOIN permisos AS p ON p.codigo = %s
                    WHERE r.tenant_id = %s AND r.nombre = %s
                    """,
                    (tenant_id, codigo, tenant_id, nombre),
                )


def _migrar_perfiles_legacy():
    for perfil in PERMISOS_ROLES_SISTEMA:
        execute_update(
            """
            INSERT IGNORE INTO usuario_roles (tenant_id, usuario_id, rol_id)
            SELECT u.tenant_id, u.id, r.id
            FROM usuarios AS u
            INNER JOIN roles AS r
                ON r.tenant_id = u.tenant_id AND r.nombre = %s
            WHERE u.tenant_id IS NOT NULL AND u.perfil = %s
            """,
            (perfil, perfil),
        )


def _vincular_medicos_por_email():
    """Vincular sólo coincidencias inequívocas disponibles en datos legacy."""

    execute_update(
        """
        INSERT IGNORE INTO usuario_medico (tenant_id, usuario_id, medico_id)
        SELECT u.tenant_id, u.id, m.id
        FROM usuarios AS u
        INNER JOIN medicos AS m
            ON m.tenant_id = u.tenant_id
            AND m.email IS NOT NULL
            AND TRIM(m.email) <> ''
            AND LOWER(TRIM(m.email)) = LOWER(TRIM(u.email))
        WHERE u.tenant_id IS NOT NULL AND u.perfil = %s
        """,
        ("Médico",),
    )


def crear_modulo():
    """Crear tablas, sembrar roles y migrar asignaciones existentes."""

    with app.app_context():
        _crear_tablas()
        with database_transaction():
            _sembrar_permisos()
            _sembrar_roles()
            _migrar_perfiles_legacy()
            _vincular_medicos_por_email()

        print("[OK] Módulo de roles y permisos disponible")


if __name__ == "__main__":
    crear_modulo()
