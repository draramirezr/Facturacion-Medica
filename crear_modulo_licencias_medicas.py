"""Crea las tablas y el catálogo inicial de Licencias Médicas."""

from app import app, execute_query, execute_update


TIPOS_INICIALES = [
    "Enfermedad común",
    "Accidente",
    "Maternidad",
    "Paternidad",
    "Incapacidad temporal",
    "Postoperatorio",
    "Otro",
]


def crear_modulo():
    with app.app_context():
        execute_update(
            """
            CREATE TABLE IF NOT EXISTS tipos_licencia_medica (
                id INT AUTO_INCREMENT PRIMARY KEY,
                tenant_id INT NOT NULL,
                nombre VARCHAR(120) NOT NULL,
                activo TINYINT(1) NOT NULL DEFAULT 1,
                created_by INT NULL,
                updated_by INT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY uq_tipo_licencia_tenant_nombre (tenant_id, nombre),
                INDEX idx_tipo_licencia_activo (tenant_id, activo)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )

        execute_update(
            """
            CREATE TABLE IF NOT EXISTS licencias_medicas (
                id INT AUTO_INCREMENT PRIMARY KEY,
                tenant_id INT NOT NULL,
                codigo VARCHAR(40) NOT NULL,
                paciente_id INT NOT NULL,
                medico_id INT NOT NULL,
                consulta_id INT NULL,
                tipo_licencia_id INT NOT NULL,
                diagnostico TEXT NOT NULL,
                codigo_cie10 VARCHAR(30) NULL,
                motivo_condicion TEXT NOT NULL,
                observaciones TEXT NULL,
                fecha_emision DATE NOT NULL,
                fecha_inicio DATE NOT NULL,
                fecha_termino DATE NOT NULL,
                cantidad_dias INT NOT NULL,
                estado VARCHAR(20) NOT NULL DEFAULT 'Borrador',
                version INT NOT NULL DEFAULT 1,
                created_by INT NULL,
                updated_by INT NULL,
                anulado_por INT NULL,
                fecha_anulacion DATETIME NULL,
                motivo_anulacion TEXT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY uq_licencia_codigo (tenant_id, codigo),
                INDEX idx_licencia_paciente (tenant_id, paciente_id, fecha_inicio),
                INDEX idx_licencia_medico (tenant_id, medico_id, fecha_emision),
                INDEX idx_licencia_estado (tenant_id, estado)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )

        execute_update(
            """
            CREATE TABLE IF NOT EXISTS auditoria_licencias_medicas (
                id INT AUTO_INCREMENT PRIMARY KEY,
                tenant_id INT NOT NULL,
                licencia_id INT NOT NULL,
                usuario_id INT NULL,
                accion VARCHAR(30) NOT NULL,
                version_anterior INT NULL,
                datos_anteriores LONGTEXT NULL,
                datos_nuevos LONGTEXT NULL,
                motivo TEXT NULL,
                ip VARCHAR(45) NULL,
                user_agent VARCHAR(500) NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_auditoria_licencia (tenant_id, licencia_id, created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )

        empresas = execute_query("SELECT id FROM empresas", fetch="all") or []
        for empresa in empresas:
            for nombre in TIPOS_INICIALES:
                execute_update(
                    """
                    INSERT IGNORE INTO tipos_licencia_medica (tenant_id, nombre)
                    VALUES (%s, %s)
                    """,
                    (empresa["id"], nombre),
                )

        print("[OK] Módulo Licencias Médicas disponible")


if __name__ == "__main__":
    crear_modulo()
