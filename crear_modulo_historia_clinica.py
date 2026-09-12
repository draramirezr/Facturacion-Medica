"""Crea las tablas del expediente clínico longitudinal."""

from app import app, execute_query, execute_update


def crear_modulo():
    with app.app_context():
        columnas = execute_query("SHOW COLUMNS FROM pacientes", fetch="all") or []
        nombres = {columna["Field"] for columna in columnas}
        if "ocupacion" not in nombres:
            execute_update(
                "ALTER TABLE pacientes ADD COLUMN ocupacion VARCHAR(150) NULL AFTER direccion"
            )

        execute_update(
            """
            CREATE TABLE IF NOT EXISTS consultas_clinicas (
                id INT AUTO_INCREMENT PRIMARY KEY,
                tenant_id INT NOT NULL,
                paciente_id INT NOT NULL,
                medico_id INT NOT NULL,
                fecha DATE NOT NULL,
                hora TIME NOT NULL,
                motivo_consulta TEXT NOT NULL,
                enfermedad_actual LONGTEXT NOT NULL,
                antecedentes_personales LONGTEXT NOT NULL,
                antecedentes_familiares LONGTEXT NOT NULL,
                signos_vitales LONGTEXT NOT NULL,
                examen_fisico LONGTEXT NOT NULL,
                diagnostico_principal TEXT NOT NULL,
                diagnosticos_secundarios TEXT NULL,
                diagnostico_presuntivo TEXT NULL,
                diagnostico_diferencial TEXT NULL,
                codigo_cie10 VARCHAR(30) NULL,
                plan_tratamiento LONGTEXT NOT NULL,
                nota_evolucion_inicial TEXT NULL,
                proxima_cita DATE NULL,
                proxima_especialidad VARCHAR(150) NULL,
                proxima_motivo TEXT NULL,
                indicaciones_seguimiento TEXT NULL,
                version INT NOT NULL DEFAULT 1,
                created_by INT NULL,
                updated_by INT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_consulta_clinica_paciente (tenant_id, paciente_id, fecha),
                INDEX idx_consulta_clinica_medico (tenant_id, medico_id),
                INDEX idx_consulta_clinica_cie10 (codigo_cie10)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )

        execute_update(
            """
            CREATE TABLE IF NOT EXISTS evoluciones_clinicas (
                id INT AUTO_INCREMENT PRIMARY KEY,
                tenant_id INT NOT NULL,
                consulta_id INT NOT NULL,
                paciente_id INT NOT NULL,
                medico_id INT NOT NULL,
                fecha DATE NOT NULL,
                hora TIME NOT NULL,
                nota_evolucion TEXT NOT NULL,
                diagnostico TEXT NULL,
                tratamiento TEXT NULL,
                created_by INT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_evolucion_consulta (tenant_id, consulta_id, fecha),
                INDEX idx_evolucion_paciente (tenant_id, paciente_id, fecha)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )

        execute_update(
            """
            CREATE TABLE IF NOT EXISTS auditoria_historia_clinica (
                id INT AUTO_INCREMENT PRIMARY KEY,
                tenant_id INT NOT NULL,
                consulta_id INT NOT NULL,
                usuario_id INT NULL,
                version_anterior INT NOT NULL,
                datos_anteriores LONGTEXT NOT NULL,
                datos_nuevos LONGTEXT NOT NULL,
                ip VARCHAR(45) NULL,
                user_agent VARCHAR(500) NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_auditoria_consulta (tenant_id, consulta_id, created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )
        print("[OK] Módulo Historia Clínica disponible")


if __name__ == "__main__":
    crear_modulo()
