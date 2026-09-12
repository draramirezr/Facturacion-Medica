"""Crea la agenda médica e importa las próximas citas de Historia Clínica."""

from app import app, execute_query, execute_update


def crear_modulo():
    with app.app_context():
        columnas = execute_query(
            "SHOW COLUMNS FROM consultas_clinicas", fetch="all"
        ) or []
        if "proxima_hora" not in {columna["Field"] for columna in columnas}:
            execute_update(
                "ALTER TABLE consultas_clinicas "
                "ADD COLUMN proxima_hora TIME NULL AFTER proxima_cita"
            )

        execute_update(
            """
            CREATE TABLE IF NOT EXISTS citas_medicas (
                id INT AUTO_INCREMENT PRIMARY KEY,
                tenant_id INT NOT NULL,
                paciente_id INT NOT NULL,
                medico_id INT NOT NULL,
                consulta_origen_id INT NULL,
                fecha DATE NOT NULL,
                hora TIME NOT NULL,
                duracion_minutos INT NOT NULL DEFAULT 30,
                especialidad VARCHAR(150) NULL,
                motivo TEXT NOT NULL,
                notas TEXT NULL,
                estado VARCHAR(20) NOT NULL DEFAULT 'Programada',
                origen VARCHAR(20) NOT NULL DEFAULT 'Manual',
                created_by INT NULL,
                updated_by INT NULL,
                cancelada_por INT NULL,
                fecha_cancelacion DATETIME NULL,
                motivo_cancelacion TEXT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY uq_cita_consulta_origen (tenant_id, consulta_origen_id),
                INDEX idx_cita_fecha (tenant_id, fecha, hora),
                INDEX idx_cita_paciente (tenant_id, paciente_id, fecha),
                INDEX idx_cita_medico (tenant_id, medico_id, fecha, hora),
                INDEX idx_cita_estado (tenant_id, estado)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )

        execute_update(
            """
            INSERT IGNORE INTO citas_medicas (
                tenant_id, paciente_id, medico_id, consulta_origen_id,
                fecha, hora, duracion_minutos, especialidad, motivo,
                notas, estado, origen, created_by, updated_by
            )
            SELECT c.tenant_id, c.paciente_id, c.medico_id, c.id,
                   c.proxima_cita, COALESCE(c.proxima_hora, '09:00:00'), 30,
                   c.proxima_especialidad,
                   COALESCE(NULLIF(c.proxima_motivo, ''), 'Seguimiento médico'),
                   c.indicaciones_seguimiento, 'Programada', 'Historia clinica',
                   c.created_by, c.updated_by
            FROM consultas_clinicas c
            WHERE c.proxima_cita IS NOT NULL
            """
        )
        total = execute_query(
            "SELECT COUNT(*) AS total FROM citas_medicas"
        )
        print(f"[OK] Agenda Médica disponible. Citas: {total['total']}")


if __name__ == "__main__":
    crear_modulo()
