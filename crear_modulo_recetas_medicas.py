"""Crea las tablas para recetas médicas y sus medicamentos."""

from app import app
from core.database import execute_query, execute_update


def crear_modulo():
    with app.app_context():
        execute_update(
            """
            CREATE TABLE IF NOT EXISTS recetas_medicas (
                id INT AUTO_INCREMENT PRIMARY KEY,
                tenant_id INT NOT NULL,
                codigo VARCHAR(40) NOT NULL,
                paciente_id INT NOT NULL,
                medico_id INT NOT NULL,
                consulta_id INT NULL,
                fecha DATE NOT NULL,
                diagnostico TEXT NULL,
                codigo_cie10 VARCHAR(30) NULL,
                indicaciones_generales TEXT NULL,
                estado VARCHAR(20) NOT NULL DEFAULT 'Emitida',
                created_by INT NULL,
                anulada_por INT NULL,
                fecha_anulacion DATETIME NULL,
                motivo_anulacion TEXT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY uq_receta_codigo (tenant_id, codigo),
                INDEX idx_receta_paciente (tenant_id, paciente_id, fecha),
                INDEX idx_receta_medico (tenant_id, medico_id, fecha),
                INDEX idx_receta_consulta (tenant_id, consulta_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )
        execute_update(
            """
            CREATE TABLE IF NOT EXISTS receta_medicamentos (
                id INT AUTO_INCREMENT PRIMARY KEY,
                tenant_id INT NOT NULL,
                receta_id INT NOT NULL,
                medicamento VARCHAR(250) NOT NULL,
                presentacion VARCHAR(150) NULL,
                dosis VARCHAR(150) NOT NULL,
                via VARCHAR(100) NULL,
                frecuencia VARCHAR(150) NOT NULL,
                duracion VARCHAR(150) NOT NULL,
                cantidad VARCHAR(100) NULL,
                indicaciones TEXT NULL,
                orden INT NOT NULL DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_medicamento_receta (tenant_id, receta_id, orden)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )
        total = execute_query(
            "SELECT COUNT(*) AS total FROM recetas_medicas"
        )
        print(f"[OK] Recetas Médicas disponibles. Recetas: {total['total']}")


if __name__ == "__main__":
    crear_modulo()
