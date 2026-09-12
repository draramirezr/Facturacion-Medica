"""Crea el almacenamiento de historias clínicas de emergencia."""

from app import app
from core.database import execute_update


def crear_tabla():
    with app.app_context():
        execute_update(
            """
            CREATE TABLE IF NOT EXISTS historias_emergencia (
                id INT AUTO_INCREMENT PRIMARY KEY,
                tenant_id INT NOT NULL,
                paciente_id INT NOT NULL,
                medico_id INT NOT NULL,
                fecha DATE NOT NULL,
                hora_servicio TIME NOT NULL,
                autorizacion VARCHAR(100) NULL,
                nombre_paciente VARCHAR(200) NOT NULL,
                edad INT NULL,
                sexo VARCHAR(10) NOT NULL,
                ars_nombre VARCHAR(200) NULL,
                numero_afiliado VARCHAR(100) NULL,
                nss VARCHAR(50) NULL,
                motivo_emergencia TEXT NOT NULL,
                historia_enfermedad TEXT NOT NULL,
                datos_clinicos LONGTEXT NOT NULL,
                diagnostico_impresion TEXT NOT NULL,
                estatus_paciente VARCHAR(50) NOT NULL,
                origen_enfermedad VARCHAR(50) NOT NULL,
                observaciones TEXT NULL,
                medico_nombre VARCHAR(200) NOT NULL,
                created_by INT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_historia_tenant_fecha (tenant_id, fecha),
                INDEX idx_historia_paciente (paciente_id),
                INDEX idx_historia_medico (medico_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )
        print("[OK] Tabla historias_emergencia disponible")


if __name__ == "__main__":
    crear_tabla()
