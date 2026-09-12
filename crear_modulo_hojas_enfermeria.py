"""Crea el almacenamiento de hojas de enfermería de emergencia."""

from app import app
from core.database import execute_update


def crear_tabla():
    with app.app_context():
        execute_update(
            """
            CREATE TABLE IF NOT EXISTS hojas_enfermeria (
                id INT AUTO_INCREMENT PRIMARY KEY,
                tenant_id INT NOT NULL,
                paciente_id INT NOT NULL,
                historia_emergencia_id INT NULL,
                fecha_servicio DATE NOT NULL,
                hora_servicio TIME NOT NULL,
                nombre_paciente VARCHAR(200) NOT NULL,
                edad INT NULL,
                sexo VARCHAR(20) NULL,
                direccion VARCHAR(500) NULL,
                responsable VARCHAR(200) NOT NULL,
                telefono_responsable VARCHAR(10) NOT NULL,
                ars_nombre VARCHAR(200) NULL,
                medicamentos_materiales LONGTEXT NOT NULL,
                observaciones TEXT NULL,
                firma_responsable VARCHAR(200) NOT NULL,
                created_by INT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_hoja_enfermeria_tenant_fecha (tenant_id, fecha_servicio),
                INDEX idx_hoja_enfermeria_paciente (tenant_id, paciente_id),
                INDEX idx_hoja_enfermeria_emergencia (tenant_id, historia_emergencia_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )
        print("[OK] Módulo Hoja de Enfermería disponible")


if __name__ == "__main__":
    crear_tabla()
