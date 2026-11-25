"""Crea la tabla de Constancias Médicas y siembra sus permisos.

Idempotente: puede ejecutarse varias veces. En producción el arranque
(core/schema_bootstrap.py) hace lo mismo automáticamente.
"""

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))  # raíz del proyecto

from app import app
from core.database import execute_query, execute_update
from rbac_catalog import PERMISOS


PERMISOS_HEREDADOS = {
    "constancias.ver": "licencias.ver",
    "constancias.crear": "licencias.crear",
    "constancias.editar": "licencias.editar",
    "constancias.anular": "licencias.anular",
    "constancias.imprimir": "licencias.imprimir",
}


def crear_modulo():
    with app.app_context():
        execute_update(
            """
            CREATE TABLE IF NOT EXISTS constancias_medicas (
                id INT AUTO_INCREMENT PRIMARY KEY,
                tenant_id INT NOT NULL,
                numero INT NOT NULL,
                codigo VARCHAR(40) NOT NULL,
                paciente_id INT NOT NULL,
                medico_id INT NOT NULL,
                consulta_id INT NULL,
                fecha_atencion DATE NOT NULL,
                hora_entrada TIME NULL,
                hora_salida TIME NULL,
                dirigida_a VARCHAR(200) NULL,
                motivo VARCHAR(500) NULL,
                estado VARCHAR(20) NOT NULL DEFAULT 'Activa',
                created_by INT NULL,
                updated_by INT NULL,
                anulado_por INT NULL,
                fecha_anulacion DATETIME NULL,
                motivo_anulacion TEXT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY uq_constancia_codigo (tenant_id, codigo),
                UNIQUE KEY uq_constancia_numero (tenant_id, numero),
                INDEX idx_constancia_paciente (tenant_id, paciente_id),
                INDEX idx_constancia_fecha (tenant_id, fecha_atencion),
                INDEX idx_constancia_medico (tenant_id, medico_id),
                INDEX idx_constancia_consulta (tenant_id, consulta_id),
                FOREIGN KEY (tenant_id) REFERENCES empresas(id) ON DELETE RESTRICT
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """
        )

        previos = {
            fila["codigo"]
            for fila in execute_query(
                "SELECT codigo FROM permisos WHERE codigo LIKE 'constancias.%%'",
                fetch="all",
            ) or []
        }
        for permiso in PERMISOS:
            if permiso["grupo"] != "constancias":
                continue
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
                    permiso["codigo"], permiso["grupo"],
                    permiso["nombre"], permiso["descripcion"],
                ),
            )

        # Los roles que ya tenían el permiso de licencias reciben el de
        # constancias (solo la primera vez que el permiso aparece).
        for nuevo, base in PERMISOS_HEREDADOS.items():
            if nuevo in previos:
                continue
            execute_update(
                """
                INSERT IGNORE INTO rol_permisos (tenant_id, rol_id, permiso_id)
                SELECT rp.tenant_id, rp.rol_id, pn.id
                FROM rol_permisos rp
                JOIN permisos pb ON pb.id = rp.permiso_id AND pb.codigo = %s
                JOIN permisos pn ON pn.codigo = %s
                """,
                (base, nuevo),
            )

        total = execute_query("SELECT COUNT(*) AS total FROM constancias_medicas")
        print(f"[OK] Módulo Constancias Médicas. Registros: {total['total']}")


if __name__ == "__main__":
    crear_modulo()
