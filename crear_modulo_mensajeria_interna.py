"""Crea las tablas de mensajería privada entre usuarios de un tenant."""

from app import app
from core.database import execute_query, execute_update


def crear_modulo():
    with app.app_context():
        columnas_usuario = execute_query(
            "SHOW COLUMNS FROM usuarios", fetch="all"
        ) or []
        if "mostrar_chat" not in {
            columna["Field"] for columna in columnas_usuario
        }:
            execute_update(
                "ALTER TABLE usuarios "
                "ADD COLUMN mostrar_chat TINYINT(1) NOT NULL DEFAULT 1"
            )

        execute_update(
            """
            CREATE TABLE IF NOT EXISTS conversaciones_internas (
                id INT AUTO_INCREMENT PRIMARY KEY,
                tenant_id INT NOT NULL,
                usuario_menor_id INT NOT NULL,
                usuario_mayor_id INT NOT NULL,
                ultimo_mensaje_at DATETIME NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY uq_conversacion_pareja (
                    tenant_id, usuario_menor_id, usuario_mayor_id
                ),
                INDEX idx_conversacion_usuario_menor (
                    tenant_id, usuario_menor_id, ultimo_mensaje_at
                ),
                INDEX idx_conversacion_usuario_mayor (
                    tenant_id, usuario_mayor_id, ultimo_mensaje_at
                )
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )
        execute_update(
            """
            CREATE TABLE IF NOT EXISTS mensajes_internos (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                tenant_id INT NOT NULL,
                conversacion_id INT NOT NULL,
                remitente_id INT NOT NULL,
                destinatario_id INT NOT NULL,
                cuerpo TEXT NOT NULL,
                leido_at DATETIME NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_mensaje_conversacion (
                    tenant_id, conversacion_id, id
                ),
                INDEX idx_mensaje_no_leido (
                    tenant_id, destinatario_id, leido_at, id
                ),
                INDEX idx_mensaje_remitente (
                    tenant_id, remitente_id, created_at
                )
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )
        print("[OK] Módulo de mensajería interna disponible")


if __name__ == "__main__":
    crear_modulo()
