"""Crea de forma idempotente el almacenamiento del módulo de turnos."""

from app import app
from core.database import execute_query, execute_update


def _nombres_columnas(tabla):
    columnas = execute_query(f"SHOW COLUMNS FROM `{tabla}`", fetch="all") or []
    return {columna["Field"] for columna in columnas}


def _nombres_indices(tabla):
    indices = execute_query(f"SHOW INDEX FROM `{tabla}`", fetch="all") or []
    return {indice["Key_name"] for indice in indices}


def _agregar_columna_si_falta(tabla, columna, definicion):
    if columna not in _nombres_columnas(tabla):
        execute_update(
            f"ALTER TABLE `{tabla}` ADD COLUMN `{columna}` {definicion}"
        )


def _agregar_indice_si_falta(tabla, nombre, columnas):
    if nombre not in _nombres_indices(tabla):
        execute_update(
            f"ALTER TABLE `{tabla}` ADD INDEX `{nombre}` ({columnas})"
        )


def crear_modulo():
    """Crear tablas y extensiones requeridas por el módulo de turnos."""

    with app.app_context():
        execute_update(
            """
            CREATE TABLE IF NOT EXISTS secuencias_turnos (
                tenant_id INT NOT NULL,
                fecha DATE NOT NULL,
                medico_id INT NOT NULL,
                ultimo_numero INT UNSIGNED NOT NULL DEFAULT 0,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                    ON UPDATE CURRENT_TIMESTAMP,
                PRIMARY KEY (tenant_id, fecha, medico_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )

        execute_update(
            """
            CREATE TABLE IF NOT EXISTS turnos_atencion (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                tenant_id INT NOT NULL,
                fecha DATE NOT NULL,
                paciente_id INT NOT NULL,
                medico_id INT NOT NULL,
                especialidad_snapshot VARCHAR(150) NULL,
                cita_id INT NULL,
                consulta_id INT NULL,
                numero INT UNSIGNED NOT NULL,
                posicion INT UNSIGNED NOT NULL,
                estado VARCHAR(20) NOT NULL DEFAULT 'EnEspera',
                motivo TEXT NULL,
                registro_incompleto TINYINT(1) NOT NULL DEFAULT 0,
                llegada_at DATETIME NULL,
                llamado_at DATETIME NULL,
                consulta_iniciada_at DATETIME NULL,
                finalizado_at DATETIME NULL,
                actor_id INT NULL,
                created_by INT NULL,
                updated_by INT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                    ON UPDATE CURRENT_TIMESTAMP,
                PRIMARY KEY (id),
                UNIQUE KEY uq_turno_tenant_id (tenant_id, id),
                UNIQUE KEY uq_turno_numero_cola (
                    tenant_id, fecha, medico_id, numero
                ),
                UNIQUE KEY uq_turno_posicion_cola (
                    tenant_id, fecha, medico_id, posicion
                ),
                UNIQUE KEY uq_turno_cita (tenant_id, cita_id),
                UNIQUE KEY uq_turno_consulta (tenant_id, consulta_id),
                INDEX idx_turno_cola_estado (
                    tenant_id, fecha, medico_id, estado, posicion
                ),
                INDEX idx_turno_paciente (
                    tenant_id, paciente_id, fecha
                )
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )

        execute_update(
            """
            CREATE TABLE IF NOT EXISTS turnos_eventos (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                tenant_id INT NOT NULL,
                turno_id BIGINT UNSIGNED NOT NULL,
                estado_anterior VARCHAR(20) NULL,
                estado_nuevo VARCHAR(20) NOT NULL,
                motivo TEXT NULL,
                actor_id INT NULL,
                datos LONGTEXT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (id),
                UNIQUE KEY uq_turno_evento_tenant_id (tenant_id, id),
                INDEX idx_turno_evento_turno (
                    tenant_id, turno_id, created_at, id
                ),
                INDEX idx_turno_evento_actor (
                    tenant_id, actor_id, created_at
                )
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )

        execute_update(
            """
            CREATE TABLE IF NOT EXISTS pantallas_turnos (
                id INT UNSIGNED NOT NULL AUTO_INCREMENT,
                tenant_id INT NOT NULL,
                token_hash CHAR(64) NOT NULL,
                nombre VARCHAR(150) NOT NULL,
                medico_id INT NULL,
                activo TINYINT(1) NOT NULL DEFAULT 1,
                created_by INT NULL,
                updated_by INT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                    ON UPDATE CURRENT_TIMESTAMP,
                PRIMARY KEY (id),
                UNIQUE KEY uq_pantalla_tenant_id (tenant_id, id),
                UNIQUE KEY uq_pantalla_token_hash (token_hash),
                UNIQUE KEY uq_pantalla_nombre (tenant_id, nombre),
                INDEX idx_pantalla_filtro (
                    tenant_id, activo, medico_id
                )
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )

        _agregar_columna_si_falta(
            "consultas_clinicas", "turno_id", "BIGINT UNSIGNED NULL"
        )
        _agregar_indice_si_falta(
            "consultas_clinicas",
            "idx_consulta_turno",
            "`tenant_id`, `turno_id`",
        )
        _agregar_columna_si_falta(
            "pacientes",
            "registro_incompleto",
            "TINYINT(1) NOT NULL DEFAULT 0",
        )
        _agregar_columna_si_falta(
            "empresas",
            "ancho_ticket_turnos",
            "VARCHAR(2) NOT NULL DEFAULT '80'",
        )

        print("[OK] Módulo de turnos disponible")


if __name__ == "__main__":
    crear_modulo()

