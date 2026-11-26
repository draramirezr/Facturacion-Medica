"""Crea las tablas del Almacén (artículos y movimientos) y siembra permisos.

Idempotente: puede ejecutarse varias veces. En producción el arranque
(core/schema_bootstrap.py) hace lo mismo automáticamente, tomando las
sentencias de database_schema.sql.
"""

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))  # raíz del proyecto

from app import app
from core.database import execute_query, execute_update
from core.schema_bootstrap import SCHEMA_PATH, extraer_sentencias_esquema
from rbac_catalog import PERMISOS


TABLAS = ("almacen_articulos", "almacen_movimientos")

PERMISOS_HEREDADOS = {
    "almacen.ver": "emergencia.crear",
    "almacen.movimientos": "emergencia.crear",
    "almacen.gestionar": "catalogos.editar",
}


def crear_modulo():
    with app.app_context():
        script = SCHEMA_PATH.read_text(encoding="utf-8")
        sentencias = extraer_sentencias_esquema(script)
        # Artículos antes que movimientos (clave foránea).
        for tabla in TABLAS:
            for sentencia in sentencias:
                if sentencia.startswith(f"CREATE TABLE IF NOT EXISTS {tabla} "):
                    execute_update(sentencia)

        previos = {
            fila["codigo"]
            for fila in execute_query(
                "SELECT codigo FROM permisos WHERE codigo LIKE 'almacen.%%'",
                fetch="all",
            ) or []
        }
        for permiso in PERMISOS:
            if permiso["grupo"] != "almacen":
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

        # Los roles con emergencia.crear reciben ver/movimientos y los que
        # editan catálogos reciben gestionar (solo la primera vez).
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

        total = execute_query("SELECT COUNT(*) AS total FROM almacen_articulos")
        print(f"[OK] Módulo Almacén. Artículos: {total['total']}")


if __name__ == "__main__":
    crear_modulo()
