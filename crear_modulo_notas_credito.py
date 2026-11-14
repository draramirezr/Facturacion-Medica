"""Crea tablas de notas de crédito (parcial o total) vinculadas a facturas."""

from app import app
from core.database import execute_query, execute_update


def crear_modulo():
    with app.app_context():
        execute_update(
            """
            CREATE TABLE IF NOT EXISTS notas_credito (
                id INT AUTO_INCREMENT PRIMARY KEY,
                tenant_id INT NOT NULL,
                factura_id INT NOT NULL,
                codigo VARCHAR(40) NOT NULL,
                tipo ENUM('parcial', 'total') NOT NULL,
                motivo TEXT NOT NULL,
                subtotal DECIMAL(12, 2) NOT NULL DEFAULT 0.00,
                itbis DECIMAL(12, 2) NOT NULL DEFAULT 0.00,
                total DECIMAL(12, 2) NOT NULL DEFAULT 0.00,
                estado ENUM('confirmada', 'anulada') NOT NULL DEFAULT 'confirmada',
                e_ncf VARCHAR(13) NULL,
                estado_ecf VARCHAR(40) NULL,
                created_by INT NULL,
                anulada_por INT NULL,
                fecha_anulacion DATETIME NULL,
                motivo_anulacion TEXT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY uq_nota_credito_codigo (tenant_id, codigo),
                INDEX idx_nota_credito_factura (tenant_id, factura_id),
                INDEX idx_nota_credito_estado (tenant_id, estado),
                FOREIGN KEY (tenant_id) REFERENCES empresas(id) ON DELETE RESTRICT,
                FOREIGN KEY (factura_id) REFERENCES facturas(id) ON DELETE RESTRICT
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """
        )
        execute_update(
            """
            CREATE TABLE IF NOT EXISTS nota_credito_detalles (
                id INT AUTO_INCREMENT PRIMARY KEY,
                tenant_id INT NOT NULL,
                nota_credito_id INT NOT NULL,
                factura_detalle_id INT NULL,
                descripcion VARCHAR(500) NOT NULL,
                cantidad DECIMAL(12, 4) NOT NULL DEFAULT 1,
                precio_unitario DECIMAL(12, 2) NOT NULL DEFAULT 0.00,
                monto_credito DECIMAL(12, 2) NOT NULL DEFAULT 0.00,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_nc_detalle_nota (tenant_id, nota_credito_id),
                FOREIGN KEY (tenant_id) REFERENCES empresas(id) ON DELETE RESTRICT,
                FOREIGN KEY (nota_credito_id) REFERENCES notas_credito(id) ON DELETE CASCADE,
                FOREIGN KEY (factura_detalle_id) REFERENCES factura_detalles(id) ON DELETE SET NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """
        )
        total = execute_query(
            "SELECT COUNT(*) AS total FROM notas_credito"
        )
        print(f"[OK] Módulo notas de crédito. Registros: {total['total']}")


if __name__ == "__main__":
    crear_modulo()