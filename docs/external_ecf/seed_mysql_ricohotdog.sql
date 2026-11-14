-- =============================================================================
-- ClinicRD — Servicio e-CF externo (RicoHotDog / API HKA)
-- Ejecutar en la MISMA base de datos que usa clinicrd.com (MySQL 8+).
--
-- Preferido en producción: Configuración → «API POS (compatible HKA)» en la web.
-- Este script sirve para despliegues, soporte o cuando no hay UI disponible.
-- ANTES DE CORRER: edita las variables de la sección 2.
-- Clave API por defecto en este script: CambiarEstaClave2026!  (cámbiala luego)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1) TABLAS (idempotente)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS ext_integration_clients (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(150) NOT NULL,
    codigo VARCHAR(50) NOT NULL,
    estado ENUM('activo', 'inactivo', 'suspendido') NOT NULL DEFAULT 'activo',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_ext_clients_codigo (codigo),
    INDEX idx_ext_clients_estado (estado)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ext_integration_emitters (
    id INT AUTO_INCREMENT PRIMARY KEY,
    client_id INT NOT NULL,
    tenant_id INT NOT NULL,
    rnc VARCHAR(20) NOT NULL,
    razon_social VARCHAR(255) NOT NULL,
    ambiente ENUM('PRUEBAS', 'CERTIFICACION', 'PRODUCCION') NOT NULL DEFAULT 'PRUEBAS',
    estado ENUM('activo', 'inactivo', 'suspendido') NOT NULL DEFAULT 'activo',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES ext_integration_clients(id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id) REFERENCES empresas(id) ON DELETE RESTRICT,
    UNIQUE KEY uq_ext_emitter_client_rnc (client_id, rnc),
    INDEX idx_ext_emitter_tenant (tenant_id),
    INDEX idx_ext_emitter_estado (estado)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ext_integration_credentials (
    id INT AUTO_INCREMENT PRIMARY KEY,
    client_id INT NOT NULL,
    emitter_id INT NULL,
    usuario VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    estado ENUM('activa', 'inactiva', 'suspendida') NOT NULL DEFAULT 'activa',
    fecha_expiracion DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES ext_integration_clients(id) ON DELETE RESTRICT,
    FOREIGN KEY (emitter_id) REFERENCES ext_integration_emitters(id) ON DELETE RESTRICT,
    UNIQUE KEY uq_ext_credentials_usuario (usuario),
    INDEX idx_ext_credentials_client (client_id),
    INDEX idx_ext_credentials_estado (estado)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ext_ecf_documents (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    client_id INT NOT NULL,
    emitter_id INT NOT NULL,
    tenant_id INT NOT NULL,
    external_document_id VARCHAR(100) NULL,
    tipo_ecf VARCHAR(10) NULL,
    encf VARCHAR(20) NULL,
    rnc_emisor VARCHAR(20) NOT NULL,
    rnc_comprador VARCHAR(20) NULL,
    fecha_documento DATE NULL,
    moneda VARCHAR(10) NULL,
    total DECIMAL(18, 4) NOT NULL DEFAULT 0,
    payload_original JSON NOT NULL,
    payload_hash CHAR(64) NOT NULL,
    canonical_document JSON NOT NULL,
    estado ENUM('recibido', 'rechazado', 'pendiente_emision', 'duplicado')
        NOT NULL DEFAULT 'recibido',
    error_codigo INT NULL,
    error_mensaje VARCHAR(500) NULL,
    response_snapshot JSON NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES ext_integration_clients(id) ON DELETE RESTRICT,
    FOREIGN KEY (emitter_id) REFERENCES ext_integration_emitters(id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id) REFERENCES empresas(id) ON DELETE RESTRICT,
    UNIQUE KEY uq_ext_doc_emitter_hash (emitter_id, payload_hash),
    UNIQUE KEY uq_ext_doc_emitter_encf (emitter_id, encf),
    INDEX idx_ext_doc_client (client_id),
    INDEX idx_ext_doc_tenant (tenant_id),
    INDEX idx_ext_doc_estado (estado),
    INDEX idx_ext_doc_created (created_at),
    INDEX idx_ext_doc_tipo (tipo_ecf)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ext_integration_audit (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    client_id INT NULL,
    emitter_id INT NULL,
    evento VARCHAR(80) NOT NULL,
    resultado VARCHAR(40) NOT NULL,
    ip_origen VARCHAR(45) NULL,
    fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ext_audit_client (client_id, fecha),
    INDEX idx_ext_audit_evento (evento, fecha)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- 2) VARIABLES — EDITA ESTO
-- -----------------------------------------------------------------------------

SET @tenant_id := 1;                    -- empresas.id del emisor (consultorio)
SET @rnc := '131793916';                 -- solo dígitos
SET @razon_social := 'Nombre legal del emisor';
SET @api_usuario := 'api-ricohotdog';
-- Hash de la clave: CambiarEstaClave2026!
-- Para otra clave, en PC: py -3 -c "from integrations.external_ecf_service.security.credentials import hash_integration_password; print(hash_integration_password('TU_CLAVE'))"
SET @password_hash := 'scrypt:32768:8:1$SaV1WDF9RjqWnLtl$4c292c7015c42c5e46c1ce7c2c1936179aeb660b28fecfb277637b7c64721d365caeb4fe49a41b01eca50fd7924cec57e93105089e336e6ec90d4ec4e0b28030';

-- Debe coincidir con EXTERNAL_ECF_ENVIRONMENT en Railway (PRUEBAS / CERTIFICACION / PRODUCCION)
SET @ambiente := 'PRUEBAS';

-- Railway / MySQL 8 suele usar utf8mb4_0900_ai_ci; estas tablas usan utf8mb4_unicode_ci.
-- Normalizar variables de texto evita Error 1267 (illegal mix of collations).
SET @rnc := CAST(@rnc AS CHAR(20) CHARACTER SET utf8mb4) COLLATE utf8mb4_unicode_ci;
SET @razon_social := CAST(@razon_social AS CHAR(255) CHARACTER SET utf8mb4) COLLATE utf8mb4_unicode_ci;
SET @api_usuario := CAST(@api_usuario AS CHAR(100) CHARACTER SET utf8mb4) COLLATE utf8mb4_unicode_ci;
SET @password_hash := CAST(@password_hash AS CHAR(255) CHARACTER SET utf8mb4) COLLATE utf8mb4_unicode_ci;
SET @ambiente := CAST(@ambiente AS CHAR(20) CHARACTER SET utf8mb4) COLLATE utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- 3) SEED RicoHotDog
-- -----------------------------------------------------------------------------

INSERT INTO ext_integration_clients (nombre, codigo, estado)
VALUES ('RicoHotDog', 'ricohotdog', 'activo')
ON DUPLICATE KEY UPDATE
    nombre = VALUES(nombre),
    estado = 'activo';

SET @client_id := (
    SELECT id FROM ext_integration_clients
    WHERE codigo = CAST('ricohotdog' AS CHAR(50) CHARACTER SET utf8mb4) COLLATE utf8mb4_unicode_ci
    LIMIT 1
);

INSERT INTO ext_integration_emitters
    (client_id, tenant_id, rnc, razon_social, ambiente, estado)
VALUES
    (@client_id, @tenant_id, @rnc, @razon_social, @ambiente, 'activo')
ON DUPLICATE KEY UPDATE
    tenant_id = VALUES(tenant_id),
    razon_social = VALUES(razon_social),
    ambiente = VALUES(ambiente),
    estado = 'activo';

SET @emitter_id := (
    SELECT id FROM ext_integration_emitters
    WHERE client_id = @client_id
      AND rnc = @rnc COLLATE utf8mb4_unicode_ci
    LIMIT 1
);

INSERT INTO ext_integration_credentials
    (client_id, emitter_id, usuario, password_hash, estado)
VALUES
    (@client_id, @emitter_id, @api_usuario, @password_hash, 'activa')
ON DUPLICATE KEY UPDATE
    client_id = VALUES(client_id),
    emitter_id = VALUES(emitter_id),
    password_hash = VALUES(password_hash),
    estado = 'activa';

-- -----------------------------------------------------------------------------
-- 4) VERIFICACIÓN
-- -----------------------------------------------------------------------------

SELECT 'cliente' AS tipo, id, codigo, estado FROM ext_integration_clients WHERE id = @client_id;
SELECT 'emisor' AS tipo, id, tenant_id, rnc, ambiente, estado FROM ext_integration_emitters WHERE id = @emitter_id;
SELECT 'credencial' AS tipo, id, usuario, estado
FROM ext_integration_credentials
WHERE usuario = @api_usuario COLLATE utf8mb4_unicode_ci;
