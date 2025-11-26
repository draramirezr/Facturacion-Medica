-- ============================================
-- SISTEMA DE FACTURACIÓN MÉDICA
-- Script de Creación de Base de Datos
-- Version: 1.0
-- ============================================

-- Crear base de datos
CREATE DATABASE IF NOT EXISTS facturacion_medica 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

USE facturacion_medica;

-- ============================================
-- TABLA: usuarios
-- Gestión de usuarios del sistema
-- ============================================
CREATE TABLE IF NOT EXISTS usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    perfil ENUM('Administrador', 'Nivel 2', 'Registro de Facturas') NOT NULL DEFAULT 'Registro de Facturas',
    activo TINYINT(1) NOT NULL DEFAULT 1,
    password_temporal TINYINT(1) NOT NULL DEFAULT 0,
    reset_token VARCHAR(255) NULL,
    reset_token_expiracion DATETIME NULL,
    last_login DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_email (email),
    INDEX idx_activo (activo),
    INDEX idx_reset_token (reset_token)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLA: ars
-- Administradoras de Riesgos de Salud
-- ============================================
CREATE TABLE IF NOT EXISTS ars (
    id INT AUTO_INCREMENT PRIMARY KEY,
    codigo VARCHAR(50) NOT NULL UNIQUE,
    nombre VARCHAR(200) NOT NULL,
    telefono VARCHAR(20) NULL,
    email VARCHAR(100) NULL,
    direccion TEXT NULL,
    contacto VARCHAR(100) NULL,
    activo TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_codigo (codigo),
    INDEX idx_activo (activo)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLA: centros_medicos
-- Centros médicos donde se prestan servicios
-- ============================================
CREATE TABLE IF NOT EXISTS centros_medicos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(200) NOT NULL,
    codigo VARCHAR(50) NULL,
    direccion TEXT NULL,
    telefono VARCHAR(20) NULL,
    email VARCHAR(100) NULL,
    ciudad VARCHAR(100) NULL,
    provincia VARCHAR(100) NULL,
    activo TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_nombre (nombre),
    INDEX idx_activo (activo)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLA: medicos
-- Médicos del sistema
-- ============================================
CREATE TABLE IF NOT EXISTS medicos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(200) NOT NULL,
    exequatur VARCHAR(50) NULL,
    especialidad VARCHAR(100) NULL,
    telefono VARCHAR(20) NULL,
    email VARCHAR(100) NULL,
    cedula VARCHAR(20) NULL,
    activo TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_nombre (nombre),
    INDEX idx_exequatur (exequatur),
    INDEX idx_activo (activo)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLA: medico_centro
-- Relación médicos con centros médicos
-- ============================================
CREATE TABLE IF NOT EXISTS medico_centro (
    id INT AUTO_INCREMENT PRIMARY KEY,
    medico_id INT NOT NULL,
    centro_medico_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (medico_id) REFERENCES medicos(id) ON DELETE CASCADE,
    FOREIGN KEY (centro_medico_id) REFERENCES centros_medicos(id) ON DELETE CASCADE,
    UNIQUE KEY unique_medico_centro (medico_id, centro_medico_id),
    INDEX idx_medico (medico_id),
    INDEX idx_centro (centro_medico_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLA: codigo_ars
-- Códigos de servicios de las ARS
-- ============================================
CREATE TABLE IF NOT EXISTS codigo_ars (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ars_id INT NOT NULL,
    codigo VARCHAR(50) NOT NULL,
    descripcion VARCHAR(500) NOT NULL,
    precio DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
    categoria VARCHAR(100) NULL,
    activo TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (ars_id) REFERENCES ars(id) ON DELETE CASCADE,
    INDEX idx_codigo (codigo),
    INDEX idx_ars (ars_id),
    INDEX idx_activo (activo),
    UNIQUE KEY unique_ars_codigo (ars_id, codigo)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLA: servicios
-- Servicios médicos disponibles
-- ============================================
CREATE TABLE IF NOT EXISTS servicios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    codigo VARCHAR(50) NULL,
    nombre VARCHAR(200) NOT NULL,
    descripcion TEXT NULL,
    precio DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
    categoria VARCHAR(100) NULL,
    activo TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_codigo (codigo),
    INDEX idx_nombre (nombre),
    INDEX idx_activo (activo)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLA: ncf
-- Números de Comprobante Fiscal
-- ============================================
CREATE TABLE IF NOT EXISTS ncf (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tipo ENUM('B01', 'B02', 'B14', 'B15') NOT NULL DEFAULT 'B01',
    secuencia_inicial VARCHAR(20) NOT NULL,
    secuencia_final VARCHAR(20) NOT NULL,
    secuencia_actual VARCHAR(20) NOT NULL,
    fecha_vencimiento DATE NOT NULL,
    activo TINYINT(1) NOT NULL DEFAULT 1,
    agotado TINYINT(1) NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_tipo (tipo),
    INDEX idx_activo (activo)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLA: pacientes
-- Pacientes del sistema
-- ============================================
CREATE TABLE IF NOT EXISTS pacientes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(200) NOT NULL,
    cedula VARCHAR(20) NULL,
    nss VARCHAR(50) NULL COMMENT 'Número de Seguridad Social',
    telefono VARCHAR(20) NULL,
    email VARCHAR(100) NULL,
    direccion TEXT NULL,
    fecha_nacimiento DATE NULL,
    sexo ENUM('M', 'F', 'Otro') NULL,
    ars_id INT NULL,
    tipo_afiliacion ENUM('Titular', 'Dependiente') NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (ars_id) REFERENCES ars(id) ON DELETE SET NULL,
    INDEX idx_cedula (cedula),
    INDEX idx_nss (nss),
    INDEX idx_nombre (nombre),
    INDEX idx_ars (ars_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLA: pacientes_pendientes
-- Pacientes pendientes de facturación
-- ============================================
CREATE TABLE IF NOT EXISTS pacientes_pendientes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    paciente_id INT NULL,
    nombre_paciente VARCHAR(200) NOT NULL,
    cedula VARCHAR(20) NULL,
    nss VARCHAR(50) NULL,
    ars_id INT NULL,
    fecha_servicio DATE NOT NULL,
    servicios_realizados TEXT NULL,
    observaciones TEXT NULL,
    monto_estimado DECIMAL(10, 2) NULL,
    estado ENUM('Pendiente', 'En Proceso', 'Facturado') NOT NULL DEFAULT 'Pendiente',
    medico_id INT NULL,
    centro_medico_id INT NULL,
    created_by INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (paciente_id) REFERENCES pacientes(id) ON DELETE SET NULL,
    FOREIGN KEY (ars_id) REFERENCES ars(id) ON DELETE SET NULL,
    FOREIGN KEY (medico_id) REFERENCES medicos(id) ON DELETE SET NULL,
    FOREIGN KEY (centro_medico_id) REFERENCES centros_medicos(id) ON DELETE SET NULL,
    FOREIGN KEY (created_by) REFERENCES usuarios(id) ON DELETE SET NULL,
    INDEX idx_estado (estado),
    INDEX idx_fecha (fecha_servicio),
    INDEX idx_ars (ars_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLA: facturas
-- Facturas generadas
-- ============================================
CREATE TABLE IF NOT EXISTS facturas (
    id INT AUTO_INCREMENT PRIMARY KEY,
    numero_factura VARCHAR(50) NOT NULL UNIQUE,
    ncf VARCHAR(20) NULL,
    fecha_emision DATE NOT NULL,
    fecha_vencimiento DATE NULL,
    
    -- Datos del paciente
    paciente_id INT NULL,
    nombre_paciente VARCHAR(200) NOT NULL,
    cedula_paciente VARCHAR(20) NULL,
    nss_paciente VARCHAR(50) NULL,
    
    -- Datos de la ARS
    ars_id INT NULL,
    nombre_ars VARCHAR(200) NULL,
    
    -- Datos del médico
    medico_id INT NULL,
    nombre_medico VARCHAR(200) NULL,
    
    -- Datos del centro médico
    centro_medico_id INT NULL,
    nombre_centro_medico VARCHAR(200) NULL,
    
    -- Montos
    subtotal DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
    itbis DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
    descuento DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
    total DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
    
    -- Estado
    estado ENUM('Pendiente', 'Pagada', 'Vencida', 'Anulada') NOT NULL DEFAULT 'Pendiente',
    
    -- Observaciones
    observaciones TEXT NULL,
    notas_internas TEXT NULL,
    
    -- Auditoría
    created_by INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (paciente_id) REFERENCES pacientes(id) ON DELETE SET NULL,
    FOREIGN KEY (ars_id) REFERENCES ars(id) ON DELETE SET NULL,
    FOREIGN KEY (medico_id) REFERENCES medicos(id) ON DELETE SET NULL,
    FOREIGN KEY (centro_medico_id) REFERENCES centros_medicos(id) ON DELETE SET NULL,
    FOREIGN KEY (created_by) REFERENCES usuarios(id) ON DELETE SET NULL,
    
    INDEX idx_numero (numero_factura),
    INDEX idx_ncf (ncf),
    INDEX idx_fecha (fecha_emision),
    INDEX idx_estado (estado),
    INDEX idx_paciente (paciente_id),
    INDEX idx_ars (ars_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLA: factura_detalles
-- Detalles de servicios en cada factura
-- ============================================
CREATE TABLE IF NOT EXISTS factura_detalles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    factura_id INT NOT NULL,
    servicio_id INT NULL,
    codigo_servicio VARCHAR(50) NULL,
    descripcion VARCHAR(500) NOT NULL,
    cantidad INT NOT NULL DEFAULT 1,
    precio_unitario DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
    subtotal DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (factura_id) REFERENCES facturas(id) ON DELETE CASCADE,
    FOREIGN KEY (servicio_id) REFERENCES servicios(id) ON DELETE SET NULL,
    INDEX idx_factura (factura_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLA: pagos
-- Registro de pagos de facturas
-- ============================================
CREATE TABLE IF NOT EXISTS pagos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    factura_id INT NOT NULL,
    fecha_pago DATE NOT NULL,
    monto DECIMAL(10, 2) NOT NULL,
    metodo_pago ENUM('Efectivo', 'Transferencia', 'Cheque', 'Tarjeta', 'Otro') NOT NULL,
    referencia VARCHAR(100) NULL,
    observaciones TEXT NULL,
    created_by INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (factura_id) REFERENCES facturas(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES usuarios(id) ON DELETE SET NULL,
    INDEX idx_factura (factura_id),
    INDEX idx_fecha (fecha_pago)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLA: auditoria
-- Registro de cambios importantes
-- ============================================
CREATE TABLE IF NOT EXISTS auditoria (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT NULL,
    accion VARCHAR(100) NOT NULL,
    tabla VARCHAR(100) NOT NULL,
    registro_id INT NULL,
    datos_anteriores TEXT NULL,
    datos_nuevos TEXT NULL,
    ip_address VARCHAR(50) NULL,
    user_agent TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE SET NULL,
    INDEX idx_usuario (usuario_id),
    INDEX idx_tabla (tabla),
    INDEX idx_fecha (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- DATOS INICIALES
-- ============================================

-- Insertar usuario administrador por defecto
-- Contraseña: Admin123 (debes cambiarla después del primer login)
INSERT INTO usuarios (nombre, email, password_hash, perfil, activo, password_temporal) 
VALUES (
    'Administrador',
    'admin@facturacion.com',
    'scrypt:32768:8:1$LrB4IzYGPmVqSJLI$e8c7f3f9c8b4e3d2a1f5c6b7d8e9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1',
    'Administrador',
    1,
    1
) ON DUPLICATE KEY UPDATE nombre = nombre;

-- Insertar algunas ARS de ejemplo
INSERT INTO ars (codigo, nombre, activo) VALUES
('ARS001', 'ARS Humano', 1),
('ARS002', 'ARS Palic Salud', 1),
('ARS003', 'ARS Futuro', 1),
('ARS004', 'ARS Universal', 1),
('ARS005', 'ARS Simag', 1)
ON DUPLICATE KEY UPDATE nombre = nombre;

-- ============================================
-- FIN DEL SCRIPT
-- ============================================

-- Para verificar la creación de las tablas:
-- SHOW TABLES;
-- Para ver la estructura de una tabla específica:
-- DESCRIBE usuarios;









