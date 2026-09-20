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
-- TABLA: empresas
-- Raíz del aislamiento multiempresa
-- ============================================
CREATE TABLE IF NOT EXISTS empresas (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(255) NOT NULL,
    razon_social VARCHAR(255) NOT NULL,
    rnc VARCHAR(20) NOT NULL,
    telefono VARCHAR(20) NOT NULL,
    email VARCHAR(100) NOT NULL,
    direccion VARCHAR(500) NOT NULL,
    fecha_inicio DATE NOT NULL,
    fecha_fin DATE NOT NULL,
    licencias_totales INT NOT NULL DEFAULT 1,
    licencias_usadas INT NOT NULL DEFAULT 0,
    plan ENUM('basico', 'profesional', 'empresarial') NOT NULL,
    estado ENUM('activo', 'suspendido', 'inactivo') NOT NULL DEFAULT 'activo',
    tipo_empresa ENUM('medico', 'centro_salud') NOT NULL,
    creado_por INT NULL,
    es_demo TINYINT(1) NOT NULL DEFAULT 0,
    ancho_ticket_turnos VARCHAR(2) NOT NULL DEFAULT '80',
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_empresas_rnc (rnc)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLA: usuarios
-- Gestión de usuarios del sistema
-- ============================================
CREATE TABLE IF NOT EXISTS usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tenant_id INT NULL COMMENT 'NULL únicamente para el Super Administrador',
    nombre VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    perfil ENUM('Administrador', 'Nivel 2', 'Registro de Facturas') NOT NULL DEFAULT 'Registro de Facturas',
    activo TINYINT(1) NOT NULL DEFAULT 1,
    password_temporal TINYINT(1) NOT NULL DEFAULT 0,
    reset_token VARCHAR(255) NULL,
    reset_token_expiracion DATETIME NULL,
    last_login DATETIME NULL,
    mostrar_chat TINYINT(1) NOT NULL DEFAULT 1,
    tema_color VARCHAR(30) NOT NULL DEFAULT 'cyan',
    fuente_ui VARCHAR(30) NOT NULL DEFAULT 'arsflow',
    idioma_correccion VARCHAR(10) NOT NULL DEFAULT 'es',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES empresas(id) ON DELETE RESTRICT,
    INDEX idx_usuarios_tenant (tenant_id),
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
    tenant_id INT NOT NULL,
    codigo VARCHAR(50) NOT NULL,
    nombre VARCHAR(200) NOT NULL,
    telefono VARCHAR(20) NULL,
    email VARCHAR(100) NULL,
    direccion TEXT NULL,
    contacto VARCHAR(100) NULL,
    activo TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES empresas(id) ON DELETE RESTRICT,
    UNIQUE KEY uq_ars_tenant_codigo (tenant_id, codigo),
    INDEX idx_ars_tenant (tenant_id),
    INDEX idx_codigo (codigo),
    INDEX idx_activo (activo)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLA: centros_medicos
-- Centros médicos donde se prestan servicios
-- ============================================
CREATE TABLE IF NOT EXISTS centros_medicos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tenant_id INT NOT NULL,
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
    FOREIGN KEY (tenant_id) REFERENCES empresas(id) ON DELETE RESTRICT,
    INDEX idx_centros_tenant (tenant_id),
    INDEX idx_nombre (nombre),
    INDEX idx_activo (activo)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLA: medicos
-- Médicos del sistema
-- ============================================
CREATE TABLE IF NOT EXISTS medicos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tenant_id INT NOT NULL,
    nombre VARCHAR(200) NOT NULL,
    exequatur VARCHAR(50) NULL,
    especialidad VARCHAR(100) NULL,
    telefono VARCHAR(20) NULL,
    email VARCHAR(100) NULL,
    cedula VARCHAR(20) NULL,
    activo TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES empresas(id) ON DELETE RESTRICT,
    INDEX idx_medicos_tenant (tenant_id),
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
    tenant_id INT NOT NULL,
    medico_id INT NOT NULL,
    centro_medico_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES empresas(id) ON DELETE RESTRICT,
    FOREIGN KEY (medico_id) REFERENCES medicos(id) ON DELETE CASCADE,
    FOREIGN KEY (centro_medico_id) REFERENCES centros_medicos(id) ON DELETE CASCADE,
    UNIQUE KEY unique_medico_centro (tenant_id, medico_id, centro_medico_id),
    INDEX idx_medico_centro_tenant (tenant_id),
    INDEX idx_medico (medico_id),
    INDEX idx_centro (centro_medico_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLA: codigo_ars
-- Códigos de servicios de las ARS
-- ============================================
CREATE TABLE IF NOT EXISTS codigo_ars (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tenant_id INT NOT NULL,
    ars_id INT NOT NULL,
    codigo VARCHAR(50) NOT NULL,
    descripcion VARCHAR(500) NOT NULL,
    precio DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
    categoria VARCHAR(100) NULL,
    activo TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES empresas(id) ON DELETE RESTRICT,
    FOREIGN KEY (ars_id) REFERENCES ars(id) ON DELETE CASCADE,
    INDEX idx_codigo (codigo),
    INDEX idx_ars (ars_id),
    INDEX idx_activo (activo),
    UNIQUE KEY unique_ars_codigo (tenant_id, ars_id, codigo),
    INDEX idx_codigo_ars_tenant (tenant_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLA: servicios
-- Servicios médicos disponibles
-- ============================================
CREATE TABLE IF NOT EXISTS servicios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tenant_id INT NOT NULL,
    codigo VARCHAR(50) NULL,
    nombre VARCHAR(200) NOT NULL,
    descripcion TEXT NULL,
    precio DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
    categoria VARCHAR(100) NULL,
    activo TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES empresas(id) ON DELETE RESTRICT,
    INDEX idx_servicios_tenant (tenant_id),
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
    tenant_id INT NOT NULL,
    tipo ENUM('B01', 'B02', 'B14', 'B15') NOT NULL DEFAULT 'B01',
    secuencia_inicial VARCHAR(20) NOT NULL,
    secuencia_final VARCHAR(20) NOT NULL,
    secuencia_actual VARCHAR(20) NOT NULL,
    fecha_vencimiento DATE NOT NULL,
    activo TINYINT(1) NOT NULL DEFAULT 1,
    agotado TINYINT(1) NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES empresas(id) ON DELETE RESTRICT,
    INDEX idx_ncf_tenant (tenant_id),
    INDEX idx_tipo (tipo),
    INDEX idx_activo (activo)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLA: pacientes
-- Pacientes del sistema
-- ============================================
CREATE TABLE IF NOT EXISTS pacientes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tenant_id INT NOT NULL,
    nombre VARCHAR(200) NOT NULL,
    cedula VARCHAR(20) NULL,
    nss VARCHAR(50) NULL COMMENT 'Número de Seguridad Social',
    telefono VARCHAR(20) NULL,
    email VARCHAR(100) NULL,
    direccion TEXT NULL,
    ocupacion VARCHAR(150) NULL,
    fecha_nacimiento DATE NULL,
    sexo ENUM('M', 'F', 'Otro') NULL,
    nombre_pariente VARCHAR(200) NULL,
    cedula_pariente VARCHAR(11) NULL,
    telefono_pariente VARCHAR(10) NULL,
    parentesco VARCHAR(50) NULL,
    ars_id INT NULL,
    tipo_afiliacion ENUM('Titular', 'Dependiente') NULL,
    registro_incompleto TINYINT(1) NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES empresas(id) ON DELETE RESTRICT,
    FOREIGN KEY (ars_id) REFERENCES ars(id) ON DELETE SET NULL,
    INDEX idx_cedula (cedula),
    INDEX idx_pacientes_tenant (tenant_id),
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
    tenant_id INT NOT NULL,
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
    FOREIGN KEY (tenant_id) REFERENCES empresas(id) ON DELETE RESTRICT,
    FOREIGN KEY (paciente_id) REFERENCES pacientes(id) ON DELETE SET NULL,
    FOREIGN KEY (ars_id) REFERENCES ars(id) ON DELETE SET NULL,
    FOREIGN KEY (medico_id) REFERENCES medicos(id) ON DELETE SET NULL,
    FOREIGN KEY (centro_medico_id) REFERENCES centros_medicos(id) ON DELETE SET NULL,
    FOREIGN KEY (created_by) REFERENCES usuarios(id) ON DELETE SET NULL,
    INDEX idx_estado (estado),
    INDEX idx_pendientes_tenant_estado_fecha (tenant_id, estado, fecha_servicio),
    INDEX idx_fecha (fecha_servicio),
    INDEX idx_ars (ars_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLA: facturas
-- Facturas generadas
-- ============================================
CREATE TABLE IF NOT EXISTS facturas (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tenant_id INT NOT NULL,
    numero_factura VARCHAR(50) NOT NULL,
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
    
    FOREIGN KEY (tenant_id) REFERENCES empresas(id) ON DELETE RESTRICT,
    FOREIGN KEY (paciente_id) REFERENCES pacientes(id) ON DELETE SET NULL,
    FOREIGN KEY (ars_id) REFERENCES ars(id) ON DELETE SET NULL,
    FOREIGN KEY (medico_id) REFERENCES medicos(id) ON DELETE SET NULL,
    FOREIGN KEY (centro_medico_id) REFERENCES centros_medicos(id) ON DELETE SET NULL,
    FOREIGN KEY (created_by) REFERENCES usuarios(id) ON DELETE SET NULL,
    
    UNIQUE KEY uq_facturas_tenant_numero (tenant_id, numero_factura),
    INDEX idx_facturas_tenant_fecha (tenant_id, fecha_emision),
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
    tenant_id INT NOT NULL,
    factura_id INT NOT NULL,
    servicio_id INT NULL,
    codigo_servicio VARCHAR(50) NULL,
    descripcion VARCHAR(500) NOT NULL,
    cantidad INT NOT NULL DEFAULT 1,
    precio_unitario DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
    subtotal DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES empresas(id) ON DELETE RESTRICT,
    FOREIGN KEY (factura_id) REFERENCES facturas(id) ON DELETE CASCADE,
    FOREIGN KEY (servicio_id) REFERENCES servicios(id) ON DELETE SET NULL,
    INDEX idx_factura (factura_id),
    INDEX idx_factura_detalles_tenant (tenant_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLA: pagos
-- Registro de pagos de facturas
-- ============================================
CREATE TABLE IF NOT EXISTS pagos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tenant_id INT NOT NULL,
    numero_pago VARCHAR(50) NULL,
    monto DECIMAL(10, 2) NULL,
    monto_total DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
    fecha_pago DATE NOT NULL,
    metodo_pago ENUM('Efectivo', 'Transferencia', 'Cheque', 'Tarjeta', 'Otro') NOT NULL,
    referencia VARCHAR(100) NULL,
    observaciones TEXT NULL,
    created_by INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES empresas(id) ON DELETE RESTRICT,
    FOREIGN KEY (created_by) REFERENCES usuarios(id) ON DELETE SET NULL,
    INDEX idx_pagos_tenant_fecha (tenant_id, fecha_pago),
    INDEX idx_pagos_numero (tenant_id, numero_pago),
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

-- No se insertan usuarios ni contraseñas predeterminadas.
-- Crear el primer administrador con crear_admin.py.

-- Los catálogos se crean desde la aplicación después de registrar una empresa.

-- ============================================
-- TABLA: solicitudes_demo
-- Leads públicos para probar ClinicRD 7 días
-- ============================================
CREATE TABLE IF NOT EXISTS solicitudes_demo (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL,
    telefono VARCHAR(20) NOT NULL,
    nombre_empresa VARCHAR(255) NOT NULL,
    tipo_empresa ENUM('medico','centro_salud') NOT NULL DEFAULT 'medico',
    mensaje VARCHAR(1000) NULL,
    estado ENUM('pendiente','activada','descartada') NOT NULL DEFAULT 'pendiente',
    empresa_id INT NULL,
    creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    activado_en DATETIME NULL,
    INDEX idx_solicitudes_demo_estado (estado),
    INDEX idx_solicitudes_demo_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLA: facturas_plataforma
-- Facturas del dueño a empresas clientes
-- ============================================
CREATE TABLE IF NOT EXISTS facturas_plataforma (
    id INT AUTO_INCREMENT PRIMARY KEY,
    empresa_id INT NOT NULL,
    numero VARCHAR(30) NOT NULL,
    fecha DATE NOT NULL,
    periodo_inicio DATE NOT NULL,
    periodo_fin DATE NOT NULL,
    plan ENUM('basico','profesional','empresarial') NOT NULL,
    licencias INT NOT NULL DEFAULT 1,
    monto DECIMAL(12,2) NOT NULL,
    estado ENUM('pendiente','pagada','anulada') NOT NULL DEFAULT 'pendiente',
    notas VARCHAR(500) NULL,
    creado_por INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_factura_plataforma_numero (numero),
    INDEX idx_fp_empresa (empresa_id),
    INDEX idx_fp_fecha (fecha),
    INDEX idx_fp_estado (estado)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLA: pago_facturas
-- Aplicación de un pago a una o más facturas
-- ============================================
CREATE TABLE IF NOT EXISTS pago_facturas (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tenant_id INT NOT NULL,
    pago_id INT NOT NULL,
    factura_id INT NOT NULL,
    monto_aplicado DECIMAL(10, 2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES empresas(id) ON DELETE RESTRICT,
    FOREIGN KEY (pago_id) REFERENCES pagos(id) ON DELETE CASCADE,
    FOREIGN KEY (factura_id) REFERENCES facturas(id) ON DELETE CASCADE,
    UNIQUE KEY uq_pago_factura (tenant_id, pago_id, factura_id),
    INDEX idx_pago_facturas_factura (factura_id, pago_id),
    INDEX idx_pago_facturas_tenant (tenant_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLA: reclamaciones
-- Reclamación de una factura a la ARS
-- ============================================
CREATE TABLE IF NOT EXISTS reclamaciones (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tenant_id INT NOT NULL,
    factura_id INT NOT NULL,
    monto_reclamado DECIMAL(10, 2) NOT NULL,
    fecha_reclamacion DATE NOT NULL,
    observaciones TEXT NULL,
    estado VARCHAR(50) NOT NULL DEFAULT 'Pendiente',
    created_by INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES empresas(id) ON DELETE RESTRICT,
    FOREIGN KEY (factura_id) REFERENCES facturas(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES usuarios(id) ON DELETE SET NULL,
    INDEX idx_reclamaciones_tenant_fecha (tenant_id, fecha_reclamacion),
    INDEX idx_reclamaciones_factura (tenant_id, factura_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLA: permisos
-- Catálogo global de permisos RBAC
-- ============================================
CREATE TABLE IF NOT EXISTS permisos (
    id INT NOT NULL AUTO_INCREMENT,
    codigo VARCHAR(100) NOT NULL,
    grupo VARCHAR(50) NOT NULL,
    nombre VARCHAR(150) NOT NULL,
    descripcion VARCHAR(500) NULL,
    activo TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_permisos_codigo (codigo),
    INDEX idx_permisos_grupo_activo (grupo, activo)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLA: roles
-- ============================================
CREATE TABLE IF NOT EXISTS roles (
    id INT NOT NULL AUTO_INCREMENT,
    tenant_id INT NOT NULL,
    nombre VARCHAR(100) NOT NULL,
    descripcion VARCHAR(500) NULL,
    es_sistema TINYINT(1) NOT NULL DEFAULT 0,
    activo TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_roles_tenant_nombre (tenant_id, nombre),
    UNIQUE KEY uq_roles_tenant_id (tenant_id, id),
    INDEX idx_roles_tenant_activo (tenant_id, activo),
    CONSTRAINT fk_roles_empresa
        FOREIGN KEY (tenant_id) REFERENCES empresas (id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS rol_permisos (
    tenant_id INT NOT NULL,
    rol_id INT NOT NULL,
    permiso_id INT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, rol_id, permiso_id),
    INDEX idx_rol_permisos_permiso (permiso_id, tenant_id),
    CONSTRAINT fk_rol_permisos_empresa
        FOREIGN KEY (tenant_id) REFERENCES empresas (id)
        ON DELETE CASCADE,
    CONSTRAINT fk_rol_permisos_rol
        FOREIGN KEY (tenant_id, rol_id) REFERENCES roles (tenant_id, id)
        ON DELETE CASCADE,
    CONSTRAINT fk_rol_permisos_permiso
        FOREIGN KEY (permiso_id) REFERENCES permisos (id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS usuario_roles (
    tenant_id INT NOT NULL,
    usuario_id INT NOT NULL,
    rol_id INT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, usuario_id, rol_id),
    INDEX idx_usuario_roles_rol (tenant_id, rol_id, usuario_id),
    CONSTRAINT fk_usuario_roles_empresa
        FOREIGN KEY (tenant_id) REFERENCES empresas (id)
        ON DELETE CASCADE,
    CONSTRAINT fk_usuario_roles_usuario
        FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
        ON DELETE CASCADE,
    CONSTRAINT fk_usuario_roles_rol
        FOREIGN KEY (tenant_id, rol_id) REFERENCES roles (tenant_id, id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS usuario_medico (
    tenant_id INT NOT NULL,
    usuario_id INT NOT NULL,
    medico_id INT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, usuario_id, medico_id),
    UNIQUE KEY uq_usuario_medico_usuario (tenant_id, usuario_id),
    UNIQUE KEY uq_usuario_medico_medico (tenant_id, medico_id),
    INDEX idx_usuario_medico_medico (medico_id, tenant_id),
    CONSTRAINT fk_usuario_medico_empresa
        FOREIGN KEY (tenant_id) REFERENCES empresas (id)
        ON DELETE CASCADE,
    CONSTRAINT fk_usuario_medico_usuario
        FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
        ON DELETE CASCADE,
    CONSTRAINT fk_usuario_medico_medico
        FOREIGN KEY (medico_id) REFERENCES medicos (id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- Historia clínica, recetas, licencias y emergencias
-- ============================================
CREATE TABLE IF NOT EXISTS consultas_clinicas (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tenant_id INT NOT NULL,
    paciente_id INT NOT NULL,
    medico_id INT NOT NULL,
    especialidad_consulta VARCHAR(150) NULL,
    plantilla_version INT NOT NULL DEFAULT 1,
    datos_especialidad LONGTEXT NULL,
    fecha DATE NOT NULL,
    hora TIME NOT NULL,
    motivo_consulta TEXT NOT NULL,
    enfermedad_actual LONGTEXT NOT NULL,
    antecedentes_personales LONGTEXT NOT NULL,
    antecedentes_familiares LONGTEXT NOT NULL,
    signos_vitales LONGTEXT NOT NULL,
    examen_fisico LONGTEXT NOT NULL,
    diagnostico_principal TEXT NOT NULL,
    diagnosticos_secundarios TEXT NULL,
    diagnostico_presuntivo TEXT NULL,
    diagnostico_diferencial TEXT NULL,
    codigo_cie10 VARCHAR(30) NULL,
    plan_tratamiento LONGTEXT NOT NULL,
    nota_evolucion_inicial TEXT NULL,
    proxima_cita DATE NULL,
    proxima_hora TIME NULL,
    proxima_especialidad VARCHAR(150) NULL,
    proxima_motivo TEXT NULL,
    indicaciones_seguimiento TEXT NULL,
    turno_id BIGINT UNSIGNED NULL,
    version INT NOT NULL DEFAULT 1,
    created_by INT NULL,
    updated_by INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_consulta_clinica_paciente (tenant_id, paciente_id, fecha),
    INDEX idx_consulta_clinica_medico (tenant_id, medico_id),
    INDEX idx_consulta_clinica_cie10 (codigo_cie10),
    INDEX idx_consulta_turno (tenant_id, turno_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS evoluciones_clinicas (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tenant_id INT NOT NULL,
    consulta_id INT NOT NULL,
    paciente_id INT NOT NULL,
    medico_id INT NOT NULL,
    fecha DATE NOT NULL,
    hora TIME NOT NULL,
    nota_evolucion TEXT NOT NULL,
    diagnostico TEXT NULL,
    tratamiento TEXT NULL,
    created_by INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_evolucion_consulta (tenant_id, consulta_id, fecha),
    INDEX idx_evolucion_paciente (tenant_id, paciente_id, fecha)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS auditoria_historia_clinica (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tenant_id INT NOT NULL,
    consulta_id INT NOT NULL,
    usuario_id INT NULL,
    version_anterior INT NOT NULL,
    datos_anteriores LONGTEXT NOT NULL,
    datos_nuevos LONGTEXT NOT NULL,
    ip VARCHAR(45) NULL,
    user_agent VARCHAR(500) NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_auditoria_consulta (tenant_id, consulta_id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS citas_medicas (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tenant_id INT NOT NULL,
    paciente_id INT NOT NULL,
    medico_id INT NOT NULL,
    consulta_origen_id INT NULL,
    fecha DATE NOT NULL,
    hora TIME NOT NULL,
    duracion_minutos INT NOT NULL DEFAULT 30,
    especialidad VARCHAR(150) NULL,
    motivo TEXT NOT NULL,
    notas TEXT NULL,
    estado VARCHAR(20) NOT NULL DEFAULT 'Programada',
    origen VARCHAR(20) NOT NULL DEFAULT 'Manual',
    created_by INT NULL,
    updated_by INT NULL,
    cancelada_por INT NULL,
    fecha_cancelacion DATETIME NULL,
    motivo_cancelacion TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_cita_consulta_origen (tenant_id, consulta_origen_id),
    INDEX idx_cita_fecha (tenant_id, fecha, hora),
    INDEX idx_cita_paciente (tenant_id, paciente_id, fecha),
    INDEX idx_cita_medico (tenant_id, medico_id, fecha, hora),
    INDEX idx_cita_estado (tenant_id, estado)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS tipos_licencia_medica (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tenant_id INT NOT NULL,
    nombre VARCHAR(120) NOT NULL,
    activo TINYINT(1) NOT NULL DEFAULT 1,
    created_by INT NULL,
    updated_by INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_tipo_licencia_tenant_nombre (tenant_id, nombre),
    INDEX idx_tipo_licencia_activo (tenant_id, activo)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS licencias_medicas (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tenant_id INT NOT NULL,
    codigo VARCHAR(40) NOT NULL,
    paciente_id INT NOT NULL,
    medico_id INT NOT NULL,
    consulta_id INT NULL,
    tipo_licencia_id INT NOT NULL,
    diagnostico TEXT NOT NULL,
    motivo_condicion TEXT NOT NULL,
    observaciones TEXT NULL,
    fecha_emision DATE NOT NULL,
    fecha_inicio DATE NOT NULL,
    fecha_termino DATE NOT NULL,
    cantidad_dias INT NOT NULL,
    estado VARCHAR(20) NOT NULL DEFAULT 'Borrador',
    version INT NOT NULL DEFAULT 1,
    created_by INT NULL,
    updated_by INT NULL,
    anulado_por INT NULL,
    fecha_anulacion DATETIME NULL,
    motivo_anulacion TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_licencia_codigo (tenant_id, codigo),
    INDEX idx_licencia_paciente (tenant_id, paciente_id, fecha_inicio),
    INDEX idx_licencia_medico (tenant_id, medico_id, fecha_emision),
    INDEX idx_licencia_estado (tenant_id, estado)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS auditoria_licencias_medicas (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tenant_id INT NOT NULL,
    licencia_id INT NOT NULL,
    usuario_id INT NULL,
    accion VARCHAR(30) NOT NULL,
    version_anterior INT NULL,
    datos_anteriores LONGTEXT NULL,
    datos_nuevos LONGTEXT NULL,
    motivo TEXT NULL,
    ip VARCHAR(45) NULL,
    user_agent VARCHAR(500) NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_auditoria_licencia (tenant_id, licencia_id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS secuencias_turnos (
    tenant_id INT NOT NULL,
    fecha DATE NOT NULL,
    medico_id INT NOT NULL,
    ultimo_numero INT UNSIGNED NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, fecha, medico_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS pantallas_turnos (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id INT NOT NULL,
    token_hash CHAR(64) NOT NULL,
    token_cifrado TEXT NULL,
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ecf_configuraciones (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tenant_id INT NOT NULL,
    habilitado TINYINT(1) NOT NULL DEFAULT 0,
    ambiente VARCHAR(20) NOT NULL DEFAULT 'PRUEBAS',
    certificado_referencia VARCHAR(500) NULL,
    secreto_referencia VARCHAR(500) NULL,
    certificado_huella VARCHAR(128) NULL,
    certificado_vence DATE NULL,
    certificado_validado_en DATETIME NULL,
    produccion_confirmada TINYINT(1) NOT NULL DEFAULT 0,
    creado_por INT NULL,
    actualizado_por INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_ecf_config_tenant (tenant_id),
    INDEX idx_ecf_config_habilitado (habilitado)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ecf_secuencias (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tenant_id INT NOT NULL,
    tipo_ecf VARCHAR(2) NOT NULL,
    serie CHAR(1) NOT NULL DEFAULT 'E',
    secuencia_inicial BIGINT UNSIGNED NOT NULL,
    secuencia_final BIGINT UNSIGNED NOT NULL,
    ultimo_numero BIGINT UNSIGNED NOT NULL DEFAULT 0,
    fecha_autorizacion DATE NULL,
    fecha_vencimiento DATE NOT NULL,
    activo TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_ecf_secuencia_rango (tenant_id, tipo_ecf, secuencia_inicial),
    INDEX idx_ecf_secuencia_activa (tenant_id, activo)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS facturas_ecf (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    tenant_id INT NOT NULL,
    factura_id INT NOT NULL,
    tipo_ecf VARCHAR(2) NOT NULL,
    e_ncf VARCHAR(13) NULL,
    estado VARCHAR(30) NOT NULL DEFAULT 'PENDIENTE_ENVIO',
    xml_generado LONGTEXT NULL,
    xml_firmado LONGTEXT NULL,
    hash_xml_generado CHAR(64) NULL,
    hash_xml_firmado CHAR(64) NULL,
    fecha_generacion DATETIME(6) NULL,
    fecha_firma DATETIME(6) NULL,
    fecha_envio DATETIME(6) NULL,
    fecha_respuesta DATETIME(6) NULL,
    track_id VARCHAR(150) NULL,
    codigo_respuesta VARCHAR(50) NULL,
    mensaje_respuesta TEXT NULL,
    respuesta_dgii LONGTEXT NULL,
    intentos INT UNSIGNED NOT NULL DEFAULT 0,
    ultimo_error TEXT NULL,
    idempotency_key CHAR(36) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_facturas_ecf_factura (factura_id),
    UNIQUE KEY uq_facturas_ecf_tenant_encf (tenant_id, e_ncf),
    UNIQUE KEY uq_facturas_ecf_idempotency (idempotency_key),
    INDEX idx_facturas_ecf_estado (tenant_id, estado),
    INDEX idx_facturas_ecf_track (track_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ecf_eventos (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    tenant_id INT NOT NULL,
    factura_ecf_id BIGINT NOT NULL,
    estado_anterior VARCHAR(30) NULL,
    estado_nuevo VARCHAR(30) NOT NULL,
    evento VARCHAR(80) NOT NULL,
    detalle LONGTEXT NULL,
    usuario_id INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ecf_eventos_documento (factura_ecf_id, created_at),
    INDEX idx_ecf_eventos_tenant (tenant_id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ecf_outbox (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    tenant_id INT NOT NULL,
    factura_ecf_id BIGINT NOT NULL,
    clave_evento VARCHAR(100) NOT NULL,
    tipo_evento VARCHAR(50) NOT NULL,
    estado VARCHAR(20) NOT NULL DEFAULT 'PENDIENTE',
    payload LONGTEXT NULL,
    intentos INT UNSIGNED NOT NULL DEFAULT 0,
    proximo_intento DATETIME NULL,
    bloqueado_en DATETIME NULL,
    bloqueado_por VARCHAR(100) NULL,
    ultimo_error TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_ecf_outbox_clave (clave_evento),
    INDEX idx_ecf_outbox_pendiente (estado, proximo_intento),
    INDEX idx_ecf_outbox_documento (factura_ecf_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- FIN DEL SCRIPT
-- ============================================

-- Para verificar la creación de las tablas:
-- SHOW TABLES;
-- Para ver la estructura de una tabla específica:
-- DESCRIBE usuarios;









