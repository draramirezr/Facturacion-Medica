# Sistema de Facturación Médica

Sistema completo de gestión de facturación médica con control de usuarios, pacientes, ARS, médicos y generación de facturas con PDFs.

## 🚀 Características

- **Autenticación y Usuarios**: Sistema completo de login, gestión de usuarios y perfiles (Administrador, Nivel 2, Registro de Facturas)
- **Módulo de Facturación Completo**:
  - Gestión de ARS (Administradoras de Riesgos de Salud)
  - Gestión de Médicos y Centros Médicos
  - Códigos ARS por médico
  - Tipos de Servicios
  - Pacientes y NSS
  - NCF (Números de Comprobante Fiscal)
  - Gestión de Pacientes Pendientes
  - Generación de Facturas (paso a paso)
  - Histórico de Facturas
  - Dashboard con indicadores
  - Exportación a PDF y Excel
  - Envío de facturas por email

## 📋 Requisitos

- Python 3.8+
- MySQL 5.7+ o MariaDB 10.3+
- Cuenta de SendGrid (opcional, para envío de emails)

## 🔧 Instalación

### 1. Clonar o copiar el proyecto

```bash
cd "Z:\Proyectos Soluciones\Facturacion Medico"
```

### 2. Crear entorno virtual

```bash
python -m venv venv
```

### 3. Activar entorno virtual

**Windows:**
```bash
venv\Scripts\activate
```

**Linux/Mac:**
```bash
source venv/bin/activate
```

### 4. Instalar dependencias

```bash
pip install -r requirements.txt
```

### 5. Configurar variables de entorno

Crear un archivo `.env` en la raíz del proyecto:

```env
# Seguridad
SECRET_KEY=tu_clave_secreta_muy_segura

# Base de Datos MySQL
MYSQL_HOST=localhost
MYSQL_USER=root
MYSQL_PASSWORD=tu_password
MYSQL_DATABASE=facturacion_medica

# O usando URL completa:
# MYSQL_URL=mysql://usuario:password@host:3306/database

# Email (SendGrid)
SENDGRID_API_KEY=tu_api_key_de_sendgrid
EMAIL_FROM=tu_email@ejemplo.com
EMAIL_DESTINATARIO=destinatario@ejemplo.com

# Entorno
FLASK_ENV=development
```

### 6. Crear base de datos

```sql
CREATE DATABASE facturacion_medica CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

### 7. Ejecutar el sistema

```bash
python app.py
```

El sistema estará disponible en: `http://localhost:5000`

## 👤 Usuario por Defecto

El sistema creará un usuario administrador por defecto:

- **Email**: admin@facturacion.com
- **Contraseña**: Admin123!

**IMPORTANTE**: Cambia esta contraseña inmediatamente después del primer login.

## 📁 Estructura del Proyecto

```
Facturacion Medico/
├── app.py                      # Aplicación principal Flask
├── requirements.txt            # Dependencias Python
├── .env                        # Variables de entorno (NO incluir en Git)
├── README.md                   # Este archivo
├── templates/                  # Templates HTML
│   ├── base.html              # Template base
│   ├── login.html             # Página de login
│   ├── cambiar_password_obligatorio.html
│   ├── facturacion/           # Templates de facturación
│   │   ├── menu.html
│   │   ├── dashboard.html
│   │   ├── ars.html
│   │   ├── medicos.html
│   │   ├── generar_factura.html
│   │   ├── historico.html
│   │   └── ...
│   └── usuarios/              # Templates de usuarios
│       ├── lista.html
│       └── form.html
└── static/                     # Archivos estáticos
    ├── css/                   # Estilos CSS
    └── js/                    # JavaScript
```

## 🔒 Perfiles de Usuario

### Administrador
- Acceso completo al sistema
- Gestión de usuarios
- Gestión de maestros (ARS, Médicos, Servicios, etc.)
- Generación y edición de facturas
- Dashboard completo

### Nivel 2
- Registro de pacientes
- Generación de facturas
- Dashboard filtrado por su médico

### Registro de Facturas
- Registro de pacientes
- Consulta de facturas
- Dashboard filtrado por su médico
- **NO** puede generar facturas

## 🗄️ Base de Datos

El sistema utiliza las siguientes tablas principales:

- `usuarios` - Usuarios del sistema
- `ars` - Administradoras de Riesgos de Salud
- `medicos` - Médicos
- `centros_medicos` - Centros médicos
- `medico_centro` - Relación médico-centro
- `codigo_ars` - Códigos ARS por médico
- `tipos_servicios` - Tipos de servicios médicos
- `pacientes` - Pacientes únicos (maestro)
- `ncf` - Números de Comprobante Fiscal
- `facturas` - Encabezados de facturas
- `facturas_detalle` - Detalle de facturas (pacientes y servicios)

## 📊 Dashboard

El dashboard incluye:
- Total de facturas generadas
- Total facturado (monto)
- ARS pendientes por facturar
- Monto pendiente
- Pacientes facturados
- Gráfico de facturación por mes (barras)
- Gráfico de facturación por ARS y mes (líneas)

Filtros disponibles:
- Rango de fechas (por defecto: últimos 12 meses)
- ARS (multiselección)
- Médico Factura (multiselección, solo Administrador)
- Médico Paciente (multiselección)

## 📧 Envío de Emails

Para habilitar el envío de facturas por email:

1. Crear cuenta en SendGrid (https://sendgrid.com)
2. Obtener API Key
3. Configurar en `.env`:
```env
SENDGRID_API_KEY=tu_api_key
EMAIL_FROM=tu_email_verificado@dominio.com
```

## 🚀 Despliegue a Producción

### Railway

1. Crear cuenta en Railway (https://railway.app)
2. Crear nuevo proyecto desde GitHub
3. Agregar servicio MySQL
4. Configurar variables de entorno
5. Railway detectará automáticamente el `requirements.txt` y `app.py`

### Otras plataformas

- Heroku
- AWS (EC2, Elastic Beanstalk)
- Google Cloud (App Engine)
- Azure (App Service)
- DigitalOcean (App Platform)

## 🛠️ Desarrollo

### Ejecutar en modo desarrollo

```bash
python app.py
```

### Debug mode

El debug mode está activado automáticamente si `FLASK_ENV != production` en `.env`

## 📝 Notas Importantes

1. **Seguridad**: Cambia el `SECRET_KEY` en producción a un valor único y seguro
2. **Contraseñas**: Las contraseñas se almacenan con hash usando Werkzeug
3. **Rate Limiting**: El sistema incluye rate limiting básico para prevenir ataques
4. **Sesiones**: Las sesiones expiran después de 8 horas de inactividad
5. **PDFs**: Los PDFs se generan en memoria y se envían directamente al navegador
6. **Excel**: La importación de pacientes acepta archivos .xlsx con formato específico

## 🐛 Solución de Problemas

### Error: "No module named 'pymysql'"
```bash
pip install -r requirements.txt
```

### Error: "Access denied for user"
Verifica las credenciales de MySQL en `.env`

### Error: "Can't connect to MySQL server"
Asegúrate de que MySQL está ejecutándose:
```bash
# Windows
net start MySQL

# Linux
sudo systemctl start mysql
```

### Los estilos no se cargan
Verifica que la carpeta `static/` contenga los archivos CSS y JS

## 📞 Soporte

Para soporte o consultas sobre el sistema, contacta al administrador del proyecto.

## 📄 Licencia

Este proyecto es propiedad privada. Todos los derechos reservados.

---

**Versión**: 1.0  
**Última actualización**: Noviembre 2024



