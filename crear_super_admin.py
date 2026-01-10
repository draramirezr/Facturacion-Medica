#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Script para crear o actualizar usuario Super Administrador (sin tenant_id)
Este usuario puede crear y gestionar todas las empresas del sistema
"""

import pymysql
import os
import re
import sys
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

# Configurar encoding para Windows
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

# Cargar variables de entorno
load_dotenv()

def parse_mysql_url(url):
    """Parsear URL de MySQL"""
    if not url:
        return None
    pattern = r'mysql://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)'
    match = re.match(pattern, url)
    if match:
        return {
            'user': match.group(1),
            'password': match.group(2),
            'host': match.group(3),
            'port': int(match.group(4)),
            'database': match.group(5),
            'charset': 'utf8mb4'
        }
    return None

# Configurar conexión MySQL
mysql_url = os.getenv('MYSQL_URL', '')
if mysql_url:
    parsed_config = parse_mysql_url(mysql_url)
    if parsed_config:
        DATABASE_CONFIG = parsed_config
    else:
        raise Exception("MYSQL_URL inválida")
else:
    DATABASE_CONFIG = {
        'host': os.getenv('MYSQL_HOST', 'localhost'),
        'user': os.getenv('MYSQL_USER', 'root'),
        'password': os.getenv('MYSQL_PASSWORD', ''),
        'database': os.getenv('MYSQL_DATABASE', 'facturacion_medica'),
        'port': int(os.getenv('MYSQL_PORT', '3306')),
        'charset': 'utf8mb4'
    }

def crear_super_admin():
    """Crear o actualizar usuario Super Administrador (sin tenant_id)"""
    try:
        print("\n" + "="*60)
        print("CREANDO/ACTUALIZANDO SUPER ADMINISTRADOR")
        print("="*60)
    except:
        print("\n" + "="*60)
        print("CREANDO/ACTUALIZANDO SUPER ADMINISTRADOR")
        print("="*60)
    
    # Solicitar datos del usuario
    print("\n📝 Ingrese los datos del Super Administrador:")
    print("   (Presione Enter para usar valores por defecto)\n")
    
    nombre = input("Nombre [Super Administrador]: ").strip() or "Super Administrador"
    email = input("Email [superadmin@facturacion.com]: ").strip() or "superadmin@facturacion.com"
    password = input("Contraseña [SuperAdmin123!]: ").strip() or "SuperAdmin123!"
    perfil = "Administrador"
    
    print(f"\n📝 Datos del usuario:")
    print(f"  Nombre: {nombre}")
    print(f"  Email: {email}")
    print(f"  Perfil: {perfil}")
    print(f"  Tenant ID: NULL (Super Admin - puede gestionar todas las empresas)")
    print(f"  Contraseña: {password}")
    print()
    
    confirmar = input("¿Desea continuar? (s/n): ").strip().lower()
    if confirmar != 's':
        print("\n❌ Operación cancelada")
        return
    
    try:
        # Conectar a la base de datos
        conn = pymysql.connect(**DATABASE_CONFIG)
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        
        print("\n✅ Conexión establecida\n")
        
        # Verificar si el usuario ya existe
        cursor.execute('SELECT id, nombre, email, activo, tenant_id FROM usuarios WHERE email = %s', (email,))
        usuario_existe = cursor.fetchone()
        
        if usuario_existe:
            print(f"⚠️  El usuario con email {email} ya existe:")
            print(f"  ID: {usuario_existe['id']}")
            print(f"  Nombre: {usuario_existe['nombre']}")
            print(f"  Activo: {'Sí' if usuario_existe['activo'] else 'No'}")
            print(f"  Tenant ID: {usuario_existe['tenant_id'] or 'NULL (Super Admin)'}")
            print(f"\n🔄 Actualizando usuario existente...")
            
            # Actualizar el usuario existente - establecer tenant_id a NULL
            password_hash = generate_password_hash(password)
            cursor.execute('''
                UPDATE usuarios 
                SET nombre = %s, 
                    password_hash = %s, 
                    perfil = %s, 
                    activo = 1,
                    password_temporal = 0,
                    tenant_id = NULL
                WHERE email = %s
            ''', (nombre, password_hash, perfil, email))
            conn.commit()
            
            print("✅ Usuario actualizado exitosamente como Super Administrador")
        else:
            print("🆕 Creando nuevo Super Administrador...\n")
            
            # Generar hash de la contraseña
            password_hash = generate_password_hash(password)
            
            # Insertar el nuevo usuario SIN tenant_id (NULL)
            cursor.execute('''
                INSERT INTO usuarios (tenant_id, nombre, email, password_hash, perfil, activo, password_temporal)
                VALUES (NULL, %s, %s, %s, %s, 1, 0)
            ''', (nombre, email, password_hash, perfil))
            conn.commit()
            
            user_id = cursor.lastrowid
            print(f"✅ Super Administrador creado exitosamente (ID: {user_id})")
        
        # Verificar que se creó/actualizó correctamente
        cursor.execute('''
            SELECT u.id, u.nombre, u.email, u.perfil, u.activo, u.tenant_id, e.nombre as empresa_nombre
            FROM usuarios u
            LEFT JOIN empresas e ON u.tenant_id = e.id
            WHERE u.email = %s
        ''', (email,))
        usuario = cursor.fetchone()
        
        print(f"\n📋 Usuario en base de datos:")
        print(f"  ID: {usuario['id']}")
        print(f"  Nombre: {usuario['nombre']}")
        print(f"  Email: {usuario['email']}")
        print(f"  Perfil: {usuario['perfil']}")
        print(f"  Activo: {'Sí' if usuario['activo'] else 'No'}")
        print(f"  Tenant ID: {usuario['tenant_id'] or 'NULL (Super Admin)'}")
        print(f"  Empresa: {usuario['empresa_nombre'] or 'Sin empresa (Super Admin)'}")
        
        cursor.close()
        conn.close()
        
        print("\n" + "="*60)
        print("✅ PROCESO COMPLETADO")
        print("="*60)
        print("\n💡 Para acceder al sistema:")
        print(f"  URL: http://localhost:5000/login")
        print(f"  Email: {email}")
        print(f"  Password: {password}")
        print("\n🔑 Este usuario puede:")
        print("  ✓ Crear nuevas empresas")
        print("  ✓ Editar todas las empresas")
        print("  ✓ Ver todas las empresas")
        print("  ✓ Gestionar usuarios de cualquier empresa")
        print("="*60 + "\n")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        print("="*60 + "\n")
        raise

if __name__ == '__main__':
    try:
        crear_super_admin()
    except KeyboardInterrupt:
        print("\n\n⚠️  Proceso cancelado por el usuario")
    except Exception as e:
        print(f"\n❌ Error fatal: {e}")
        exit(1)

