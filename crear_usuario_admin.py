#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Script para crear usuario administrador
"""

import pymysql
import os
import re
import sys
from getpass import getpass
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

def crear_usuario():
    """Crear usuario administrador"""
    print("\n" + "="*60)
    print("👤 CREANDO USUARIO ADMINISTRADOR")
    print("="*60)
    
    # Nunca mantener datos personales ni credenciales en el código.
    nombre = input("Nombre del administrador: ").strip()
    email = input("Email del administrador: ").strip().lower()
    password = getpass("Contraseña temporal (mínimo 12 caracteres): ")
    password_confirm = getpass("Confirma la contraseña: ")
    perfil = "Administrador"

    if not nombre or not email or len(password) < 12 or password != password_confirm:
        print("Datos incompletos, contraseña corta o confirmación diferente.")
        return
    
    print(f"\n📝 Datos del usuario:")
    print(f"  Nombre: {nombre}")
    print(f"  Email: {email}")
    print(f"  Perfil: {perfil}")
    print()
    
    try:
        # Conectar a la base de datos
        conn = pymysql.connect(**DATABASE_CONFIG)
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        
        print("✅ Conexión establecida\n")
        
        # Verificar si el usuario ya existe
        cursor.execute('SELECT id, nombre, email FROM usuarios WHERE email = %s', (email,))
        usuario_existe = cursor.fetchone()
        
        if usuario_existe:
            print(f"⚠️  El usuario con email {email} ya existe:")
            print(f"  ID: {usuario_existe['id']}")
            print(f"  Nombre: {usuario_existe['nombre']}")
            print(f"\n🔄 Actualizando usuario existente...")
            
            # Actualizar el usuario existente
            password_hash = generate_password_hash(password)
            cursor.execute('''
                UPDATE usuarios 
                SET nombre = %s, 
                    password_hash = %s, 
                    perfil = %s, 
                    activo = 1,
                    password_temporal = 0
                WHERE email = %s
            ''', (nombre, password_hash, perfil, email))
            conn.commit()
            
            print("✅ Usuario actualizado exitosamente")
        else:
            print("🆕 Creando nuevo usuario...\n")
            
            # Generar hash de la contraseña
            password_hash = generate_password_hash(password)
            
            # Insertar el nuevo usuario
            cursor.execute('''
                INSERT INTO usuarios (nombre, email, password_hash, perfil, activo, password_temporal)
                VALUES (%s, %s, %s, %s, 1, 0)
            ''', (nombre, email, password_hash, perfil))
            conn.commit()
            
            user_id = cursor.lastrowid
            print(f"✅ Usuario creado exitosamente (ID: {user_id})")
        
        # Verificar que se creó correctamente
        cursor.execute('SELECT id, nombre, email, perfil, activo FROM usuarios WHERE email = %s', (email,))
        usuario = cursor.fetchone()
        
        print(f"\n📋 Usuario en base de datos:")
        print(f"  ID: {usuario['id']}")
        print(f"  Nombre: {usuario['nombre']}")
        print(f"  Email: {usuario['email']}")
        print(f"  Perfil: {usuario['perfil']}")
        print(f"  Activo: {'Sí' if usuario['activo'] else 'No'}")
        
        cursor.close()
        conn.close()
        
        print("\n" + "="*60)
        print("✅ PROCESO COMPLETADO")
        print("="*60)
        print("\n💡 Para acceder al sistema:")
        print(f"  URL: http://localhost:5000/login")
        print(f"  Email: {email}")
        print(f"  Password: {password}")
        print("="*60 + "\n")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("="*60 + "\n")
        raise

if __name__ == '__main__':
    try:
        crear_usuario()
    except KeyboardInterrupt:
        print("\n\n⚠️  Proceso cancelado por el usuario")
    except Exception as e:
        print(f"\n❌ Error fatal: {e}")
        exit(1)









