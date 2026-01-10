#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Script para convertir un usuario existente en Super Administrador
Establece tenant_id = NULL para que pueda gestionar todas las empresas
"""

import pymysql
import os
import re
import sys
from dotenv import load_dotenv

# Configurar encoding para Windows
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

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

def convertir_a_super_admin():
    """Convertir usuario existente a Super Administrador"""
    print("\n" + "="*60)
    print("CONVERTIR USUARIO A SUPER ADMINISTRADOR")
    print("="*60)
    
    email = input("\n📧 Ingrese el email del usuario a convertir: ").strip()
    
    if not email:
        print("❌ Email es obligatorio")
        return
    
    try:
        conn = pymysql.connect(**DATABASE_CONFIG)
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        
        # Buscar usuario
        cursor.execute('''
            SELECT u.id, u.nombre, u.email, u.perfil, u.activo, u.tenant_id, e.nombre as empresa_nombre
            FROM usuarios u
            LEFT JOIN empresas e ON u.tenant_id = e.id
            WHERE u.email = %s
        ''', (email,))
        usuario = cursor.fetchone()
        
        if not usuario:
            print(f"\n❌ No se encontró usuario con email: {email}")
            return
        
        print(f"\n📋 Usuario encontrado:")
        print(f"  ID: {usuario['id']}")
        print(f"  Nombre: {usuario['nombre']}")
        print(f"  Email: {usuario['email']}")
        print(f"  Perfil: {usuario['perfil']}")
        print(f"  Tenant ID: {usuario['tenant_id'] or 'NULL (ya es Super Admin)'}")
        print(f"  Empresa: {usuario['empresa_nombre'] or 'Sin empresa'}")
        
        if usuario['tenant_id'] is None:
            print("\n⚠️  Este usuario ya es Super Administrador (tenant_id = NULL)")
            return
        
        confirmar = input(f"\n¿Convertir a Super Administrador? (s/n): ").strip().lower()
        if confirmar != 's':
            print("\n❌ Operación cancelada")
            return
        
        # Actualizar tenant_id a NULL
        cursor.execute('''
            UPDATE usuarios 
            SET tenant_id = NULL 
            WHERE email = %s
        ''', (email,))
        conn.commit()
        
        print("\n✅ Usuario convertido a Super Administrador exitosamente")
        print("   Ahora puede gestionar todas las empresas del sistema")
        
        cursor.close()
        conn.close()
        
        print("\n" + "="*60)
        print("✅ PROCESO COMPLETADO")
        print("="*60 + "\n")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    try:
        convertir_a_super_admin()
    except KeyboardInterrupt:
        print("\n\n⚠️  Proceso cancelado por el usuario")
    except Exception as e:
        print(f"\n❌ Error fatal: {e}")
        exit(1)

