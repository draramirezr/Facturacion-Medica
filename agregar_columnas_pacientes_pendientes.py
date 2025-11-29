#!/usr/bin/env python3
"""
Script para agregar las columnas 'tenant_id' y 'created_by' a la tabla pacientes_pendientes
si no existen.
"""

import pymysql
import os
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv('config_mysql.env')

# Obtener credenciales de la base de datos
DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_USER = os.getenv('DB_USER', 'root')
DB_PASSWORD = os.getenv('DB_PASSWORD', '')
DB_NAME = os.getenv('DB_NAME', 'facturacion_medica')
DB_PORT = int(os.getenv('DB_PORT', 3306))

def agregar_columnas():
    """Agregar columnas tenant_id y created_by si no existen"""
    try:
        # Conectar a la base de datos
        connection = pymysql.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            port=DB_PORT,
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor
        )
        
        print(f"✅ Conectado a la base de datos: {DB_NAME}")
        
        with connection.cursor() as cursor:
            # Verificar si la columna tenant_id existe
            cursor.execute("""
                SELECT COUNT(*) as count 
                FROM information_schema.COLUMNS 
                WHERE TABLE_SCHEMA = %s 
                AND TABLE_NAME = 'pacientes_pendientes' 
                AND COLUMN_NAME = 'tenant_id'
            """, (DB_NAME,))
            result = cursor.fetchone()
            
            if result['count'] == 0:
                print("📝 Agregando columna 'tenant_id'...")
                cursor.execute("""
                    ALTER TABLE pacientes_pendientes 
                    ADD COLUMN tenant_id INT NULL AFTER id,
                    ADD INDEX idx_tenant_id (tenant_id)
                """)
                print("✅ Columna 'tenant_id' agregada exitosamente")
            else:
                print("ℹ️  La columna 'tenant_id' ya existe")
            
            # Verificar si la columna created_by existe
            cursor.execute("""
                SELECT COUNT(*) as count 
                FROM information_schema.COLUMNS 
                WHERE TABLE_SCHEMA = %s 
                AND TABLE_NAME = 'pacientes_pendientes' 
                AND COLUMN_NAME = 'created_by'
            """, (DB_NAME,))
            result = cursor.fetchone()
            
            if result['count'] == 0:
                print("📝 Agregando columna 'created_by'...")
                cursor.execute("""
                    ALTER TABLE pacientes_pendientes 
                    ADD COLUMN created_by INT NULL AFTER centro_medico_id,
                    ADD FOREIGN KEY (created_by) REFERENCES usuarios(id) ON DELETE SET NULL
                """)
                print("✅ Columna 'created_by' agregada exitosamente")
            else:
                print("ℹ️  La columna 'created_by' ya existe")
            
            # Commit de los cambios
            connection.commit()
            print("\n✅ Todas las columnas están presentes en la tabla pacientes_pendientes")
        
        connection.close()
        print("✅ Conexión cerrada")
        
    except pymysql.Error as e:
        print(f"❌ Error de MySQL: {e}")
        return False
    except Exception as e:
        print(f"❌ Error inesperado: {e}")
        return False
    
    return True

if __name__ == "__main__":
    print("=" * 60)
    print("Script para agregar columnas a pacientes_pendientes")
    print("=" * 60)
    print()
    
    if agregar_columnas():
        print("\n✅ Proceso completado exitosamente")
    else:
        print("\n❌ El proceso falló")
        exit(1)

