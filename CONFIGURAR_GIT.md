# 🚀 Configuración de Git - Guía Rápida

## ⚠️ Problema detectado
Git está instalado en tu PC pero **no está en el PATH**, por lo que no se puede usar directamente desde PowerShell.

## ✅ Solución: Agregar Git al PATH

### Opción 1: Agregar Git al PATH del Sistema (Recomendado)

1. **Buscar la ubicación de Git:**
   - Normalmente está en: `C:\Program Files\Git\bin\`
   - O en: `C:\Program Files (x86)\Git\bin\`

2. **Agregar al PATH:**
   - Presiona `Win + R`, escribe `sysdm.cpl` y presiona Enter
   - Ve a la pestaña "Opciones avanzadas"
   - Click en "Variables de entorno"
   - En "Variables del sistema", busca "Path" y haz click en "Editar"
   - Click en "Nuevo" y agrega la ruta: `C:\Program Files\Git\bin`
   - Click en "Aceptar" en todas las ventanas
   - **Reinicia PowerShell o VS Code** para que tome efecto

3. **Verificar:**
   - Abre PowerShell y escribe: `git --version`
   - Debería mostrar la versión de Git

### Opción 2: Usar Git Bash (Alternativa)

Si no quieres modificar el PATH, puedes usar **Git Bash**:
- Busca "Git Bash" en el menú de inicio
- Abre Git Bash y navega a tu proyecto:
  ```bash
  cd "/z/Proyectos Soluciones/Facturacion Medico"
  ```

## 📝 Uso diario - Guardar cambios

### Método 1: Script PowerShell (Fácil)

1. Abre PowerShell en la carpeta del proyecto
2. Ejecuta:
   ```powershell
   .\git_commit.ps1 "Descripción de los cambios"
   ```

   Ejemplo:
   ```powershell
   .\git_commit.ps1 "Agregar campo precio_base a servicios"
   ```

### Método 2: Comandos Git directos

Una vez que Git esté en el PATH:

```bash
# Ver qué archivos cambiaron
git status

# Agregar todos los archivos modificados
git add .

# Hacer commit con mensaje
git commit -m "Descripción de los cambios"

# Ver historial
git log --oneline
```

## 🔒 Archivos protegidos

El archivo `config_mysql.env` está en `.gitignore` para proteger tus credenciales.
**NUNCA** hagas commit de archivos con contraseñas o información sensible.

## 💡 Consejos importantes

1. **Haz commits frecuentes**: Después de cada cambio importante
2. **Mensajes descriptivos**: 
   - ✅ "Corregir validación campo cédula"
   - ❌ "cambios"
3. **Antes de cerrar**: Siempre haz commit antes de cerrar el editor
4. **Verificar estado**: Usa `git status` antes de hacer commit

## 📚 Más información

Lee el archivo `GIT_INSTRUCCIONES.md` para más detalles y comandos avanzados.





