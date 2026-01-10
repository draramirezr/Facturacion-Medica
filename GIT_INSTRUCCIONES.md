# Instrucciones para usar Git en este proyecto

## Configuración inicial (solo la primera vez)

### 1. Configurar tu identidad en Git
```bash
git config --global user.name "Tu Nombre"
git config --global user.email "tu.email@ejemplo.com"
```

### 2. Verificar que Git esté en el PATH
Si Git no está en el PATH, agrégalo:
- Busca la instalación de Git (normalmente en `C:\Program Files\Git\bin`)
- Agrega esa ruta al PATH del sistema en Variables de Entorno

## Uso diario - Guardar cambios

### Opción 1: Usar el script automático (Recomendado)
1. Doble clic en `git_commit.bat`
2. Ingresa un mensaje descriptivo del cambio
3. El script hará el commit automáticamente

### Opción 2: Usar Git desde la terminal

#### Ver el estado de los cambios:
```bash
git status
```

#### Agregar todos los archivos modificados:
```bash
git add .
```

#### Hacer commit con un mensaje:
```bash
git commit -m "Descripción de los cambios realizados"
```

#### Ver el historial de commits:
```bash
git log --oneline
```

## Buenas prácticas

### Mensajes de commit descriptivos:
✅ **Buenos ejemplos:**
- `git commit -m "Agregar campo precio_base a tabla servicios"`
- `git commit -m "Corregir validación del campo cédula en formulario médicos"`
- `git commit -m "Actualizar estilos de badges de estado con colores del tema"`

❌ **Evitar:**
- `git commit -m "cambios"`
- `git commit -m "fix"`
- `git commit -m "update"`

### Frecuencia de commits:
- **Haz commits frecuentes**: Después de completar una funcionalidad o corregir un bug
- **Commits pequeños**: Es mejor hacer varios commits pequeños que uno grande
- **Commits antes de cerrar**: Siempre haz commit antes de cerrar el editor o apagar la PC

## Comandos útiles

### Ver qué archivos cambiaron:
```bash
git status
```

### Ver los cambios específicos en un archivo:
```bash
git diff nombre_archivo.py
```

### Deshacer cambios no guardados (antes de hacer commit):
```bash
git checkout -- nombre_archivo.py
```

### Ver el historial completo:
```bash
git log
```

### Ver el historial resumido:
```bash
git log --oneline --graph
```

## Respaldo remoto (Opcional pero recomendado)

Si quieres respaldar en GitHub, GitLab u otro servicio:

1. Crea un repositorio en el servicio
2. Agrega el remoto:
```bash
git remote add origin https://github.com/tu-usuario/tu-repositorio.git
```

3. Sube los cambios:
```bash
git push -u origin main
```

## Nota importante

El archivo `config_mysql.env` está en `.gitignore` para proteger información sensible (contraseñas, etc.). 
**NUNCA** hagas commit de archivos con información sensible.





