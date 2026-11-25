# Scripts de mantenimiento

Se ejecutan a mano desde la raíz del proyecto (usan el `.env` de la raíz):

```bash
py scripts/migraciones/migrar_catalogo_ncf.py
```

| Carpeta | Contenido |
| --- | --- |
| `migraciones/` | Cambios de esquema históricos (`agregar_*`, `crear_modulo_*`, `migrar_*`). La app ya aplica al arrancar las columnas que necesita (`core/schema_bootstrap.py`); estos quedan para bases antiguas. |
| `admin/` | Crear o promover administradores y revisar la preparación de e-CF. |
| `datos_prueba/` | Datos de demostración. **No ejecutar contra producción.** |

Ojo: el `.env` local puede apuntar a la base de Railway. Revise `MYSQL_URL` antes de correr cualquier script.
