# Preparación controlada de e-CF para producción

La aplicación está preparada para certificación y producción, pero el entorno
local permanece desactivado. Ningún despliegue ni cambio de este documento
habilita por sí solo los envíos a DGII.

## Controles de activación

Un envío productivo requiere simultáneamente:

1. `ECF_ENABLED=true`.
2. `ECF_ENVIRONMENT=PRODUCCION`.
3. `ECF_ALLOW_PRODUCTION=true`.
4. `FLASK_ENV=production`.
5. `ECF_TENANT_SECRETS_ROOT` en una ruta absoluta fuera del repositorio.
   Cada cuenta utiliza su propia carpeta `tenant-<ID>`.
6. Registro de la cuenta en `ecf_configuraciones` con:
   - `habilitado=1`;
   - `ambiente='PRODUCCION'`;
   - `produccion_confirmada=1`.

Si falta cualquiera de estos controles, la cuenta no puede emitir. Desactivar
`habilitado` detiene documentos nuevos, pero conserva la consulta de documentos
enviados que necesiten resolución.

## Antes de certificación

1. Ejecutar la migración idempotente:

   ```powershell
   py -3.13 crear_base_facturacion_electronica.py
   ```

2. Configurar las URL oficiales de certificación con el segmento `certecf`.
3. Instalar el certificado y el secreto de cada emisor:

   ```text
   <ECF_TENANT_SECRETS_ROOT>/
     tenant-123/
       certificate.p12
       password.txt
   ```

   El número de carpeta corresponde al `tenant_id`. Los archivos no deben
   guardarse en Git ni en la base de datos.
4. Cargar exclusivamente rangos E31 otorgados por DGII.
5. Ejecutar el diagnóstico local:

   ```powershell
   py -3.13 verificar_preparacion_ecf.py
   ```

6. Completar los casos y la aprobación formal de certificación exigidos por
   DGII. El diagnóstico local no reemplaza dicha aprobación.

## Corte productivo

1. Respaldar base de datos, XML firmados, respuestas y eventos.
2. Confirmar que no existan envíos inciertos:

   ```sql
   SELECT tenant_id, factura_ecf_id, estado, ultimo_error
   FROM ecf_outbox
   WHERE estado = 'REQUIERE_CONSULTA';
   ```

3. Desplegar primero con `ECF_ENABLED=false`.
4. Configurar las cinco URL oficiales con el segmento `ecf`.
5. Mantener vacías las credenciales globales y utilizar exclusivamente
   `ECF_TENANT_SECRETS_ROOT` con una carpeta aislada por cuenta.
6. Registrar la cuenta inicialmente deshabilitada:

   ```sql
   SET @tenant_id = 123; -- reemplazar por la cuenta autorizada

   INSERT INTO ecf_configuraciones
       (tenant_id, habilitado, ambiente, produccion_confirmada)
   VALUES
       (@tenant_id, 0, 'PRODUCCION', 1)
   ON DUPLICATE KEY UPDATE
       habilitado=0,
       ambiente='PRODUCCION',
       produccion_confirmada=1;
   ```

7. Ejecutar pruebas y `verificar_preparacion_ecf.py` en el entorno desplegado.
8. Habilitar una cuenta piloto mediante una transacción controlada:

   ```sql
   UPDATE ecf_configuraciones
   SET habilitado=1
   WHERE tenant_id=@tenant_id
     AND ambiente='PRODUCCION'
     AND produccion_confirmada=1;
   ```

9. Emitir un documento controlado, consultar su TrackID y confirmar que DGII
   lo marque `ACEPTADO` antes de ampliar el uso.

## Detención segura

Para detener documentos nuevos sin perder la capacidad de consultar envíos:

```sql
UPDATE ecf_configuraciones
SET habilitado=0
WHERE tenant_id=@tenant_id;
```

No eliminar documentos, no reducir `ultimo_numero`, no generar otro e-NCF para
un envío incierto y no reenviar antes de consultar TrackID.

## Operación obligatoria

- Alertar por rechazos, errores de firma y `REQUIERE_CONSULTA`.
- Alertar con anticipación por vencimiento de certificados y secuencias.
- Conservar XML generado, XML firmado, respuesta DGII y eventos con respaldo
  cifrado conforme al plazo legal aplicable.
- Restringir acceso al certificado y su secreto a la identidad del proceso.
- Probar restauración de respaldos y el procedimiento de contingencia DGII.
- Revisar documentación y XSD oficiales antes de cada actualización.
