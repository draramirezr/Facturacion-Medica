# Fase 3 — Emisión fiscal (API externa / Rico)

**Estado:** en curso · **Fase 2 cerrada:** recepción + `ext_ecf_documents` + respuesta `procesado: false`

## Objetivo

Tras `POST /api/Enviar`, ClinicRD debe:

1. Construir XML e-CF válido (E32 consumo + ITBIS para Rico; E31 para médico).
2. Firmar con certificado PKCS#12 del **tenant** (`ecf_configuraciones` + volumen).
3. Enviar a DGII (ambiente PRUEBAS/CERTIFICACIÓN).
4. Responder contrato HKA: `codigo: 0`, `procesado: true`, `xmlBase64`, `codigoSeguridad`, `fechaFirma`.

## Situación actual (Shirley, tenant 16)

| Ítem | Estado |
|------|--------|
| API Autenticación / Enviar | OK |
| Stubs Series / Licencia (prueba Rico) | OK |
| Certificado DGII en ClinicRD | OK (PRUEBAS) |
| Venta E32 desde Rico | Recibida; Rico muestra “rechazada” porque `procesado: false` |
| Motor XML E32 | **En curso** (`ecf/builder_e32.py` + XSD `e-CF-32-v1.0.xsd`) |
| Secuencias e-NCF E32 en tenant | Revisar `ecf_secuencias` / DGII |

## Hitos

### 3.1 Infraestructura

- Variable `EXTERNAL_ECF_EMIT_ENABLED` (default `false`).
- Orquestador `ExternalEmitOrchestrator`: cola E32 como `pendiente_emision`.
- Con `EMIT_ENABLED=true` + stack e-CF del tenant: intento síncrono E32 (`e32_fiscal_emitter`).

### 3.2 E32 consumo (Rico)

- Obtener XSD oficial e-CF 32 (mismo origen que `ecf/schemas/SOURCE.md`).
- `ecf/builder_e32.py` desde modelo canónico HKA.
- Asignación e-NCF (secuencia tenant, no NCF inventado por el POS si está vacío).
- Firma (`ECFSigner`) y envío `DGIIClient` reutilizando `ecf/dgii.py`.
- Mapper: marcar E32 `dgii_motor_ready` cuando builder listo.

### 3.3 Respuesta POS + pruebas

- Golden test JSON Rico Hot Dog → XML → DGII prueba.
- Confirmar con Rico interpretación de `procesado: true`.
- Implementar `POST /api/EstatusDocumento` si Rico lo exige post-venta.

### 3.4 Producción

- `EXTERNAL_ECF_ENVIRONMENT=PRODUCCION`, certificado producción, secuencias DGII.
- Desactivar stubs “demo” de licencia/series donde no apliquen.

## Variables de entorno (nuevas)

```env
# false = Fase 2 (solo recepción). true = intentar cola/emisión (Fase 3+).
EXTERNAL_ECF_EMIT_ENABLED=false
```

Requiere además el stack e-CF del tenant:

- `ECF_ENABLED=true`
- URLs DGII del ambiente
- `ECF_TENANT_SECRETS_ROOT` en Railway

## Criterio de éxito Rico (prueba)

Mismo flujo que la venta del 14/11/2026:

- E32, ITBIS, cliente final.
- Rico deja de marcar “rechazada” con timbre/QR o estado “aceptado DGII” según acuerdo §6 `validacion_compatibilidad_rico_hotdog.md`.

## Qué no hacer

- No enviar `procesado: true` sin XML firmado y evidencia DGII (política `revision_fase2.md`).
- No mezclar flujo en `facturas` / `facturas_ecf` médicas; persistir en `ext_ecf_documents` (+ outbox si se añade).