# Fase 2 — Recepción y registro (`POST /api/Enviar`)

## Alcance

- Valida JWT de Fase 1 (sin Flask-Login).
- Mapea `documentoElectronico` (HKA) a modelo canónico interno.
- Persiste en `ext_ecf_documents` (sin tocar `facturas` / `facturas_ecf`).
- **No envía a DGII** ni genera XML firmado en esta fase.
- Respuesta compatible con `RespuestaEnviar` (HTTP 200).

## Migración

```powershell
py -3 scripts/migraciones/crear_modulo_external_ecf_integracion.py
```

Crea (si no existe) la tabla `ext_ecf_documents`.

## Endpoint

| Método | Ruta | Body |
|--------|------|------|
| POST | `/api/Enviar` | `{ "token", "documentoElectronico" }` |

Éxito típico: `codigo: 0`, `procesado: false`, `mensaje` de recepción, `xmlBase64: null` (hasta Fase 3).

## Idempotencia

- Hash SHA-256 estable del JSON `documentoElectronico`.
- Unicidad `(emitter_id, payload_hash)`.
- Si existe e-NCF, unicidad `(emitter_id, encf)`; mismo e-NCF con otro contenido → error.
- Reenvío idéntico devuelve la misma respuesta almacenada (`response_snapshot`).

## Pruebas

```powershell
py -3 -m unittest tests.test_external_ecf_enviar tests.test_external_ecf_authentication -v
```

## Nota RicoHotDog

Sin `xmlBase64` real, el POS puede seguir incompleto hasta la fase de emisión DGII. Esta fase valida contrato, auth y persistencia.
