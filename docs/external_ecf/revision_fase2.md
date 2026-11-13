# Revisión técnica — Fase 2 (recepción `/api/Enviar`)

**Fecha:** 2026-11-13  
**Alcance:** código en `integrations/external_ecf_service/` (Fase 1 + 2). Sin DGII, sin motor médico, sin despliegue.  
**Referencias:** `_swagger_hka_raw.json`, `analisis_contrato_hka.md`, `fase2_recepcion.md`.

**Pruebas ejecutadas:**

```powershell
py -3 -m unittest tests.test_external_ecf_enviar tests.test_external_ecf_authentication -v
```

Resultado: **20 tests OK** (7 auth + 13 enviar/mapper/hash/errores).

---

## 1. Respuesta `POST /api/Enviar` vs contrato HKA

### Semántica Swagger (sin documentación de códigos numéricos)

| Campo | Tipo (OpenAPI) | Interpretación razonable (HKA + informe interno) |
|--------|----------------|-----------------------------------------------------|
| `codigo` | int32 | Resultado de negocio de la operación (catálogo no publicado en Swagger). |
| `mensaje` | string | Texto humano asociado al código. |
| `procesado` | boolean | Indica si el documento fue **procesado** por el proveedor. El summary del endpoint es *“Envíe el documento a ser procesado”*. |
| `xmlBase64` | string? | XML firmado del e-CF (emisión completa en HKA). |
| `codigoSeguridad` | string? | Código QR / timbre de seguridad. |
| `fechaFirma` | string? | Marca temporal de firma. |
| `fechaEmision` | string? | Fecha de emisión informada en la respuesta. |

En `analisis_contrato_hka.md` se documenta que HKA devuelve el documento **ya procesado** (XML + metadatos) y que la política acordada internamente es: **`procesado: true` solo con firma válida y evidencia de emisión fiscal**.

### Hallazgo: falsa confirmación (corregido en esta revisión)

| Estado | Detalle |
|--------|---------|
| **Antes** | `codigo: 0`, `procesado: true`, `xmlBase64: null`, sin `codigoSeguridad` ni `fechaFirma`. |
| **Riesgo** | Clientes que validan solo `codigo === 0` o `procesado === true` pueden asumir emisión exitosa, imprimir o cerrar venta sin comprobante fiscal real. |
| **Corrección aplicada** | Respuesta de Fase 2: `codigo: 0`, **`procesado: false`**, `xmlBase64: null`, `codigoSeguridad: null`, `fechaFirma: null`, `mensaje: "Documento recibido; emisión fiscal pendiente"`. |
| **Clasificación** | *Requiere corrección* → **corregido** en `send_service.py` (`_reception_success`). |

### Riesgo residual — **Pendiente de información de RicoHotDog**

| Tema | Nota |
|------|------|
| Uso de `codigo: 0` con `procesado: false` | Swagger no define si `codigo: 0` implica emisión completa. Si RicoHotDog solo mira `codigo`, seguiría interpretando éxito. |
| Estrategia cliente | Confirmar si el POS consulta `procesado`, `xmlBase64` o `POST /api/EstatusDocumento` tras `Enviar`. |
| Fase 3 | Emisión real debe devolver `procesado: true` con `xmlBase64` y `codigoSeguridad` poblados, alineado al informe § planificación. |

**No se inventaron códigos nuevos:** se mantienen `0`, `1`, `2`, `99` ya usados en Fase 1 / validaciones.

---

## 2. Idempotencia

### Implementación actual

| Mecanismo | Estado |
|-----------|--------|
| Hash SHA-256 de `documentoElectronico` | `payload_hash.py` — `json.dumps(..., sort_keys=True, separators=(',', ':'))` |
| Unicidad BD | `UNIQUE (emitter_id, payload_hash)`; `UNIQUE (emitter_id, encf)` |
| Replays | Lectura previa por hash; `response_snapshot` JSON |
| e-NCF conflictivo | Si existe mismo `encf` con distinto hash → `codigo: 2` |
| Concurrencia | Tras revisión: captura `pymysql.IntegrityError` → relectura y respuesta idempotente |

### Verificaciones

| Pregunta | Conclusión | Clasificación |
|----------|------------|---------------|
| ¿Canonicalización JSON estable? | Sí, con `sort_keys=True`. Tests: orden de propiedades y round-trip JSON. | **Correcto** |
| ¿Colisiones SHA-256? | Despreciables en la práctica. | **Correcto** |
| ¿Dos ventas legítimas con contenido fiscal idéntico? | Mismo hash → segunda solicitud se trata como reintento (idempotente). Sin `numeroFacturaInterna` / `numeroPedidoInterno` distintos, **no** se distinguen. | **Requiere corrección** (estrategia, no bloqueante para cerrar Fase 2) |
| ¿Identificador externo de venta? | Se persiste `external_document_id` desde `numeroFacturaInterna` / `numeroPedidoInterno`, **no** participa en unicidad ni en el hash si el cliente no lo envía. | **Pendiente Fase 3 / RicoHotDog** |
| ¿`UNIQUE (emitter_id, encf)` con `encf` NULL? | En MySQL, múltiples filas con `encf` NULL están permitidas (comportamiento estándar). | **Correcto** para comprobantes sin NCF previo |
| ¿Concurrencia dos inserts iguales? | Ventana entre SELECT y INSERT; mitigación con `IntegrityError` + relectura (añadida en revisión). | **Correcto** (mejorado) |
| ¿`response_snapshot`? | Se guarda en insert; tras insert exitoso se **actualiza** con `document_id` (`update_response_snapshot`). Replays antiguos con snapshot sin `document_id` siguen funcionando. | **Correcto** (mejorado) |

### Estrategia recomendada (evitar duplicar emisiones sin rechazar ventas)

1. **Reintentos de red (mismo payload):** mantener idempotencia por `(emitter_id, payload_hash)` — **correcto**.
2. **Ventas distintas con mismo detalle fiscal:** exigir que RicoHotDog envíe identificador único en `emisor.numeroFacturaInterna` o `numeroPedidoInterno` (campo ya mapeado). Si se confirma uso estable, añadir en Fase 3:
   - `UNIQUE (emitter_id, external_document_id)` cuando no sea NULL, **o**
   - incorporar ese campo en la clave de idempotencia además del hash completo.
3. **Tras emisión DGII (Fase 3):** idempotencia de negocio por `encf` asignado + política “misma `RespuestaEnviar` si ya `procesado`” (informe §8).

---

## 3. Integridad de datos

| Aspecto | Evaluación | Clasificación |
|---------|------------|---------------|
| **Transacciones** | `insert_document` usa `database_transaction()`. | **Correcto** |
| **Rollback** | Excepción en insert → rollback vía `database_transaction`; respuesta `codigo: 99`. | **Correcto** |
| **Precisión decimal** | Montos en mapper con `Decimal`; persistencia `total DECIMAL(18,4)`. | **Correcto** |
| **Payload original** | Columna JSON `payload_original` (dump del request). | **Correcto** |
| **RNC / tenant** | Tenant y emisor desde JWT; RNC documento debe coincidir con token en mapper; no se confía en tenant del JSON. | **Correcto** |
| **Auditoría** | `ext_integration_audit` en OK, validación fallida, error persistencia, idempotente concurrente. | **Correcto** |
| **Aislamiento multi-cliente** | Consultas acotadas por `emitter_id` del token; emisor validado `(emitter_id, client_id)`. | **Correcto** |
| **`fecha_documento` en INSERT** | Se pasa ISO string desde mapper; MySQL suele coercionar a `DATE`. | **Correcto** (verificar en integración real) |
| **Validación vs persistencia** | Fallo de mapper no inserta; fallo de insert no deja fila (transacción). | **Correcto** |

---

## 4. Pruebas

### Cobertura actual (tras ampliación)

| Área | Tests |
|------|-------|
| Autenticación JWT / endpoint | `test_external_ecf_authentication` |
| Mapper E31, E32, RNC | `HkaMapperTests` |
| Hash estable / orden / número interno | `PayloadHashTests` |
| Registro y `procesado: false` | `SendServiceTests.test_enviar_registra_documento` |
| Idempotencia por hash | `test_idempotencia_mismo_hash` |
| e-NCF duplicado contenido distinto | `SendServiceErrorTests.test_encf_duplicado_distinto_contenido` |
| `IntegrityError` concurrente | `test_integrity_error_relee_registro` |
| Error BD genérico | `test_persistencia_falla_codigo_99` |
| Token sin emisor | `TokenIsolationTests` |
| Formato HTTP respuesta HKA | `EnviarRouteTests` |

### Gaps (no bloqueantes para Fase 3 diseño)

| Gap | Clasificación |
|-----|---------------|
| Prueba de integración con MySQL real + migración | **Pendiente** (entorno local del equipo) |
| Concurrencia real (dos threads) | **Pendiente**; lógica cubierta con mock `IntegrityError` |
| Multi-empresa con dos emisores en BD | **Pendiente**; lógica cubierta por aislamiento `emitter_id` |
| Replay cuando `response_snapshot` tiene `procesado: true` legado | **Correcto** si se reenvía snapshot histórico; migración de datos no requerida |

---

## 5. Cambios aplicados en esta revisión

| Archivo | Cambio |
|---------|--------|
| `services/send_service.py` | `procesado: false` en recepción; manejo `IntegrityError`; actualización de `response_snapshot` con `document_id`. |
| `repositories/document_repository.py` | `update_response_snapshot()`. |
| `tests/test_external_ecf_enviar.py` | +6 casos (hash, errores, concurrencia, aislamiento). |
| `docs/external_ecf/fase2_recepcion.md` | Alineado a `procesado: false`. |

---

## 6. Resumen por clasificación

### Correcto

- Autenticación JWT reutilizada; sin Flask-Login.
- Mapper HKA + modelo canónico + tablas independientes.
- Hash estable con `sort_keys`.
- Transacciones en insert; auditoría básica.
- Aislamiento por `emitter_id` / token.
- Suite de 20 pruebas unitarias en verde.

### Requiere corrección

| Item | Estado |
|------|--------|
| `procesado: true` sin XML/firma | **Corregido** (`procesado: false`). |
| Carrera SELECT/INSERT | **Mitigado** (`IntegrityError`). |
| Snapshot sin `document_id` | **Corregido** (`update_response_snapshot`). |
| Idempotencia solo por hash sin ID de venta | **Abierto** — ver estrategia §2; depende de campos que envíe RicoHotDog. |

### Pendiente de información de RicoHotDog

- Criterio de éxito en POS: `codigo` vs `procesado` vs `xmlBase64`.
- Uso de `numeroFacturaInterna` / `numeroPedidoInterno` como clave de venta.
- Comportamiento ante `procesado: false` (¿reintento?, ¿EstatusDocumento?).

### Pendiente para Fase 3

- Emisión DGII: `procesado: true`, `xmlBase64`, `codigoSeguridad`, `fechaFirma`.
- Posible `UNIQUE (emitter_id, external_document_id)`.
- `POST /api/EstatusDocumento` para reintentos alineados a HKA.
- Soporte tipos e-CF comerciales (E32 + ITBIS) sin asumir E31 exento.

---

## 7. Recomendación operativa antes de apuntar RicoHotDog a ClinicRD

1. No usar Fase 2 sola en producción POS: **no hay emisión fiscal**.
2. En staging, capturar una respuesta HKA real de demo para comparar campo a campo con ClinicRD.
3. Tras Fase 3, validar golden test: mismo JSON → misma forma que HKA demo en éxito.
4. Mantener `EXTERNAL_ECF_ENVIRONMENT=PRUEBAS` hasta cerrar pruebas DGII.
