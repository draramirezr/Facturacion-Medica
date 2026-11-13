# Plantilla — solicitud técnica a integrador RicoHotDog

**Uso:** copiar el cuerpo del correo (§2) al cliente de correo. Adjuntar opcionalmente `validacion_compatibilidad_rico_hotdog.md` (sin credenciales).  
**Registrar respuestas en:** `validacion_compatibilidad_rico_hotdog.md` §7.

---

## 1. Asunto (elegir uno)

- `Coordinación pruebas API facturación electrónica (compatible HKA) — [Su empresa] / ClinicRD`
- `RicoHotDog — confirmación interpretación respuesta POST /api/Enviar`

---

## 2. Cuerpo del correo

Estimado equipo de [RicoHotDog / integrador POS]:

Somos **[nombre de su empresa / emisor]**. Estamos integrando un proveedor de facturación electrónica **compatible con el contrato API de The Factory HKA** (mismas rutas y formato JSON: `POST /api/Autenticacion`, `POST /api/Enviar`, etc.), alojado en nuestra plataforma **ClinicRD**.

El punto de venta permite **sustituir la URL del proveedor**; no tenemos acceso al código fuente del POS. Antes de activar la emisión fiscal en producción, necesitamos alinear el comportamiento del cajero con la **interpretación que RicoHotDog hace de las respuestas del API**, en particular los campos `codigo`, `procesado`, `xmlBase64` y `mensaje` de `RespuestaEnviar`.

Les agradeceríamos sus respuestas por escrito a las preguntas siguientes y, si es posible, una **sesión corta de prueba** en ambiente de demostración apuntando a nuestro servidor de staging (URL la compartimos cuando esté lista).

### A. Interpretación de `POST /api/Enviar`

1. Cuando reciben HTTP 200 con `codigo: 0`, ¿consideran la venta fiscalmente cerrada **sin revisar otros campos**?
2. ¿Exigen `procesado === true` antes de imprimir o liberar el comprobante?
3. ¿Exigen que `xmlBase64` tenga contenido (no null ni vacío)?
4. ¿Usan `codigoSeguridad`, `fechaFirma` o `fechaEmision` para impresión o código QR?
5. ¿Muestran el campo `mensaje` al cajero cuando hay error o cuando `procesado` es false?
6. ¿Qué valores de `codigo` manejan además de `0`? (lista o documentación interna)
7. Si llegara `codigo: 0` y `procesado: false` (sin XML), ¿qué hace el sistema: reintenta `Enviar`, llama `EstatusDocumento`, o muestra error?

### B. Reintentos y conectividad

8. ¿Cuántos reintentos realizan a `Enviar` ante timeout de red?
9. ¿Cuál es el timeout (en segundos) configurado hacia el proveedor?
10. En un reintento, ¿envían exactamente el mismo JSON del documento?
11. ¿Utilizan `POST /api/EstatusDocumento`? ¿En qué situaciones (timeout, duda, cierre de caja)?
12. ¿Qué valor envían en el campo `documento` de `EstatusDocumento`? (e-NCF, número interno, otro)

### C. Contenido del comprobante que envía RicoHotDog

13. ¿Incluyen siempre `emisor.numeroFacturaInterna` o `numeroPedidoInterno` en cada venta?
14. ¿Envían `ncf` vacío para que el proveedor asigne la secuencia, o lo traen precargado?
15. ¿Qué `tipoDocumento` usan en operación comercial habitual (por ejemplo E32)?

### D. Configuración en el POS

16. En configuración del proveedor fiscal, ¿solo cambian la URL base o también usuario/clave/RNC en pantalla?
17. ¿Qué URL de HKA (o demo) tienen configurada hoy en pruebas?
18. Además de `Autenticacion` y `Enviar`, ¿son **obligatorios** otros endpoints para producción (`EstatusDocumento`, `DescargaArchivo`, otros)?

### E. Evidencia para alinear pruebas (confidencial)

19. ¿Pueden compartir un **log redactado** de 3 a 5 transacciones exitosas contra HKA (sin contraseñas ni certificados), con request/response de `Enviar`?
20. ¿Pueden enviar una captura de la pantalla donde se configura la URL del proveedor de facturación electrónica?

### Prueba coordinada propuesta

Cuando tengamos staging disponible, proponemos el escenario **T01** de nuestra matriz interna:

- Respuesta esperada de nuestro servidor en fase de recepción (sin DGII aún): `codigo: 0`, `procesado: false`, `xmlBase64: null`, mensaje indicando emisión fiscal pendiente.
- Necesitamos observar en caja si el POS **no** marca la venta como emitida en ese caso, o si requiere otro flujo.

Quedamos atentos a sus respuestas para fijar fecha de prueba.

Saludos cordiales,

**[Nombre]**  
**[Cargo]** — **[Empresa / RNC]**  
**[Teléfono]**  
**[Correo]**

---

## 3. Checklist interno (antes de enviar el correo)

| Ítem | Listo |
|------|-------|
| Definir contacto en RicoHotDog o integrador | ☐ |
| Staging URL y credenciales de prueba preparadas (cuando vayan a probar T01) | ☐ |
| Seed `ext_integration_*` + emisor de prueba | ☐ |
| `EXTERNAL_ECF_ENABLED=true` en staging | ☐ |
| Acuerdo legal/confidencialidad para logs (pregunta 19) | ☐ |

## 4. Tras recibir respuestas

1. Completar §7 en `validacion_compatibilidad_rico_hotdog.md`.
2. Ejecutar T01–T06 según matriz §5.
3. Evaluar criterios A1–A10 (§6) para go/no-go Fase 3.
