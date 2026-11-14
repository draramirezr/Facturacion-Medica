# Esquemas oficiales e-CF (DGII)

Fuente: [Documentación sobre e-CF](https://dgii.gov.do/cicloContribuyente/facturacion/comprobantesFiscalesElectronicosE-CF/Paginas/documentacionSobreE-CF.aspx) — República Dominicana.

Los XSD deben conservarse sin modificar contenido. La integridad se verifica con SHA-256 tras normalizar finales de línea a **LF**.

Para volver a descargar desde la publicación oficial:

```bash
py -3 tools/download_ecf_xsd.py 32
py -3 tools/download_ecf_xsd.py 31
```

## e-CF 31 v.1.0

- Archivo en repo: `e-CF-31-v1.0.xsd`
- Publicación DGII: 16/10/2025
- Tamaño (LF): 121323 bytes
- SHA-256: `cc66cbc418ceefaa6437c97607308c3e0814d73070fbbf9e9a2a331d12cb8abc`

## e-CF 32 v.1.0 (consumo)

- Archivo en repo: `e-CF-32-v1.0.xsd`
- Publicación DGII: 16/10/2025
- Tamaño (LF): verificar con `download_ecf_xsd.py`
- SHA-256: `ab66dff0b08d743e2f188242025a0dcef45203ad05687280860d3b07a475991b`

### Diferencia relevante vs E31

En el XSD **32**, el bloque **Comprador** admite `RNCComprador` y `RazonSocialComprador` **opcionales** (consumidor final). El **31** los exige.

## Errata conocida (31 y 32)

El publicado incluye el nombre de tipo `" IndicadorServicioTodoIncluidoType"` con un espacio inicial. `ECFValidator` corrige eso solo en memoria.

Durante la validación previa a la firma, el espacio `xs:any` de XMLDSig se trata como opcional; con documento firmado se exige de nuevo.