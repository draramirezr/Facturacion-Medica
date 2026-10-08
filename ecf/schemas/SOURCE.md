# Esquema oficial e-CF 31

Fuente: Dirección General de Impuestos Internos (DGII), República Dominicana.

- Documento: `e-CF 31 v.1.0.xsd`
- Publicación indicada por DGII: 16/10/2025
- Página oficial: https://dgii.gov.do/cicloContribuyente/facturacion/comprobantesFiscalesElectronicosE-CF/Paginas/documentacionSobreE-CF.aspx
- Tamaño (LF): 121323 bytes
- SHA-256 (sobre bytes normalizados a LF): `cc66cbc418ceefaa6437c97607308c3e0814d73070fbbf9e9a2a331d12cb8abc`

El archivo XSD debe conservarse sin modificaciones de contenido. Su integridad
se verifica mediante el hash SHA-256 después de normalizar finales de línea a
LF, para que Windows (CRLF) y Linux (LF) acepten la misma copia oficial.

Nota: el archivo publicado contiene el nombre de tipo
`" IndicadorServicioTodoIncluidoType"` con un espacio inicial. Esa errata
impide compilar el XSD con validadores estrictos y se conserva para no alterar
un documento oficial.

`ECFValidator` verifica primero este hash y aplica la corrección conocida
únicamente sobre una copia en memoria. Durante la validación previa a la firma
también hace opcional, solo en memoria, el último `xs:any` reservado para
XMLDSig. La validación posterior a la firma vuelve a exigir dicho elemento.
