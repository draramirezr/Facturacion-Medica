# Esquema oficial e-CF 31

Fuente: Dirección General de Impuestos Internos (DGII), República Dominicana.

- Documento: `e-CF 31 v.1.0.xsd`
- Publicación indicada por DGII: 16/10/2025
- Página oficial: https://dgii.gov.do/cicloContribuyente/facturacion/comprobantesFiscalesElectronicosE-CF/Paginas/documentacionSobreE-CF.aspx
- Tamaño descargado: 123019 bytes
- SHA-256: `6f2909a93d84919518d2ae3c77fead4b35c3e8c95996b8af67b0040c2e2be298`

El archivo XSD debe conservarse sin modificaciones. Su integridad se verifica
mediante el hash SHA-256 registrado después de la descarga.

Nota: el archivo publicado contiene el nombre de tipo
`" IndicadorServicioTodoIncluidoType"` con un espacio inicial. Esa errata
impide compilar el XSD con validadores estrictos y se conserva para no alterar
un documento oficial.

`ECFValidator` verifica primero este hash y aplica la corrección conocida
únicamente sobre una copia en memoria. Durante la validación previa a la firma
también hace opcional, solo en memoria, el último `xs:any` reservado para
XMLDSig. La validación posterior a la firma vuelve a exigir dicho elemento.
