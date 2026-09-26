"""Papelería del consultorio: membrete y logo aislados por empresa."""

import logging
from pathlib import Path

from core.database import execute_query, execute_update
from routes.support import sanitize_input

logger = logging.getLogger(__name__)

MAX_LOGO_BYTES = 512 * 1024
ENCABEZADO_MAX = 120
SUBTITULO_MAX = 160
PIE_MAX = 350

_TIPOS_LOGO = (
    (b'\x89PNG\r\n\x1a\n', 'png', 'image/png'),
    (b'\xff\xd8\xff', 'jpg', 'image/jpeg'),
)


def _raiz_papeleria():
    return (Path.cwd() / 'instance' / 'papeleria').resolve()


def _carpeta_tenant(tenant_id):
    tenant_id = int(tenant_id)
    if tenant_id <= 0:
        raise ValueError('Empresa inválida')
    raiz = _raiz_papeleria()
    carpeta = (raiz / str(tenant_id)).resolve()
    try:
        carpeta.relative_to(raiz)
    except ValueError as error:
        raise ValueError('Ruta de papelería inválida') from error
    return carpeta


def asegurar_tabla_papeleria():
    execute_update(
        '''
        CREATE TABLE IF NOT EXISTS papeleria_empresa (
            tenant_id INT NOT NULL,
            encabezado VARCHAR(120) NOT NULL DEFAULT '',
            subtitulo VARCHAR(160) NOT NULL DEFAULT '',
            pie_pagina VARCHAR(350) NOT NULL DEFAULT '',
            logo_ext VARCHAR(8) NULL,
            actualizado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (tenant_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        '''
    )


def detectar_imagen(contenido):
    if not contenido or len(contenido) > MAX_LOGO_BYTES:
        return None
    if contenido.lstrip()[:1] in (b'<', b'{'):
        return None
    for firma, ext, mime in _TIPOS_LOGO:
        if contenido.startswith(firma):
            return ext, mime
    if contenido[:4] == b'RIFF' and contenido[8:12] == b'WEBP':
        return 'webp', 'image/webp'
    return None


def obtener_papeleria(tenant_id):
    if not tenant_id:
        return None
    asegurar_tabla_papeleria()
    fila = execute_query(
        'SELECT * FROM papeleria_empresa WHERE tenant_id=%s',
        (int(tenant_id),),
    ) or {}
    ext = (fila.get('logo_ext') or '').strip().lower()
    ruta = ruta_logo(tenant_id, ext) if ext else None
    return {
        'encabezado': fila.get('encabezado') or '',
        'subtitulo': fila.get('subtitulo') or '',
        'pie_pagina': fila.get('pie_pagina') or '',
        'logo_ext': ext,
        'tiene_logo': bool(ruta and ruta.is_file()),
        'logo_mime': {
            'png': 'image/png',
            'jpg': 'image/jpeg',
            'webp': 'image/webp',
        }.get(ext, ''),
    }


def ruta_logo(tenant_id, ext=None):
    if ext is None:
        datos = obtener_papeleria(tenant_id) or {}
        ext = datos.get('logo_ext')
    ext = (ext or '').strip().lower()
    if ext not in {'png', 'jpg', 'webp'}:
        return None
    return _carpeta_tenant(tenant_id) / f'logo.{ext}'


def guardar_papeleria(tenant_id, valores, logo_bytes=None, quitar_logo=False):
    tenant_id = int(tenant_id)
    if tenant_id <= 0:
        raise ValueError('Empresa inválida')
    asegurar_tabla_papeleria()
    actual = obtener_papeleria(tenant_id) or {}
    ext = actual.get('logo_ext') or None
    if quitar_logo:
        _borrar_logos(tenant_id)
        ext = None
    if logo_bytes:
        tipo = detectar_imagen(logo_bytes)
        if not tipo:
            raise ValueError(
                'El logo debe ser PNG, JPG o WEBP y pesar menos de 512 KB.'
            )
        ext, _mime = tipo
        carpeta = _carpeta_tenant(tenant_id)
        carpeta.mkdir(parents=True, exist_ok=True)
        _borrar_logos(tenant_id)
        (carpeta / f'logo.{ext}').write_bytes(logo_bytes)
    encabezado = sanitize_input(valores.get('encabezado') or '', ENCABEZADO_MAX)
    subtitulo = sanitize_input(valores.get('subtitulo') or '', SUBTITULO_MAX)
    pie_pagina = sanitize_input(valores.get('pie_pagina') or '', PIE_MAX)
    execute_update(
        '''
        INSERT INTO papeleria_empresa (
            tenant_id, encabezado, subtitulo, pie_pagina, logo_ext
        ) VALUES (%s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            encabezado=VALUES(encabezado),
            subtitulo=VALUES(subtitulo),
            pie_pagina=VALUES(pie_pagina),
            logo_ext=VALUES(logo_ext)
        ''',
        (tenant_id, encabezado, subtitulo, pie_pagina, ext),
    )
    return obtener_papeleria(tenant_id)


def _borrar_logos(tenant_id):
    try:
        carpeta = _carpeta_tenant(tenant_id)
    except ValueError:
        return
    if not carpeta.is_dir():
        return
    for archivo in carpeta.glob('logo.*'):
        if archivo.suffix.lower() in {'.png', '.jpg', '.jpeg', '.webp'}:
            try:
                archivo.unlink()
            except OSError as error:
                logger.warning('No se pudo quitar logo: %s', error)
