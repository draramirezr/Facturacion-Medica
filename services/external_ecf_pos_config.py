"""Alta y mantenimiento de credenciales API de punto de venta por consultorio."""

from __future__ import annotations

import re
import secrets
import unicodedata

from core.config import url_publica_base
from core.database import execute_query, execute_update
from integrations.external_ecf_service.security.credentials import (
    hash_integration_password,
)
from integrations.external_ecf_service.tenant.resolver import normalize_rnc


def modulo_integracion_pos_disponible() -> bool:
    fila = execute_query(
        '''
        SELECT 1 AS ok
        FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'ext_integration_emitters'
        LIMIT 1
        ''',
    )
    return bool(fila)


def listar_clientes_integracion_pos() -> list[dict]:
    if not modulo_integracion_pos_disponible():
        return []
    return (
        execute_query(
            '''
            SELECT id, codigo, nombre, estado
            FROM ext_integration_clients
            WHERE estado = 'activo'
            ORDER BY nombre
            ''',
            fetch='all',
        )
        or []
    )


def obtener_cliente_integracion_por_codigo(codigo: str) -> dict | None:
    codigo = (codigo or '').strip()
    if not codigo:
        return None
    return execute_query(
        '''
        SELECT id, codigo, nombre, estado
        FROM ext_integration_clients
        WHERE codigo = %s AND estado = 'activo'
        LIMIT 1
        ''',
        (codigo,),
    )


def _slug_desde_empresa(empresa: dict | None) -> str:
    """Identificador corto legible a partir del nombre del consultorio en ClinicRD."""
    if not empresa:
        return ''
    texto = (
        (empresa.get('nombre') or '').strip()
        or (empresa.get('razon_social') or '').strip()
    )
    if not texto:
        rnc = normalize_rnc(empresa.get('rnc') or '')
        if rnc:
            return rnc[-8:] if len(rnc) > 8 else rnc
        return f'e{int(empresa.get("id") or 0)}'
    texto = unicodedata.normalize('NFKD', texto)
    texto = texto.encode('ascii', 'ignore').decode('ascii')
    slug = re.sub(r'[^a-zA-Z0-9]+', '', texto.lower())[:20]
    if len(slug) >= 3:
        return slug
    rnc = normalize_rnc(empresa.get('rnc') or '')
    return (rnc[-8:] if len(rnc) > 8 else rnc) or f'e{int(empresa.get("id") or 0)}'


def _usuario_api_por_defecto(
    tenant_id: int,
    *,
    empresa_slug: str,
    client_codigo: str | None = None,
    multiples_integradores: bool = False,
) -> str:
    base = f'api-t{int(tenant_id)}'
    partes = []
    if empresa_slug:
        partes.append(
            re.sub(r'[^a-zA-Z0-9]', '', empresa_slug.lower())[:24]
        )
    if multiples_integradores and client_codigo:
        pos = re.sub(r'[^a-zA-Z0-9]', '', client_codigo.lower())[:10]
        if pos:
            partes.append(pos)
    if partes:
        return f'{base}-{"-".join(partes)}'[:100]
    return base


def _normalizar_usuario_api(
    value: str | None,
    tenant_id: int,
    *,
    empresa_slug: str,
    client_codigo: str | None = None,
    multiples_integradores: bool = False,
) -> str:
    limpio = re.sub(r'[^a-zA-Z0-9_-]', '', (value or '').strip())
    if len(limpio) < 3:
        return _usuario_api_por_defecto(
            tenant_id,
            empresa_slug=empresa_slug,
            client_codigo=client_codigo,
            multiples_integradores=multiples_integradores,
        )
    return limpio[:100]


def _generar_clave_api() -> str:
    return secrets.token_urlsafe(18)


def obtener_integracion_pos_por_tenant(
    tenant_id: int,
    client_codigo: str,
) -> dict | None:
    if not tenant_id or not client_codigo or not modulo_integracion_pos_disponible():
        return None
    return execute_query(
        '''
        SELECT
            e.id AS emitter_id,
            e.tenant_id,
            e.rnc,
            e.razon_social,
            e.ambiente,
            e.estado AS emisor_estado,
            c.id AS credential_id,
            c.usuario,
            c.estado AS credencial_estado,
            cl.codigo AS client_codigo,
            cl.nombre AS client_nombre
        FROM ext_integration_emitters e
        INNER JOIN ext_integration_clients cl ON cl.id = e.client_id
            AND cl.codigo = %s
        LEFT JOIN ext_integration_credentials c
            ON c.emitter_id = e.id AND c.estado = 'activa'
        WHERE e.tenant_id = %s
        ORDER BY e.id DESC
        LIMIT 1
        ''',
        (client_codigo, tenant_id),
    )


def _resolver_codigo_cliente_ui(
    clientes: list[dict],
    *,
    preferido: str | None,
    integracion: dict | None,
) -> str | None:
    if not clientes:
        return None
    codigos = {c['codigo'] for c in clientes}
    if preferido and preferido in codigos:
        return preferido
    if integracion and integracion.get('client_codigo') in codigos:
        return integracion['client_codigo']
    return clientes[0]['codigo']


def contexto_configuracion_api_pos(
    tenant_id: int,
    *,
    emisor: dict,
    empresa_info: dict | None,
    ambiente_servidor: str,
    servicio_habilitado: bool,
    client_codigo_preferido: str | None = None,
) -> dict:
    base_url = (url_publica_base() or '').rstrip('/')
    clientes = listar_clientes_integracion_pos()
    integracion_preview = None
    if client_codigo_preferido:
        integracion_preview = obtener_integracion_pos_por_tenant(
            tenant_id, client_codigo_preferido
        )
    client_codigo = _resolver_codigo_cliente_ui(
        clientes,
        preferido=client_codigo_preferido,
        integracion=integracion_preview,
    )
    integracion = (
        obtener_integracion_pos_por_tenant(tenant_id, client_codigo)
        if client_codigo
        else None
    )
    cliente_sel = next(
        (c for c in clientes if c['codigo'] == client_codigo),
        None,
    )
    rnc = normalize_rnc(emisor.get('rnc') or '')
    razon = (emisor.get('razon_social') or emisor.get('nombre') or '').strip()
    if integracion:
        razon = integracion.get('razon_social') or razon
    empresa_slug = _slug_desde_empresa(empresa_info)
    varios_integradores = len(clientes) > 1
    usuario = (
        (integracion or {}).get('usuario')
        or _usuario_api_por_defecto(
            tenant_id,
            empresa_slug=empresa_slug,
            client_codigo=client_codigo,
            multiples_integradores=varios_integradores,
        )
    )
    activa = bool(
        integracion
        and integracion.get('emisor_estado') == 'activo'
        and integracion.get('credencial_estado') == 'activa'
        and integracion.get('usuario')
    )
    return {
        'modulo_disponible': modulo_integracion_pos_disponible(),
        'servicio_habilitado': servicio_habilitado,
        'url_base': base_url or 'Configure APP_BASE_URL en el servidor',
        'ambiente_servidor': ambiente_servidor,
        'tenant_id': tenant_id,
        'rnc': rnc,
        'razon_social': razon,
        'usuario_api': usuario,
        'activa': activa,
        'integracion': integracion,
        'clientes_pos': clientes,
        'client_codigo': client_codigo,
        'client_nombre': (cliente_sel or {}).get('nombre') or '—',
        'endpoints': {
            'autenticacion': f'{base_url}/api/Autenticacion' if base_url else '',
            'enviar': f'{base_url}/api/Enviar' if base_url else '',
            'salud': f'{base_url}/external-ecf/health' if base_url else '',
        },
    }


def _usuario_api_en_uso_por_otro_tenant(usuario: str, tenant_id: int) -> bool:
    fila = execute_query(
        '''
        SELECT e.tenant_id
        FROM ext_integration_credentials c
        INNER JOIN ext_integration_emitters e ON e.id = c.emitter_id
        WHERE c.usuario = %s
        LIMIT 1
        ''',
        (usuario,),
    )
    if not fila:
        return False
    return int(fila['tenant_id']) != int(tenant_id)


def provisionar_integracion_pos(
    tenant_id: int,
    *,
    client_codigo: str,
    rnc: str,
    razon_social: str,
    usuario_api: str | None,
    ambiente: str,
    rotar_clave: bool,
) -> tuple[bool, str, str | None]:
    """
    Crea o actualiza emisor + credencial API para el tenant y el integrador elegido.
    Devuelve (ok, mensaje, clave_en_claro_solo_si_se_generó).
    """
    if not modulo_integracion_pos_disponible():
        return (
            False,
            'El módulo de integración con caja no está instalado en la base de datos.',
            None,
        )
    cliente = obtener_cliente_integracion_por_codigo(client_codigo)
    if not cliente:
        return (
            False,
            'Ese sistema de caja no está habilitado. Solicite a soporte ClinicRD '
            'que lo registre en el catálogo de integradores.',
            None,
        )
    client_id = int(cliente['id'])

    rnc_norm = normalize_rnc(rnc)
    if not rnc_norm:
        return False, 'Indique el RNC del emisor en el certificado e-CF primero.', None

    empresa = execute_query(
        '''
        SELECT id, nombre, razon_social, rnc FROM empresas WHERE id = %s LIMIT 1
        ''',
        (tenant_id,),
    )
    if not empresa:
        return False, 'Consultorio no encontrado.', None

    varios = len(listar_clientes_integracion_pos()) > 1
    empresa_slug = _slug_desde_empresa(empresa)
    usuario = _normalizar_usuario_api(
        usuario_api,
        tenant_id,
        empresa_slug=empresa_slug,
        client_codigo=client_codigo,
        multiples_integradores=varios,
    )
    if _usuario_api_en_uso_por_otro_tenant(usuario, tenant_id):
        return (
            False,
            'Ese usuario API ya está en uso por otra cuenta. Elija otro nombre.',
            None,
        )

    amb = str(ambiente or 'PRUEBAS').strip().upper()
    if amb not in {'PRUEBAS', 'CERTIFICACION', 'PRODUCCION'}:
        amb = 'PRUEBAS'

    razon = (razon_social or '').strip()[:255]
    if not razon:
        return False, 'La razón social del emisor es obligatoria.', None

    integracion = obtener_integracion_pos_por_tenant(tenant_id, client_codigo)
    clave_nueva: str | None = None
    if rotar_clave or not integracion or not integracion.get('credential_id'):
        clave_nueva = _generar_clave_api()

    emisor = execute_query(
        '''
        SELECT id FROM ext_integration_emitters
        WHERE client_id = %s AND rnc = %s LIMIT 1
        ''',
        (client_id, rnc_norm),
    )
    if emisor:
        emitter_id = int(emisor['id'])
        execute_update(
            '''
            UPDATE ext_integration_emitters
            SET tenant_id = %s,
                razon_social = %s,
                ambiente = %s,
                estado = 'activo'
            WHERE id = %s
            ''',
            (tenant_id, razon, amb, emitter_id),
        )
    else:
        emitter_id = execute_update(
            '''
            INSERT INTO ext_integration_emitters
                (client_id, tenant_id, rnc, razon_social, ambiente, estado)
            VALUES (%s, %s, %s, %s, %s, 'activo')
            ''',
            (client_id, tenant_id, rnc_norm, razon, amb),
        )

    cred = execute_query(
        '''
        SELECT id, usuario FROM ext_integration_credentials
        WHERE emitter_id = %s
        ORDER BY id DESC
        LIMIT 1
        ''',
        (emitter_id,),
    )
    if not cred:
        cred = execute_query(
            '''
            SELECT id, usuario FROM ext_integration_credentials
            WHERE usuario = %s LIMIT 1
            ''',
            (usuario,),
        )
    password_hash = (
        hash_integration_password(clave_nueva) if clave_nueva is not None else None
    )
    if cred:
        cred_id = int(cred['id'])
        if password_hash:
            execute_update(
                '''
                UPDATE ext_integration_credentials
                SET client_id = %s,
                    emitter_id = %s,
                    usuario = %s,
                    password_hash = %s,
                    estado = 'activa'
                WHERE id = %s
                ''',
                (client_id, emitter_id, usuario, password_hash, cred_id),
            )
        else:
            execute_update(
                '''
                UPDATE ext_integration_credentials
                SET client_id = %s,
                    emitter_id = %s,
                    usuario = %s,
                    estado = 'activa'
                WHERE id = %s
                ''',
                (client_id, emitter_id, usuario, cred_id),
            )
    else:
        if not clave_nueva:
            clave_nueva = _generar_clave_api()
            password_hash = hash_integration_password(clave_nueva)
        execute_update(
            '''
            INSERT INTO ext_integration_credentials
                (client_id, emitter_id, usuario, password_hash, estado)
            VALUES (%s, %s, %s, %s, 'activa')
            ''',
            (client_id, emitter_id, usuario, password_hash),
        )

    if clave_nueva:
        return (
            True,
            'Integración activada. Copie la clave API ahora; no se volverá a mostrar.',
            clave_nueva,
        )
    return True, 'Datos de integración actualizados.', None


def procesar_accion_configuracion_api_pos(
    tenant_id: int,
    *,
    accion: str,
    client_codigo: str | None,
    usuario_api: str | None,
    razon_social: str | None,
    emisor: dict,
    empresa_info: dict | None,
    ambiente_servidor: str,
) -> tuple[bool, str, str | None, str]:
    """Devuelve (ok, mensaje, clave_opcional, categoria_flash)."""
    razon = (razon_social or '').strip() or (emisor.get('razon_social') or '').strip()
    rotar = accion == 'api_pos_rotar'
    if accion not in {'api_pos_activar', 'api_pos_rotar'}:
        return False, 'Acción no reconocida.', None, 'error'
    if not (client_codigo or '').strip():
        return False, 'Seleccione el sistema de caja a integrar.', None, 'error'
    client_codigo = client_codigo.strip()

    integracion = obtener_integracion_pos_por_tenant(tenant_id, client_codigo)
    ok, mensaje, clave = provisionar_integracion_pos(
        tenant_id,
        client_codigo=client_codigo,
        rnc=emisor.get('rnc') or '',
        razon_social=razon,
        usuario_api=usuario_api,
        ambiente=ambiente_servidor,
        rotar_clave=rotar or not integracion or not integracion.get('credential_id'),
    )
    categoria = 'success' if ok else 'error'
    if ok and clave:
        categoria = 'warning'
    return ok, mensaje, clave, categoria