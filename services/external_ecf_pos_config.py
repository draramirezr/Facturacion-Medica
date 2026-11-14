"""Alta y mantenimiento de credenciales API POS (compatibilidad HKA) por consultorio."""

from __future__ import annotations

import re
import secrets

from core.config import url_publica_base
from core.database import execute_query, execute_update
from integrations.external_ecf_service.security.credentials import (
    hash_integration_password,
)
from integrations.external_ecf_service.tenant.resolver import normalize_rnc

INTEGRATION_CLIENT_CODE = 'ricohotdog'
INTEGRATION_CLIENT_NAME = 'RicoHotDog'


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


def _usuario_api_por_defecto(tenant_id: int) -> str:
    return f'api-t{int(tenant_id)}'


def _normalizar_usuario_api(value: str | None, tenant_id: int) -> str:
    limpio = re.sub(r'[^a-zA-Z0-9_-]', '', (value or '').strip())
    if len(limpio) < 3:
        return _usuario_api_por_defecto(tenant_id)
    return limpio[:100]


def _generar_clave_api() -> str:
    return secrets.token_urlsafe(18)


def _obtener_client_id_ricohotdog() -> int | None:
    fila = execute_query(
        '''
        SELECT id FROM ext_integration_clients
        WHERE codigo = %s LIMIT 1
        ''',
        (INTEGRATION_CLIENT_CODE,),
    )
    return int(fila['id']) if fila else None


def _asegurar_cliente_ricohotdog() -> int:
    existente = _obtener_client_id_ricohotdog()
    if existente:
        execute_update(
            '''
            UPDATE ext_integration_clients
            SET nombre = %s, estado = 'activo'
            WHERE id = %s
            ''',
            (INTEGRATION_CLIENT_NAME, existente),
        )
        return existente
    return execute_update(
        '''
        INSERT INTO ext_integration_clients (nombre, codigo, estado)
        VALUES (%s, %s, 'activo')
        ''',
        (INTEGRATION_CLIENT_NAME, INTEGRATION_CLIENT_CODE),
    )


def obtener_integracion_pos_por_tenant(tenant_id: int) -> dict | None:
    if not tenant_id or not modulo_integracion_pos_disponible():
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
            c.estado AS credencial_estado
        FROM ext_integration_emitters e
        INNER JOIN ext_integration_clients cl ON cl.id = e.client_id
            AND cl.codigo = %s
        LEFT JOIN ext_integration_credentials c
            ON c.emitter_id = e.id AND c.estado = 'activa'
        WHERE e.tenant_id = %s
        ORDER BY e.id DESC
        LIMIT 1
        ''',
        (INTEGRATION_CLIENT_CODE, tenant_id),
    )


def contexto_configuracion_api_pos(
    tenant_id: int,
    *,
    emisor: dict,
    ambiente_servidor: str,
    servicio_habilitado: bool,
) -> dict:
    base_url = (url_publica_base() or '').rstrip('/')
    integracion = obtener_integracion_pos_por_tenant(tenant_id) if tenant_id else None
    rnc = normalize_rnc(emisor.get('rnc') or '')
    razon = (emisor.get('razon_social') or emisor.get('nombre') or '').strip()
    if integracion:
        razon = integracion.get('razon_social') or razon
    usuario = (
        (integracion or {}).get('usuario')
        or _usuario_api_por_defecto(tenant_id)
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
        'integrador': INTEGRATION_CLIENT_NAME,
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
    rnc: str,
    razon_social: str,
    usuario_api: str | None,
    ambiente: str,
    rotar_clave: bool,
) -> tuple[bool, str, str | None]:
    """
    Crea o actualiza emisor + credencial API para el tenant actual.
    Devuelve (ok, mensaje, clave_en_claro_solo_si_se_generó).
    """
    if not modulo_integracion_pos_disponible():
        return (
            False,
            'El módulo de integración POS no está instalado en la base de datos.',
            None,
        )
    rnc_norm = normalize_rnc(rnc)
    if not rnc_norm:
        return False, 'Indique el RNC del emisor en el certificado e-CF primero.', None

    empresa = execute_query(
        'SELECT id FROM empresas WHERE id = %s LIMIT 1',
        (tenant_id,),
    )
    if not empresa:
        return False, 'Consultorio no encontrado.', None

    usuario = _normalizar_usuario_api(usuario_api, tenant_id)
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

    integracion = obtener_integracion_pos_por_tenant(tenant_id)
    clave_nueva: str | None = None
    if rotar_clave or not integracion or not integracion.get('credential_id'):
        clave_nueva = _generar_clave_api()

    client_id = _asegurar_cliente_ricohotdog()

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
            'Integración POS activada. Copie la clave API ahora; no se volverá a mostrar.',
            clave_nueva,
        )
    return True, 'Datos de integración POS actualizados.', None


def procesar_accion_configuracion_api_pos(
    tenant_id: int,
    *,
    accion: str,
    usuario_api: str | None,
    razon_social: str | None,
    emisor: dict,
    ambiente_servidor: str,
) -> tuple[bool, str, str | None, str]:
    """Devuelve (ok, mensaje, clave_opcional, categoria_flash)."""
    razon = (razon_social or '').strip() or (emisor.get('razon_social') or '').strip()
    rotar = accion == 'api_pos_rotar'
    if accion not in {'api_pos_activar', 'api_pos_rotar'}:
        return False, 'Acción no reconocida.', None, 'error'

    ok, mensaje, clave = provisionar_integracion_pos(
        tenant_id,
        rnc=emisor.get('rnc') or '',
        razon_social=razon,
        usuario_api=usuario_api,
        ambiente=ambiente_servidor,
        rotar_clave=rotar or not obtener_integracion_pos_por_tenant(tenant_id),
    )
    categoria = 'success' if ok else 'error'
    if ok and clave:
        categoria = 'warning'
    return ok, mensaje, clave, categoria