"""Mensajer?a interna entre usuarios de un tenant."""

from datetime import datetime

from flask import jsonify, request
from flask_login import current_user, login_required

from core.database import execute_query, execute_update, transactional_methods
from core.security import rate_limit
from core.tenant import get_current_tenant_id
from routes.support import sanitize_input, validate_int

def obtener_usuario_mensajeria(usuario_id, tenant_id):
    """Resolver un destinatario activo sin salir del tenant actual."""
    return execute_query(
        'SELECT id, nombre, perfil FROM usuarios '
        'WHERE id=%s AND tenant_id=%s AND activo=1',
        (usuario_id, tenant_id)
    )

def obtener_conversacion_directa(usuario_id, tenant_id):
    """Buscar la conversación canónica entre el usuario actual y otro usuario."""
    usuario_actual = int(current_user.id)
    usuario_menor, usuario_mayor = sorted((usuario_actual, int(usuario_id)))
    return execute_query(
        'SELECT id FROM conversaciones_internas '
        'WHERE tenant_id=%s AND usuario_menor_id=%s AND usuario_mayor_id=%s',
        (tenant_id, usuario_menor, usuario_mayor)
    )

def serializar_mensaje_interno(mensaje):
    fecha = mensaje.get('created_at')
    leido = mensaje.get('leido_at')
    return {
        'id': mensaje['id'],
        'remitente_id': mensaje['remitente_id'],
        'destinatario_id': mensaje['destinatario_id'],
        'cuerpo': mensaje['cuerpo'],
        'created_at': fecha.isoformat() if hasattr(fecha, 'isoformat') else str(fecha),
        'leido_at': (
            leido.isoformat() if hasattr(leido, 'isoformat')
            else (str(leido) if leido else None)
        ),
    }

@login_required
def api_mensajeria_usuarios():
    tenant_id = get_current_tenant_id()
    if not tenant_id:
        return jsonify({'error': 'Usuario sin consultorio asignado'}), 403
    usuarios = execute_query(
        'SELECT id, nombre, perfil FROM usuarios '
        'WHERE tenant_id=%s AND activo=1 AND id<>%s '
        'ORDER BY nombre, id',
        (tenant_id, current_user.id),
        fetch='all'
    ) or []
    return jsonify({'usuarios': usuarios})

@login_required
def api_mensajeria_conversaciones():
    tenant_id = get_current_tenant_id()
    if not tenant_id:
        return jsonify({'error': 'Usuario sin consultorio asignado'}), 403
    conversaciones = execute_query('''
        SELECT c.id,
               CASE WHEN c.usuario_menor_id=%s
                    THEN c.usuario_mayor_id ELSE c.usuario_menor_id END
                    AS usuario_id,
               u.nombre, u.perfil, c.ultimo_mensaje_at,
               (
                   SELECT m.cuerpo
                   FROM mensajes_internos m
                   WHERE m.tenant_id=c.tenant_id
                     AND m.conversacion_id=c.id
                   ORDER BY m.id DESC LIMIT 1
               ) AS ultimo_mensaje,
               (
                   SELECT COUNT(*)
                   FROM mensajes_internos m
                   WHERE m.tenant_id=c.tenant_id
                     AND m.conversacion_id=c.id
                     AND m.destinatario_id=%s
                     AND m.leido_at IS NULL
               ) AS no_leidos
        FROM conversaciones_internas c
        JOIN usuarios u
          ON u.id=CASE WHEN c.usuario_menor_id=%s
                       THEN c.usuario_mayor_id ELSE c.usuario_menor_id END
         AND u.tenant_id=c.tenant_id
         AND u.activo=1
        WHERE c.tenant_id=%s
          AND (c.usuario_menor_id=%s OR c.usuario_mayor_id=%s)
        ORDER BY c.ultimo_mensaje_at DESC, c.id DESC
        LIMIT 100
    ''', (
        current_user.id, current_user.id, current_user.id, tenant_id,
        current_user.id, current_user.id
    ), fetch='all') or []
    for conversacion in conversaciones:
        fecha = conversacion.get('ultimo_mensaje_at')
        conversacion['ultimo_mensaje_at'] = (
            fecha.isoformat() if hasattr(fecha, 'isoformat')
            else (str(fecha) if fecha else None)
        )
    return jsonify({'conversaciones': conversaciones})

@login_required
def api_mensajeria_mensajes(usuario_id):
    tenant_id = get_current_tenant_id()
    if not tenant_id:
        return jsonify({'error': 'Usuario sin consultorio asignado'}), 403
    if usuario_id == current_user.id:
        return jsonify({'error': 'El destinatario no es válido'}), 400
    destinatario = obtener_usuario_mensajeria(usuario_id, tenant_id)
    if not destinatario:
        return jsonify({'error': 'Usuario no encontrado'}), 404
    conversacion = obtener_conversacion_directa(usuario_id, tenant_id)
    if not conversacion:
        return jsonify({
            'usuario': destinatario,
            'conversacion_id': None,
            'mensajes': [],
        })

    after_id = validate_int(
        request.args.get('after_id', 0),
        min_value=0,
        default=0,
    )
    if after_id:
        query = '''
            SELECT id, remitente_id, destinatario_id, cuerpo,
                   created_at, leido_at
            FROM mensajes_internos
            WHERE tenant_id=%s AND conversacion_id=%s AND id>%s
            ORDER BY id ASC LIMIT 100
        '''
        params = (tenant_id, conversacion['id'], after_id)
    else:
        query = '''
            SELECT id, remitente_id, destinatario_id, cuerpo,
                   created_at, leido_at
            FROM mensajes_internos
            WHERE tenant_id=%s AND conversacion_id=%s
            ORDER BY id DESC LIMIT 100
        '''
        params = (tenant_id, conversacion['id'])
    mensajes = execute_query(query, params, fetch='all') or []
    if not after_id:
        mensajes.reverse()
    return jsonify({
        'usuario': destinatario,
        'conversacion_id': conversacion['id'],
        'mensajes': [
            serializar_mensaje_interno(mensaje) for mensaje in mensajes
        ],
    })

@login_required
@rate_limit(max_requests=60, window=60)
@transactional_methods('POST')
def api_mensajeria_enviar():
    tenant_id = get_current_tenant_id()
    if not tenant_id:
        return jsonify({'error': 'Usuario sin consultorio asignado'}), 403
    payload = request.get_json(silent=True) or {}
    destinatario_id = validate_int(
        payload.get('destinatario_id'),
        min_value=1,
        default=None,
    )
    cuerpo_original = str(payload.get('cuerpo') or '').strip()
    if not destinatario_id or destinatario_id == current_user.id:
        return jsonify({'error': 'El destinatario no es válido'}), 400
    if not cuerpo_original:
        return jsonify({'error': 'Escribe un mensaje antes de enviarlo'}), 400
    if len(cuerpo_original) > 4000:
        return jsonify({'error': 'El mensaje no puede superar 4,000 caracteres'}), 400
    cuerpo = sanitize_input(cuerpo_original, 4000)
    if not cuerpo:
        return jsonify({'error': 'El mensaje no contiene texto válido'}), 400
    destinatario = obtener_usuario_mensajeria(destinatario_id, tenant_id)
    if not destinatario:
        return jsonify({'error': 'Usuario no encontrado'}), 404

    usuario_menor, usuario_mayor = sorted(
        (int(current_user.id), destinatario_id)
    )
    conversacion_id = execute_update('''
        INSERT INTO conversaciones_internas (
            tenant_id, usuario_menor_id, usuario_mayor_id
        ) VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE id=LAST_INSERT_ID(id)
    ''', (tenant_id, usuario_menor, usuario_mayor))
    if not conversacion_id:
        raise RuntimeError('No se pudo crear la conversación interna')
    mensaje_id = execute_update('''
        INSERT INTO mensajes_internos (
            tenant_id, conversacion_id, remitente_id,
            destinatario_id, cuerpo
        ) VALUES (%s, %s, %s, %s, %s)
    ''', (
        tenant_id, conversacion_id, current_user.id,
        destinatario_id, cuerpo
    ))
    if not mensaje_id:
        raise RuntimeError('No se pudo guardar el mensaje interno')
    execute_update(
        'UPDATE conversaciones_internas SET ultimo_mensaje_at=NOW() '
        'WHERE id=%s AND tenant_id=%s',
        (conversacion_id, tenant_id)
    )
    return jsonify({
        'mensaje': {
            'id': mensaje_id,
            'remitente_id': current_user.id,
            'destinatario_id': destinatario_id,
            'cuerpo': cuerpo,
            'created_at': datetime.now().isoformat(),
            'leido_at': None,
        },
        'conversacion_id': conversacion_id,
    }), 201

@login_required
@transactional_methods('POST')
def api_mensajeria_marcar_leidos():
    tenant_id = get_current_tenant_id()
    if not tenant_id:
        return jsonify({'error': 'Usuario sin consultorio asignado'}), 403
    payload = request.get_json(silent=True) or {}
    usuario_id = validate_int(
        payload.get('usuario_id'),
        min_value=1,
        default=None,
    )
    hasta_id = validate_int(
        payload.get('hasta_id'),
        min_value=1,
        default=None,
    )
    if not usuario_id or usuario_id == current_user.id:
        return jsonify({'error': 'El usuario no es válido'}), 400
    if not obtener_usuario_mensajeria(usuario_id, tenant_id):
        return jsonify({'error': 'Usuario no encontrado'}), 404
    conversacion = obtener_conversacion_directa(usuario_id, tenant_id)
    if not conversacion:
        return jsonify({'ok': True})

    query = '''
        UPDATE mensajes_internos
        SET leido_at=NOW()
        WHERE tenant_id=%s AND conversacion_id=%s
          AND destinatario_id=%s AND remitente_id=%s
          AND leido_at IS NULL
    '''
    params = [
        tenant_id, conversacion['id'], current_user.id, usuario_id
    ]
    if hasta_id:
        query += ' AND id<=%s'
        params.append(hasta_id)
    execute_update(query, tuple(params))
    return jsonify({'ok': True})

@login_required
def api_mensajeria_no_leidos():
    tenant_id = get_current_tenant_id()
    if not tenant_id:
        return jsonify({'error': 'Usuario sin consultorio asignado'}), 403
    resultado = execute_query('''
        SELECT COUNT(*) AS total
        FROM mensajes_internos m
        JOIN usuarios u
          ON u.id=m.remitente_id AND u.tenant_id=m.tenant_id
         AND u.activo=1
        WHERE m.tenant_id=%s AND m.destinatario_id=%s
          AND m.leido_at IS NULL
    ''', (tenant_id, current_user.id)) or {'total': 0}
    return jsonify({'total': int(resultado.get('total') or 0)})

def register_messaging_routes(app):
    app.add_url_rule('/api/mensajeria/usuarios', endpoint='api_mensajeria_usuarios', view_func=api_mensajeria_usuarios)
    app.add_url_rule('/api/mensajeria/conversaciones', endpoint='api_mensajeria_conversaciones', view_func=api_mensajeria_conversaciones)
    app.add_url_rule('/api/mensajeria/mensajes/<int:usuario_id>', endpoint='api_mensajeria_mensajes', view_func=api_mensajeria_mensajes)
    app.add_url_rule('/api/mensajeria/mensajes', endpoint='api_mensajeria_enviar', view_func=api_mensajeria_enviar, methods=['POST'])
    app.add_url_rule('/api/mensajeria/leer', endpoint='api_mensajeria_marcar_leidos', view_func=api_mensajeria_marcar_leidos, methods=['POST'])
    app.add_url_rule('/api/mensajeria/no-leidos', endpoint='api_mensajeria_no_leidos', view_func=api_mensajeria_no_leidos)
