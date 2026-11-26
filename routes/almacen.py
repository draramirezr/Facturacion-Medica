"""Almacén general de la empresa: medicamentos y materiales.

Un único almacén por empresa (sin configuración de bodegas). Cada artículo
lleva su existencia en caché (``almacen_articulos.existencia``) que solo se
modifica junto con un movimiento del kardex, dentro de la misma transacción
y con la fila del artículo bloqueada (``SELECT ... FOR UPDATE``). Los
movimientos nunca se borran: las correcciones se registran como movimientos
nuevos.

Tipos de movimiento (``cantidad`` lleva signo: + entra, - sale):
- ENTRADA / SALIDA: registrados a mano desde el almacén.
- CONSUMO_EMERGENCIA: lo que se usó al registrar una historia de emergencia.
- AJUSTE_EMERGENCIA: compensación (+/-) al corregir ese consumo.
"""

import csv
from datetime import datetime
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from io import StringIO

from flask import Response, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from auth import permission_required, user_has_permission
from core.clock import fecha_clinica
from core.database import execute_query, execute_update, transactional_methods
from core.tenant import get_current_tenant_id
from routes.support import execute_paginated_query, sanitize_input, validate_int

TIPOS_ARTICULO = {'MEDICAMENTO': 'MED', 'MATERIAL': 'MAT'}
ETIQUETAS_TIPO_ARTICULO = {'MEDICAMENTO': 'Medicamento', 'MATERIAL': 'Material'}

MOV_ENTRADA = 'ENTRADA'
MOV_SALIDA = 'SALIDA'
MOV_CONSUMO_EMERGENCIA = 'CONSUMO_EMERGENCIA'
MOV_AJUSTE_EMERGENCIA = 'AJUSTE_EMERGENCIA'
TIPOS_MOVIMIENTO = (
    MOV_ENTRADA, MOV_SALIDA, MOV_CONSUMO_EMERGENCIA, MOV_AJUSTE_EMERGENCIA,
)
TIPOS_MOVIMIENTO_EMERGENCIA = (MOV_CONSUMO_EMERGENCIA, MOV_AJUSTE_EMERGENCIA)
ETIQUETAS_MOVIMIENTO = {
    MOV_ENTRADA: 'Entrada',
    MOV_SALIDA: 'Salida',
    MOV_CONSUMO_EMERGENCIA: 'Consumo en emergencia',
    MOV_AJUSTE_EMERGENCIA: 'Ajuste de emergencia',
}

UNIDAD_PREDETERMINADA = 'Unidad'
CENTAVO = Decimal('0.01')
CERO = Decimal('0.00')
# DECIMAL(10,2) para la cantidad del movimiento y DECIMAL(12,2) para saldos.
CANTIDAD_MAXIMA = Decimal('99999999.99')
EXISTENCIA_MAXIMA = Decimal('9999999999.99')
MAX_LINEAS_CONSUMO = 40


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------

def a_decimal(valor):
    try:
        numero = Decimal(str(valor if valor is not None else 0))
    except (InvalidOperation, ValueError):
        return CERO
    return numero if numero.is_finite() else CERO


def formato_cantidad(valor):
    """2.00 -> '2'; 1.50 -> '1.5'; 1250 -> '1,250'."""
    numero = a_decimal(valor).quantize(CENTAVO, rounding=ROUND_HALF_UP)
    if numero == numero.to_integral_value():
        return f'{int(numero):,}'
    return f'{numero:,.2f}'.rstrip('0')


def parsear_cantidad(valor):
    """Cantidad positiva, finita y con dos decimales como máximo."""
    texto = str(valor if valor is not None else '').strip()
    if not texto:
        return None, 'Indique la cantidad'
    try:
        cantidad = Decimal(texto)
    except (InvalidOperation, ValueError):
        return None, 'La cantidad no es válida'
    if not cantidad.is_finite():
        return None, 'La cantidad no es válida'
    if cantidad <= 0:
        return None, 'La cantidad debe ser mayor que cero'
    if cantidad > CANTIDAD_MAXIMA:
        return None, 'La cantidad es demasiado grande'
    if cantidad != cantidad.quantize(CENTAVO):
        return None, 'La cantidad admite como máximo dos decimales'
    return cantidad.quantize(CENTAVO), None


def parsear_fecha_movimiento(valor):
    texto = (valor or '').strip()
    if not texto:
        return fecha_clinica(), None
    try:
        fecha = datetime.strptime(texto[:10], '%Y-%m-%d').date()
    except ValueError:
        return None, 'La fecha no es válida'
    if fecha > fecha_clinica():
        return None, 'La fecha del movimiento no puede ser futura'
    return fecha, None


def _fecha_filtro(valor):
    try:
        return datetime.strptime((valor or '').strip()[:10], '%Y-%m-%d').date()
    except ValueError:
        return None


def _etiqueta_articulo(articulo):
    return f"{articulo.get('codigo')} {articulo.get('descripcion')}".strip()


# ---------------------------------------------------------------------------
# Artículos
# ---------------------------------------------------------------------------

def siguiente_codigo_articulo(tenant_id, tipo):
    """Correlativo por empresa y tipo: MED-0001, MAT-0001.

    Se llama dentro de la transacción del POST; FOR UPDATE serializa altas
    simultáneas y UNIQUE(tenant_id, codigo) impide duplicados en cualquier caso.
    """
    prefijo = TIPOS_ARTICULO[tipo]
    fila = execute_query(
        "SELECT COALESCE(MAX(numero), 0) + 1 AS siguiente "
        "FROM almacen_articulos WHERE tenant_id=%s AND tipo=%s FOR UPDATE",
        (tenant_id, tipo),
    ) or {}
    numero = int(fila.get('siguiente') or 1)
    return numero, f'{prefijo}-{numero:04d}'


def obtener_articulo(articulo_id, tenant_id, bloquear=False):
    sql = "SELECT * FROM almacen_articulos WHERE id=%s AND tenant_id=%s"
    if bloquear:
        sql += " FOR UPDATE"
    return execute_query(sql, (articulo_id, tenant_id))


def validar_datos_articulo(tenant_id, fuente=None, articulo=None):
    """Valida el formulario. En edición el tipo (y por tanto el código) no cambia."""
    form = fuente if fuente is not None else request.form
    if articulo:
        tipo = articulo['tipo']
    else:
        tipo = (form.get('tipo') or '').strip().upper()
        if tipo not in TIPOS_ARTICULO:
            return None, 'Seleccione si es medicamento o material'
    descripcion = sanitize_input(form.get('descripcion', ''), 200)
    if not descripcion:
        return None, 'La descripción es obligatoria'
    unidad = sanitize_input(form.get('unidad', ''), 30) or UNIDAD_PREDETERMINADA
    duplicado = execute_query(
        "SELECT id FROM almacen_articulos "
        "WHERE tenant_id=%s AND tipo=%s AND descripcion=%s AND id<>%s",
        (tenant_id, tipo, descripcion, articulo['id'] if articulo else 0),
    )
    if duplicado:
        return None, 'Ya existe un artículo de ese tipo con la misma descripción'
    return {'tipo': tipo, 'descripcion': descripcion, 'unidad': unidad}, None


def insertar_articulo(tenant_id, datos):
    numero, codigo = siguiente_codigo_articulo(tenant_id, datos['tipo'])
    articulo_id = execute_update(
        """
        INSERT INTO almacen_articulos (
            tenant_id, tipo, numero, codigo, descripcion, unidad,
            existencia, activo, created_by, updated_by
        ) VALUES (%s, %s, %s, %s, %s, %s, 0, 1, %s, %s)
        """,
        (
            tenant_id, datos['tipo'], numero, codigo, datos['descripcion'],
            datos['unidad'], current_user.id, current_user.id,
        ),
    )
    return articulo_id, codigo


def articulos_activos(tenant_id):
    return execute_query(
        "SELECT id, codigo, descripcion, unidad, tipo, existencia "
        "FROM almacen_articulos WHERE tenant_id=%s AND activo=1 "
        "ORDER BY tipo, descripcion",
        (tenant_id,), fetch='all',
    ) or []


# ---------------------------------------------------------------------------
# Movimientos (núcleo transaccional)
# ---------------------------------------------------------------------------

def bloquear_articulos(tenant_id, articulo_ids):
    """Bloquear las filas en orden de id (evita interbloqueos entre sesiones)."""
    ids = sorted({int(articulo_id) for articulo_id in articulo_ids})
    if not ids:
        return {}
    marcadores = ', '.join(['%s'] * len(ids))
    filas = execute_query(
        "SELECT id, codigo, descripcion, unidad, tipo, activo, existencia "
        f"FROM almacen_articulos WHERE tenant_id=%s AND id IN ({marcadores}) "
        "ORDER BY id FOR UPDATE",
        (tenant_id, *ids), fetch='all',
    ) or []
    return {fila['id']: fila for fila in filas}


def planificar_movimientos(tenant_id, cambios):
    """Bloquear artículos y validar los cambios antes de escribir nada.

    ``cambios``: lista de ``(articulo_id, tipo, delta)`` donde ``delta`` es
    el efecto con signo sobre la existencia. Devuelve ``(plan, error)``.
    La existencia se toma de la fila bloqueada, nunca del cliente.
    """
    if not cambios:
        return [], None
    articulos = bloquear_articulos(tenant_id, [cambio[0] for cambio in cambios])
    saldos = {}
    plan = []
    for articulo_id, tipo, delta in cambios:
        if tipo not in TIPOS_MOVIMIENTO:
            return None, 'Tipo de movimiento no válido'
        delta = a_decimal(delta)
        if delta == 0:
            continue
        articulo = articulos.get(articulo_id)
        if not articulo:
            return None, 'El artículo seleccionado no existe en el almacén'
        etiqueta = _etiqueta_articulo(articulo)
        # Solo una devolución al almacén (ajuste positivo) se admite en un
        # artículo desactivado: corrige un consumo ya registrado.
        devolucion = tipo == MOV_AJUSTE_EMERGENCIA and delta > 0
        if not articulo.get('activo') and not devolucion:
            return None, f'El artículo {etiqueta} está desactivado'
        saldo = saldos.get(articulo_id, a_decimal(articulo.get('existencia')))
        nuevo_saldo = saldo + delta
        if nuevo_saldo < 0:
            return None, (
                f'Existencia insuficiente de {etiqueta}: disponible '
                f"{formato_cantidad(saldo)} {articulo.get('unidad') or ''}".rstrip()
            )
        if nuevo_saldo > EXISTENCIA_MAXIMA:
            return None, f'La existencia de {etiqueta} excede el máximo permitido'
        saldos[articulo_id] = nuevo_saldo
        plan.append({
            'articulo_id': articulo_id,
            'tipo': tipo,
            'cantidad': delta,
            'saldo_resultante': nuevo_saldo,
        })
    return plan, None


def aplicar_movimientos(
    tenant_id, plan, fecha, nota=None, historia_emergencia_id=None,
):
    """Escribir un plan ya validado (las filas siguen bloqueadas)."""
    movimientos = []
    for movimiento in plan:
        execute_update(
            "UPDATE almacen_articulos SET existencia = existencia + %s "
            "WHERE id=%s AND tenant_id=%s",
            (movimiento['cantidad'], movimiento['articulo_id'], tenant_id),
        )
        movimientos.append(execute_update(
            """
            INSERT INTO almacen_movimientos (
                tenant_id, articulo_id, tipo, fecha, cantidad,
                saldo_resultante, nota, historia_emergencia_id, created_by
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                tenant_id, movimiento['articulo_id'], movimiento['tipo'],
                fecha, movimiento['cantidad'], movimiento['saldo_resultante'],
                nota or None, historia_emergencia_id, current_user.id,
            ),
        ))
    return movimientos


def registrar_movimiento(tenant_id, tipo, articulo_id, cantidad, fecha, nota=None):
    """Entrada o salida manual. Devuelve ``(movimiento, error)``."""
    if tipo not in (MOV_ENTRADA, MOV_SALIDA):
        return None, 'Tipo de movimiento no válido'
    delta = cantidad if tipo == MOV_ENTRADA else -cantidad
    plan, error = planificar_movimientos(tenant_id, [(articulo_id, tipo, delta)])
    if error:
        return None, error
    aplicar_movimientos(tenant_id, plan, fecha, nota)
    return plan[0], None


# ---------------------------------------------------------------------------
# Consumo en historias de emergencia
# ---------------------------------------------------------------------------

def leer_consumo_formulario(form):
    """Filas dinámicas del formulario -> ``{articulo_id: cantidad total}``."""
    ids = form.getlist('almacen_articulo_id')
    cantidades = form.getlist('almacen_cantidad')
    if len(ids) > MAX_LINEAS_CONSUMO:
        return None, f'Almacén: máximo {MAX_LINEAS_CONSUMO} artículos por historia'
    consumo = {}
    for indice, valor_id in enumerate(ids):
        valor_cantidad = cantidades[indice] if indice < len(cantidades) else ''
        if not str(valor_id or '').strip() and not str(valor_cantidad or '').strip():
            continue
        articulo_id = validate_int(valor_id, min_value=1, default=None)
        if not articulo_id:
            return None, 'Almacén: seleccione el artículo en cada fila con cantidad'
        cantidad, error = parsear_cantidad(valor_cantidad)
        if error:
            return None, f'Almacén: {error}'
        total = consumo.get(articulo_id, CERO) + cantidad
        if total > CANTIDAD_MAXIMA:
            return None, 'Almacén: la cantidad es demasiado grande'
        consumo[articulo_id] = total
    return consumo, None


def consumo_registrado_historia(tenant_id, historia_id):
    """Consumo neto ya registrado para la historia: ``{articulo_id: cantidad}``."""
    filas = execute_query(
        """
        SELECT articulo_id, -SUM(cantidad) AS consumido
        FROM almacen_movimientos
        WHERE tenant_id=%s AND historia_emergencia_id=%s
          AND tipo IN (%s, %s)
        GROUP BY articulo_id
        """,
        (tenant_id, historia_id, *TIPOS_MOVIMIENTO_EMERGENCIA), fetch='all',
    ) or []
    consumo = {}
    for fila in filas:
        cantidad = a_decimal(fila.get('consumido'))
        if cantidad > 0:
            consumo[fila['articulo_id']] = cantidad
    return consumo


def cambios_consumo_emergencia(nuevo, previo, es_edicion):
    """Diferencia por artículo entre lo pedido y lo ya consumido.

    Al crear todo es CONSUMO_EMERGENCIA; al editar, cada diferencia es un
    AJUSTE_EMERGENCIA (negativo si se consume más, positivo si se devuelve).
    """
    tipo = MOV_AJUSTE_EMERGENCIA if es_edicion else MOV_CONSUMO_EMERGENCIA
    cambios = []
    for articulo_id in sorted(set(nuevo) | set(previo)):
        diferencia = a_decimal(nuevo.get(articulo_id)) - a_decimal(previo.get(articulo_id))
        if diferencia:
            cambios.append((articulo_id, tipo, -diferencia))
    return cambios


def preparar_consumo_emergencia(tenant_id, nuevo, previo=None, es_edicion=False):
    """Bloquear y validar el consumo antes de escribir (devuelve plan, error)."""
    return planificar_movimientos(
        tenant_id,
        cambios_consumo_emergencia(nuevo, previo or {}, es_edicion=es_edicion),
    )


def detalle_consumo_historia(tenant_id, historia_id):
    """Artículos consumidos (neto) para mostrar en la historia."""
    filas = execute_query(
        """
        SELECT a.id, a.codigo, a.descripcion, a.unidad, a.tipo,
               -SUM(m.cantidad) AS cantidad
        FROM almacen_movimientos m
        JOIN almacen_articulos a
          ON a.id=m.articulo_id AND a.tenant_id=m.tenant_id
        WHERE m.tenant_id=%s AND m.historia_emergencia_id=%s
          AND m.tipo IN (%s, %s)
        GROUP BY a.id, a.codigo, a.descripcion, a.unidad, a.tipo
        HAVING -SUM(m.cantidad) > 0
        ORDER BY a.descripcion
        """,
        (tenant_id, historia_id, *TIPOS_MOVIMIENTO_EMERGENCIA), fetch='all',
    ) or []
    for fila in filas:
        fila['cantidad'] = a_decimal(fila.get('cantidad'))
    return filas


def articulos_para_consumo(tenant_id, previo=None):
    """Artículos activos (y los ya consumidos en la historia, aunque se hayan
    desactivado) con lo disponible para esa historia."""
    previo = previo or {}
    sql = (
        "SELECT id, codigo, descripcion, unidad, tipo, existencia, activo "
        "FROM almacen_articulos WHERE tenant_id=%s AND (activo=1"
    )
    params = [tenant_id]
    if previo:
        sql += f" OR id IN ({', '.join(['%s'] * len(previo))})"
        params.extend(sorted(previo))
    sql += ") ORDER BY tipo, descripcion"
    filas = execute_query(sql, tuple(params), fetch='all') or []
    for fila in filas:
        fila['disponible'] = (
            a_decimal(fila.get('existencia')) + previo.get(fila['id'], CERO)
        )
    return filas


# ---------------------------------------------------------------------------
# Vistas: artículos
# ---------------------------------------------------------------------------

@login_required
@permission_required('almacen.ver')
def facturacion_almacen():
    tenant_id = get_current_tenant_id()
    buscar = request.args.get('buscar', '').strip()[:100]
    tipo = request.args.get('tipo', '').strip().upper()
    estado = request.args.get('estado', 'activos').strip()
    existencia = request.args.get('existencia', '').strip()
    orden = request.args.get('orden', 'descripcion').strip()

    query = """
        SELECT a.id, a.tipo, a.codigo, a.descripcion, a.unidad,
               a.existencia, a.activo
        FROM almacen_articulos a
        WHERE a.tenant_id=%s
    """
    params = [tenant_id]
    if buscar:
        patron = f'%{buscar}%'
        query += " AND (a.codigo LIKE %s OR a.descripcion LIKE %s)"
        params.extend([patron, patron])
    if tipo in TIPOS_ARTICULO:
        query += " AND a.tipo=%s"
        params.append(tipo)
    if estado == 'activos':
        query += " AND a.activo=1"
    elif estado == 'inactivos':
        query += " AND a.activo=0"
    if existencia == 'sin':
        query += " AND a.existencia<=0"
    elif existencia == 'con':
        query += " AND a.existencia>0"
    ordenes = {
        'descripcion': 'a.descripcion ASC, a.id ASC',
        'codigo': 'a.tipo ASC, a.numero ASC',
        'existencia_asc': 'a.existencia ASC, a.descripcion ASC',
        'existencia_desc': 'a.existencia DESC, a.descripcion ASC',
    }
    articulos, pagination = execute_paginated_query(
        query, params, ordenes.get(orden, ordenes['descripcion']),
    )
    resumen = execute_query(
        """
        SELECT COUNT(*) AS total,
               COALESCE(SUM(activo=1), 0) AS activos,
               COALESCE(SUM(activo=1 AND existencia<=0), 0) AS sin_existencia
        FROM almacen_articulos WHERE tenant_id=%s
        """,
        (tenant_id,),
    ) or {}
    return render_template(
        'facturacion/almacen_articulos.html',
        articulos=articulos, pagination=pagination, filtros=request.args,
        estado=estado, resumen=resumen,
        etiquetas_tipo=ETIQUETAS_TIPO_ARTICULO,
    )


@login_required
@transactional_methods('POST')
@permission_required('almacen.gestionar')
def facturacion_almacen_nuevo():
    tenant_id = get_current_tenant_id()
    if request.method == 'POST':
        datos, error = validar_datos_articulo(tenant_id)
        if error:
            flash(error, 'error')
            return render_template(
                'facturacion/almacen_articulo_form.html', articulo=None,
                form_data=request.form, etiquetas_tipo=ETIQUETAS_TIPO_ARTICULO,
            )
        articulo_id, codigo = insertar_articulo(tenant_id, datos)
        if user_has_permission(current_user, 'almacen.movimientos'):
            flash(
                f'Artículo {codigo} creado. Registre su existencia inicial con una entrada.',
                'success',
            )
            return redirect(url_for('facturacion_almacen_entrada', articulo_id=articulo_id))
        flash(f'Artículo {codigo} creado', 'success')
        return redirect(url_for('facturacion_almacen'))
    tipo = (request.args.get('tipo') or '').strip().upper()
    return render_template(
        'facturacion/almacen_articulo_form.html', articulo=None,
        form_data={'tipo': tipo if tipo in TIPOS_ARTICULO else 'MEDICAMENTO'},
        etiquetas_tipo=ETIQUETAS_TIPO_ARTICULO,
    )


@login_required
@transactional_methods('POST')
@permission_required('almacen.gestionar')
def facturacion_almacen_editar(articulo_id):
    tenant_id = get_current_tenant_id()
    articulo = obtener_articulo(
        articulo_id, tenant_id, bloquear=request.method == 'POST',
    )
    if not articulo:
        flash('Artículo no encontrado', 'error')
        return redirect(url_for('facturacion_almacen'))
    if request.method == 'POST':
        datos, error = validar_datos_articulo(tenant_id, articulo=articulo)
        if error:
            flash(error, 'error')
            return render_template(
                'facturacion/almacen_articulo_form.html', articulo=articulo,
                form_data=request.form, etiquetas_tipo=ETIQUETAS_TIPO_ARTICULO,
            )
        execute_update(
            "UPDATE almacen_articulos SET descripcion=%s, unidad=%s, updated_by=%s "
            "WHERE id=%s AND tenant_id=%s",
            (
                datos['descripcion'], datos['unidad'], current_user.id,
                articulo_id, tenant_id,
            ),
        )
        flash(f"Artículo {articulo['codigo']} actualizado", 'success')
        return redirect(url_for('facturacion_almacen'))
    return render_template(
        'facturacion/almacen_articulo_form.html', articulo=articulo,
        form_data=articulo, etiquetas_tipo=ETIQUETAS_TIPO_ARTICULO,
    )


@login_required
@transactional_methods('POST')
@permission_required('almacen.gestionar')
def facturacion_almacen_estado(articulo_id):
    tenant_id = get_current_tenant_id()
    articulo = obtener_articulo(articulo_id, tenant_id, bloquear=True)
    if not articulo:
        flash('Artículo no encontrado', 'error')
        return redirect(url_for('facturacion_almacen'))
    activo = 0 if articulo.get('activo') else 1
    execute_update(
        "UPDATE almacen_articulos SET activo=%s, updated_by=%s "
        "WHERE id=%s AND tenant_id=%s",
        (activo, current_user.id, articulo_id, tenant_id),
    )
    if activo:
        flash(f"Artículo {articulo['codigo']} activado", 'success')
    else:
        flash(
            f"Artículo {articulo['codigo']} desactivado; su historial se conserva",
            'success',
        )
    return redirect(url_for('facturacion_almacen'))


# ---------------------------------------------------------------------------
# Vistas: entradas, salidas y kardex
# ---------------------------------------------------------------------------

def _vista_movimiento(tipo):
    tenant_id = get_current_tenant_id()
    contexto = {
        'tipo': tipo,
        'etiqueta': ETIQUETAS_MOVIMIENTO[tipo],
        'fecha_actual': fecha_clinica().isoformat(),
    }
    if request.method == 'POST':
        articulo_id = validate_int(
            request.form.get('articulo_id'), min_value=1, default=None,
        )
        cantidad, error = parsear_cantidad(request.form.get('cantidad'))
        fecha = None
        if not error:
            fecha, error = parsear_fecha_movimiento(request.form.get('fecha'))
        nota = sanitize_input(request.form.get('nota', ''), 500)
        if not error and not articulo_id:
            error = 'Seleccione el artículo'
        if not error and tipo == MOV_SALIDA and not nota:
            error = 'Indique el motivo de la salida'
        movimiento = None
        if not error:
            movimiento, error = registrar_movimiento(
                tenant_id, tipo, articulo_id, cantidad, fecha, nota,
            )
        if error:
            flash(error, 'error')
            return render_template(
                'facturacion/almacen_movimiento_form.html',
                articulos=articulos_activos(tenant_id),
                form_data=request.form, **contexto,
            )
        flash(
            f"{ETIQUETAS_MOVIMIENTO[tipo]} registrada. Existencia actual: "
            f"{formato_cantidad(movimiento['saldo_resultante'])}",
            'success',
        )
        return redirect(url_for(
            'facturacion_almacen_movimientos', articulo_id=articulo_id,
        ))
    form_data = {}
    articulo_id = validate_int(request.args.get('articulo_id'), min_value=1, default=None)
    if articulo_id:
        form_data['articulo_id'] = articulo_id
    return render_template(
        'facturacion/almacen_movimiento_form.html',
        articulos=articulos_activos(tenant_id), form_data=form_data, **contexto,
    )


@login_required
@transactional_methods('POST')
@permission_required('almacen.movimientos')
def facturacion_almacen_entrada():
    return _vista_movimiento(MOV_ENTRADA)


@login_required
@transactional_methods('POST')
@permission_required('almacen.movimientos')
def facturacion_almacen_salida():
    return _vista_movimiento(MOV_SALIDA)


@login_required
@permission_required('almacen.ver')
def facturacion_almacen_movimientos():
    tenant_id = get_current_tenant_id()
    articulo_id = validate_int(request.args.get('articulo_id'), min_value=1, default=None)
    tipo = request.args.get('tipo', '').strip().upper()
    desde = _fecha_filtro(request.args.get('desde'))
    hasta = _fecha_filtro(request.args.get('hasta'))
    if desde and hasta and desde > hasta:
        desde, hasta = hasta, desde

    query = """
        SELECT m.id, m.articulo_id, m.tipo, m.fecha, m.cantidad,
               m.saldo_resultante, m.nota, m.historia_emergencia_id,
               m.created_at, a.codigo, a.descripcion, a.unidad,
               u.nombre AS usuario_nombre
        FROM almacen_movimientos m
        JOIN almacen_articulos a
          ON a.id=m.articulo_id AND a.tenant_id=m.tenant_id
        LEFT JOIN usuarios u
          ON u.id=m.created_by AND u.tenant_id=m.tenant_id
        WHERE m.tenant_id=%s
    """
    params = [tenant_id]
    if articulo_id:
        query += " AND m.articulo_id=%s"
        params.append(articulo_id)
    if tipo in TIPOS_MOVIMIENTO:
        query += " AND m.tipo=%s"
        params.append(tipo)
    if desde:
        query += " AND m.fecha>=%s"
        params.append(desde)
    if hasta:
        query += " AND m.fecha<=%s"
        params.append(hasta)
    # El saldo resultante sigue el orden de registro (id), no la fecha.
    movimientos, pagination = execute_paginated_query(query, params, 'm.id DESC')
    articulos = execute_query(
        "SELECT id, codigo, descripcion, unidad, existencia, activo "
        "FROM almacen_articulos WHERE tenant_id=%s ORDER BY descripcion",
        (tenant_id,), fetch='all',
    ) or []
    articulo = next((a for a in articulos if a['id'] == articulo_id), None)
    return render_template(
        'facturacion/almacen_movimientos.html',
        movimientos=movimientos, pagination=pagination, articulos=articulos,
        articulo=articulo, filtros=request.args,
        desde=desde.isoformat() if desde else '',
        hasta=hasta.isoformat() if hasta else '',
        etiquetas_movimiento=ETIQUETAS_MOVIMIENTO,
    )


# ---------------------------------------------------------------------------
# Reporte
# ---------------------------------------------------------------------------

def rango_reporte_por_defecto(hoy=None):
    hoy = hoy or fecha_clinica()
    return hoy.replace(day=1), hoy


def consultar_reporte_almacen(tenant_id, desde, hasta, tipo=None, estado=None):
    """Existencia actual y movimiento del periodo por artículo."""
    query = """
        SELECT a.id, a.codigo, a.descripcion, a.tipo, a.unidad, a.activo,
               a.existencia,
               COALESCE(SUM(CASE WHEN m.tipo='ENTRADA'
                                 THEN m.cantidad ELSE 0 END), 0) AS entradas,
               COALESCE(SUM(CASE WHEN m.tipo='SALIDA'
                                 THEN -m.cantidad ELSE 0 END), 0) AS salidas,
               COALESCE(SUM(CASE WHEN m.tipo IN ('CONSUMO_EMERGENCIA', 'AJUSTE_EMERGENCIA')
                                 THEN -m.cantidad ELSE 0 END), 0) AS consumo_emergencias
        FROM almacen_articulos a
        LEFT JOIN almacen_movimientos m
          ON m.articulo_id=a.id AND m.tenant_id=a.tenant_id
         AND m.fecha BETWEEN %s AND %s
        WHERE a.tenant_id=%s
    """
    params = [desde, hasta, tenant_id]
    if tipo in TIPOS_ARTICULO:
        query += " AND a.tipo=%s"
        params.append(tipo)
    if estado == 'activos':
        query += " AND a.activo=1"
    elif estado == 'inactivos':
        query += " AND a.activo=0"
    query += (
        " GROUP BY a.id, a.codigo, a.descripcion, a.tipo, a.unidad,"
        " a.activo, a.existencia ORDER BY a.tipo, a.descripcion"
    )
    filas = execute_query(query, tuple(params), fetch='all') or []
    totales = {
        'articulos': 0, 'sin_existencia': 0,
        'entradas': CERO, 'salidas': CERO, 'consumo_emergencias': CERO,
    }
    resultado = []
    for fila in filas:
        item = {
            'id': fila.get('id'),
            'codigo': fila.get('codigo'),
            'descripcion': fila.get('descripcion'),
            'tipo': fila.get('tipo'),
            'tipo_etiqueta': ETIQUETAS_TIPO_ARTICULO.get(fila.get('tipo'), fila.get('tipo')),
            'unidad': fila.get('unidad') or UNIDAD_PREDETERMINADA,
            'activo': bool(fila.get('activo')),
            'existencia': a_decimal(fila.get('existencia')),
            'entradas': a_decimal(fila.get('entradas')),
            'salidas': a_decimal(fila.get('salidas')),
            'consumo_emergencias': a_decimal(fila.get('consumo_emergencias')),
        }
        item['sin_existencia'] = item['existencia'] <= 0
        resultado.append(item)
        totales['articulos'] += 1
        totales['sin_existencia'] += int(item['sin_existencia'])
        for clave in ('entradas', 'salidas', 'consumo_emergencias'):
            totales[clave] += item[clave]
    return resultado, totales


def csv_reporte_almacen(filas, totales, desde, hasta):
    salida = StringIO()
    escritor = csv.writer(salida)
    escritor.writerow([f'Reporte de almacén del {desde.isoformat()} al {hasta.isoformat()}'])
    escritor.writerow([
        'Código', 'Descripción', 'Tipo', 'Unidad', 'Estado',
        'Entradas', 'Salidas', 'Consumo en emergencias', 'Existencia actual',
    ])
    for fila in filas:
        escritor.writerow([
            fila['codigo'], fila['descripcion'], fila['tipo_etiqueta'],
            fila['unidad'], 'Activo' if fila['activo'] else 'Desactivado',
            fila['entradas'], fila['salidas'], fila['consumo_emergencias'],
            fila['existencia'],
        ])
    escritor.writerow([
        'TOTAL', f"{totales['articulos']} artículos", '', '', '',
        totales['entradas'], totales['salidas'],
        totales['consumo_emergencias'], '',
    ])
    # BOM para que Excel abra bien los acentos.
    return '﻿' + salida.getvalue()


@login_required
@permission_required('almacen.ver')
def facturacion_reporte_almacen():
    tenant_id = get_current_tenant_id()
    desde_def, hasta_def = rango_reporte_por_defecto()
    desde = _fecha_filtro(request.args.get('desde')) or desde_def
    hasta = _fecha_filtro(request.args.get('hasta')) or hasta_def
    if desde > hasta:
        desde, hasta = hasta, desde
    tipo = request.args.get('tipo', '').strip().upper()
    tipo = tipo if tipo in TIPOS_ARTICULO else ''
    estado = request.args.get('estado', 'activos').strip()
    if estado not in ('activos', 'inactivos', 'todos'):
        estado = 'activos'

    filas, totales = consultar_reporte_almacen(tenant_id, desde, hasta, tipo, estado)
    if request.args.get('formato') == 'csv':
        nombre = f'almacen_{desde.isoformat()}_{hasta.isoformat()}.csv'
        return Response(
            csv_reporte_almacen(filas, totales, desde, hasta),
            mimetype='text/csv; charset=utf-8',
            headers={'Content-Disposition': f'attachment; filename="{nombre}"'},
        )
    return render_template(
        'facturacion/reporte_almacen.html',
        filas=filas, totales=totales, tipo=tipo, estado=estado,
        desde=desde.isoformat(), hasta=hasta.isoformat(),
        etiquetas_tipo=ETIQUETAS_TIPO_ARTICULO,
    )


def register_almacen_routes(app):
    app.add_template_filter(formato_cantidad, 'cantidad')
    app.add_url_rule('/facturacion/almacen', endpoint='facturacion_almacen', view_func=facturacion_almacen)
    app.add_url_rule('/facturacion/almacen/nuevo', endpoint='facturacion_almacen_nuevo', view_func=facturacion_almacen_nuevo, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/almacen/<int:articulo_id>/editar', endpoint='facturacion_almacen_editar', view_func=facturacion_almacen_editar, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/almacen/<int:articulo_id>/estado', endpoint='facturacion_almacen_estado', view_func=facturacion_almacen_estado, methods=['POST'])
    app.add_url_rule('/facturacion/almacen/entrada', endpoint='facturacion_almacen_entrada', view_func=facturacion_almacen_entrada, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/almacen/salida', endpoint='facturacion_almacen_salida', view_func=facturacion_almacen_salida, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/almacen/movimientos', endpoint='facturacion_almacen_movimientos', view_func=facturacion_almacen_movimientos)
    app.add_url_rule('/facturacion/reportes/almacen', endpoint='facturacion_reporte_almacen', view_func=facturacion_reporte_almacen)
