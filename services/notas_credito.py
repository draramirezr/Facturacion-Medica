"""Notas de crédito sobre facturas (parcial o total)."""

from __future__ import annotations

from decimal import Decimal, ROUND_HALF_UP
from typing import Any

from core.database import execute_query, execute_update

_CENTS = Decimal("0.01")
_ESTADOS_NC_ACTIVOS = ("confirmada",)


class NotaCreditoError(ValueError):
    """Validación de negocio."""


def _money(value) -> Decimal:
    try:
        number = Decimal(str(value or "0"))
    except Exception as error:
        raise NotaCreditoError("Monto inválido") from error
    return number.quantize(_CENTS, rounding=ROUND_HALF_UP)


def monto_credito_acumulado_factura(tenant_id: int, factura_id: int) -> Decimal:
    row = execute_query(
        """
        SELECT COALESCE(SUM(total), 0) AS acumulado
        FROM notas_credito
        WHERE tenant_id=%s AND factura_id=%s AND estado IN ('confirmada')
        """,
        (tenant_id, factura_id),
    )
    return _money(row.get("acumulado") if row else 0)


def saldo_creditable_factura(tenant_id: int, factura_id: int) -> Decimal:
    factura = execute_query(
        "SELECT total, estado FROM facturas WHERE id=%s AND tenant_id=%s",
        (factura_id, tenant_id),
    )
    if not factura:
        raise NotaCreditoError("Factura no encontrada")
    if (factura.get("estado") or "") == "Anulada":
        raise NotaCreditoError("No se puede acreditar una factura anulada")
    total = _money(factura.get("total"))
    acumulado = monto_credito_acumulado_factura(tenant_id, factura_id)
    saldo = (total - acumulado).quantize(_CENTS)
    if saldo < 0:
        saldo = Decimal("0.00")
    return saldo


def lineas_credito_pendientes(
    tenant_id: int, factura_id: int
) -> list[dict[str, Any]]:
    detalles = execute_query(
        """
        SELECT id, descripcion, cantidad, precio_unitario, subtotal
        FROM factura_detalles
        WHERE factura_id=%s AND tenant_id=%s
        ORDER BY id
        """,
        (factura_id, tenant_id),
        fetch="all",
    ) or []
    out: list[dict[str, Any]] = []
    for detalle in detalles:
        detalle_id = detalle["id"]
        monto_linea = _money(detalle.get("subtotal") or detalle.get("precio_unitario"))
        usado = execute_query(
            """
            SELECT COALESCE(SUM(nd.monto_credito), 0) AS usado
            FROM nota_credito_detalles nd
            INNER JOIN notas_credito nc
              ON nc.id = nd.nota_credito_id AND nc.tenant_id = nd.tenant_id
            WHERE nd.tenant_id=%s
              AND nd.factura_detalle_id=%s
              AND nc.estado='confirmada'
            """,
            (tenant_id, detalle_id),
        )
        pendiente = (monto_linea - _money(usado.get("usado") if usado else 0)).quantize(
            _CENTS
        )
        if pendiente > 0:
            out.append(
                {
                    **detalle,
                    "monto_linea": monto_linea,
                    "monto_pendiente": pendiente,
                }
            )
    return out


def listar_notas_factura(tenant_id: int, factura_id: int) -> list[dict]:
    return (
        execute_query(
            """
            SELECT id, codigo, tipo, total, estado, created_at, e_ncf, estado_ecf
            FROM notas_credito
            WHERE tenant_id=%s AND factura_id=%s
            ORDER BY id DESC
            """,
            (tenant_id, factura_id),
            fetch="all",
        )
        or []
    )


def _generar_codigo(tenant_id: int, factura_id: int) -> str:
    row = execute_query(
        """
        SELECT COUNT(*) AS n
        FROM notas_credito
        WHERE tenant_id=%s AND factura_id=%s
        """,
        (tenant_id, factura_id),
    )
    secuencia = int((row or {}).get("n") or 0) + 1
    return f"NC-{factura_id}-{secuencia:03d}"


def puede_emitir_nota_credito(tenant_id: int, factura_id: int) -> tuple[bool, str]:
    try:
        saldo = saldo_creditable_factura(tenant_id, factura_id)
    except NotaCreditoError as error:
        return False, str(error)
    if saldo <= 0:
        return False, "La factura ya fue cubierta por notas de crédito"
    return True, ""


def crear_nota_credito(
    *,
    tenant_id: int,
    factura_id: int,
    tipo: str,
    motivo: str,
    usuario_id: int | None,
    lineas: list[dict] | None = None,
) -> int:
    tipo = (tipo or "").strip().lower()
    if tipo not in {"parcial", "total"}:
        raise NotaCreditoError("Tipo de nota de crédito inválido")
    motivo = (motivo or "").strip()
    if not motivo:
        raise NotaCreditoError("Indique el motivo de la nota de crédito")

    # Bloquear la factura hasta el commit: dos notas simultáneas sobre la
    # misma factura se procesan en fila y la segunda ve el saldo ya rebajado.
    from flask import g, has_app_context

    if has_app_context() and not g.get("db_transaction_active", False):
        raise RuntimeError("crear_nota_credito debe ejecutarse dentro de database_transaction()")
    bloqueada = execute_query(
        "SELECT id FROM facturas WHERE id=%s AND tenant_id=%s FOR UPDATE",
        (factura_id, tenant_id),
    )
    if not bloqueada:
        raise NotaCreditoError("Factura no encontrada")

    saldo = saldo_creditable_factura(tenant_id, factura_id)
    if saldo <= 0:
        raise NotaCreditoError("No queda saldo creditable en la factura")

    pendientes = lineas_credito_pendientes(tenant_id, factura_id)
    if not pendientes and tipo == "parcial":
        raise NotaCreditoError("No hay líneas con saldo pendiente para acreditar")

    seleccion: list[dict] = []
    if tipo == "total":
        for linea in pendientes:
            seleccion.append(
                {
                    "factura_detalle_id": linea["id"],
                    "descripcion": linea["descripcion"],
                    "cantidad": linea.get("cantidad") or 1,
                    "precio_unitario": linea.get("precio_unitario") or 0,
                    "monto_credito": linea["monto_pendiente"],
                }
            )
        if not seleccion:
            seleccion.append(
                {
                    "factura_detalle_id": None,
                    "descripcion": "Nota de crédito total",
                    "cantidad": 1,
                    "precio_unitario": saldo,
                    "monto_credito": saldo,
                }
            )
        total_nc = saldo
    else:
        if not lineas:
            raise NotaCreditoError("Seleccione al menos una línea para la nota parcial")
        pendientes_por_id = {p["id"]: p for p in pendientes}
        total_nc = Decimal("0")
        for raw in lineas:
            detalle_id = int(raw.get("factura_detalle_id") or 0)
            if detalle_id not in pendientes_por_id:
                raise NotaCreditoError("Línea no válida o sin saldo pendiente")
            monto = _money(raw.get("monto_credito"))
            maximo = pendientes_por_id[detalle_id]["monto_pendiente"]
            if monto <= 0:
                raise NotaCreditoError("El monto a acreditar debe ser mayor que cero")
            if monto > maximo:
                raise NotaCreditoError(
                    f"El monto excede lo pendiente en la línea ({maximo})"
                )
            pendiente = pendientes_por_id[detalle_id]
            seleccion.append(
                {
                    "factura_detalle_id": detalle_id,
                    "descripcion": pendiente["descripcion"],
                    "cantidad": pendiente.get("cantidad") or 1,
                    "precio_unitario": pendiente.get("precio_unitario") or 0,
                    "monto_credito": monto,
                }
            )
            total_nc += monto
        total_nc = total_nc.quantize(_CENTS, rounding=ROUND_HALF_UP)

    if total_nc <= 0:
        raise NotaCreditoError("El total de la nota de crédito debe ser mayor que cero")
    if total_nc > saldo:
        raise NotaCreditoError(
            f"El total ({total_nc}) supera el saldo creditable ({saldo})"
        )

    factura = execute_query(
        "SELECT subtotal, itbis, total FROM facturas WHERE id=%s AND tenant_id=%s",
        (factura_id, tenant_id),
    )
    factura_total = _money(factura.get("total"))
    factura_itbis = _money(factura.get("itbis"))
    itbis_ratio = (
        (factura_itbis / factura_total) if factura_total > 0 else Decimal("0")
    )
    itbis_nc = (total_nc * itbis_ratio).quantize(_CENTS, rounding=ROUND_HALF_UP)
    subtotal_nc = (total_nc - itbis_nc).quantize(_CENTS, rounding=ROUND_HALF_UP)

    ecf = execute_query(
        """
        SELECT estado, e_ncf FROM facturas_ecf
        WHERE factura_id=%s AND tenant_id=%s
        LIMIT 1
        """,
        (factura_id, tenant_id),
    )
    estado_ecf = None
    if ecf and (ecf.get("estado") or "") == "ACEPTADO":
        estado_ecf = "PENDIENTE_E34"

    codigo = _generar_codigo(tenant_id, factura_id)
    nota_id = execute_update(
        """
        INSERT INTO notas_credito (
            tenant_id, factura_id, codigo, tipo, motivo,
            subtotal, itbis, total, estado, estado_ecf, created_by
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'confirmada', %s, %s)
        """,
        (
            tenant_id,
            factura_id,
            codigo,
            tipo,
            motivo,
            str(subtotal_nc),
            str(itbis_nc),
            str(total_nc),
            estado_ecf,
            usuario_id,
        ),
    )
    for linea in seleccion:
        execute_update(
            """
            INSERT INTO nota_credito_detalles (
                tenant_id, nota_credito_id, factura_detalle_id,
                descripcion, cantidad, precio_unitario, monto_credito
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                tenant_id,
                nota_id,
                linea["factura_detalle_id"],
                linea["descripcion"],
                linea["cantidad"],
                linea["precio_unitario"],
                str(linea["monto_credito"]),
            ),
        )
    return int(nota_id)


def buscar_facturas_para_nota_credito(
    tenant_id: int, term: str, *, limit: int = 25
) -> list[dict]:
    """Busca facturas por número interno, NCF o ID."""
    q = (term or "").strip()
    if not q:
        return []

    params: list = [tenant_id]
    where = "f.tenant_id=%s AND f.estado != 'Anulada'"
    if q.isdigit() and len(q) <= 9:
        where += " AND (f.id=%s OR f.numero_factura LIKE %s OR f.ncf LIKE %s)"
        pattern = f"%{q}%"
        params.extend([int(q), pattern, pattern])
    else:
        pattern = f"%{q}%"
        where += " AND (f.numero_factura LIKE %s OR f.ncf LIKE %s)"
        params.extend([pattern, pattern])

    rows = (
        execute_query(
            f"""
            SELECT f.id, f.numero_factura, f.ncf, f.fecha_emision,
                   f.nombre_ars, f.total, f.estado
            FROM facturas f
            WHERE {where}
            ORDER BY f.fecha_emision DESC, f.id DESC
            LIMIT {int(limit)}
            """,
            tuple(params),
            fetch="all",
        )
        or []
    )
    out: list[dict] = []
    for row in rows:
        ok, _ = puede_emitir_nota_credito(tenant_id, row["id"])
        if not ok:
            continue
        row["saldo_creditable"] = saldo_creditable_factura(tenant_id, row["id"])
        out.append(row)
    return out


def listar_notas_credito_recientes(
    tenant_id: int, *, limit: int = 15
) -> list[dict]:
    return (
        execute_query(
            """
            SELECT nc.id, nc.codigo, nc.tipo, nc.total, nc.created_at,
                   nc.factura_id, f.numero_factura, f.ncf
            FROM notas_credito nc
            INNER JOIN facturas f
              ON f.id = nc.factura_id AND f.tenant_id = nc.tenant_id
            WHERE nc.tenant_id=%s AND nc.estado='confirmada'
            ORDER BY nc.id DESC
            LIMIT %s
            """,
            (tenant_id, int(limit)),
            fetch="all",
        )
        or []
    )


def cargar_nota_credito(tenant_id: int, nota_id: int) -> dict | None:
    nota = execute_query(
        """
        SELECT nc.*, f.numero_factura, f.ncf, f.fecha_emision, f.nombre_ars
        FROM notas_credito nc
        INNER JOIN facturas f ON f.id = nc.factura_id AND f.tenant_id = nc.tenant_id
        WHERE nc.id=%s AND nc.tenant_id=%s
        """,
        (nota_id, tenant_id),
    )
    if not nota:
        return None
    nota["detalles"] = (
        execute_query(
            """
            SELECT * FROM nota_credito_detalles
            WHERE nota_credito_id=%s AND tenant_id=%s
            ORDER BY id
            """,
            (nota_id, tenant_id),
            fetch="all",
        )
        or []
    )
    return nota