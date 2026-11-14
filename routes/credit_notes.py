"""Rutas de notas de crédito (parcial / total)."""

from __future__ import annotations

import logging

from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from auth import permission_required
from core.database import database_transaction, execute_query
from core.security import sanitize_input
from core.tenant import get_current_tenant_id, validate_tenant_access
from services.notas_credito import (
    NotaCreditoError,
    cargar_nota_credito,
    crear_nota_credito,
    lineas_credito_pendientes,
    listar_notas_factura,
    puede_emitir_nota_credito,
    saldo_creditable_factura,
)

logger = logging.getLogger(__name__)


@login_required
@permission_required("facturacion.nota_credito")
def facturacion_nota_credito_nueva(factura_id):
    tenant_id = get_current_tenant_id()
    if not validate_tenant_access("facturas", factura_id):
        flash("No tienes acceso a esta factura", "error")
        return redirect(url_for("facturacion_historico"))

    ok, motivo = puede_emitir_nota_credito(tenant_id, factura_id)
    if not ok:
        flash(motivo, "error")
        return redirect(url_for("facturacion_ver_factura", factura_id=factura_id))

    tipo = (request.args.get("tipo") or request.form.get("tipo") or "parcial").lower()
    if tipo not in {"parcial", "total"}:
        tipo = "parcial"

    factura = execute_query(
        """
        SELECT f.*, fe.estado AS ecf_estado, fe.e_ncf
        FROM facturas f
        LEFT JOIN facturas_ecf fe
          ON fe.factura_id = f.id AND fe.tenant_id = f.tenant_id
        WHERE f.id=%s AND f.tenant_id=%s
        """,
        (factura_id, tenant_id),
    )
    if not factura:
        flash("Factura no encontrada", "error")
        return redirect(url_for("facturacion_historico"))

    lineas = lineas_credito_pendientes(tenant_id, factura_id)
    saldo = saldo_creditable_factura(tenant_id, factura_id)

    if request.method == "POST":
        motivo_nc = sanitize_input(request.form.get("motivo", ""), 2000)
        tipo_post = (request.form.get("tipo") or tipo).lower()
        lineas_post = []
        if tipo_post == "parcial":
            for linea in lineas:
                detalle_id = str(linea["id"])
                if request.form.get(f"incluir_{detalle_id}") != "1":
                    continue
                monto = request.form.get(f"monto_{detalle_id}", "").strip()
                lineas_post.append(
                    {
                        "factura_detalle_id": linea["id"],
                        "monto_credito": monto,
                    }
                )
        try:
            with database_transaction():
                nota_id = crear_nota_credito(
                    tenant_id=tenant_id,
                    factura_id=factura_id,
                    tipo=tipo_post,
                    motivo=motivo_nc,
                    usuario_id=current_user.id,
                    lineas=lineas_post if tipo_post == "parcial" else None,
                )
        except NotaCreditoError as error:
            flash(str(error), "error")
            return redirect(
                url_for(
                    "facturacion_nota_credito_nueva",
                    factura_id=factura_id,
                    tipo=tipo_post,
                )
            )
        except Exception:
            logger.exception("Error al crear NC factura_id=%s", factura_id)
            flash("No se pudo registrar la nota de crédito", "error")
            return redirect(url_for("facturacion_ver_factura", factura_id=factura_id))

        nota = cargar_nota_credito(tenant_id, nota_id)
        if nota and nota.get("estado_ecf") == "PENDIENTE_E34":
            flash(
                "Nota de crédito registrada. La emisión electrónica E34 "
                "a DGII se habilitará en la siguiente fase.",
                "warning",
            )
        else:
            flash("Nota de crédito registrada correctamente.", "success")
        return redirect(url_for("facturacion_nota_credito_ver", nota_id=nota_id))

    return render_template(
        "facturacion/nota_credito_form.html",
        factura=factura,
        lineas=lineas,
        saldo=saldo,
        tipo=tipo,
        titulo="Nota de crédito total" if tipo == "total" else "Nota de crédito parcial",
    )


@login_required
@permission_required("facturacion.ver")
def facturacion_nota_credito_ver(nota_id):
    tenant_id = get_current_tenant_id()
    nota = cargar_nota_credito(tenant_id, nota_id)
    if not nota:
        flash("Nota de crédito no encontrada", "error")
        return redirect(url_for("facturacion_historico"))
    if not validate_tenant_access("facturas", nota["factura_id"]):
        flash("No tienes acceso a este documento", "error")
        return redirect(url_for("facturacion_historico"))
    return render_template("facturacion/nota_credito_ver.html", nota=nota)


def register_credit_note_routes(app):
    app.add_url_rule(
        "/facturacion/facturas/<int:factura_id>/nota-credito/nueva",
        endpoint="facturacion_nota_credito_nueva",
        view_func=facturacion_nota_credito_nueva,
        methods=["GET", "POST"],
    )
    app.add_url_rule(
        "/facturacion/notas-credito/<int:nota_id>",
        endpoint="facturacion_nota_credito_ver",
        view_func=facturacion_nota_credito_ver,
    )