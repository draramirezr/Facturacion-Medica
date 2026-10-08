"""Selector de centro de trabajo para médicos multi-centro."""

from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from auth.helpers import usuario_es_medico_operativo
from services.centro_contexto import (
    centros_del_medico,
    debe_elegir_centro,
    preparar_contexto_al_login,
    requiere_selector_centro,
    set_contexto_centro,
)

_ENDPOINTS_LIBRES = frozenset({
    'elegir_centro_trabajo',
    'cambiar_centro_trabajo',
    'logout',
    'static',
    'index',
    'login',
})


@login_required
def elegir_centro_trabajo():
    """Pregunta al médico: ver todos o trabajar en un centro."""
    preparar_contexto_al_login(current_user)
    if not requiere_selector_centro(current_user):
        return redirect(url_for(_destino_despues_centro(current_user)))

    centros = centros_del_medico(
        current_user.tenant_id, current_user.medico_id
    )
    if request.method == 'POST':
        eleccion = (request.form.get('centro_id') or '').strip()
        if eleccion == 'todos':
            set_contexto_centro(None)
            flash('Viendo todos tus pacientes', 'success')
            return redirect(url_for(_destino_despues_centro(current_user)))
        try:
            centro_id = int(eleccion)
        except (TypeError, ValueError):
            flash('Selecciona un centro válido', 'error')
            return redirect(url_for('elegir_centro_trabajo'))
        if not any(int(c['id']) == centro_id for c in centros):
            flash('Ese centro no está vinculado a tu usuario', 'error')
            return redirect(url_for('elegir_centro_trabajo'))
        set_contexto_centro(centro_id)
        nombre = next(
            (c['nombre'] for c in centros if int(c['id']) == centro_id),
            'el centro',
        )
        flash(f'Trabajando en {nombre}', 'success')
        return redirect(url_for(_destino_despues_centro(current_user)))

    return render_template(
        'facturacion/elegir_centro_trabajo.html',
        centros=centros,
        cambio=request.args.get('cambio') == '1',
    )


@login_required
def cambiar_centro_trabajo():
    """Reabrir el selector sin cerrar sesión."""
    if not requiere_selector_centro(current_user):
        flash('No tienes varios centros asignados', 'error')
        return redirect(url_for(_destino_despues_centro(current_user)))
    return redirect(url_for('elegir_centro_trabajo', cambio=1))


def _destino_despues_centro(user):
    if usuario_es_medico_operativo(user):
        return 'turnos_mi_cola'
    return 'facturacion_menu'


def register_centro_contexto_routes(app):
    @app.before_request
    def _exigir_centro_trabajo():
        if not getattr(current_user, 'is_authenticated', False):
            return None
        endpoint = request.endpoint or ''
        if endpoint in _ENDPOINTS_LIBRES or endpoint.startswith('static'):
            return None
        if debe_elegir_centro(current_user):
            return redirect(url_for('elegir_centro_trabajo'))
        return None

    app.add_url_rule(
        '/facturacion/centro-trabajo',
        endpoint='elegir_centro_trabajo',
        view_func=elegir_centro_trabajo,
        methods=['GET', 'POST'],
    )
    app.add_url_rule(
        '/facturacion/centro-trabajo/cambiar',
        endpoint='cambiar_centro_trabajo',
        view_func=cambiar_centro_trabajo,
        methods=['GET'],
    )
