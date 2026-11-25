"""Validaciones y utilidades compartidas de facturación."""
import re
from datetime import timedelta
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from flask import redirect, render_template, url_for
from flask_login import current_user, login_required
from auth import user_has_permission
from auth.helpers import usuario_es_dueno_software
from core.clock import fecha_clinica


# Validaciones de carga de consultas (alineadas con Shirley)
FECHA_MIN_CONSULTA_DIAS = 45


_RE_NSS = re.compile(r'^[0-9\-]+$')


_RE_AUTORIZACION = re.compile(r'^[A-Z0-9\-]+$')


_RE_NOMBRE = re.compile(r'^[A-ZÁÉÍÓÚÜÑ\s\.\-]+$')


_RE_TEXTO_GENERAL = re.compile(r'^[A-ZÁÉÍÓÚÜÑ\s\.\-/]+$')


def _upper_clean_spaces(value: str) -> str:
    value = (value or '').strip().upper()
    return re.sub(r'\s+', ' ', value).strip()


def _validate_or_raise(
    value: str,
    pattern: re.Pattern,
    field_name: str,
    idx=None,
    max_len=None,
    required: bool = True,
) -> str:
    """Valida y retorna valor limpio en mayúsculas. Lanza ValueError si inválido."""
    cleaned = _upper_clean_spaces(value)
    prefix = f'Línea {idx}: ' if idx else ''
    if max_len is not None and len(cleaned) > max_len:
        raise ValueError(f'{prefix}{field_name} supera el máximo de {max_len} caracteres')
    if not cleaned:
        if not required:
            return ''
        raise ValueError(f'{prefix}{field_name} es obligatorio')
    if not pattern.fullmatch(cleaned):
        raise ValueError(f'{prefix}{field_name} contiene caracteres no permitidos')
    return cleaned


def fecha_minima_consulta_rd(hoy_rd=None):
    """Fecha mínima permitida para consulta: hoy (RD) menos 45 días."""
    if hoy_rd is None:
        hoy_rd = fecha_clinica()
    return hoy_rd - timedelta(days=FECHA_MIN_CONSULTA_DIAS)


def _extraer_autorizacion_servicios(servicios_realizados) -> str:
    texto = (servicios_realizados or '').strip()
    if ' - Autorización:' in texto:
        return texto.split(' - Autorización:', 1)[1].strip().upper()
    return ''


@login_required
def facturacion_menu():
    """Menú principal de facturación"""
    if usuario_es_dueno_software(current_user):
        return redirect(url_for('admin_empresas'))
    roles_rbac = set(getattr(current_user, 'rbac_roles', ()))
    es_administrador = (
        'Administrador' in roles_rbac
        or getattr(current_user, 'perfil', None) == 'Administrador'
    )
    if (
        getattr(current_user, 'medico_id', None)
        and user_has_permission(current_user, 'turnos.cola_propia')
        and not es_administrador
    ):
        return redirect(url_for('turnos_mi_cola'))
    return render_template('facturacion/menu.html')


CENTAVO = Decimal('0.01')


def _monto(valor):
    """Convierte a Decimal con 2 decimales. Lanza ValueError si no es un número finito."""
    try:
        numero = Decimal(str(valor if valor not in (None, '') else '0').replace(',', ''))
    except (InvalidOperation, TypeError, ValueError):
        raise ValueError(f'Monto inválido: {valor!r}') from None
    if not numero.is_finite():
        raise ValueError(f'Monto inválido: {valor!r}')
    return numero.quantize(CENTAVO, rounding=ROUND_HALF_UP)
