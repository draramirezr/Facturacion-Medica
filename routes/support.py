"""Dependencias compartidas por las rutas extra?das."""

import logging
import re
from datetime import datetime

from flask import request, url_for

from core.database import execute_query

logger = logging.getLogger(__name__)

ESPECIALIDADES_MEDICAS = (
    'Medicina General', 'Medicina Interna', 'Pediatría',
    'Ginecología y Obstetricia', 'Cardiología', 'Dermatología',
    'Medicina Familiar', 'Ortopedia y Traumatología', 'Oftalmología',
    'Otorrinolaringología', 'Urología', 'Gastroenterología',
    'Endocrinología', 'Neurología', 'Psiquiatría', 'Neumología',
    'Cirugía General', 'Nefrología', 'Oncología', 'Infectología',
    'Radiología',
)

def sanitize_input(text, max_length=500, allow_html=False):
    if not text:
        return ''
    text = str(text).strip()
    if not allow_html:
        text = re.sub(r'<[^>]*>', '', text)
        text = text.replace('javascript:', '').replace('onerror=', '')
        text = text.replace('onclick=', '').replace('onload=', '')
    if max_length and len(text) > max_length:
        text = text[:max_length]
        logger.warning('Texto truncado por exceder longitud m?xima: %s', max_length)
    return text

def validate_int(value, min_value=None, max_value=None, default=None):
    try:
        value = int(value)
        if min_value is not None and value < min_value:
            return default
        if max_value is not None and value > max_value:
            return default
        return value
    except (ValueError, TypeError):
        return default

def validate_email(email):
    return re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email) is not None

def validate_digits(value, length):
    return bool(re.fullmatch(rf'\d{{{length}}}', value or ''))

def calcular_edad_clinica(fecha_nacimiento, fecha_referencia=None):
    if not fecha_nacimiento:
        return None
    if isinstance(fecha_nacimiento, str):
        fecha_nacimiento = datetime.strptime(
            fecha_nacimiento, '%Y-%m-%d'
        ).date()
    fecha_referencia = fecha_referencia or datetime.now().date()
    return fecha_referencia.year - fecha_nacimiento.year - (
        (fecha_referencia.month, fecha_referencia.day)
        < (fecha_nacimiento.month, fecha_nacimiento.day)
    )

def get_especialidad_form(form):
    especialidad = sanitize_input(form.get('especialidad', ''), 100)
    if especialidad == '__otra__':
        return sanitize_input(form.get('especialidad_otra', ''), 100)
    return especialidad

def validar_password_segura(password):
    errores = []
    if len(password) < 8: errores.append('M?nimo 8 caracteres')
    if not re.search(r'[A-Z]', password): errores.append('Al menos una may?scula')
    if not re.search(r'[a-z]', password): errores.append('Al menos una min?scula')
    if not re.search(r'\d', password): errores.append('Al menos un n?mero')
    return errores

def execute_paginated_query(base_query, params, order_by, default_per_page=25):
    page = validate_int(request.args.get('page', 1), min_value=1, default=1)
    per_page = validate_int(request.args.get('per_page', default_per_page), min_value=10, max_value=100, default=default_per_page)
    params = tuple(params or ())
    total_row = execute_query(f'SELECT COUNT(*) AS total FROM ({base_query}) AS filtered_rows', params) or {'total': 0}
    total = int(total_row.get('total', 0) or 0)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, total_pages)
    offset = (page - 1) * per_page
    rows = execute_query(f'{base_query} ORDER BY {order_by} LIMIT %s OFFSET %s', params + (per_page, offset), fetch='all') or []
    def page_url(target):
        query_args = request.args.to_dict(flat=True)
        query_args.update(page=target, per_page=per_page)
        return url_for(request.endpoint, **query_args)
    return rows, {'page': page, 'per_page': per_page, 'total': total, 'total_pages': total_pages, 'first_item': offset + 1 if total else 0, 'last_item': min(offset + per_page, total), 'previous_url': page_url(page - 1) if page > 1 else None, 'next_url': page_url(page + 1) if page < total_pages else None}


def id_consulta_retorno():
    """Consulta a la que hay que volver tras emitir receta o licencia."""
    return validate_int(
        request.form.get('volver_consulta_id') or request.args.get('volver_consulta_id'),
        min_value=1,
        default=None,
    )


def url_historia_clinica(consulta_id, pestana=None):
    url = url_for('facturacion_historia_clinica_ver', consulta_id=consulta_id)
    if pestana:
        return f'{url}#{pestana}'
    return url

