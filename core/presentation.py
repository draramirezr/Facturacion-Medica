"""Filtros y contexto visual compartidos por las plantillas."""

import os
import re
from datetime import timedelta
from urllib.parse import urlparse

from flask_login import current_user

from auth.helpers import (
    user_has_permission,
    usuario_es_administrador,
    usuario_es_dueno_software,
    usuario_es_medico_operativo,
)

SOPORTE_EMAIL_PREDETERMINADO = 'soporte@clinicrd.com'
SOPORTE_TELEFONO_PREDETERMINADO = '8098446360'

PRODUCTO = {
    'nombre': 'ClinicRD',
    'eslogan': 'Gestión Médica',
}


FUENTES_UI = {
    'arsflow': {
        'nombre': 'ClinicRD',
        'descripcion': 'Montserrat + Be Vietnam Pro',
        'muestra': 'Claridad clínica y moderna',
    },
    'inter': {
        'nombre': 'Inter',
        'descripcion': 'Precisa y muy legible',
        'muestra': 'Información médica ordenada',
    },
    'manrope': {
        'nombre': 'Manrope',
        'descripcion': 'Amable y contemporánea',
        'muestra': 'Gestión sencilla y cercana',
    },
    'jakarta': {
        'nombre': 'Plus Jakarta Sans',
        'descripcion': 'Elegante y profesional',
        'muestra': 'Una experiencia más refinada',
    },
}

TEMAS = {
    'cyan': {
        'primary': '#06B6D4', 'primary_dark': '#0891B2',
        'primary_light': '#22D3EE', 'background': '#F0FDFA',
        'gradient_start': '#06B6D4', 'gradient_end': '#0891B2',
        'nombre': 'Verde Azulado', 'categoria': 'Fresco',
    },
    'ocean': {
        'primary': '#0EA5E9', 'primary_dark': '#0284C7',
        'primary_light': '#38BDF8', 'background': '#F0F9FF',
        'gradient_start': '#0EA5E9', 'gradient_end': '#0284C7',
        'nombre': 'Azul Océano', 'categoria': 'Fresco',
    },
    'emerald': {
        'primary': '#10B981', 'primary_dark': '#059669',
        'primary_light': '#34D399', 'background': '#F0FDF4',
        'gradient_start': '#10B981', 'gradient_end': '#059669',
        'nombre': 'Verde Esmeralda', 'categoria': 'Fresco',
    },
    'teal': {
        'primary': '#14B8A6', 'primary_dark': '#0D9488',
        'primary_light': '#2DD4BF', 'background': '#F0FDFA',
        'gradient_start': '#14B8A6', 'gradient_end': '#0D9488',
        'nombre': 'Verde Azulado Oscuro', 'categoria': 'Fresco',
    },
    'aqua': {
        'primary': '#22B8CF', 'primary_dark': '#1098AD',
        'primary_light': '#66D9E8', 'background': '#F0FCFF',
        'gradient_start': '#22B8CF', 'gradient_end': '#1098AD',
        'nombre': 'Brisa Aqua', 'categoria': 'Fresco',
    },
    'mint': {
        'primary': '#2CB67D', 'primary_dark': '#218C61',
        'primary_light': '#65D6A5', 'background': '#F1FCF7',
        'gradient_start': '#2CB67D', 'gradient_end': '#218C61',
        'nombre': 'Menta Clínica', 'categoria': 'Fresco',
    },
    'lagoon': {
        'primary': '#0F9D8A', 'primary_dark': '#0B7568',
        'primary_light': '#4EC7B5', 'background': '#F0FBF9',
        'gradient_start': '#0F9D8A', 'gradient_end': '#0B7568',
        'nombre': 'Laguna Serena', 'categoria': 'Fresco',
    },
    'sky': {
        'primary': '#3B9AE1', 'primary_dark': '#2778B8',
        'primary_light': '#73BDF0', 'background': '#F2F9FE',
        'gradient_start': '#3B9AE1', 'gradient_end': '#2778B8',
        'nombre': 'Azul Cielo', 'categoria': 'Fresco',
    },
    'sage': {
        'primary': '#56A68B', 'primary_dark': '#3E7E68',
        'primary_light': '#86C7B1', 'background': '#F4FAF7',
        'gradient_start': '#56A68B', 'gradient_end': '#3E7E68',
        'nombre': 'Verde Salvia', 'categoria': 'Fresco',
    },
}


def formato_moneda(valor):
    try:
        return '{:,.2f}'.format(float(valor))
    except (ValueError, TypeError):
        return '0.00'


def hora_input(valor):
    if valor is None:
        return ''
    if isinstance(valor, timedelta):
        segundos = int(valor.total_seconds())
        return f'{(segundos // 3600) % 24:02d}:{(segundos % 3600) // 60:02d}'
    if hasattr(valor, 'strftime'):
        return valor.strftime('%H:%M')
    partes = str(valor).split(':')
    if len(partes) >= 2:
        return f'{partes[0].zfill(2)}:{partes[1].zfill(2)}'
    return str(valor)


def _telefono_soporte():
    crudo = os.getenv('SOPORTE_TELEFONO', '').strip() or SOPORTE_TELEFONO_PREDETERMINADO
    digitos = re.sub(r'\D', '', crudo)
    if len(digitos) == 11 and digitos.startswith('1'):
        digitos = digitos[1:]
    if len(digitos) != 10:
        digitos = SOPORTE_TELEFONO_PREDETERMINADO
    visible = f'{digitos[:3]}-{digitos[3:6]}-{digitos[6:]}'
    return {
        'telefono': visible,
        'telefono_digits': digitos,
        'whatsapp': f'1{digitos}',
    }


def obtener_soporte():
    """Datos del centro de ayuda y contacto público."""
    manual_url = os.getenv('MANUAL_URL', '').strip()
    if urlparse(manual_url).scheme.lower() not in ('http', 'https'):
        manual_url = ''
    email = (
        os.getenv('SOPORTE_EMAIL', '').strip() or SOPORTE_EMAIL_PREDETERMINADO
    )
    return {'manual_url': manual_url, 'email': email, **_telefono_soporte()}


def datos_seo():
    """Metadatos públicos de ClinicRD para buscadores y redes."""
    from core.config import url_publica_base

    base = (url_publica_base() or 'https://www.clinicrd.com').rstrip('/')
    soporte = obtener_soporte()
    titulo = (
        'ClinicRD | Software médico y facturación e-CF en República Dominicana'
    )
    descripcion = (
        'Software para consultorios y centros médicos en República Dominicana: '
        'pacientes, historia clínica, recetas, licencias, agenda con reagendar, '
        'turnos, ARS, backup y facturación electrónica e-CF.'
    )
    imagen = f'{base}/static/img/logo.png'
    return {
        'base_url': base,
        'canonical': f'{base}/',
        'titulo': titulo,
        'descripcion': descripcion,
        'keywords': (
            'software médico República Dominicana, facturación electrónica e-CF, '
            'software para consultorios y centros médicos, historia clínica, agenda, ARS, ClinicRD'
        ),
        'imagen': imagen,
        'locale': 'es_DO',
        'telefono': soporte['telefono'],
        'telefono_e164': f'+1{soporte["telefono_digits"]}',
        'email': soporte['email'],
        'json_ld': {
            '@context': 'https://schema.org',
            '@graph': [
                {
                    '@type': 'Organization',
                    '@id': f'{base}/#organizacion',
                    'name': 'ClinicRD',
                    'url': f'{base}/',
                    'logo': imagen,
                    'email': soporte['email'],
                    'telephone': f'+1{soporte["telefono_digits"]}',
                    'areaServed': {
                        '@type': 'Country',
                        'name': 'República Dominicana',
                    },
                },
                {
                    '@type': 'SoftwareApplication',
                    'name': 'ClinicRD',
                    'applicationCategory': 'HealthApplication',
                    'operatingSystem': 'Web',
                    'url': f'{base}/',
                    'description': descripcion,
                    'inLanguage': 'es-DO',
                    'offers': {
                        '@type': 'AggregateOffer',
                        'lowPrice': '20',
                        'highPrice': '100',
                        'priceCurrency': 'USD',
                    },
                    'publisher': {'@id': f'{base}/#organizacion'},
                },
                {
                    '@type': 'WebSite',
                    '@id': f'{base}/#sitio',
                    'name': 'ClinicRD',
                    'url': f'{base}/',
                    'inLanguage': 'es-DO',
                    'publisher': {'@id': f'{base}/#organizacion'},
                },
            ],
        },
    }


def inject_theme():
    tema_actual = (
        (getattr(current_user, 'tema_color', None) or 'cyan')
        if current_user.is_authenticated else 'cyan'
    )
    if tema_actual not in TEMAS:
        tema_actual = 'cyan'
    fuente_actual = (
        getattr(current_user, 'fuente_ui', 'arsflow')
        if current_user.is_authenticated else 'arsflow'
    )
    if fuente_actual not in FUENTES_UI:
        fuente_actual = 'arsflow'
    empresa = {}
    if current_user.is_authenticated and hasattr(current_user, 'tenant_id'):
        from services.subscriptions import get_empresa_info
        try:
            empresa_db = get_empresa_info(current_user.tenant_id) or {}
        except Exception:
            empresa_db = {}
        empresa = {
            'tenant_id': current_user.tenant_id,
            'empresa_nombre': (
                empresa_db.get('nombre')
                or current_user.empresa_nombre
                or 'Sin empresa'
            ),
            'tipo_empresa': empresa_db.get('tipo_empresa') or '',
        }
    return {
        'tema': TEMAS[tema_actual],
        'tema_nombre': tema_actual,
        'temas_disponibles': TEMAS,
        'fuente_nombre': fuente_actual,
        'fuente': FUENTES_UI[fuente_actual],
        'fuentes_disponibles': FUENTES_UI,
        'empresa': empresa,
        'soporte': obtener_soporte(),
        'can': lambda codigo: (
            current_user.is_authenticated
            and user_has_permission(current_user, codigo)
        ),
        'es_administrador': (
            current_user.is_authenticated
            and usuario_es_administrador(current_user)
        ),
        'es_dueno_software': (
            current_user.is_authenticated
            and usuario_es_dueno_software(current_user)
        ),
        'es_medico_operativo': (
            current_user.is_authenticated
            and usuario_es_medico_operativo(current_user)
        ),
        'producto': PRODUCTO,
        'product_name': PRODUCTO['nombre'],
        'seo': datos_seo(),
    }


def inject_soporte():
    return {'soporte': obtener_soporte()}


def init_presentation(app):
    app.add_template_filter(formato_moneda, 'formato_moneda')
    app.add_template_filter(hora_input, 'hora_input')
    app.context_processor(inject_theme)
    app.context_processor(inject_soporte)
    app.jinja_env.globals['soporte'] = obtener_soporte()
