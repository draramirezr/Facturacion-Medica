"""Filtros y contexto visual compartidos por las plantillas."""

import os
import re
from datetime import timedelta
from urllib.parse import urlparse

from flask import has_request_context, request
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


FAQ_SEO = (
    {
        'pregunta': '¿Qué es ClinicRD?',
        'respuesta': (
            'ClinicRD es un software web para consultorios, médicos independientes '
            'y centros de salud en República Dominicana. Une pacientes, agenda, '
            'historia clínica, recetas, licencias médicas, turnos, ARS y '
            'facturación electrónica e-CF.'
        ),
    },
    {
        'pregunta': '¿ClinicRD emite facturas electrónicas e-CF de la DGII?',
        'respuesta': (
            'Sí. ClinicRD permite facturación electrónica e-CF para el consultorio, '
            'con certificado por empresa, NCF electrónicos y el flujo de emisión '
            'hacia los servicios oficiales de la DGII cuando la cuenta está configurada.'
        ),
    },
    {
        'pregunta': '¿Sirve para un médico solo o para una clínica?',
        'respuesta': (
            'Hay planes para un profesional independiente, para un consultorio con '
            'varios usuarios y para clínicas o centros médicos con más volumen, '
            'turnos, pantalla de espera e historia de emergencia.'
        ),
    },
    {
        'pregunta': '¿Hay prueba gratis?',
        'respuesta': (
            'Sí. Puedes crear una cuenta y usar ClinicRD 7 días sin compromiso. '
            'Después eliges el plan según el tamaño de tu operación.'
        ),
    },
    {
        'pregunta': '¿Por qué ClinicRD es la mejor opción para gestionar pacientes?',
        'respuesta': (
            'Porque el paciente vive en un solo expediente: datos, ARS, citas, '
            'consultas, recetas, licencias y facturas. Recepción, médico y '
            'administración trabajan el mismo registro, sin hojas sueltas ni '
            'programas desconectados.'
        ),
    },
    {
        'pregunta': '¿ClinicRD sirve para un centro médico o solo para un consultorio?',
        'respuesta': (
            'Sirve para el médico independiente, el consultorio con varios usuarios '
            'y el centro médico o clínica: turnos, pantalla de espera, varios '
            'médicos, historia de emergencia y facturación e-CF en el mismo sistema.'
        ),
    },
    {
        'pregunta': '¿Qué palabras cubre ClinicRD si busco software médico?',
        'respuesta': (
            'Gestión de pacientes, expediente clínico, historia clínica, agenda '
            'médica, turnos, recetas, licencias, ARS, reclamaciones, e-CF, '
            'consultorio, clínica y centro de salud en República Dominicana.'
        ),
    },
)

SEO_PAGINAS = {
    'inicio': {
        'path': '/',
        'titulo': (
            'ClinicRD | Software de gestión de pacientes, consultorios y centros médicos en RD'
        ),
        'descripcion': (
            'La plataforma completa para médicos, consultorios y centros de salud '
            'en República Dominicana: gestión de pacientes, historia clínica, agenda, '
            'turnos, recetas, licencias, ARS y facturación electrónica e-CF.'
        ),
        'keywords': (
            'software gestión de pacientes, software médico República Dominicana, '
            'software para consultorio, software centro médico, software clínica, '
            'expediente clínico, historia clínica, agenda médica, turnos, e-CF, '
            'ARS, recetas, licencias médicas, ClinicRD, Santo Domingo, Santiago'
        ),
        'prioridad': '1.0',
        'frecuencia': 'weekly',
    },
    'software-medico': {
        'path': '/software-medico',
        'h1': 'Software médico para consultorios en República Dominicana',
        'titulo': (
            'Software médico para consultorios en RD | ClinicRD'
        ),
        'descripcion': (
            'Gestiona pacientes, citas, turnos, historia clínica, recetas y el '
            'equipo del consultorio en una sola plataforma hecha para República Dominicana.'
        ),
        'keywords': (
            'software para consultorio médico, sistema clínico RD, gestión de pacientes, '
            'agenda médica República Dominicana, ClinicRD'
        ),
        'prioridad': '0.9',
        'frecuencia': 'monthly',
        'bloques': (
            (
                'Hecho para el consultorio dominicano',
                'ClinicRD concentra recepción, médico y administración: el paciente '
                'no se duplica entre agenda, historia y factura. Cada empresa ve '
                'solo sus datos.',
            ),
            (
                'Del turno a la consulta',
                'Recepción registra la llegada, el médico ve su cola, anota signos '
                'vitales y deja receta o licencia vinculada al expediente. La agenda '
                'permite reagendar la misma cita si el paciente no pudo asistir.',
            ),
            (
                'Roles y respaldo',
                'Defines quién ve facturación, quién ve historias y el administrador '
                'puede descargar un Excel por módulo desde Configuración.',
            ),
        ),
    },
    'facturacion-electronica-ecf': {
        'path': '/facturacion-electronica-ecf',
        'h1': 'Facturación electrónica e-CF para consultorios y clínicas',
        'titulo': (
            'Facturación electrónica e-CF DGII para médicos | ClinicRD'
        ),
        'descripcion': (
            'Emite facturas electrónicas e-CF desde el consultorio: certificado por '
            'empresa, NCF, ARS, reclamaciones y el flujo hacia los servicios de la DGII.'
        ),
        'keywords': (
            'facturación electrónica e-CF, e-CF DGII, software factura electrónica '
            'médicos RD, NCF electrónico, ClinicRD'
        ),
        'prioridad': '0.9',
        'frecuencia': 'monthly',
        'bloques': (
            (
                'e-CF en el mismo sistema clínico',
                'No hace falta un programa aparte para facturar: la atención del '
                'paciente y la factura conviven en ClinicRD, con ARS, reclamaciones '
                'y pagos.',
            ),
            (
                'Certificado de la empresa',
                'Cada consultorio carga su certificado PKCS#12. La contraseña no se '
                'guarda en la base de datos. El RNC de la empresa debe coincidir '
                'con el certificado.',
            ),
            (
                'Listo para el entorno DGII',
                'La integración usa los servicios oficiales de autenticación y '
                'recepción e-CF cuando la cuenta y el servidor están configurados.',
            ),
        ),
    },
    'historia-clinica': {
        'path': '/historia-clinica',
        'h1': 'Historia clínica digital, recetas y licencias médicas',
        'titulo': (
            'Historia clínica digital, recetas y licencias | ClinicRD'
        ),
        'descripcion': (
            'Expediente por paciente, consultas por especialidad, recetas y '
            'licencias médicas trazables, con papelería del consultorio al imprimir.'
        ),
        'keywords': (
            'historia clínica digital RD, receta médica electrónica, licencia médica, '
            'expediente clínico, ClinicRD'
        ),
        'prioridad': '0.8',
        'frecuencia': 'monthly',
        'bloques': (
            (
                'Un expediente, no mil papeles',
                'En Paciente 360 ves datos, aseguradora, consultas, citas, recetas y '
                'licencias. La consulta guarda signos vitales y plantillas por especialidad.',
            ),
            (
                'Documentos con rastro',
                'Recetas y licencias se pueden anular sin borrar el historial. Al '
                'imprimir, el consultorio puede usar su logo y membrete.',
            ),
            (
                'Emergencias y enfermería',
                'Los centros médicos pueden registrar historia de emergencia y hojas '
                'de enfermería en el mismo entorno.',
            ),
        ),
    },
    'preguntas-frecuentes': {
        'path': '/preguntas-frecuentes',
        'h1': 'Preguntas frecuentes sobre ClinicRD',
        'titulo': 'Preguntas frecuentes | ClinicRD software médico RD',
        'descripcion': (
            'Respuestas sobre ClinicRD: e-CF, planes, prueba de 7 días, consultorios '
            'y clínicas en República Dominicana.'
        ),
        'keywords': (
            'ClinicRD preguntas, software médico RD FAQ, prueba gratis consultorio, e-CF'
        ),
        'prioridad': '0.8',
        'frecuencia': 'monthly',
        'bloques': (),
    },
    'gestion-de-pacientes': {
        'path': '/gestion-de-pacientes',
        'h1': 'Software de gestión de pacientes para médicos y centros de salud',
        'titulo': (
            'Gestión de pacientes: expediente 360, citas y ARS | ClinicRD'
        ),
        'descripcion': (
            'Administra el censo de pacientes, aseguradora, citas, consultas y '
            'seguimiento en un solo sistema. ClinicRD es el software de gestión '
            'de pacientes para consultorios y centros médicos en RD.'
        ),
        'keywords': (
            'gestión de pacientes, software pacientes médicos, censo de pacientes, '
            'expediente del paciente, Paciente 360, ClinicRD'
        ),
        'prioridad': '0.9',
        'frecuencia': 'monthly',
        'bloques': (
            (
                'El paciente no se pierde entre módulos',
                'Altas, cédula, ARS, teléfono, citas y documentos clínicos quedan '
                'en el mismo registro. Recepción y médico ven la misma ficha.',
            ),
            (
                'Vista 360 del paciente',
                'Consultas, recetas, licencias, citas reagendables y pendientes de '
                'factura se consultan sin salir del expediente.',
            ),
            (
                'Hecho para el volumen real',
                'Pacientes ilimitados en los planes. Buscas, filtras y das seguimiento '
                'sin Excel paralelo ni carpetas físicas como sistema principal.',
            ),
        ),
    },
    'software-consultorio': {
        'path': '/software-consultorio',
        'h1': 'Software para consultorio médico: todo el día clínico en un solo lugar',
        'titulo': (
            'Software para consultorio médico en República Dominicana | ClinicRD'
        ),
        'descripcion': (
            'El software del consultorio: recepción, agenda, historia, recetas, '
            'roles y facturación e-CF. ClinicRD reemplaza herramientas sueltas '
            'con una operación conectada.'
        ),
        'keywords': (
            'software para consultorio, sistema para consultorio médico, '
            'programa consultorio RD, ClinicRD consultorio'
        ),
        'prioridad': '0.9',
        'frecuencia': 'monthly',
        'bloques': (
            (
                'El consultorio completo, no un módulo aislado',
                'Agenda, turno, consulta y factura usan el mismo paciente. El '
                'administrador controla usuarios, papelería y backup en Excel.',
            ),
            (
                'Para uno o varios profesionales',
                'Plan independiente o consultorio con hasta tres usuarios, con '
                'permisos por rol: recepción no ve lo que no le toca.',
            ),
            (
                'Listo para crecer a clínica',
                'Si el consultorio pasa a centro médico, el mismo ClinicRD suma '
                'turnos, pantalla de espera y más usuarios.',
            ),
        ),
    },
    'software-centro-medico': {
        'path': '/software-centro-medico',
        'h1': 'Software para centro médico y clínica: médicos, turnos y emergencia',
        'titulo': (
            'Software para centro médico y clínica en RD | ClinicRD'
        ),
        'descripcion': (
            'Sistema para centros de salud y clínicas: varios médicos, colas, '
            'pantalla de espera, historia de emergencia, enfermería y facturación '
            'e-CF. ClinicRD es la plataforma del centro, no un Excel por área.'
        ),
        'keywords': (
            'software centro médico, software clínica, sistema hospitalario ligero, '
            'turnos centro de salud, ClinicRD clínica República Dominicana'
        ),
        'prioridad': '0.9',
        'frecuencia': 'monthly',
        'bloques': (
            (
                'Varios médicos, una sola operación',
                'Cada médico tiene su cola. Recepción dirige al paciente. La '
                'pantalla de espera llama el turno sin exponer datos sensibles.',
            ),
            (
                'Emergencia y enfermería',
                'Historia de emergencia y hojas de enfermería quedan en el mismo '
                'entorno que el resto del centro.',
            ),
            (
                'Administración del centro',
                'Roles, papelería institucional, ARS, reclamaciones y e-CF para '
                'que facturación no viva en otro programa.',
            ),
        ),
    },
    'agenda-medica': {
        'path': '/agenda-medica',
        'h1': 'Agenda médica con citas, confirmación y reagendar',
        'titulo': (
            'Agenda médica y citas para consultorios | ClinicRD'
        ),
        'descripcion': (
            'Agenda del consultorio: programa, confirma y reagenda la misma cita '
            'sin duplicar al paciente. ClinicRD conecta la agenda con el expediente '
            'y la cola del médico.'
        ),
        'keywords': (
            'agenda médica, software citas médicas, reagendar cita, calendario '
            'consultorio, ClinicRD agenda'
        ),
        'prioridad': '0.8',
        'frecuencia': 'monthly',
        'bloques': (
            (
                'La cita es del paciente, no un recuadro suelto',
                'Al reagendar se mueve la misma cita. Lo ya completado no se '
                'vuelve a abrir como si fuera una visita nueva inventada.',
            ),
            (
                'De la agenda al turno',
                'El paciente programado llega, recepción lo pone en cola y el '
                'médico lo atiende con el expediente a la vista.',
            ),
            (
                'Avisos cuando el consultorio lo configura',
                'Con el correo SMTP del consultorio se pueden enviar avisos de '
                'citas desde la misma plataforma.',
            ),
        ),
    },
}


def rutas_seo_publicas():
    return tuple(SEO_PAGINAS.values())


def datos_seo(clave='inicio'):
    """Metadatos públicos de ClinicRD para buscadores y redes."""
    from core.config import url_publica_base

    base = (url_publica_base() or 'https://www.clinicrd.com').rstrip('/')
    soporte = obtener_soporte()
    pagina = SEO_PAGINAS.get(clave) or SEO_PAGINAS['inicio']
    titulo = pagina['titulo']
    descripcion = pagina['descripcion']
    canonical = f"{base}{pagina['path']}"
    imagen = f'{base}/static/img/logo.png'
    telefono_e164 = f'+1{soporte["telefono_digits"]}'
    faq_entities = [
        {
            '@type': 'Question',
            'name': item['pregunta'],
            'acceptedAnswer': {
                '@type': 'Answer',
                'text': item['respuesta'],
            },
        }
        for item in FAQ_SEO
    ]
    graph = [
        {
            '@type': 'Organization',
            '@id': f'{base}/#organizacion',
            'name': 'ClinicRD',
            'alternateName': [
                'Clinic RD',
                'software de gestión médica',
                'software de gestión de pacientes',
            ],
            'slogan': (
                'El software de gestión de pacientes, consultorios y centros médicos '
                'en República Dominicana'
            ),
            'url': f'{base}/',
            'logo': {
                '@type': 'ImageObject',
                'url': imagen,
            },
            'email': soporte['email'],
            'telephone': telefono_e164,
            'address': {
                '@type': 'PostalAddress',
                'addressCountry': 'DO',
            },
            'areaServed': {
                '@type': 'Country',
                'name': 'República Dominicana',
            },
            'contactPoint': {
                '@type': 'ContactPoint',
                'telephone': telefono_e164,
                'contactType': 'customer support',
                'availableLanguage': ['Spanish'],
                'areaServed': 'DO',
            },
        },
        {
            '@type': 'SoftwareApplication',
            '@id': f'{base}/#software',
            'name': 'ClinicRD',
            'alternateName': [
                'software médico RD',
                'sistema de gestión de pacientes',
                'software para consultorio y centro médico',
            ],
            'applicationCategory': 'HealthApplication',
            'applicationSubCategory': 'Electronic medical records',
            'operatingSystem': 'Web',
            'url': f'{base}/',
            'description': SEO_PAGINAS['inicio']['descripcion'],
            'inLanguage': 'es-DO',
            'keywords': SEO_PAGINAS['inicio']['keywords'],
            'featureList': [
                'Gestión de pacientes',
                'Expediente clínico Paciente 360',
                'Historia clínica',
                'Facturación electrónica e-CF',
                'Agenda médica y reagendar',
                'Turnos y sala de espera',
                'Recetas y licencias médicas',
                'ARS y reclamaciones',
                'Software para consultorio',
                'Software para centro médico y clínica',
            ],
            'offers': {
                '@type': 'AggregateOffer',
                'lowPrice': '20',
                'highPrice': '100',
                'priceCurrency': 'USD',
                'availability': 'https://schema.org/InStock',
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
        {
            '@type': 'WebPage',
            '@id': f'{canonical}#pagina',
            'url': canonical,
            'name': titulo,
            'description': descripcion,
            'inLanguage': 'es-DO',
            'isPartOf': {'@id': f'{base}/#sitio'},
            'about': {'@id': f'{base}/#software'},
        },
    ]
    if clave in {'inicio', 'preguntas-frecuentes'}:
        graph.append({
            '@type': 'FAQPage',
            '@id': f'{canonical}#faq',
            'mainEntity': faq_entities,
            'inLanguage': 'es-DO',
        })
    return {
        'base_url': base,
        'canonical': canonical,
        'titulo': titulo,
        'descripcion': descripcion,
        'keywords': pagina['keywords'],
        'imagen': imagen,
        'imagen_alt': 'Logo de ClinicRD, software médico en República Dominicana',
        'locale': 'es_DO',
        'clave': clave,
        'pagina': pagina,
        'faq': FAQ_SEO,
        'telefono': soporte['telefono'],
        'telefono_e164': telefono_e164,
        'email': soporte['email'],
        'google_site_verification': os.getenv(
            'GOOGLE_SITE_VERIFICATION', ''
        ).strip(),
        'bing_site_verification': os.getenv(
            'BING_SITE_VERIFICATION', ''
        ).strip(),
        'json_ld': {
            '@context': 'https://schema.org',
            '@graph': graph,
        },
    }


def _clave_seo_actual():
    if not has_request_context():
        return 'inicio'
    args = request.view_args or {}
    clave = args.get('clave_seo')
    if clave in SEO_PAGINAS:
        return clave
    return 'inicio'


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
    papeleria = None
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
        if current_user.tenant_id:
            try:
                from services.stationery import obtener_papeleria
                papeleria = obtener_papeleria(current_user.tenant_id)
            except Exception:
                papeleria = None
    return {
        'tema': TEMAS[tema_actual],
        'tema_nombre': tema_actual,
        'temas_disponibles': TEMAS,
        'fuente_nombre': fuente_actual,
        'fuente': FUENTES_UI[fuente_actual],
        'fuentes_disponibles': FUENTES_UI,
        'empresa': empresa,
        'papeleria': papeleria,
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
        'seo': datos_seo(_clave_seo_actual()),
    }


def inject_soporte():
    return {'soporte': obtener_soporte()}


def init_presentation(app):
    app.add_template_filter(formato_moneda, 'formato_moneda')
    app.add_template_filter(hora_input, 'hora_input')
    app.context_processor(inject_theme)
    app.context_processor(inject_soporte)
    app.jinja_env.globals['soporte'] = obtener_soporte()
