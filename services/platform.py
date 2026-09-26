"""Operaciones del dueño: demos, facturas a empresas y alertas de licencia."""

import base64
import logging
import os
import secrets
from datetime import date, datetime, timedelta
from io import BytesIO

from core.database import execute_query, execute_update, database_transaction
from core.presentation import PRODUCTO, SOPORTE_EMAIL_PREDETERMINADO
from services.catalogos_ars import sembrar_ars_tenant

logger = logging.getLogger(__name__)

DEMO_DIAS = 7
PLAN_PRECIOS = {
    'basico': 995,
    'profesional': 1995,
    'empresarial': 3995,
}
PLAN_LICENCIAS = {
    'basico': 1,
    'profesional': 3,
    'empresarial': 5,
}


def asegurar_tablas_plataforma():
    """Crear tablas del dueño si aún no existen."""
    execute_update(
        '''
        CREATE TABLE IF NOT EXISTS solicitudes_demo (
            id INT AUTO_INCREMENT PRIMARY KEY,
            nombre VARCHAR(100) NOT NULL,
            email VARCHAR(100) NOT NULL,
            telefono VARCHAR(20) NOT NULL,
            nombre_empresa VARCHAR(255) NOT NULL,
            tipo_empresa ENUM('medico','centro_salud') NOT NULL DEFAULT 'medico',
            mensaje VARCHAR(1000) NULL,
            estado ENUM('pendiente','activada','descartada') NOT NULL DEFAULT 'pendiente',
            empresa_id INT NULL,
            creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            activado_en DATETIME NULL,
            INDEX idx_solicitudes_demo_estado (estado),
            INDEX idx_solicitudes_demo_email (email)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        '''
    )
    execute_update(
        '''
        CREATE TABLE IF NOT EXISTS facturas_plataforma (
            id INT AUTO_INCREMENT PRIMARY KEY,
            empresa_id INT NOT NULL,
            numero VARCHAR(30) NOT NULL,
            fecha DATE NOT NULL,
            periodo_inicio DATE NOT NULL,
            periodo_fin DATE NOT NULL,
            plan ENUM('basico','profesional','empresarial') NOT NULL,
            licencias INT NOT NULL DEFAULT 1,
            monto DECIMAL(12,2) NOT NULL,
            estado ENUM('pendiente','pagada','anulada') NOT NULL DEFAULT 'pendiente',
            notas VARCHAR(500) NULL,
            creado_por INT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uq_factura_plataforma_numero (numero),
            INDEX idx_fp_empresa (empresa_id),
            INDEX idx_fp_fecha (fecha),
            INDEX idx_fp_estado (estado)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        '''
    )
    execute_update(
        '''
        CREATE TABLE IF NOT EXISTS visitas_pagina (
            pagina VARCHAR(64) NOT NULL,
            fecha DATE NOT NULL,
            vistas INT NOT NULL DEFAULT 0,
            PRIMARY KEY (pagina, fecha),
            INDEX idx_visitas_fecha (fecha)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        '''
    )
    if not execute_query("SHOW COLUMNS FROM empresas LIKE 'es_demo'"):
        execute_update(
            '''
            ALTER TABLE empresas
            ADD COLUMN es_demo TINYINT(1) NOT NULL DEFAULT 0
            '''
        )


def alertas_licencias(limite=20):
    """Empresas vencidas o que vencen en 30 días."""
    return execute_query(
        '''
        SELECT e.id, e.nombre, e.email, e.plan, e.estado, e.fecha_fin,
               e.licencias_totales, e.licencias_usadas, e.es_demo,
               DATEDIFF(e.fecha_fin, CURDATE()) AS dias_restantes
        FROM empresas e
        WHERE e.fecha_fin IS NOT NULL
          AND DATEDIFF(e.fecha_fin, CURDATE()) <= 30
        ORDER BY e.fecha_fin ASC, e.nombre
        LIMIT %s
        ''',
        (limite,),
        fetch='all',
    ) or []


def contar_solicitudes_pendientes():
    fila = execute_query(
        "SELECT COUNT(*) AS total FROM solicitudes_demo WHERE estado='pendiente'"
    ) or {}
    return int(fila.get('total') or 0)


def registrar_solicitud_demo(valores):
    return execute_update(
        '''
        INSERT INTO solicitudes_demo (
            nombre, email, telefono, nombre_empresa, tipo_empresa, mensaje
        ) VALUES (%s,%s,%s,%s,%s,%s)
        ''',
        (
            valores['nombre'], valores['email'], valores['telefono'],
            valores['nombre_empresa'], valores['tipo_empresa'],
            valores.get('mensaje') or None,
        ),
    )


def listar_solicitudes_demo(estado=None):
    if estado in ('pendiente', 'activada', 'descartada'):
        return execute_query(
            '''
            SELECT s.*, e.nombre AS empresa_activada
            FROM solicitudes_demo s
            LEFT JOIN empresas e ON e.id=s.empresa_id
            WHERE s.estado=%s
            ORDER BY s.creado_en DESC
            ''',
            (estado,),
            fetch='all',
        ) or []
    return execute_query(
        '''
        SELECT s.*, e.nombre AS empresa_activada
        FROM solicitudes_demo s
        LEFT JOIN empresas e ON e.id=s.empresa_id
        ORDER BY FIELD(s.estado,'pendiente','activada','descartada'),
                 s.creado_en DESC
        ''',
        fetch='all',
    ) or []


def _clave_temporal_demo():
    return f'Demo7d#{secrets.token_hex(3)}'


def habilitar_demo_empresa(empresa_id):
    """Reactivar o extender una empresa por 7 días."""
    empresa = execute_query('SELECT id FROM empresas WHERE id=%s', (empresa_id,))
    if not empresa:
        return False
    hoy = date.today()
    execute_update(
        '''
        UPDATE empresas
        SET fecha_inicio=%s, fecha_fin=%s, estado='activo', es_demo=1
        WHERE id=%s
        ''',
        (hoy, hoy + timedelta(days=DEMO_DIAS), empresa_id),
    )
    return True


def dar_de_alta_empresa(empresa_id, plan='basico', meses=1, crear_factura=True, creado_por=None):
    """Convierte un demo en cliente de alta al cerrar la negociación."""
    if plan not in PLAN_PRECIOS:
        return None
    meses = 12 if int(meses or 1) >= 12 else 1
    empresa = execute_query('SELECT * FROM empresas WHERE id=%s', (empresa_id,))
    if not empresa:
        return None
    hoy = date.today()
    dias = 365 if meses == 12 else 30
    licencias = PLAN_LICENCIAS.get(plan, empresa.get('licencias_totales') or 1)
    monto = PLAN_PRECIOS[plan] * (meses * 0.85 if meses == 12 else 1)
    execute_update(
        '''
        UPDATE empresas
        SET es_demo=0, estado='activo', plan=%s,
            licencias_totales=%s, fecha_inicio=%s, fecha_fin=%s
        WHERE id=%s
        ''',
        (plan, licencias, hoy, hoy + timedelta(days=dias), empresa_id),
    )
    factura_id = None
    if crear_factura:
        factura_id = crear_factura_plataforma(
            {
                'empresa_id': empresa_id,
                'fecha': hoy.isoformat(),
                'periodo_inicio': hoy.isoformat(),
                'periodo_fin': (hoy + timedelta(days=dias)).isoformat(),
                'plan': plan,
                'licencias': licencias,
                'monto': round(monto, 2),
                'notas': 'Alta de cliente tras negociación',
            },
            creado_por=creado_por,
        )
    return {
        'empresa_id': empresa_id,
        'plan': plan,
        'meses': meses,
        'fecha_fin': hoy + timedelta(days=dias),
        'factura_id': factura_id,
        'monto': round(monto, 2),
    }


def _crear_empresa_demo(nombre, email, telefono, tipo_empresa):
    hoy = date.today()
    return execute_update(
        '''
        INSERT INTO empresas (
            nombre, razon_social, telefono, email, fecha_inicio, fecha_fin,
            licencias_totales, licencias_usadas, plan, estado, tipo_empresa,
            es_demo
        ) VALUES (%s,%s,%s,%s,%s,%s,2,1,'basico','activo',%s,1)
        ''',
        (
            nombre, nombre, telefono, email, hoy,
            hoy + timedelta(days=DEMO_DIAS), tipo_empresa,
        ),
    )


def activar_demo_solicitud(solicitud_id):
    """Crear o reactivar el demo de 7 días a partir de una solicitud."""
    solicitud = execute_query(
        'SELECT * FROM solicitudes_demo WHERE id=%s',
        (solicitud_id,),
    )
    if not solicitud or solicitud['estado'] != 'pendiente':
        return None
    usuario = execute_query(
        'SELECT id, tenant_id, email FROM usuarios WHERE email=%s',
        (solicitud['email'],),
    )
    clave = None
    with database_transaction():
        if usuario and usuario.get('tenant_id'):
            empresa_id = usuario['tenant_id']
            habilitar_demo_empresa(empresa_id)
        else:
            empresa_id = _crear_empresa_demo(
                solicitud['nombre_empresa'],
                solicitud['email'],
                solicitud['telefono'],
                solicitud['tipo_empresa'],
            )
            if not empresa_id:
                raise RuntimeError('No se pudo crear la empresa demo')
            sembrar_ars_tenant(empresa_id)
            if not usuario:
                clave = _clave_temporal_demo()
                from werkzeug.security import generate_password_hash
                user_id = execute_update(
                    '''
                    INSERT INTO usuarios (
                        tenant_id, nombre, email, password_hash, perfil,
                        activo, password_temporal
                    ) VALUES (%s,%s,%s,%s,'Administrador',1,1)
                    ''',
                    (
                        empresa_id, solicitud['nombre'], solicitud['email'],
                        generate_password_hash(clave),
                    ),
                )
                if not user_id:
                    raise RuntimeError('No se pudo crear el usuario demo')
        execute_update(
            '''
            UPDATE solicitudes_demo
            SET estado='activada', empresa_id=%s, activado_en=%s
            WHERE id=%s
            ''',
            (empresa_id, datetime.now(), solicitud_id),
        )
    return {
        'empresa_id': empresa_id,
        'email': solicitud['email'],
        'clave': clave,
        'dias': DEMO_DIAS,
    }


def descartar_solicitud_demo(solicitud_id):
    execute_update(
        "UPDATE solicitudes_demo SET estado='descartada' WHERE id=%s AND estado='pendiente'",
        (solicitud_id,),
    )


def _siguiente_numero_factura():
    fila = execute_query(
        '''
        SELECT numero FROM facturas_plataforma
        WHERE numero LIKE %s
        ORDER BY id DESC LIMIT 1
        ''',
        (f'FP-{date.today().year}-%',),
    )
    siguiente = 1
    if fila and fila.get('numero'):
        try:
            siguiente = int(str(fila['numero']).rsplit('-', 1)[-1]) + 1
        except ValueError:
            siguiente = 1
    return f'FP-{date.today().year}-{siguiente:04d}'


def crear_factura_plataforma(valores, creado_por=None):
    numero = _siguiente_numero_factura()
    return execute_update(
        '''
        INSERT INTO facturas_plataforma (
            empresa_id, numero, fecha, periodo_inicio, periodo_fin,
            plan, licencias, monto, estado, notas, creado_por
        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'pendiente',%s,%s)
        ''',
        (
            valores['empresa_id'], numero, valores['fecha'],
            valores['periodo_inicio'], valores['periodo_fin'],
            valores['plan'], valores['licencias'], valores['monto'],
            valores.get('notas') or None, creado_por,
        ),
    )


def listar_facturas_plataforma(filtros=None):
    filtros = filtros or {}
    sql = '''
        SELECT f.*, e.nombre AS empresa_nombre, e.razon_social AS empresa_razon,
               e.email AS empresa_email
        FROM facturas_plataforma f
        JOIN empresas e ON e.id=f.empresa_id
        WHERE 1=1
    '''
    params = []
    if filtros.get('estado'):
        sql += ' AND f.estado=%s'
        params.append(filtros['estado'])
    if filtros.get('empresa_id'):
        sql += ' AND f.empresa_id=%s'
        params.append(filtros['empresa_id'])
    if filtros.get('desde'):
        sql += ' AND f.fecha>=%s'
        params.append(filtros['desde'])
    if filtros.get('hasta'):
        sql += ' AND f.fecha<=%s'
        params.append(filtros['hasta'])
    sql += ' ORDER BY f.fecha DESC, f.id DESC'
    return execute_query(sql, tuple(params) if params else None, fetch='all') or []


def empresas_pendientes_pago():
    """Empresas con al menos una factura de suscripción sin cobrar."""
    return execute_query(
        '''
        SELECT e.id, e.razon_social, e.nombre, e.email, e.plan, e.estado,
               e.fecha_fin, e.es_demo,
               COUNT(f.id) AS facturas_pendientes,
               COALESCE(SUM(f.monto), 0) AS monto_pendiente,
               MIN(f.fecha) AS factura_mas_vieja,
               MAX(f.fecha) AS ultima_factura
        FROM empresas e
        JOIN facturas_plataforma f ON f.empresa_id=e.id AND f.estado='pendiente'
        GROUP BY e.id, e.razon_social, e.nombre, e.email, e.plan, e.estado,
                 e.fecha_fin, e.es_demo
        ORDER BY monto_pendiente DESC, factura_mas_vieja ASC
        ''',
        fetch='all',
    ) or []


def resumen_facturacion_plataforma(filtros=None):
    facturas = listar_facturas_plataforma(filtros)
    resumen = {
        'total': 0,
        'pendiente': 0,
        'pagada': 0,
        'anulada': 0,
        'cantidad': len(facturas),
        'cantidad_pagada': 0,
        'cantidad_pendiente': 0,
    }
    for factura in facturas:
        monto = float(factura.get('monto') or 0)
        estado = factura.get('estado')
        resumen['total'] += monto
        if estado in resumen:
            resumen[estado] += monto
        if estado == 'pagada':
            resumen['cantidad_pagada'] += 1
        elif estado == 'pendiente':
            resumen['cantidad_pendiente'] += 1
    return facturas, resumen


def cambiar_estado_factura_plataforma(factura_id, estado):
    if estado not in ('pendiente', 'pagada', 'anulada'):
        return False
    execute_update(
        'UPDATE facturas_plataforma SET estado=%s WHERE id=%s',
        (estado, factura_id),
    )
    return True


def listar_empresas_activas():
    return execute_query(
        'SELECT id, nombre, plan, email, licencias_totales FROM empresas ORDER BY nombre',
        fetch='all',
    ) or []


def obtener_factura_plataforma(factura_id):
    return execute_query(
        '''
        SELECT f.*, e.nombre AS empresa_nombre, e.email AS empresa_email,
               e.telefono AS empresa_telefono, e.rnc AS empresa_rnc
        FROM facturas_plataforma f
        JOIN empresas e ON e.id=f.empresa_id
        WHERE f.id=%s
        ''',
        (factura_id,),
    )


def generar_pdf_factura_plataforma(factura):
    """PDF de cobro de suscripción para enviar o descargar."""
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_RIGHT
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    buffer = BytesIO()
    documento = SimpleDocTemplate(
        buffer, pagesize=letter,
        leftMargin=0.7 * inch, rightMargin=0.7 * inch,
        topMargin=0.6 * inch, bottomMargin=0.6 * inch,
    )
    estilos = getSampleStyleSheet()
    titulo = ParagraphStyle(
        'Titulo', parent=estilos['Heading1'], fontSize=18,
        textColor=colors.HexColor('#087d73'), spaceAfter=4,
    )
    etiqueta = ParagraphStyle(
        'Etiqueta', parent=estilos['Normal'], fontSize=9,
        textColor=colors.HexColor('#64748b'),
    )
    valor = ParagraphStyle(
        'Valor', parent=estilos['Normal'], fontSize=11, leading=15,
    )
    monto = ParagraphStyle(
        'Monto', parent=estilos['Normal'], fontSize=16, alignment=TA_RIGHT,
        textColor=colors.HexColor('#087d73'), fontName='Helvetica-Bold',
    )
    monto_valor = float(factura.get('monto') or 0)
    filas = [
        ['Cliente', factura.get('empresa_nombre') or ''],
        ['Correo', factura.get('empresa_email') or ''],
        ['Teléfono', factura.get('empresa_telefono') or '—'],
        ['Plan', (factura.get('plan') or '').title()],
        ['Licencias', str(factura.get('licencias') or 1)],
        ['Periodo', f"{factura.get('periodo_inicio')} · {factura.get('periodo_fin')}"],
        ['Estado', (factura.get('estado') or '').title()],
        ['Notas', factura.get('notas') or '—'],
    ]
    tabla = Table(filas, colWidths=[1.6 * inch, 5.2 * inch])
    tabla.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#64748b')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LINEBELOW', (0, 0), (-1, -2), 0.4, colors.HexColor('#e5edf3')),
    ]))
    contenido = [
        Paragraph(PRODUCTO['nombre'], titulo),
        Paragraph(f"{PRODUCTO['eslogan']} · Factura de suscripción", etiqueta),
        Spacer(1, 0.15 * inch),
        Paragraph(factura.get('numero') or '', estilos['Heading2']),
        Paragraph(f"Fecha: {factura.get('fecha')}", valor),
        Spacer(1, 0.2 * inch),
        tabla,
        Spacer(1, 0.25 * inch),
        Paragraph(f"Total RD$ {monto_valor:,.2f}", monto),
        Spacer(1, 0.35 * inch),
        Paragraph(
            f"ClinicRD · {os.getenv('SOPORTE_EMAIL', SOPORTE_EMAIL_PREDETERMINADO)}",
            etiqueta,
        ),
    ]
    documento.build(contenido)
    buffer.seek(0)
    return buffer


def enviar_factura_plataforma_por_correo(factura, destinatario=None):
    """Enviar el PDF de cobro al correo de la empresa cliente."""
    correo = (destinatario or factura.get('empresa_email') or '').strip()
    if not correo:
        return False, 'La empresa no tiene correo para enviar la factura'
    try:
        from sendgrid import SendGridAPIClient
        from sendgrid.helpers.mail import Mail
    except ImportError:
        return False, 'El envío de correo no está disponible'
    api_key = os.getenv('SENDGRID_API_KEY', '').strip()
    if not api_key:
        return False, 'Falta configurar SENDGRID_API_KEY'
    pdf = generar_pdf_factura_plataforma(factura).getvalue()
    numero = factura.get('numero') or factura.get('id')
    mensaje = Mail(
        from_email=os.getenv('SENDGRID_FROM_EMAIL', 'noreply@clinicrd.com'),
        to_emails=correo,
        subject=f'Factura {numero} · ClinicRD',
        html_content=(
            f"<p>Hola,</p>"
            f"<p>Adjuntamos la factura <strong>{numero}</strong> de "
            f"{PRODUCTO['nombre']} para {factura.get('empresa_nombre') or 'su empresa'}.</p>"
            f"<p>Periodo: {factura.get('periodo_inicio')} · {factura.get('periodo_fin')}<br>"
            f"Monto: RD$ {float(factura.get('monto') or 0):,.2f}</p>"
            f"<p>Gracias.</p>"
        ),
    )
    mensaje.attachment = {
        'content': base64.b64encode(pdf).decode(),
        'filename': f'{numero}.pdf',
        'type': 'application/pdf',
        'disposition': 'attachment',
    }
    respuesta = SendGridAPIClient(api_key).send(mensaje)
    if respuesta.status_code not in (200, 202):
        return False, f'No se pudo enviar el correo ({respuesta.status_code})'
    return True, correo


PAGINAS_PUBLICAS = {
    'index': 'Página de inicio',
    'registro': 'Registro',
}

_USER_AGENTS_BOT = (
    'bot', 'crawler', 'spider', 'preview', 'slurp', 'monitor', 'headless',
)


def _es_bot_visita():
    try:
        from flask import request
        ua = (request.user_agent.string or '').lower()
    except Exception:
        return False
    return any(marca in ua for marca in _USER_AGENTS_BOT)


def registrar_vista_pagina(pagina):
    """Sumar una visita pública. No cuenta usuarios logueados ni bots."""
    if pagina not in PAGINAS_PUBLICAS:
        return False
    try:
        from flask_login import current_user
        if getattr(current_user, 'is_authenticated', False):
            return False
    except Exception:
        pass
    if _es_bot_visita():
        return False
    try:
        execute_update(
            '''
            INSERT INTO visitas_pagina (pagina, fecha, vistas)
            VALUES (%s, CURDATE(), 1)
            ON DUPLICATE KEY UPDATE vistas = visitas_pagina.vistas + 1
            ''',
            (pagina,),
        )
        return True
    except Exception as error:
        logger.debug('No se pudo registrar visita de %s: %s', pagina, error)
        return False


def _suma_visitas(filas, pagina=None, desde=None):
    total = 0
    for fila in filas or []:
        if pagina and fila.get('pagina') != pagina:
            continue
        if desde:
            fecha = fila.get('fecha')
            if fecha and str(fecha) < str(desde):
                continue
        total += int(fila.get('vistas') or 0)
    return total


def resumen_visitas_pagina(dias=30):
    """Totales y detalle diario para el dueño de ClinicRD."""
    hoy = date.today()
    desde = hoy - timedelta(days=max(int(dias), 1) - 1)
    filas = execute_query(
        '''
        SELECT pagina, fecha, vistas
        FROM visitas_pagina
        WHERE fecha >= %s
        ORDER BY fecha DESC, pagina
        ''',
        (desde,),
        fetch='all',
    ) or []
    total_row = execute_query(
        'SELECT COALESCE(SUM(vistas), 0) AS total FROM visitas_pagina',
        fetch='one',
    ) or {}
    por_dia = {}
    for fila in filas:
        clave = str(fila.get('fecha') or '')
        dia = por_dia.setdefault(
            clave,
            {'fecha': fila.get('fecha'), 'index': 0, 'registro': 0, 'total': 0},
        )
        pagina = fila.get('pagina')
        vistas = int(fila.get('vistas') or 0)
        if pagina in ('index', 'registro'):
            dia[pagina] += vistas
        dia['total'] += vistas
    semanal_desde = hoy - timedelta(days=6)
    return {
        'hoy': _suma_visitas(filas, desde=hoy),
        'semana': _suma_visitas(filas, desde=semanal_desde),
        'total': int(total_row.get('total') or 0),
        'inicio_hoy': _suma_visitas(filas, pagina='index', desde=hoy),
        'registro_hoy': _suma_visitas(filas, pagina='registro', desde=hoy),
        'por_dia': list(por_dia.values()),
        'etiquetas': PAGINAS_PUBLICAS,
    }
