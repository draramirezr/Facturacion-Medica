"""PDF de facturas y envío por correo."""
import logging
import re
from io import BytesIO
from flask import flash, redirect, request, send_file, url_for
from flask_login import login_required
from markupsafe import escape
from auth import permission_required
from core.database import execute_query
from core.tenant import get_current_tenant_id, validate_tenant_access
from services.subscriptions import get_empresa_info
try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_RIGHT
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

logger = logging.getLogger(__name__)


def generar_pdf_factura_vista_previa(factura_id, tenant_id=None):
    """Generar PDF de factura con el mismo formato que la vista previa"""
    if not REPORTLAB_AVAILABLE:
        return None
    
    if tenant_id is None:
        tenant_id = get_current_tenant_id()
    
    factura = execute_query('''
        SELECT f.*, a.nombre as nombre_ars, a.rnc as ars_rnc,
               m.nombre as medico_nombre, m.especialidad as medico_especialidad,
               m.cedula as medico_cedula, m.exequatur as medico_exequatur,
               m.id as medico_id
        FROM facturas f
        LEFT JOIN ars a
          ON f.ars_id = a.id AND a.tenant_id = f.tenant_id
        LEFT JOIN medicos m
          ON f.medico_id = m.id AND m.tenant_id = f.tenant_id
        WHERE f.id = %s AND f.tenant_id = %s
    ''', (factura_id, tenant_id))
    
    if not factura:
        logger.error(f"Factura {factura_id} no encontrada para tenant {tenant_id}")
        print(f"ERROR: Factura {factura_id} no encontrada para tenant {tenant_id}")
        return None
    
    logger.info(f"Iniciando generación de PDF para factura {factura_id}")
    print(f"INFO: Factura {factura_id} encontrada. Datos básicos: ncf={factura.get('ncf')}, fecha_emision={factura.get('fecha_emision')}, ars_id={factura.get('ars_id')}")
    
    # Obtener información de la empresa para determinar tipo
    empresa_info = get_empresa_info(tenant_id)
    tipo_empresa = empresa_info.get('tipo_empresa') if empresa_info else None
    
    # Obtener médico o empresa según tipo
    medico_factura = None
    if tipo_empresa == 'centro_salud':
        medico_factura = {
            'id': empresa_info.get('id'),
            'nombre': empresa_info.get('razon_social', empresa_info.get('nombre', 'N/A')),
            'especialidad': 'Centro de Salud',
            'cedula': empresa_info.get('rnc', '')
        }
    else:
        medico_factura = {
            'id': factura.get('medico_id'),
            'nombre': factura.get('medico_nombre', 'N/A'),
            'especialidad': factura.get('medico_especialidad', ''),
            'cedula': factura.get('medico_cedula', '')
        }
    
    # Obtener ARS
    ars = {
        'id': factura.get('ars_id'),
        'nombre': factura.get('nombre_ars', 'N/A'),
        'rnc': factura.get('ars_rnc', '')
    }
    
    # Obtener NCF
    ncf_numero = factura.get('ncf', '')
    ncf_prefijo = ncf_numero[:3] if len(ncf_numero) >= 3 else ''
    ncf_obj = execute_query('SELECT * FROM ncf WHERE prefijo = %s AND tenant_id = %s LIMIT 1', (ncf_prefijo, tenant_id))
    
    ncf_tipos_descripciones = {
        'B01': 'Factura de Crédito Fiscal',
        'B02': 'Factura de Consumo',
        'B14': 'Registro Único de Ingresos',
        'B15': 'GUBERNAMENTAL'
    }
    ncf_tipo_descripcion = ncf_tipos_descripciones.get(ncf_obj.get('tipo', '') if ncf_obj else '', '') if ncf_obj else ''
    ncf_fecha_fin = ncf_obj.get('fecha_fin', '') if ncf_obj else ''
    
    # Obtener fecha de factura para usar en consultas
    fecha_factura = factura.get('fecha_emision', '')
    
    # Obtener detalles de la factura (pacientes/servicios)
    detalles = execute_query('''
        SELECT * FROM factura_detalles
        WHERE factura_id = %s AND tenant_id = %s
        ORDER BY id
    ''', (factura_id, tenant_id), fetch='all') or []
    
    # Intentar obtener pacientes desde pacientes_pendientes que fueron facturados
    # Buscar pacientes_pendientes con estado 'Facturado' que coincidan con esta factura
    # Por fecha y ARS como aproximación
    pacientes_pendientes_facturados = []
    try:
        pacientes_pendientes_facturados = execute_query('''
            SELECT pp.*, a.nombre as ars_nombre
            FROM pacientes_pendientes pp
            LEFT JOIN ars a
              ON pp.ars_id = a.id AND a.tenant_id = pp.tenant_id
            WHERE pp.estado = 'Facturado'
              AND pp.ars_id = %s
              AND DATE(pp.updated_at) = DATE(%s)
              AND pp.tenant_id = %s
            ORDER BY pp.id
        ''', (
            factura.get('ars_id'),
            fecha_factura,
            tenant_id,
        ), fetch='all') or []
    except Exception as e:
        logger.error(f"Error al obtener pacientes_pendientes_facturados: {str(e)}")
        pacientes_pendientes_facturados = []
    
    # Validar que hay detalles antes de procesar
    if not detalles:
        logger.error(f"Factura {factura_id} no tiene detalles asociados. Query ejecutada: SELECT * FROM factura_detalles WHERE factura_id = {factura_id}")
        return None
    
    logger.info(f"Factura {factura_id} tiene {len(detalles)} detalles. Primer detalle: {detalles[0] if detalles else 'N/A'}")
    
    # Procesar pacientes desde detalles y pacientes_pendientes
    pacientes = []
    if pacientes_pendientes_facturados and len(pacientes_pendientes_facturados) == len(detalles):
        # Si encontramos pacientes_pendientes que coinciden, usarlos
        for idx, (detalle, pp) in enumerate(zip(detalles, pacientes_pendientes_facturados), 1):
            servicio_completo = pp.get('servicios_realizados', '') or ''
            if ' - Autorización:' in servicio_completo:
                partes = servicio_completo.split(' - Autorización:')
                descripcion_servicio = partes[0].strip()
                autorizacion = partes[1].strip() if len(partes) > 1 else ''
            else:
                descripcion_servicio = servicio_completo.strip()
                autorizacion = ''
            
            paciente = {
                'nombre_paciente': pp.get('nombre_paciente', factura.get('nombre_paciente', 'N/A')),
                'nss': pp.get('nss', factura.get('nss_paciente', '')),
                'fecha_servicio': pp.get('fecha_servicio', factura.get('fecha_emision', '')),
                'autorizacion': autorizacion,
                'descripcion_servicio': descripcion_servicio if descripcion_servicio else detalle.get('descripcion', ''),
                'monto_estimado': float(detalle.get('precio_unitario', 0) or 0),
                'monto': float(detalle.get('precio_unitario', 0) or 0)
            }
            pacientes.append(paciente)
    else:
        # Si no encontramos pacientes_pendientes, usar datos de la factura (como en ver_factura)
        for idx, detalle in enumerate(detalles, 1):
            descripcion = detalle.get('descripcion', '')
            # Intentar extraer autorización de la descripción si está presente
            autorizacion = ''
            descripcion_servicio = descripcion
            if ' - Autorización:' in descripcion:
                partes = descripcion.split(' - Autorización:')
                descripcion_servicio = partes[0].strip()
                autorizacion = partes[1].strip() if len(partes) > 1 else ''
            
            paciente = {
                'nombre_paciente': factura.get('nombre_paciente', 'N/A'),
                'nss': factura.get('nss_paciente', ''),
                'fecha_servicio': fecha_factura,
                'autorizacion': autorizacion,
                'descripcion_servicio': descripcion_servicio if descripcion_servicio else '',
                'monto_estimado': float(detalle.get('precio_unitario', 0) or 0),
                'monto': float(detalle.get('precio_unitario', 0) or 0)
            }
            pacientes.append(paciente)
    
    # Obtener centro médico
    centro_medico = None
    if factura.get('centro_medico_id'):
        centro_medico = execute_query('SELECT * FROM centros_medicos WHERE id = %s AND tenant_id = %s', 
                                     (factura['centro_medico_id'], tenant_id))
    
    if not centro_medico:
        centro_medico = execute_query('SELECT * FROM centros_medicos WHERE tenant_id = %s LIMIT 1', (tenant_id,))
    
    if not centro_medico:
        centro_medico = {
            'nombre': 'Centro Médico',
            'direccion': ''
        }
    
    # Calcular totales
    subtotal = float(factura.get('subtotal', 0) or 0)
    total = float(factura.get('total', 0) or 0)
    
    # Obtener datos completos del médico para el footer y remitente (antes de generar PDF)
    medico_completo = None
    if tipo_empresa != 'centro_salud' and medico_factura.get('id'):
        medico_completo = execute_query(
            'SELECT * FROM medicos WHERE id = %s AND tenant_id = %s',
            (medico_factura.get('id'), tenant_id),
        )
        # Actualizar medico_factura con datos completos si están disponibles
        if medico_completo:
            medico_factura['nombre'] = medico_completo.get('nombre', medico_factura.get('nombre', 'N/A'))
            medico_factura['especialidad'] = medico_completo.get('especialidad', medico_factura.get('especialidad', ''))
            medico_factura['cedula'] = medico_completo.get('cedula', medico_factura.get('cedula', ''))
            medico_factura['exequatur'] = medico_completo.get('exequatur', '')
    
    # Validar datos mínimos necesarios antes de generar PDF
    if not pacientes:
        logger.error(f"Factura {factura_id} no tiene pacientes procesados después de procesar {len(detalles)} detalles")
        logger.error(f"Detalles procesados: {detalles}")
        logger.error(f"Pacientes pendientes encontrados: {len(pacientes_pendientes_facturados)}")
        return None
    
    # Validar que tenemos datos esenciales
    if not fecha_factura:
        logger.error(f"Factura {factura_id} no tiene fecha_emision. factura['fecha_emision'] = {factura.get('fecha_emision')}")
        return None
    
    if not ars.get('nombre'):
        logger.error(f"Factura {factura_id} no tiene nombre de ARS. ars = {ars}, factura['nombre_ars'] = {factura.get('nombre_ars')}")
        return None
    
    if not ncf_numero:
        logger.error(f"Factura {factura_id} no tiene número de NCF. factura['ncf'] = {factura.get('ncf')}")
        return None
    
    logger.info(f"Iniciando generación de PDF para factura {factura_id}: {len(pacientes)} pacientes, subtotal: {subtotal}, total: {total}")
    logger.info(f"Datos validados: fecha_factura={fecha_factura}, ars={ars.get('nombre')}, ncf={ncf_numero}, tipo_empresa={tipo_empresa}")
    
    # Generar PDF
    try:
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, 
                                leftMargin=0.5*inch, rightMargin=0.5*inch,
                                topMargin=0.5*inch, bottomMargin=0.5*inch)
        story = []
        
        styles = getSampleStyleSheet()
        
        # Color primario (puede obtenerse del tema, por defecto usamos un color)
        primary_color_hex = '#CEB0B7'
        primary_color = colors.HexColor(primary_color_hex)
        primary_dark = colors.HexColor('#B89CA3')
        
        # Estilo para título
        title_style = ParagraphStyle(
            'FacturaTitle',
            parent=styles['Heading1'],
            fontSize=28,
            textColor=primary_color,
            spaceAfter=15,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        # Header: FACTURA centrado
        story.append(Paragraph("FACTURA", title_style))
        story.append(Spacer(1, 0.25*inch))
        
        # Información en 3 columnas (simuladas con tabla) - Formato como imagen
        info_box_style = ParagraphStyle(
            'InfoBox',
            parent=styles['Normal'],
            fontSize=8,
            leading=11,
            textColor=colors.black
        )
        
        info_header_style = ParagraphStyle(
            'InfoHeader',
            parent=styles['Normal'],
            fontSize=7,
            textColor=colors.white,
            fontName='Helvetica-Bold',
            spaceAfter=4
        )
        
        # Columna 1: Información de Factura
        info_factura_data = [
            [Paragraph('<b>Información de Factura</b>', info_header_style)],
            [Paragraph(f"<b>Fecha:</b> {escape(str(fecha_factura))}", info_box_style)],
            [Paragraph(f"<b>Cliente:</b> {escape(str(ars.get('nombre', 'N/A')))}", info_box_style)],
        ]
        if ars.get('rnc'):
            info_factura_data.append([Paragraph(f"<b>RNC:</b> {escape(str(ars.get('rnc')))}", info_box_style)])
        
        info_factura_table = Table(info_factura_data, colWidths=[2.4*inch])
        info_factura_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), primary_color),
            ('TEXTCOLOR', (0, 0), (0, 0), colors.white),
            ('BACKGROUND', (0, 1), (0, -1), colors.white),
            ('LEFTPADDING', (0, 0), (0, -1), 8),
            ('RIGHTPADDING', (0, 0), (0, -1), 8),
            ('TOPPADDING', (0, 0), (0, -1), 8),
            ('BOTTOMPADDING', (0, 0), (0, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, primary_color),  # Borde delgado
            ('BOX', (0, 0), (-1, -1), 1, primary_color),  # Borde alrededor de toda la tabla
        ]))
        
        # Columna 2: NCF
        ncf_data = [
            [Paragraph('<b>NCF</b>', info_header_style)],
            [Paragraph(f"<font color='{primary_color_hex}'>{escape(str(ncf_numero))}</font>", ParagraphStyle('NCFNumber', parent=info_box_style, fontSize=10, textColor=primary_color))],
        ]
        if ncf_tipo_descripcion:
            ncf_data.append([Paragraph(f"<b>Tipo:</b> {escape(str(ncf_tipo_descripcion))}", info_box_style)])
        if ncf_fecha_fin:
            ncf_data.append([Paragraph(f"<b>Válido hasta:</b> {escape(str(ncf_fecha_fin))}", info_box_style)])
        
        ncf_table = Table(ncf_data, colWidths=[2.4*inch])
        ncf_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), primary_color),
            ('TEXTCOLOR', (0, 0), (0, 0), colors.white),
            ('BACKGROUND', (0, 1), (0, -1), colors.white),
            ('LEFTPADDING', (0, 0), (0, -1), 8),
            ('RIGHTPADDING', (0, 0), (0, -1), 8),
            ('TOPPADDING', (0, 0), (0, -1), 8),
            ('BOTTOMPADDING', (0, 0), (0, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, primary_color),  # Borde delgado
            ('BOX', (0, 0), (-1, -1), 1, primary_color),  # Borde alrededor de toda la tabla
        ]))
        
        # Columna 3: Remitente
        remitente_data = [
            [Paragraph('<b>Remitente</b>', info_header_style)],
        ]
        if tipo_empresa == 'centro_salud':
            remitente_data.append([Paragraph(f"<b>{empresa_info.get('razon_social', empresa_info.get('nombre', 'N/A'))}</b>", info_box_style)])
            if empresa_info.get('rnc'):
                remitente_data.append([Paragraph(f"<b>RNC:</b> {empresa_info.get('rnc')}", info_box_style)])
        else:
            # Nombre del médico sin label "Médico:" - en negrita
            remitente_data.append([Paragraph(f"<b>{medico_factura.get('nombre', 'N/A')}</b>", info_box_style)])
            if medico_factura.get('especialidad'):
                especialidad_style = ParagraphStyle('Especialidad', parent=info_box_style, fontSize=7, textColor=colors.HexColor('#666'))
                remitente_data.append([Paragraph(medico_factura.get('especialidad', ''), especialidad_style)])
            if medico_factura.get('cedula'):
                remitente_data.append([Paragraph(f"<b>Código:</b> {medico_factura.get('cedula', '')}", info_box_style)])
            if medico_completo and medico_completo.get('exequatur'):
                remitente_data.append([Paragraph(f"<b>Exequátur:</b> {medico_completo.get('exequatur', '')}", info_box_style)])
        
        remitente_table = Table(remitente_data, colWidths=[2.4*inch])
        remitente_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), primary_color),
            ('TEXTCOLOR', (0, 0), (0, 0), colors.white),
            ('BACKGROUND', (0, 1), (0, -1), colors.white),
            ('LEFTPADDING', (0, 0), (0, -1), 8),
            ('RIGHTPADDING', (0, 0), (0, -1), 8),
            ('TOPPADDING', (0, 0), (0, -1), 8),
            ('BOTTOMPADDING', (0, 0), (0, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, primary_color),  # Borde delgado
            ('BOX', (0, 0), (-1, -1), 1, primary_color),  # Borde alrededor de toda la tabla
        ]))
        
        # Combinar las 3 columnas en una tabla con espaciado entre columnas
        info_combined = Table([[info_factura_table, ncf_table, remitente_table]], colWidths=[2.4*inch, 2.4*inch, 2.4*inch])
        info_combined.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 0),
            ('RIGHTPADDING', (0, 0), (-1, -1), 0),
            ('TOPPADDING', (0, 0), (-1, -1), 0),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ]))
        story.append(info_combined)
        story.append(Spacer(1, 0.25*inch))
        
        # Tabla de pacientes/servicios
        if pacientes:
            tabla_headers = ['No.', 'NOMBRES PACIENTE', 'NSS/CONTRATO', 'FECHA', 'AUTORIZACIÓN', 'SERVICIO', 'V/UNITARIO']
            tabla_data = [tabla_headers]
            
            for idx, paciente in enumerate(pacientes, 1):
                monto = float(paciente.get('monto') or paciente.get('monto_estimado', 0) or 0)
                tabla_data.append([
                    str(idx),
                    Paragraph(f"<b>{escape(str(paciente.get('nombre_paciente', 'N/A')))}</b>", info_box_style),
                    escape(str(paciente.get('nss', ''))),
                    escape(str(paciente.get('fecha_servicio', ''))),
                    escape(str(paciente.get('autorizacion', ''))),
                    escape(str(paciente.get('descripcion_servicio', ''))),
                    Paragraph(f"<b>{monto:,.2f}</b>", ParagraphStyle('Monto', parent=info_box_style, alignment=TA_RIGHT, fontName='Helvetica-Bold'))
                ])
            
            # Ajustar anchos de columnas según la imagen: No. (4%), NOMBRES (30%), NSS (10%), FECHA (12%), AUTORIZACIÓN (12%), SERVICIO (20%), V/UNITARIO (12%)
            # Ancho total disponible: ~7.5 inch (letter size - márgenes)
            tabla = Table(tabla_data, colWidths=[0.3*inch, 2.25*inch, 0.75*inch, 0.9*inch, 0.9*inch, 1.5*inch, 0.9*inch])
            tabla.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), primary_color),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 7),
                ('ALIGN', (0, 0), (0, -1), 'CENTER'),  # No.
                ('ALIGN', (3, 1), (3, -1), 'CENTER'),  # FECHA
                ('ALIGN', (6, 1), (6, -1), 'RIGHT'),  # V/UNITARIO
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#DDD')),
                ('LEFTPADDING', (0, 0), (-1, -1), 4),
                ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('FONTSIZE', (0, 1), (-1, -1), 7),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            story.append(tabla)
        
        story.append(Spacer(1, 0.25*inch))
        
        # Totales - alineados a la derecha
        total_style = ParagraphStyle('Total', parent=styles['Normal'], fontSize=9, alignment=TA_RIGHT, fontName='Helvetica-Bold')
        total_label_style = ParagraphStyle('TotalLabel', parent=styles['Normal'], fontSize=9, alignment=TA_RIGHT, fontName='Helvetica-Bold')
        total_final_style = ParagraphStyle('TotalFinal', parent=styles['Normal'], fontSize=12, alignment=TA_RIGHT, fontName='Helvetica-Bold', textColor=primary_color)
        
        # Crear tabla de totales alineada a la derecha
        totales_data = [
            [Paragraph('SUB-TOTAL:', total_label_style), Paragraph(f"{subtotal:,.2f}", total_style)],
            [Paragraph('ITBIS:', total_label_style), Paragraph('*E', total_style)],
            [Paragraph('TOTAL:', total_label_style), Paragraph(f"{total:,.2f}", total_final_style)],
        ]
        
        # Tabla de totales más ancha y alineada a la derecha
        totales_table = Table(totales_data, colWidths=[1.2*inch, 1.2*inch])
        totales_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LINEABOVE', (0, -1), (-1, -1), 1, primary_color),
            ('TOPPADDING', (0, -1), (-1, -1), 8),
        ]))
        
        # Contenedor para alinear totales a la derecha
        from reportlab.platypus import KeepTogether
        totales_container = Table([[totales_table]], colWidths=[7.5*inch])
        totales_container.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, 0), 'RIGHT'),
            ('VALIGN', (0, 0), (0, 0), 'TOP'),
        ]))
        story.append(totales_container)
        
        story.append(Spacer(1, 0.4*inch))
        
        # Footer
        footer_style = ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, alignment=TA_CENTER, textColor=colors.HexColor('#666'))
        footer_bold_style = ParagraphStyle('FooterBold', parent=styles['Normal'], fontSize=9, alignment=TA_CENTER, textColor=primary_color, fontName='Helvetica-Bold')
        
        if tipo_empresa == 'centro_salud':
            footer_data = [
                [Paragraph(f"<b>{empresa_info.get('razon_social', empresa_info.get('nombre', 'N/A'))}</b>", footer_bold_style)],
            ]
            if empresa_info.get('direccion'):
                footer_data.append([Paragraph(empresa_info.get('direccion', ''), footer_style)])
            footer_text = []
            if empresa_info.get('rnc'):
                footer_text.append(f"RNC: {empresa_info.get('rnc')}")
            if empresa_info.get('telefono'):
                footer_text.append(f"Tel: {empresa_info.get('telefono')}")
            if empresa_info.get('email'):
                footer_text.append(f"Email: {empresa_info.get('email')}")
            if footer_text:
                footer_data.append([Paragraph(' | '.join(footer_text), footer_style)])
        else:
            # Footer para médico - formato como ejemplo del PDF
            footer_data = [
                [Paragraph(f"<b>{medico_factura.get('nombre', 'N/A')}</b>", footer_bold_style)],
            ]
            
            # Segunda línea: Especialidad | Cédula | EXEQUATUR (en mayúsculas)
            footer_text_line1 = []
            if medico_factura.get('especialidad'):
                footer_text_line1.append(medico_factura.get('especialidad', ''))
            if medico_factura.get('cedula'):
                footer_text_line1.append(f"Cédula: {medico_factura.get('cedula', '')}")
            if medico_completo and medico_completo.get('exequatur'):
                footer_text_line1.append(f"EXEQUATUR: {medico_completo.get('exequatur', '')}")
            if footer_text_line1:
                footer_data.append([Paragraph(' | '.join(footer_text_line1), footer_style)])
            
            # Tercera línea: Dirección del centro médico (si está disponible)
            if centro_medico and centro_medico.get('nombre'):
                centro_text = centro_medico.get('nombre', '')
                if centro_medico.get('direccion'):
                    centro_text += f", {centro_medico.get('direccion', '')}"
                footer_data.append([Paragraph(centro_text, footer_style)])
        
        footer_table = Table(footer_data, colWidths=[7*inch])
        footer_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, -1), 'CENTER'),
            ('TOPPADDING', (0, 0), (0, -1), 4),
            ('BOTTOMPADDING', (0, 0), (0, -1), 4),
        ]))
        story.append(footer_table)
        
        # Construir PDF
        try:
            logger.info(f"Construyendo PDF para factura {factura_id} con {len(story)} elementos en story")
            doc.build(story)
            logger.info(f"PDF construido exitosamente para factura {factura_id}")
            
            # Obtener el contenido del buffer y crear un nuevo BytesIO para retornar
            buffer.seek(0)
            buffer_content = buffer.read()
            
            # Verificar que el buffer tiene contenido
            buffer_size = len(buffer_content) if buffer_content else 0
            if buffer_size == 0:
                logger.error(f"PDF generado para factura {factura_id} está vacío (buffer_size=0)")
                return None
            
            # Crear un nuevo BytesIO con el contenido del PDF para evitar problemas de lectura
            pdf_buffer = BytesIO(buffer_content)
            pdf_buffer.seek(0)
            
            logger.info(f"PDF generado exitosamente para factura {factura_id}, tamaño: {buffer_size} bytes")
            return pdf_buffer
        except Exception as build_error:
            import traceback
            error_trace = traceback.format_exc()
            logger.error(f"Error al construir PDF para factura {factura_id}: {error_trace}")
            print(f"Error al construir PDF para factura {factura_id}: {str(build_error)}")
            print(f"Traceback: {error_trace}")
            return None
        
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        logger.error(f"Error al generar PDF para factura {factura_id}: {error_trace}")
        logger.error(f"Tipo de error: {type(e).__name__}, Mensaje: {str(e)}")
        print(f"ERROR CRÍTICO al generar PDF para factura {factura_id}: {str(e)}")
        print(f"Traceback completo: {error_trace}")
        # También imprimir información de debug
        print(f"DEBUG - factura encontrada: {factura is not None}")
        print(f"DEBUG - detalles encontrados: {len(detalles) if detalles else 0}")
        print(f"DEBUG - pacientes procesados: {len(pacientes) if 'pacientes' in locals() else 'N/A'}")
        return None


@login_required
@permission_required('facturacion.imprimir')
def facturacion_descargar_pdf(factura_id):
    """Descargar PDF de factura"""
    if not REPORTLAB_AVAILABLE:
        flash('ReportLab no está disponible. Por favor, instale la librería reportlab.', 'error')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))
    
    tenant_id = get_current_tenant_id()
    if not validate_tenant_access('facturas', factura_id):
        flash('No tienes acceso a esta factura', 'error')
        return redirect(url_for('facturacion_historico'))
    
    try:
        factura_check = execute_query(
            'SELECT id FROM facturas WHERE id = %s AND tenant_id = %s',
            (factura_id, tenant_id),
        )
        
        if not factura_check:
            flash('La factura no existe o no tiene permisos para acceder a ella.', 'error')
            return redirect(url_for('facturacion_historico'))
        
        logger.info(f"Iniciando descarga de PDF para factura {factura_id}, tenant_id={tenant_id}")
        print(f"=== INICIANDO DESCARGA PDF FACTURA {factura_id} ===")
        
        factura_data = execute_query(
            '''
            SELECT id, ncf, fecha_emision, ars_id, subtotal, total
            FROM facturas
            WHERE id = %s AND tenant_id = %s
            ''',
            (factura_id, tenant_id),
        )
        
        if factura_data:
            logger.info(f"Datos de factura {factura_id}: ncf={factura_data.get('ncf')}, fecha={factura_data.get('fecha_emision')}, ars_id={factura_data.get('ars_id')}")
            print(f"Factura encontrada: ncf={factura_data.get('ncf')}, fecha={factura_data.get('fecha_emision')}, ars_id={factura_data.get('ars_id')}")
        else:
            logger.error(f"No se encontraron datos básicos de factura {factura_id}")
            print(f"ERROR: No se encontraron datos básicos de factura {factura_id}")
        
        detalles_check = execute_query(
            '''
            SELECT COUNT(*) as count
            FROM factura_detalles
            WHERE factura_id = %s AND tenant_id = %s
            ''',
            (factura_id, tenant_id),
        )
        detalles_count = detalles_check.get('count', 0) if detalles_check else 0
        logger.info(f"Factura {factura_id} tiene {detalles_count} detalles")
        print(f"Detalles encontrados: {detalles_count}")
        
        if detalles_count == 0:
            logger.error(f"Factura {factura_id} no tiene detalles. No se puede generar PDF.")
            print(f"ERROR: Factura {factura_id} no tiene detalles")
            flash('Error: La factura no tiene detalles asociados. No se puede generar el PDF.', 'error')
            return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))
        
        print(f"Llamando a generar_pdf_factura_vista_previa para factura {factura_id}...")
        buffer = generar_pdf_factura_vista_previa(factura_id, tenant_id)
        
        if buffer is None:
            logger.error(f"No se pudo generar PDF para factura {factura_id}")
            print(f"ERROR: generar_pdf_factura_vista_previa retornó None para factura {factura_id}")
            flash('Error al generar PDF. Verifique que la factura tiene datos válidos y detalles asociados.', 'error')
            return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))
        
        print(f"PDF generado exitosamente. Buffer tipo: {type(buffer)}")
        
        # Verificar que el buffer tiene contenido y prepararlo para envío
        try:
            # Asegurarse de que el buffer esté al inicio
            buffer.seek(0)
            
            # Verificar que el buffer tiene contenido sin leerlo (para no consumirlo)
            buffer_size = len(buffer.getvalue()) if hasattr(buffer, 'getvalue') else 0
            
            if buffer_size == 0:
                logger.error(f"PDF generado para factura {factura_id} está vacío en facturacion_descargar_pdf")
                flash('Error: El PDF generado está vacío.', 'error')
                return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))
            
            logger.info(f"PDF listo para descarga: factura {factura_id}, tamaño: {buffer_size} bytes")
            
            # Asegurarse de que el buffer esté al inicio antes de enviarlo
            buffer.seek(0)
            
            factura = execute_query(
                '''
                SELECT numero_factura
                FROM facturas
                WHERE id = %s AND tenant_id = %s
                ''',
                (factura_id, tenant_id),
            )
            filename = f"factura_{factura_id}_{factura.get('numero_factura', '') if factura else ''}.pdf"
            
            logger.info(f"Enviando PDF: factura {factura_id}, filename={filename}")
            return send_file(buffer, mimetype='application/pdf', as_attachment=True, download_name=filename)
        except Exception as buffer_error:
            import traceback
            error_trace = traceback.format_exc()
            logger.error(f"Error al preparar/enviar buffer para factura {factura_id}: {str(buffer_error)}")
            logger.error(f"Traceback: {error_trace}")
            flash(f'Error al generar/enviar PDF: {str(buffer_error)}', 'error')
            return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        logger.error(f"Error en facturacion_descargar_pdf para factura {factura_id}: {error_trace}")
        flash(f'Error al generar PDF: {str(e)}', 'error')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))


@login_required
@permission_required('facturacion.imprimir')
def facturacion_enviar_email(factura_id):
    """Enviar factura por email"""
    tenant_id = get_current_tenant_id()
    if not validate_tenant_access('facturas', factura_id):
        flash('No tienes acceso a esta factura', 'error')
        return redirect(url_for('facturacion_historico'))
    
    # Obtener email del destinatario
    destinatario = request.form.get('destinatario', '').strip()
    if not destinatario:
        flash('Debe especificar un email destinatario', 'error')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))
    
    # Validar email
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, destinatario):
        flash('Email inválido', 'error')
        return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))
    
    factura = execute_query('''
        SELECT f.*, a.nombre as nombre_ars, a.rnc as ars_rnc,
               m.nombre as medico_nombre, m.especialidad as medico_especialidad,
               m.cedula as medico_cedula, m.exequatur as medico_exequatur,
               m.email as medico_email
        FROM facturas f
        LEFT JOIN ars a
          ON f.ars_id = a.id AND a.tenant_id = f.tenant_id
        LEFT JOIN medicos m
          ON f.medico_id = m.id AND m.tenant_id = f.tenant_id
        WHERE f.id = %s AND f.tenant_id = %s
    ''', (factura_id, tenant_id))
    
    if not factura:
        flash('Factura no encontrada', 'error')
        return redirect(url_for('facturacion_historico'))
    
    if REPORTLAB_AVAILABLE:
        try:
            # Generar PDF usando la función auxiliar
            buffer = generar_pdf_factura_vista_previa(factura_id, tenant_id)
            
            if not buffer:
                flash('Error al generar PDF', 'error')
                return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))
            
            pdf_data = buffer.getvalue()
            from services.tenant_mail import enviar_correo_consultorio
            from services.email_content import correo_factura_clinica

            asunto, texto, html = correo_factura_clinica(
                factura.get('numero_factura', factura_id),
                factura.get('fecha_emision', ''),
                factura.get('ncf', ''),
                f"{float(factura.get('total') or 0):,.2f}",
                factura.get('medico_nombre') or factura.get('nombre_ars'),
            )
            ok, detalle = enviar_correo_consultorio(
                tenant_id,
                destinatario,
                asunto,
                html,
                texto=texto,
                adjuntos=[(
                    f"factura_{factura_id}_{factura.get('numero_factura', '')}.pdf",
                    pdf_data,
                    'application/pdf',
                )],
            )
            flash(
                f'Factura enviada exitosamente a {destinatario}' if ok else detalle,
                'success' if ok else 'error',
            )
            
        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            print(f"Error al enviar email: {error_trace}")
            flash(f'Error al enviar email: {str(e)}', 'error')
    else:
        flash('El servicio de envío de emails no está disponible. Contacte al administrador.', 'error')
    
    return redirect(url_for('facturacion_ver_factura', factura_id=factura_id))
