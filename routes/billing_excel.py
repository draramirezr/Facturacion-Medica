"""Plantilla Excel de consultas y su importación masiva."""
import logging
import os
import zipfile
from datetime import date, datetime
from io import BytesIO
from flask import flash, jsonify, redirect, request, send_file, url_for
from flask_login import current_user, login_required
from auth import permission_required
from core.database import execute_query
from core.tenant import get_current_tenant_id
from core.clock import fecha_clinica
from routes.billing_common import FECHA_MIN_CONSULTA_DIAS, _RE_AUTORIZACION, _RE_NOMBRE, _RE_NSS, _RE_TEXTO_GENERAL, _monto, _validate_or_raise, fecha_minima_consulta_rd
try:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill, Protection
    from openpyxl.utils import get_column_letter
    from openpyxl.worksheet.datavalidation import DataValidation
    OPENPYXL_AVAILABLE = True
except ImportError:
    OPENPYXL_AVAILABLE = False

logger = logging.getLogger(__name__)


@login_required
@permission_required('facturacion.crear')
def descargar_plantilla_excel():
    """Descargar plantilla Excel para importar pacientes"""
    try:
        if not OPENPYXL_AVAILABLE:
            flash('La funcionalidad de Excel no está disponible', 'error')
            return redirect(url_for('facturacion_facturas_nueva'))
        
        tenant_id = get_current_tenant_id()
        if tenant_id is None:
            flash('Error al obtener el tenant', 'error')
            return redirect(url_for('facturacion_facturas_nueva'))
        
        # Obtener tema del usuario
        TEMAS = {
            'cyan': {'primary': '#06B6D4', 'primary_dark': '#0891B2'},
            'ocean': {'primary': '#0EA5E9', 'primary_dark': '#0284C7'},
            'emerald': {'primary': '#10B981', 'primary_dark': '#059669'},
            'teal': {'primary': '#14B8A6', 'primary_dark': '#0D9488'},
            'coral': {'primary': '#FF6B6B', 'primary_dark': '#EE5A52'},
            'sunset': {'primary': '#F59E0B', 'primary_dark': '#D97706'},
            'rose': {'primary': '#F43F5E', 'primary_dark': '#E11D48'},
            'amber': {'primary': '#F59E0B', 'primary_dark': '#D97706'},
            'indigo': {'primary': '#6366F1', 'primary_dark': '#4F46E5'},
            'purple': {'primary': '#A855F7', 'primary_dark': '#9333EA'},
            'violet': {'primary': '#8B5CF6', 'primary_dark': '#7C3AED'},
            'slate': {'primary': '#64748B', 'primary_dark': '#475569'},
            'navy': {'primary': '#1E3A8A', 'primary_dark': '#1E40AF'},
            'forest': {'primary': '#166534', 'primary_dark': '#14532D'},
            'wine': {'primary': '#7F1D1D', 'primary_dark': '#991B1B'},
            'bronze': {'primary': '#92400E', 'primary_dark': '#78350F'}
        }
        
        tema_actual = 'cyan'  # Default
        if current_user.is_authenticated and hasattr(current_user, 'tema_color') and current_user.tema_color:
            tema_actual = current_user.tema_color
        
        # Asegurar que tema_actual sea válido
        if tema_actual not in TEMAS:
            tema_actual = 'cyan'
        
        tema = TEMAS.get(tema_actual, TEMAS['cyan'])
        if not tema or 'primary' not in tema:
            tema = TEMAS['cyan']
        
        color_primary = tema.get('primary', '#06B6D4')
        if not color_primary:
            color_primary = '#06B6D4'
        
        # Convertir color hexadecimal a formato de openpyxl (sin #)
        color_hex_clean = color_primary.lstrip('#')
        if not color_hex_clean:
            color_hex_clean = '06B6D4'
        
        # Convertir color hexadecimal a RGB
        def hex_to_rgb(hex_color):
            if not hex_color:
                hex_color = '#06B6D4'
            hex_color = hex_color.lstrip('#')
            if not hex_color or len(hex_color) < 6:
                hex_color = '06B6D4'
            try:
                return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
            except Exception:
                return (6, 182, 212)  # Color cyan por defecto
        
        rgb_color = hex_to_rgb(color_primary)
        
        # Obtener servicios activos del tenant
        try:
            servicios_result = execute_query(
                'SELECT descripcion FROM servicios WHERE tenant_id = %s AND activo = 1 ORDER BY descripcion', 
                (tenant_id,), fetch='all'
            )
            if servicios_result is None:
                servicios_list = []
            elif isinstance(servicios_result, list):
                servicios_list = [s for s in servicios_result if s and isinstance(s, dict)]
            else:
                servicios_list = []
        except Exception as e:
            servicios_list = []
        
        # Crear workbook
        wb = Workbook()
        
        # Eliminar hoja por defecto (si existe)
        if wb.active is not None:
            try:
                wb.remove(wb.active)
            except Exception:
                pass  # Si hay error al eliminar, continuar
    
        # ========== HOJA 1: INSTRUCCIONES ==========
        ws_instrucciones = wb.create_sheet("Instrucciones", 0)
        if ws_instrucciones is None:
            raise ValueError("No se pudo crear la hoja de Instrucciones")
        
        # Título
        title_cell = ws_instrucciones.cell(row=1, column=1, value="INSTRUCCIONES PARA CARGAR PACIENTES")
        title_cell.font = Font(bold=True, size=16, color="8B5A9F")
        ws_instrucciones.merge_cells('A1:D1')
        
        hoy_rd = fecha_clinica()
        min_rd = fecha_minima_consulta_rd(hoy_rd)
        # Instrucciones numeradas
        instrucciones = [
            "Complete la hoja \"Pacientes\" con los datos de los pacientes",
            "NSS: Solo números y guiones (ej: 001-234-5678)",
            "NOMBRE: Solo letras, espacios, punto y guion (mayúsculas)",
            (
                f"FECHA: Formato AAAA-MM-DD o DD/MM/AAAA. "
                f"Rango permitido: últimos {FECHA_MIN_CONSULTA_DIAS} días "
                f"hasta hoy ({min_rd.strftime('%Y-%m-%d')} a {hoy_rd.strftime('%Y-%m-%d')})"
            ),
            "AUTORIZACIÓN: Letras, números y guiones; única por NSS+fecha+ARS",
            "SERVICIO: Seleccione de la lista desplegable (se alimenta de la hoja \"Servicios\")",
            "MONTO: Cantidad en pesos mayor a cero (solo números)"
        ]
        
        row = 3
        if instrucciones and isinstance(instrucciones, list):
            for i, instruccion in enumerate(instrucciones, 1):
                if instruccion is not None:
                    num_cell = ws_instrucciones.cell(row=row, column=1, value=f"{i}.")
                    num_cell.font = Font(bold=True)
                    text_cell = ws_instrucciones.cell(row=row, column=2, value=instruccion)
                    ws_instrucciones.merge_cells(f'B{row}:D{row}')
                    row += 1
        
        # Sección IMPORTANTE
        row += 1
        importante_cell = ws_instrucciones.cell(row=row, column=1, value="IMPORTANTE:")
        importante_cell.font = Font(bold=True, size=12, color="8B5A9F")
        row += 1
        
        importantes = [
            "Los encabezados están protegidos y NO se pueden modificar",
            "La columna SERVICIO tiene lista desplegable - haga clic en la flecha para seleccionar",
            f"La fecha no puede ser futura ni anterior a {FECHA_MIN_CONSULTA_DIAS} días",
            "No se permiten caracteres especiales fuera de los permitidos por campo",
            "Complete directamente desde la fila 2"
        ]
        
        if importantes and isinstance(importantes, list):
            for importante in importantes:
                if importante is not None:
                    bullet_cell = ws_instrucciones.cell(row=row, column=1, value="•")
                    bullet_cell.font = Font(bold=True)
                    text_cell = ws_instrucciones.cell(row=row, column=2, value=importante)
                    ws_instrucciones.merge_cells(f'B{row}:D{row}')
                    row += 1
        
        # Sección NOTA
        row += 1
        nota_title = ws_instrucciones.cell(row=row, column=1, value="NOTA:")
        nota_title.font = Font(bold=True, size=12, color="8B5A9F")
        row += 1
        nota_text = ws_instrucciones.cell(row=row, column=1, value="Antes de cargar, debe seleccionar el Médico y ARS en la página web")
        ws_instrucciones.merge_cells(f'A{row}:D{row}')
        
        # Ajustar ancho de columnas
        ws_instrucciones.column_dimensions['A'].width = 5
        ws_instrucciones.column_dimensions['B'].width = 80
        ws_instrucciones.column_dimensions['C'].width = 10
        ws_instrucciones.column_dimensions['D'].width = 10
        
        # Proteger hoja de instrucciones
        try:
            if ws_instrucciones is not None:
                # Iterar sobre las filas que tienen datos
                rows_iter = ws_instrucciones.iter_rows(min_row=1, max_row=100)
                if rows_iter is not None:
                    for row in rows_iter:
                        if row is not None:
                            for cell in row:
                                if cell is not None:
                                    cell.protection = Protection(locked=True)
            if ws_instrucciones is not None:
                ws_instrucciones.protection.sheet = True
        except Exception as e:
            # Si hay error, solo activar la protección sin bloquear celdas
            try:
                if ws_instrucciones is not None:
                    ws_instrucciones.protection.sheet = True
            except:
                pass
        
        # ========== HOJA 2: SERVICIOS ==========
        ws_servicios = wb.create_sheet("Servicios", 1)
        if ws_servicios is None:
            raise ValueError("No se pudo crear la hoja de Servicios")
        
        # Encabezado (usar color del tema del usuario)
        header_cell = ws_servicios.cell(row=1, column=1, value="SERVICIOS DISPONIBLES")
        header_cell.font = Font(bold=True, size=14, color="FFFFFF")
        header_cell.fill = PatternFill(start_color=color_hex_clean, end_color=color_hex_clean, fill_type="solid")
        header_cell.alignment = Alignment(horizontal="center", vertical="center")
        ws_servicios.merge_cells('A1:B1')
        
        # Encabezados de tabla
        ws_servicios.cell(row=2, column=1, value="Servicio").font = Font(bold=True)
        ws_servicios.cell(row=2, column=1).fill = PatternFill(start_color="E0E0E0", end_color="E0E0E0", fill_type="solid")
        
        # Agregar servicios
        if servicios_list and isinstance(servicios_list, list) and len(servicios_list) > 0:
            try:
                for idx, servicio in enumerate(servicios_list, 3):
                    if servicio and isinstance(servicio, dict):
                        descripcion = servicio.get('descripcion', '')
                        if descripcion:
                            ws_servicios.cell(row=idx, column=1, value=descripcion)
            except Exception as e:
                ws_servicios.cell(row=3, column=1, value="Error al cargar servicios")
        else:
            ws_servicios.cell(row=3, column=1, value="No hay servicios disponibles")
        
        # Ajustar ancho
        ws_servicios.column_dimensions['A'].width = 50
        ws_servicios.column_dimensions['B'].width = 10
        
        # Proteger hoja de servicios
        try:
            if ws_servicios is not None:
                # Iterar sobre las filas que tienen datos
                rows_iter = ws_servicios.iter_rows(min_row=1, max_row=100)
                if rows_iter is not None:
                    for row in rows_iter:
                        if row is not None:
                            for cell in row:
                                if cell is not None:
                                    cell.protection = Protection(locked=True)
            if ws_servicios is not None:
                ws_servicios.protection.sheet = True
        except Exception as e:
            # Si hay error, solo activar la protección sin bloquear celdas
            try:
                if ws_servicios is not None:
                    ws_servicios.protection.sheet = True
            except:
                pass
        
        # ========== HOJA 3: PACIENTES ==========
        ws = wb.create_sheet("Pacientes", 2)
        if ws is None:
            raise ValueError("No se pudo crear la hoja de Pacientes")
        
        # Estilos para encabezados (usar color del tema del usuario)
        header_fill = PatternFill(start_color=color_hex_clean, end_color=color_hex_clean, fill_type="solid")
        header_font = Font(bold=True, color="FFFFFF", size=12)
        header_alignment = Alignment(horizontal="center", vertical="center")
        
        # Primero, desbloquear TODAS las celdas por defecto
        # Luego bloquearemos solo la fila 1 (encabezado)
        if ws is not None:
            try:
                # Desbloquear todas las celdas primero (fila 2 en adelante, hasta fila 1000)
                for row_num in range(2, 1001):
                    for col_num in range(1, 7):  # 6 columnas (A-F)
                        try:
                            cell = ws.cell(row=row_num, column=col_num)
                            if cell is not None:
                                cell.protection = Protection(locked=False)
                        except Exception:
                            pass
            except Exception:
                pass
        
        # Encabezados (bloqueados) - Solo la fila 1 estará protegida
        headers = ['NSS', 'Nombre Completo', 'Fecha', 'Autorización', 'Servicio', 'Monto']
        if headers and isinstance(headers, list):
            for col_num, header in enumerate(headers, 1):
                if header is not None:
                    cell = ws.cell(row=1, column=col_num, value=header)
                    cell.fill = header_fill
                    cell.font = header_font
                    cell.alignment = header_alignment
                    cell.protection = Protection(locked=True)  # Bloquear solo el encabezado
        
        # No agregar fila de ejemplo - el usuario llenará desde la fila 2
        
        # Validación de datos: Lista desplegable para SERVICIO (columna E)
        servicios_nombres = []
        if servicios_list and isinstance(servicios_list, list) and len(servicios_list) > 0:
            try:
                # Validar cada elemento antes de procesarlo
                for s in servicios_list:
                    if s is not None and isinstance(s, dict):
                        descripcion = s.get('descripcion', '')
                        if descripcion:
                            servicios_nombres.append(descripcion)
            except Exception as e:
                servicios_nombres = []
            
            if servicios_nombres and len(servicios_nombres) > 0:
                # Crear referencia a la hoja Servicios
                servicios_range = f"Servicios!$A$3:$A${2 + len(servicios_nombres)}"
                dv_servicio = DataValidation(type="list", formula1=servicios_range, allow_blank=False)
                dv_servicio.error = "Seleccione un servicio de la lista"
                dv_servicio.errorTitle = "Servicio inválido"
                dv_servicio.prompt = "Seleccione un servicio de la lista desplegable"
                dv_servicio.promptTitle = "Seleccionar Servicio"
                # Aplicar a toda la columna E (Servicio) desde la fila 2
                ws.add_data_validation(dv_servicio)
                dv_servicio.add(f"E2:E1048576")  # Aplicar a toda la columna E desde fila 2
        
        # Validación de datos: Autorización (columna D) — alfanumérico + guiones
        dv_autorizacion = DataValidation(
            type="custom",
            formula1="COUNTIF($D:$D,D2)=1",
            allow_blank=True,
        )
        dv_autorizacion.error = "Esta autorización ya existe en la plantilla."
        dv_autorizacion.errorTitle = "Autorización duplicada"
        dv_autorizacion.prompt = "Obligatoria. Letras, números y guiones"
        dv_autorizacion.promptTitle = "Autorización"
        ws.add_data_validation(dv_autorizacion)
        dv_autorizacion.add('D2:D1048576')

        # Validación de fecha: últimos 45 días hasta hoy (RD)
        dv_fecha = DataValidation(
            type='date',
            operator='between',
            formula1=f'DATE({min_rd.year},{min_rd.month},{min_rd.day})',
            formula2=f'DATE({hoy_rd.year},{hoy_rd.month},{hoy_rd.day})',
            allow_blank=False,
        )
        dv_fecha.error = (
            f'La FECHA debe ser válida. No puede ser futura ni anterior a '
            f'{FECHA_MIN_CONSULTA_DIAS} días.'
        )
        dv_fecha.errorTitle = 'Fecha inválida'
        dv_fecha.prompt = (
            f'Seleccione una fecha. Rango: últimos {FECHA_MIN_CONSULTA_DIAS} días hasta hoy.'
        )
        dv_fecha.promptTitle = 'Fecha de consulta'
        ws.add_data_validation(dv_fecha)
        dv_fecha.add('C2:C1048576')

        # Validación de datos: Solo números para MONTO (columna F)
        dv_monto = DataValidation(type="decimal", operator="greaterThan", formula1=0, allow_blank=False)
        dv_monto.error = "El monto debe ser un número mayor a cero"
        dv_monto.errorTitle = "Monto inválido"
        dv_monto.prompt = "Ingrese solo números (ej: 500.00)"
        dv_monto.promptTitle = "Monto"
        ws.add_data_validation(dv_monto)
        dv_monto.add(f"F2:F1048576")  # Aplicar a toda la columna F desde fila 2
        
        # Ajustar ancho de columnas
        column_widths = [15, 35, 12, 15, 30, 12]
        if column_widths and isinstance(column_widths, list):
            for col_num, width in enumerate(column_widths, 1):
                if width is not None:
                    try:
                        ws.column_dimensions[get_column_letter(col_num)].width = width
                    except Exception:
                        pass
        
        # Proteger la hoja - Solo el encabezado (fila 1) estará protegido
        # Las celdas de datos (fila 2 en adelante) permanecerán desbloqueadas
        try:
            if ws is not None and hasattr(ws, 'protection') and ws.protection is not None:
                ws.protection.sheet = True
                ws.protection.password = None
                ws.protection.formatCells = False
                ws.protection.formatColumns = False
                ws.protection.formatRows = False
                ws.protection.insertColumns = True
                ws.protection.insertRows = True
                ws.protection.insertHyperlinks = True
                ws.protection.deleteColumns = True
                ws.protection.deleteRows = True
                ws.protection.selectLockedCells = True
                ws.protection.sort = True
                ws.protection.autoFilter = True
                ws.protection.pivotTables = True
                ws.protection.selectUnlockedCells = True
            elif ws is not None:
                # Si protection no existe, solo activar la protección básica
                ws.protection.sheet = True
        except Exception as e:
            # Si hay error con la protección, continuar sin ella (no es crítico)
            try:
                if ws is not None:
                    ws.protection.sheet = True
            except:
                pass
    
        # Guardar en BytesIO
        output = BytesIO()
        wb.save(output)
        output.seek(0)
        
        # Nombre del archivo
        filename = 'plantilla_pacientes.xlsx'
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )
    except TypeError as e:
        import traceback
        error_details = traceback.format_exc()
        flash(f'Error al generar la plantilla: {str(e)}. Detalles: {error_details[:200]}', 'error')
        return redirect(url_for('facturacion_facturas_nueva'))
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        flash(f'Error inesperado al generar la plantilla: {str(e)}. Detalles: {error_details[:200]}', 'error')
        return redirect(url_for('facturacion_facturas_nueva'))


@login_required
@permission_required('facturacion.crear')
def facturacion_procesar_excel():
    """Procesar archivo Excel y devolver pacientes en formato JSON"""
    try:
        if not OPENPYXL_AVAILABLE:
            return jsonify({
                'error': True,
                'mensaje': 'La funcionalidad de Excel no está disponible',
                'errores': ['OpenPyXL no está instalado'],
                'total_errores': 1
            }), 400
        
        # Verificar que se haya enviado un archivo
        if 'archivo_excel' not in request.files:
            return jsonify({
                'error': True,
                'mensaje': 'No se recibió ningún archivo',
                'errores': ['Debe seleccionar un archivo Excel'],
                'total_errores': 1
            }), 400
        
        file = request.files['archivo_excel']
        if file.filename == '':
            return jsonify({
                'error': True,
                'mensaje': 'No se seleccionó ningún archivo',
                'errores': ['Debe seleccionar un archivo Excel'],
                'total_errores': 1
            }), 400
        
        # OpenPyXL solo procesa el formato OOXML (.xlsx).
        if not file.filename.lower().endswith('.xlsx'):
            return jsonify({
                'error': True,
                'mensaje': 'Formato de archivo inválido',
                'errores': ['El archivo debe ser .xlsx'],
                'total_errores': 1
            }), 400

        if not zipfile.is_zipfile(file.stream):
            return jsonify({
                'error': True,
                'mensaje': 'Archivo Excel inválido',
                'errores': ['El contenido no corresponde a un archivo .xlsx válido'],
                'total_errores': 1
            }), 400
        file.stream.seek(0)

        # Leer el archivo Excel
        from openpyxl import load_workbook
        wb = load_workbook(file, data_only=True, read_only=True)
        
        # Buscar la hoja "Pacientes"
        if 'Pacientes' not in wb.sheetnames:
            return jsonify({
                'error': True,
                'mensaje': 'Hoja "Pacientes" no encontrada',
                'errores': ['El archivo Excel debe contener una hoja llamada "Pacientes"'],
                'total_errores': 1
            }), 400
        
        ws = wb['Pacientes']
        max_excel_rows = int(os.getenv('MAX_EXCEL_ROWS', '5000'))
        if ws.max_row and ws.max_row - 1 > max_excel_rows:
            wb.close()
            return jsonify({
                'error': True,
                'mensaje': 'El archivo supera el límite permitido',
                'errores': [f'Máximo permitido: {max_excel_rows} pacientes'],
                'total_errores': 1
            }), 400
        
        # Obtener tenant_id
        tenant_id = get_current_tenant_id()
        if not tenant_id:
            return jsonify({
                'error': True,
                'mensaje': 'Error al obtener el tenant',
                'errores': ['No se pudo identificar la empresa'],
                'total_errores': 1
            }), 400
        
        # Obtener servicios válidos del tenant
        servicios_result = execute_query(
            'SELECT descripcion FROM servicios WHERE tenant_id = %s AND activo = 1',
            (tenant_id,), fetch='all'
        ) or []
        servicios_validos = [s['descripcion'].upper() for s in servicios_result if s and s.get('descripcion')]
        
        # Leer datos desde la fila 2 (la fila 1 es el encabezado)
        pacientes = []
        errores = []
        claves_vistas = set()
        numero_fila = 1
        hoy_rd = fecha_clinica()
        min_rd = fecha_minima_consulta_rd(hoy_rd)

        for row in ws.iter_rows(min_row=2, values_only=False):
            numero_fila += 1
            
            # Obtener valores de las celdas
            nss = str(row[0].value).strip() if row[0].value else ''  # Columna A
            nombre = str(row[1].value).strip() if row[1].value else ''  # Columna B
            # Fecha puede venir como datetime de Excel o como string
            fecha_raw = row[2].value if row[2].value else ''
            if fecha_raw:
                if isinstance(fecha_raw, (datetime, date)):
                    fecha = fecha_raw.strftime('%Y-%m-%d')
                else:
                    fecha = str(fecha_raw).strip()
            else:
                fecha = ''
            autorizacion = str(row[3].value).strip() if row[3].value else ''  # Columna D
            servicio = str(row[4].value).strip() if row[4].value else ''  # Columna E
            monto = row[5].value if row[5].value else ''  # Columna F
            
            # Si la fila está vacía, saltarla
            if not nss and not nombre and not fecha and not autorizacion and not servicio and not monto:
                continue
            
            # Validaciones
            errores_fila = []
            fecha_obj = None

            try:
                nss = _validate_or_raise(nss, _RE_NSS, 'NSS', idx=numero_fila, max_len=20)
            except ValueError as error:
                errores_fila.append(str(error).replace(f'Línea {numero_fila}:', f'Fila {numero_fila}:'))

            try:
                nombre = _validate_or_raise(
                    nombre, _RE_NOMBRE, 'Nombre', idx=numero_fila, max_len=200
                )
            except ValueError as error:
                errores_fila.append(str(error).replace(f'Línea {numero_fila}:', f'Fila {numero_fila}:'))

            try:
                autorizacion = _validate_or_raise(
                    autorizacion,
                    _RE_AUTORIZACION,
                    'Autorización',
                    idx=numero_fila,
                    max_len=50,
                    required=True,
                )
            except ValueError as error:
                errores_fila.append(str(error).replace(f'Línea {numero_fila}:', f'Fila {numero_fila}:'))

            try:
                servicio = _validate_or_raise(
                    servicio, _RE_TEXTO_GENERAL, 'Servicio', idx=numero_fila, max_len=200
                )
            except ValueError as error:
                errores_fila.append(str(error).replace(f'Línea {numero_fila}:', f'Fila {numero_fila}:'))

            # Validar y normalizar Fecha
            if not fecha:
                errores_fila.append(f'Fila {numero_fila}: Fecha es obligatoria')
            else:
                try:
                    fecha_normalizada = None
                    try:
                        datetime.strptime(fecha, '%Y-%m-%d')
                        fecha_normalizada = fecha
                    except ValueError:
                        fecha_str = fecha.replace('/', '-').strip()
                        formatos_fecha = [
                            '%Y-%m-%d',
                            '%d-%m-%Y',
                            '%m-%d-%Y',
                            '%Y/%m/%d',
                            '%d/%m/%Y',
                            '%m/%d/%Y',
                        ]
                        parsed = None
                        for formato in formatos_fecha:
                            try:
                                parsed = datetime.strptime(fecha_str, formato)
                                break
                            except ValueError:
                                continue
                        if parsed:
                            fecha_normalizada = parsed.strftime('%Y-%m-%d')
                        else:
                            raise ValueError(f'No se pudo parsear la fecha: {fecha}')

                    fecha_obj = date.fromisoformat(fecha_normalizada)
                    fecha = fecha_normalizada
                    if fecha_obj > hoy_rd:
                        errores_fila.append(
                            f'Fila {numero_fila}: La fecha de consulta no puede ser futura'
                        )
                    elif fecha_obj < min_rd:
                        errores_fila.append(
                            f'Fila {numero_fila}: La fecha no puede ser anterior a '
                            f'{FECHA_MIN_CONSULTA_DIAS} días '
                            f'(mínimo {min_rd.strftime("%Y-%m-%d")})'
                        )
                except Exception:
                    errores_fila.append(
                        f'Fila {numero_fila}: Fecha inválida "{fecha}" '
                        '(formato esperado: AAAA-MM-DD o DD/MM/AAAA)'
                    )

            if servicios_validos and servicio and servicio.upper() not in servicios_validos:
                errores_fila.append(
                    f'Fila {numero_fila}: Servicio "{servicio}" no existe. '
                    f'Servicios válidos: {", ".join(servicios_validos[:5])}...'
                )

            # Validar Monto
            try:
                if monto == '' or monto is None:
                    errores_fila.append(f'Fila {numero_fila}: Monto es obligatorio')
                else:
                    monto_float = _monto(monto)
                    if monto_float <= 0:
                        errores_fila.append(f'Fila {numero_fila}: Monto debe ser mayor a cero')
            except (ValueError, TypeError):
                errores_fila.append(f'Fila {numero_fila}: Monto inválido (debe ser un número)')

            if fecha_obj and nss and not errores_fila:
                clave = (nss, fecha, autorizacion)
                if clave in claves_vistas:
                    errores_fila.append(
                        f'Fila {numero_fila}: Registro duplicado en el Excel '
                        f'(NSS {nss}, fecha {fecha}, autorización {autorizacion or "(vacía)"})'
                    )
                else:
                    claves_vistas.add(clave)

            # Si hay errores en esta fila, agregarlos y continuar
            if errores_fila:
                errores.extend(errores_fila)
                continue
            
            # Si no hay errores, agregar el paciente
            pacientes.append({
                'nss': nss,
                'nombre': nombre,
                'fecha': fecha,
                'autorizacion': autorizacion,
                'servicio': servicio,
                'monto': float(_monto(monto))
            })
        
        # Si hay errores, devolverlos
        if errores:
            wb.close()
            return jsonify({
                'error': True,
                'mensaje': f'Se encontraron {len(errores)} error(es) en el archivo',
                'errores': errores,
                'total_errores': len(errores),
                'pacientes': []
            }), 400
        
        # Si no hay pacientes, devolver error
        if not pacientes:
            wb.close()
            return jsonify({
                'error': True,
                'mensaje': 'No se encontraron pacientes válidos en el archivo',
                'errores': ['El archivo Excel no contiene datos válidos en la hoja "Pacientes"'],
                'total_errores': 1,
                'pacientes': []
            }), 400
        
        # Si todo está bien, devolver los pacientes
        wb.close()
        return jsonify({
            'error': False,
            'mensaje': f'Se procesaron {len(pacientes)} paciente(s) correctamente',
            'pacientes': pacientes,
            'total': len(pacientes)
        }), 200
        
    except Exception as e:
        logger.error('Error al procesar archivo Excel', exc_info=True)
        return jsonify({
            'error': True,
            'mensaje': 'No fue posible procesar el archivo',
            'errores': ['Verifica el formato y vuelve a intentarlo'],
            'total_errores': 1,
        }), 500
