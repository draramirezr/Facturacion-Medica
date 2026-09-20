"""Rutas y helpers de pacientes."""

import re
from datetime import datetime
from io import BytesIO

from flask import flash, jsonify, redirect, render_template, request, send_file, url_for
from flask_login import login_required

from auth import permission_required
from core.database import execute_query, execute_update
from core.tenant import get_current_tenant_id
from routes.support import (
    execute_paginated_query, sanitize_input, validate_digits, validate_email,
    validate_int,
)

try:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter
    OPENPYXL_AVAILABLE = True
except ImportError:
    OPENPYXL_AVAILABLE = False

@login_required
@permission_required('pacientes.ver')
def facturacion_pacientes():
    """Lista de pacientes - Filtrado por tenant"""
    tenant_id = get_current_tenant_id()
    search = request.args.get('search', '').strip()
    
    query = '''
        SELECT p.*, a.nombre as ars_nombre 
        FROM pacientes p
        LEFT JOIN ars a
          ON p.ars_id = a.id AND a.tenant_id = p.tenant_id
        WHERE p.tenant_id = %s
    '''
    params = [tenant_id]
    
    if search:
        query += (' AND (p.nombre LIKE %s OR p.nss LIKE %s OR p.cedula LIKE %s '
                  'OR REPLACE(REPLACE(REPLACE(REPLACE(REPLACE('
                  "COALESCE(p.telefono,''),'-',''),' ',''),'(',''),')',''),'+','') "
                  'LIKE %s OR REPLACE(REPLACE(REPLACE(REPLACE(REPLACE('
                  "COALESCE(p.telefono_pariente,''),'-',''),' ',''),'(',''),')',''),'+','') "
                  'LIKE %s)')
        search_pattern = f'%{search}%'
        phone_digits = re.sub(r'\D', '', search)
        phone_pattern = f'%{phone_digits}%' if phone_digits else search_pattern
        params.extend([
            search_pattern, search_pattern, search_pattern,
            phone_pattern, phone_pattern
        ])
    
    if search:
        query += ' ORDER BY p.nombre, p.id LIMIT 50'
    else:
        query += ' ORDER BY p.created_at DESC, p.id DESC LIMIT 10'
    pacientes_list = execute_query(
        query,
        tuple(params),
        fetch='all',
    ) or []
    return render_template(
        'facturacion/pacientes.html',
        pacientes_list=pacientes_list,
        search=search,
    )

@login_required
@permission_required('pacientes.crear')
def facturacion_pacientes_nuevo():
    """Crear un paciente manualmente."""
    tenant_id = get_current_tenant_id()

    if request.method == 'POST':
        nombre = sanitize_input(request.form.get('nombre', ''), 200)
        cedula = sanitize_input(request.form.get('cedula', ''), 20)
        nss = sanitize_input(request.form.get('nss', ''), 50)
        telefono = sanitize_input(request.form.get('telefono', ''), 20)
        email = request.form.get('email', '').strip().lower()
        direccion = sanitize_input(request.form.get('direccion', ''), 500)
        fecha_nacimiento = request.form.get('fecha_nacimiento') or None
        sexo = request.form.get('sexo') or None
        ars_id = request.form.get('ars_id') or None
        es_asegurado = request.form.get('es_asegurado') == '1'
        nombre_pariente = sanitize_input(request.form.get('nombre_pariente', ''), 200)
        cedula_pariente = sanitize_input(request.form.get('cedula_pariente', ''), 20)
        telefono_pariente = sanitize_input(request.form.get('telefono_pariente', ''), 20)
        parentesco = sanitize_input(request.form.get('parentesco', ''), 50)

        if (not nombre or not telefono or not email or not direccion or
                not fecha_nacimiento or not sexo):
            flash('Todos los campos del paciente son obligatorios', 'error')
            return redirect(url_for('facturacion_pacientes_nuevo'))

        if cedula and not validate_digits(cedula, 11):
            flash('La cédula debe contener exactamente 11 números', 'error')
            return redirect(url_for('facturacion_pacientes_nuevo'))
        if not validate_digits(telefono, 10):
            flash('El teléfono debe contener exactamente 10 números', 'error')
            return redirect(url_for('facturacion_pacientes_nuevo'))
        if not validate_email(email):
            flash('Debe introducir un correo electrónico válido', 'error')
            return redirect(url_for('facturacion_pacientes_nuevo'))
        if sexo not in ['M', 'F', 'Otro']:
            flash('Debe seleccionar el sexo del paciente', 'error')
            return redirect(url_for('facturacion_pacientes_nuevo'))

        try:
            nacimiento = datetime.strptime(fecha_nacimiento, '%Y-%m-%d').date()
            hoy = datetime.now().date()
            if nacimiento > hoy:
                flash('La fecha de nacimiento no puede ser futura', 'error')
                return redirect(url_for('facturacion_pacientes_nuevo'))
            edad = hoy.year - nacimiento.year - (
                (hoy.month, hoy.day) < (nacimiento.month, nacimiento.day)
            )
        except ValueError:
            flash('La fecha de nacimiento no es válida', 'error')
            return redirect(url_for('facturacion_pacientes_nuevo'))

        if edad < 18:
            if not nombre_pariente or not cedula_pariente or not telefono_pariente or not parentesco:
                flash('El nombre, la cédula, el teléfono y el parentesco son obligatorios para menores de 18 años', 'error')
                return redirect(url_for('facturacion_pacientes_nuevo'))
            if not validate_digits(cedula_pariente, 11):
                flash('La cédula del pariente debe contener exactamente 11 números', 'error')
                return redirect(url_for('facturacion_pacientes_nuevo'))
            if not validate_digits(telefono_pariente, 10):
                flash('El teléfono del pariente debe contener exactamente 10 números', 'error')
                return redirect(url_for('facturacion_pacientes_nuevo'))
        else:
            if not cedula:
                flash('La cédula del paciente es obligatoria para mayores de edad', 'error')
                return redirect(url_for('facturacion_pacientes_nuevo'))
            nombre_pariente = ''
            cedula_pariente = ''
            telefono_pariente = ''
            parentesco = ''

        if es_asegurado:
            if not nss or not ars_id:
                flash('Para un paciente asegurado, el NSS y la ARS son obligatorios', 'error')
                return redirect(url_for('facturacion_pacientes_nuevo'))
            try:
                ars_id = int(ars_id)
            except (TypeError, ValueError):
                flash('Debe seleccionar una ARS válida', 'error')
                return redirect(url_for('facturacion_pacientes_nuevo'))
            ars_valida = execute_query(
                'SELECT id FROM ars WHERE id = %s AND tenant_id = %s AND activo = 1',
                (ars_id, tenant_id)
            )
            if not ars_valida:
                flash('La ARS seleccionada no es válida', 'error')
                return redirect(url_for('facturacion_pacientes_nuevo'))
        else:
            nss = ''
            ars_id = None

        cedula_existente = execute_query(
            'SELECT id FROM pacientes WHERE cedula = %s AND tenant_id = %s',
            (cedula, tenant_id)
        ) if cedula else None
        if cedula_existente:
            flash('Ya existe un paciente con esta cédula', 'error')
            return redirect(url_for('facturacion_pacientes_nuevo'))

        paciente_id = execute_update('''
            INSERT INTO pacientes (
                tenant_id, nombre, cedula, nss, telefono, email, direccion,
                fecha_nacimiento, sexo, nombre_pariente, cedula_pariente,
                telefono_pariente, parentesco, ars_id
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (
            tenant_id, nombre, cedula or None, nss or None, telefono, email, direccion,
            fecha_nacimiento, sexo, nombre_pariente or None, cedula_pariente or None,
            telefono_pariente or None, parentesco or None, ars_id
        ))
        flash('Paciente creado exitosamente', 'success')
        return redirect(url_for('facturacion_paciente_acciones', paciente_id=paciente_id))

    ars_list = execute_query(
        'SELECT * FROM ars WHERE activo = 1 AND tenant_id = %s ORDER BY nombre',
        (tenant_id,), fetch='all'
    ) or []
    return render_template('facturacion/paciente_form.html', paciente=None, ars_list=ars_list)

def paciente_adulto_sin_cedula(paciente):
    """Indicar si un paciente ya cumplió 18 años y requiere cédula propia."""
    if not paciente or paciente.get('cedula') or not paciente.get('fecha_nacimiento'):
        return False
    try:
        nacimiento = paciente['fecha_nacimiento']
        if isinstance(nacimiento, str):
            nacimiento = datetime.strptime(nacimiento, '%Y-%m-%d').date()
        hoy = datetime.now().date()
        edad = hoy.year - nacimiento.year - (
            (hoy.month, hoy.day) < (nacimiento.month, nacimiento.day)
        )
        return edad >= 18
    except (ValueError, TypeError):
        return False

@login_required
@permission_required('pacientes.ver')
def facturacion_paciente_acciones(paciente_id):
    """Mostrar los siguientes pasos después de crear un paciente."""
    tenant_id = get_current_tenant_id()
    paciente = execute_query(
        'SELECT id, nombre, cedula, fecha_nacimiento FROM pacientes WHERE id=%s AND tenant_id=%s',
        (paciente_id, tenant_id)
    )
    if not paciente:
        flash('Paciente no encontrado', 'error')
        return redirect(url_for('facturacion_pacientes'))
    return render_template(
        'facturacion/paciente_acciones.html',
        paciente=paciente,
        requiere_cedula=paciente_adulto_sin_cedula(paciente)
    )

@login_required
@permission_required('pacientes.editar')
def facturacion_paciente_actualizar_cedula(paciente_id):
    """Solicitar la cédula propia cuando un paciente alcanza la mayoría de edad."""
    tenant_id = get_current_tenant_id()
    paciente = execute_query(
        'SELECT id, cedula, fecha_nacimiento FROM pacientes WHERE id=%s AND tenant_id=%s',
        (paciente_id, tenant_id)
    )
    if not paciente:
        flash('Paciente no encontrado', 'error')
        return redirect(url_for('facturacion_pacientes'))
    if not paciente_adulto_sin_cedula(paciente):
        return redirect(url_for('facturacion_paciente_acciones', paciente_id=paciente_id))

    cedula = sanitize_input(request.form.get('cedula', ''), 20)
    if not validate_digits(cedula, 11):
        flash('La cédula del paciente debe contener exactamente 11 números', 'error')
        return redirect(url_for('facturacion_paciente_acciones', paciente_id=paciente_id))
    existente = execute_query(
        'SELECT id FROM pacientes WHERE cedula=%s AND tenant_id=%s AND id<>%s',
        (cedula, tenant_id, paciente_id)
    )
    if existente:
        flash('Esta cédula ya está registrada con otro paciente', 'error')
        return redirect(url_for('facturacion_paciente_acciones', paciente_id=paciente_id))

    execute_update(
        'UPDATE pacientes SET cedula=%s WHERE id=%s AND tenant_id=%s',
        (cedula, paciente_id, tenant_id)
    )
    flash('Cédula propia del paciente actualizada correctamente', 'success')
    return redirect(url_for('facturacion_paciente_acciones', paciente_id=paciente_id))

@login_required
@permission_required('pacientes.editar')
def facturacion_pacientes_editar(paciente_id):
    """Editar paciente"""
    tenant_id = get_current_tenant_id()
    paciente = execute_query('''
        SELECT p.*, a.nombre as ars_nombre 
        FROM pacientes p
        LEFT JOIN ars a
          ON p.ars_id = a.id AND a.tenant_id = p.tenant_id
        WHERE p.id = %s AND p.tenant_id = %s
    ''', (paciente_id, tenant_id))
    
    if not paciente:
        flash('Paciente no encontrado', 'error')
        return redirect(url_for('facturacion_pacientes'))
    
    if request.method == 'POST':
        nombre = sanitize_input(request.form.get('nombre', ''), 200)
        cedula = sanitize_input(request.form.get('cedula', ''), 20)
        nss = sanitize_input(request.form.get('nss', ''), 50)
        telefono = sanitize_input(request.form.get('telefono', ''), 20)
        email = request.form.get('email', '').strip().lower()
        direccion = request.form.get('direccion', '').strip()
        fecha_nacimiento = request.form.get('fecha_nacimiento') or None
        sexo = request.form.get('sexo') or None
        ars_id = request.form.get('ars_id') or None
        tipo_afiliacion = request.form.get('tipo_afiliacion') or None
        es_asegurado = request.form.get('es_asegurado') == '1'
        nombre_pariente = sanitize_input(request.form.get('nombre_pariente', ''), 200)
        cedula_pariente = sanitize_input(request.form.get('cedula_pariente', ''), 20)
        telefono_pariente = sanitize_input(request.form.get('telefono_pariente', ''), 20)
        parentesco = sanitize_input(request.form.get('parentesco', ''), 50)
        
        if (not nombre or not telefono or not email or not direccion or
                not fecha_nacimiento or not sexo):
            flash('Todos los campos del paciente son obligatorios', 'error')
            return redirect(url_for('facturacion_pacientes_editar', paciente_id=paciente_id))
        
        if cedula and not validate_digits(cedula, 11):
            flash('La cédula debe contener exactamente 11 números', 'error')
            return redirect(url_for('facturacion_pacientes_editar', paciente_id=paciente_id))

        if not validate_digits(telefono, 10):
            flash('El teléfono debe contener exactamente 10 números', 'error')
            return redirect(url_for('facturacion_pacientes_editar', paciente_id=paciente_id))

        if not validate_email(email):
            flash('Debe introducir un correo electrónico válido', 'error')
            return redirect(url_for('facturacion_pacientes_editar', paciente_id=paciente_id))

        if sexo not in ['M', 'F', 'Otro']:
            flash('Debe seleccionar el sexo del paciente', 'error')
            return redirect(url_for('facturacion_pacientes_editar', paciente_id=paciente_id))

        try:
            nacimiento = datetime.strptime(fecha_nacimiento, '%Y-%m-%d').date()
            hoy = datetime.now().date()
            if nacimiento > hoy:
                flash('La fecha de nacimiento no puede ser futura', 'error')
                return redirect(url_for('facturacion_pacientes_editar', paciente_id=paciente_id))
            edad = hoy.year - nacimiento.year - (
                (hoy.month, hoy.day) < (nacimiento.month, nacimiento.day)
            )
        except ValueError:
            flash('La fecha de nacimiento no es válida', 'error')
            return redirect(url_for('facturacion_pacientes_editar', paciente_id=paciente_id))

        if edad < 18:
            if not nombre_pariente or not cedula_pariente or not telefono_pariente or not parentesco:
                flash('El nombre, la cédula, el teléfono y el parentesco son obligatorios para menores de 18 años', 'error')
                return redirect(url_for('facturacion_pacientes_editar', paciente_id=paciente_id))
            if not validate_digits(cedula_pariente, 11):
                flash('La cédula del pariente debe contener exactamente 11 números', 'error')
                return redirect(url_for('facturacion_pacientes_editar', paciente_id=paciente_id))
            if not validate_digits(telefono_pariente, 10):
                flash('El teléfono del pariente debe contener exactamente 10 números', 'error')
                return redirect(url_for('facturacion_pacientes_editar', paciente_id=paciente_id))
        else:
            if not cedula:
                flash('La cédula del paciente es obligatoria para mayores de edad', 'error')
                return redirect(url_for('facturacion_pacientes_editar', paciente_id=paciente_id))
            nombre_pariente = ''
            cedula_pariente = ''
            telefono_pariente = ''
            parentesco = ''

        if es_asegurado:
            if not nss or not ars_id:
                flash('Para un paciente asegurado, el NSS y la ARS son obligatorios', 'error')
                return redirect(url_for('facturacion_pacientes_editar', paciente_id=paciente_id))
            try:
                ars_id = int(ars_id)
            except (TypeError, ValueError):
                flash('Debe seleccionar una ARS válida', 'error')
                return redirect(url_for('facturacion_pacientes_editar', paciente_id=paciente_id))

            ars_valida = execute_query(
                'SELECT id FROM ars WHERE id = %s AND tenant_id = %s AND activo = 1',
                (ars_id, tenant_id)
            )
            if not ars_valida:
                flash('La ARS seleccionada no es válida', 'error')
                return redirect(url_for('facturacion_pacientes_editar', paciente_id=paciente_id))
        else:
            nss = ''
            ars_id = None
        
        execute_update('''
            UPDATE pacientes 
            SET nombre = %s, cedula = %s, nss = %s, telefono = %s, email = %s, 
                direccion = %s, fecha_nacimiento = %s, sexo = %s,
                nombre_pariente = %s, cedula_pariente = %s, telefono_pariente = %s,
                parentesco = %s, ars_id = %s, tipo_afiliacion = %s
            WHERE id = %s AND tenant_id = %s
        ''', (nombre, cedula or None, nss or None, telefono or None, email or None, 
              direccion or None, fecha_nacimiento, sexo, nombre_pariente or None,
              cedula_pariente or None, telefono_pariente or None, parentesco or None,
              ars_id, tipo_afiliacion, paciente_id, tenant_id))
        
        flash('Paciente actualizado exitosamente', 'success')
        return redirect(url_for('facturacion_pacientes'))
    
    # Obtener lista de ARS para el dropdown
    ars_list = execute_query('SELECT * FROM ars WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    
    return render_template('facturacion/paciente_form.html', paciente=paciente, ars_list=ars_list)

@login_required
@permission_required('pacientes.eliminar')
def facturacion_pacientes_eliminar(paciente_id):
    """Eliminar paciente"""
    tenant_id = get_current_tenant_id()
    
    # Verificar que el paciente existe y pertenece al tenant
    paciente = execute_query('SELECT id FROM pacientes WHERE id = %s AND tenant_id = %s', (paciente_id, tenant_id))
    if not paciente:
        flash('Paciente no encontrado', 'error')
        return redirect(url_for('facturacion_pacientes'))
    
    # Eliminar el paciente
    execute_update('DELETE FROM pacientes WHERE id = %s AND tenant_id = %s', (paciente_id, tenant_id))
    
    flash('Paciente eliminado exitosamente', 'success')
    return redirect(url_for('facturacion_pacientes'))

@login_required
@permission_required('facturacion.editar')
def facturacion_pacientes_pendientes_eliminar(paciente_id):
    """Eliminar paciente pendiente"""
    tenant_id = get_current_tenant_id()

    paciente = execute_query(
        'SELECT id FROM pacientes_pendientes WHERE id = %s AND tenant_id = %s',
        (paciente_id, tenant_id),
    )
    if not paciente:
        flash('Registro no encontrado', 'error')
        return redirect(url_for('facturacion_pacientes_pendientes'))

    execute_update(
        'DELETE FROM pacientes_pendientes WHERE id = %s AND tenant_id = %s',
        (paciente_id, tenant_id),
    )
    
    flash('Registro eliminado exitosamente', 'success')
    return redirect(url_for('facturacion_pacientes_pendientes'))

@login_required
@permission_required('facturacion.ver')
def api_facturacion_pacientes_pendientes_get(paciente_id):
    """Obtener datos de un paciente pendiente para editar"""
    tenant_id = get_current_tenant_id()

    paciente = execute_query('''
        SELECT pp.*, a.nombre as ars_nombre, m.nombre as medico_nombre
        FROM pacientes_pendientes pp
        LEFT JOIN ars a
          ON pp.ars_id = a.id AND a.tenant_id = pp.tenant_id
        LEFT JOIN medicos m
          ON pp.medico_id = m.id AND m.tenant_id = pp.tenant_id
        WHERE pp.id = %s AND pp.tenant_id = %s
    ''', (paciente_id, tenant_id))
    
    if not paciente:
        return jsonify({'error': 'Registro no encontrado'}), 404
    
    # Extraer solo el servicio sin la autorización
    servicio_completo = paciente.get('servicios_realizados', '') or ''
    servicio = servicio_completo.split(' - Autorización:')[0].strip() if ' - Autorización:' in servicio_completo else servicio_completo.strip()
    autorizacion = ''
    if ' - Autorización:' in servicio_completo:
        partes = servicio_completo.split(' - Autorización:')
        if len(partes) > 1:
            autorizacion = partes[1].strip()
    
    # Formatear fecha para input type="date" (YYYY-MM-DD)
    fecha_servicio = paciente.get('fecha_servicio', '')
    if fecha_servicio:
        if isinstance(fecha_servicio, str):
            # Si es string, verificar formato y convertir si es necesario
            if '/' in fecha_servicio:
                # Formato MM/DD/YYYY o DD/MM/YYYY
                partes = fecha_servicio.split('/')
                if len(partes) == 3:
                    fecha_servicio = f"{partes[2]}-{partes[0].zfill(2)}-{partes[1].zfill(2)}"
            elif fecha_servicio.count('-') == 2 and len(fecha_servicio.split('-')[0]) == 2:
                # Formato DD-MM-YYYY
                partes = fecha_servicio.split('-')
                fecha_servicio = f"{partes[2]}-{partes[1]}-{partes[0]}"
        else:
            # Si es objeto date/datetime, convertir a string YYYY-MM-DD
            from datetime import date, datetime
            if isinstance(fecha_servicio, (date, datetime)):
                fecha_servicio = fecha_servicio.strftime('%Y-%m-%d')
    
    return jsonify({
        'id': paciente['id'],
        'nombre_paciente': paciente.get('nombre_paciente', ''),
        'nss': paciente.get('nss', ''),
        'fecha_servicio': fecha_servicio,
        'servicio': servicio,
        'autorizacion': autorizacion,
        'monto_estimado': float(paciente.get('monto_estimado', 0)),
        'estado': paciente.get('estado', 'pendiente'),
        'ars_id': paciente.get('ars_id'),
        'ars_nombre': paciente.get('ars_nombre', ''),
        'medico_id': paciente.get('medico_id'),
        'medico_nombre': paciente.get('medico_nombre', ''),
        'centro_medico_id': paciente.get('centro_medico_id'),
        'observaciones': paciente.get('observaciones', '')
    })

@login_required
@permission_required('facturacion.editar')
def api_facturacion_pacientes_pendientes_update(paciente_id):
    """Actualizar un paciente pendiente"""
    try:
        tenant_id = get_current_tenant_id()
        
        if not request.is_json:
            return jsonify({'error': 'Content-Type debe ser application/json'}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No se recibieron datos'}), 400
        
        # Validar datos
        nombre_paciente = sanitize_input(data.get('nombre_paciente', ''), 200)
        nss = sanitize_input(data.get('nss', ''), 50)
        fecha_servicio = data.get('fecha_servicio', '')
        servicio_completo = sanitize_input(data.get('servicio', ''), 500)  # Ya viene con autorización si existe
        
        try:
            monto_estimado = float(data.get('monto_estimado', 0))
        except (ValueError, TypeError):
            monto_estimado = 0.0
        
        ars_id = data.get('ars_id') or None
        medico_id = data.get('medico_id') or None
        centro_medico_id = data.get('centro_medico_id') or None
        
        # Manejar observaciones de forma segura
        observaciones = data.get('observaciones')
        if observaciones:
            observaciones = str(observaciones).strip()
            if not observaciones:
                observaciones = None
        else:
            observaciones = None
        
        if not nombre_paciente:
            return jsonify({'error': 'El nombre del paciente es obligatorio'}), 400
        
        if not fecha_servicio:
            return jsonify({'error': 'La fecha de servicio es obligatoria'}), 400

        paciente = execute_query(
            '''
            SELECT id
            FROM pacientes_pendientes
            WHERE id = %s AND tenant_id = %s
            ''',
            (paciente_id, tenant_id),
        )
        if not paciente:
            return jsonify({'error': 'Registro no encontrado'}), 404
        
        # El servicio ya viene completo con autorización desde el frontend
        servicios_realizados = servicio_completo
        
        # Convertir IDs a enteros si existen
        try:
            if ars_id:
                ars_id = int(ars_id)
        except (ValueError, TypeError):
            ars_id = None
            
        try:
            if medico_id:
                medico_id = int(medico_id)
        except (ValueError, TypeError):
            medico_id = None
            
        try:
            if centro_medico_id:
                centro_medico_id = int(centro_medico_id)
        except (ValueError, TypeError):
            centro_medico_id = None
        
        updated_id = execute_update('''
            UPDATE pacientes_pendientes
            SET nombre_paciente = %s, nss = %s, fecha_servicio = %s,
                servicios_realizados = %s, monto_estimado = %s,
                ars_id = %s, medico_id = %s, centro_medico_id = %s,
                observaciones = %s
            WHERE id = %s AND tenant_id = %s
        ''', (
            nombre_paciente, nss or None, fecha_servicio,
            servicios_realizados, monto_estimado, ars_id, medico_id,
            centro_medico_id, observaciones, paciente_id, tenant_id,
        ))
        if updated_id is None:
            return jsonify({'error': 'No se pudo actualizar el registro'}), 500
        
        return jsonify({'success': True, 'message': 'Registro actualizado exitosamente'})
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"Error al actualizar paciente pendiente: {error_trace}")
        return jsonify({'error': f'Error al actualizar: {str(e)}'}), 500
    
    return jsonify({'success': True, 'message': 'Registro actualizado exitosamente'})

@login_required
@permission_required('reportes.exportar')
def facturacion_pacientes_exportar_excel():
    """Exportar lista de pacientes a Excel"""
    if not OPENPYXL_AVAILABLE:
        flash('La funcionalidad de Excel no está disponible', 'error')
        return redirect(url_for('facturacion_pacientes'))
    
    tenant_id = get_current_tenant_id()
    search = request.args.get('search', '').strip()
    
    # Obtener pacientes con el mismo filtro que la vista
    query = '''
        SELECT p.*, a.nombre as ars_nombre 
        FROM pacientes p
        LEFT JOIN ars a
          ON p.ars_id = a.id AND a.tenant_id = p.tenant_id
        WHERE p.tenant_id = %s
    '''
    params = [tenant_id]
    
    if search:
        query += (
            ' AND (p.nombre LIKE %s OR p.nss LIKE %s OR p.cedula LIKE %s '
            'OR REPLACE(REPLACE(REPLACE(REPLACE(REPLACE('
            "COALESCE(p.telefono,''),'-',''),' ',''),'(',''),')',''),'+','') "
            'LIKE %s)'
        )
        search_pattern = f'%{search}%'
        phone_digits = re.sub(r'\D', '', search)
        phone_pattern = f'%{phone_digits}%' if phone_digits else search_pattern
        params.extend([
            search_pattern, search_pattern, search_pattern, phone_pattern,
        ])
    
    query += ' ORDER BY p.nombre'
    
    pacientes_list = execute_query(query, tuple(params), fetch='all') or []
    
    # Crear workbook
    wb = Workbook()
    ws = wb.active
    ws.title = "Pacientes"
    
    # Estilos para encabezados
    header_fill = PatternFill(start_color="366092", end_color="366092", fill_type="solid")
    header_font = Font(bold=True, color="FFFFFF", size=12)
    header_alignment = Alignment(horizontal="center", vertical="center")
    
    # Encabezados
    headers = ['NSS', 'Nombre Completo', 'Cédula', 'Teléfono', 'Email', 'Fecha de Nacimiento', 
               'Sexo', 'ARS', 'Tipo de Afiliación', 'Dirección']
    for col_num, header in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col_num, value=header)
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = header_alignment
    
    # Datos
    for row_num, paciente in enumerate(pacientes_list, 2):
        ws.cell(row=row_num, column=1, value=paciente.get('nss') or '')
        ws.cell(row=row_num, column=2, value=paciente.get('nombre') or '')
        ws.cell(row=row_num, column=3, value=paciente.get('cedula') or '')
        ws.cell(row=row_num, column=4, value=paciente.get('telefono') or '')
        ws.cell(row=row_num, column=5, value=paciente.get('email') or '')
        ws.cell(row=row_num, column=6, value=paciente.get('fecha_nacimiento') or '')
        ws.cell(row=row_num, column=7, value=paciente.get('sexo') or '')
        ws.cell(row=row_num, column=8, value=paciente.get('ars_nombre') or 'Sin ARS')
        ws.cell(row=row_num, column=9, value=paciente.get('tipo_afiliacion') or '')
        ws.cell(row=row_num, column=10, value=paciente.get('direccion') or '')
    
    # Ajustar ancho de columnas
    column_widths = [15, 30, 15, 15, 25, 15, 10, 20, 15, 40]
    for col_num, width in enumerate(column_widths, 1):
        ws.column_dimensions[get_column_letter(col_num)].width = width
    
    # Guardar en BytesIO
    output = BytesIO()
    wb.save(output)
    output.seek(0)
    
    # Nombre del archivo con fecha
    fecha_actual = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'pacientes_{fecha_actual}.xlsx'
    
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=filename
    )

@login_required
@permission_required('facturacion.ver')
def facturacion_pacientes_pendientes():
    """Estado de facturación - Pacientes pendientes"""
    # Obtener filtros de la query string
    medico_id_filtro = request.args.get('medico_id', '')
    ars_id_filtro = request.args.get('ars_id', '')
    estado_filtro = request.args.get('estado', 'pendiente')  # Por defecto 'pendiente'
    
    # Construir query con filtros - consultar tabla pacientes_pendientes
    tenant_id = get_current_tenant_id()
    
    # Construir query base
    query = '''
        SELECT pp.*, 
               a.nombre as nombre_ars,
               m.nombre as medico_nombre,
               m.especialidad as medico_especialidad,
               pp.servicios_realizados as descripcion_servicio,
               pp.monto_estimado as monto
        FROM pacientes_pendientes pp
        LEFT JOIN ars a
          ON pp.ars_id = a.id AND a.tenant_id = pp.tenant_id
        LEFT JOIN medicos m
          ON pp.medico_id = m.id AND m.tenant_id = pp.tenant_id
        WHERE pp.tenant_id = %s
    '''
    params = [tenant_id]
    
    # Filtro por estado
    if estado_filtro:
        # Convertir 'pendiente' a 'Pendiente' y 'facturado' a 'Facturado'
        estado_db = estado_filtro.capitalize()
        if estado_db == 'Facturado':
            query += ' AND pp.estado = %s'
            params.append('Facturado')
        elif estado_db == 'Pendiente':
            query += ' AND pp.estado = %s'
            params.append('Pendiente')
    
    # Filtro por médico
    if medico_id_filtro:
        medico_id_filtro = validate_int(
            medico_id_filtro, min_value=1, default=None
        )
        query += ' AND pp.medico_id = %s'
        params.append(medico_id_filtro)
    
    # Filtro por ARS
    if ars_id_filtro:
        ars_id_filtro = validate_int(
            ars_id_filtro, min_value=1, default=None
        )
        query += ' AND pp.ars_id = %s'
        params.append(ars_id_filtro)
    
    pendientes, pagination = execute_paginated_query(
        query,
        params,
        'pp.fecha_servicio DESC, pp.id DESC',
        default_per_page=50,
    )
    
    # Obtener listas para filtros
    medicos = execute_query('SELECT * FROM medicos WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    ars_list = execute_query('SELECT * FROM ars WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    
    # Obtener nombres para mostrar en los badges de filtros activos
    medico_seleccionado = None
    if medico_id_filtro:
        medico = execute_query(
            'SELECT nombre FROM medicos WHERE id = %s AND tenant_id = %s',
            (medico_id_filtro, tenant_id),
        )
        if medico:
            medico_seleccionado = medico['nombre']
    
    ars_seleccionada = None
    if ars_id_filtro:
        ars = execute_query(
            'SELECT nombre FROM ars WHERE id = %s AND tenant_id = %s',
            (ars_id_filtro, tenant_id),
        )
        if ars:
            ars_seleccionada = ars['nombre']
    
    # Obtener servicios para el combobox
    servicios_list = execute_query('''
        SELECT descripcion, precio_base 
        FROM servicios 
        WHERE tenant_id = %s AND activo = 1 
        ORDER BY descripcion
    ''', (tenant_id,), fetch='all') or []
    
    return render_template('facturacion/pacientes_pendientes.html', 
                          pendientes=pendientes,
                          medicos=medicos,
                          ars_list=ars_list,
                          servicios_list=servicios_list,
                          medico_id_filtro=medico_id_filtro,
                          ars_id_filtro=ars_id_filtro,
                          estado_filtro=estado_filtro,
                          medico_seleccionado=medico_seleccionado,
                          ars_seleccionada=ars_seleccionada,
                          pagination=pagination)

@login_required
@permission_required('facturacion.imprimir')
def facturacion_pacientes_pendientes_pdf():
    """Descargar PDF de pacientes pendientes"""
    flash('Funcionalidad de PDF en desarrollo', 'info')
    return redirect(url_for('facturacion_pacientes_pendientes'))

def register_patient_routes(app):
    app.add_url_rule('/facturacion/pacientes', endpoint='facturacion_pacientes', view_func=facturacion_pacientes)
    app.add_url_rule('/facturacion/pacientes/nuevo', endpoint='facturacion_pacientes_nuevo', view_func=facturacion_pacientes_nuevo, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/pacientes/<int:paciente_id>/acciones', endpoint='facturacion_paciente_acciones', view_func=facturacion_paciente_acciones)
    app.add_url_rule('/facturacion/pacientes/<int:paciente_id>/actualizar-cedula', endpoint='facturacion_paciente_actualizar_cedula', view_func=facturacion_paciente_actualizar_cedula, methods=['POST'])
    app.add_url_rule('/facturacion/pacientes/<int:paciente_id>/editar', endpoint='facturacion_pacientes_editar', view_func=facturacion_pacientes_editar, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/pacientes/<int:paciente_id>/eliminar', endpoint='facturacion_pacientes_eliminar', view_func=facturacion_pacientes_eliminar, methods=['POST'])
    app.add_url_rule('/facturacion/pacientes-pendientes/<int:paciente_id>/eliminar', endpoint='facturacion_pacientes_pendientes_eliminar', view_func=facturacion_pacientes_pendientes_eliminar, methods=['POST'])
    app.add_url_rule('/api/facturacion/pacientes-pendientes/<int:paciente_id>', endpoint='api_facturacion_pacientes_pendientes_get', view_func=api_facturacion_pacientes_pendientes_get, methods=['GET'])
    app.add_url_rule('/api/facturacion/pacientes-pendientes/<int:paciente_id>', endpoint='api_facturacion_pacientes_pendientes_update', view_func=api_facturacion_pacientes_pendientes_update, methods=['PUT'])
    app.add_url_rule('/facturacion/pacientes/exportar-excel', endpoint='facturacion_pacientes_exportar_excel', view_func=facturacion_pacientes_exportar_excel)
    app.add_url_rule('/facturacion/pacientes-pendientes', endpoint='facturacion_pacientes_pendientes', view_func=facturacion_pacientes_pendientes)
    app.add_url_rule('/facturacion/pacientes-pendientes/pdf', endpoint='facturacion_pacientes_pendientes_pdf', view_func=facturacion_pacientes_pendientes_pdf)
