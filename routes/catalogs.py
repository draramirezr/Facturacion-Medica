"""Rutas de cat?logos operativos de facturaci?n."""

import re
from datetime import datetime

from flask import flash, jsonify, redirect, render_template, request, url_for
from flask_login import login_required

from auth import permission_required
from core.database import execute_query, execute_update, transactional_methods
from core.tenant import get_current_tenant_id, validate_tenant_access
from ecf import ECF_TYPE_CATALOG
from routes.support import (
    ESPECIALIDADES_MEDICAS, get_especialidad_form, sanitize_input,
    validate_digits, validate_email,
)
from services.subscriptions import get_empresa_info

NCF_TIPOS_TRADICIONALES = {
    'B01': 'Factura de Crédito Fiscal',
    'B02': 'Factura de Consumo',
    'B03': 'Nota de Débito',
    'B04': 'Nota de Crédito',
    'B11': 'Comprobante de Compras',
    'B12': 'Registro Único de Ingresos',
    'B13': 'Comprobante para Gastos Menores',
    'B14': 'Comprobante para Regímenes Especiales',
    'B15': 'Comprobante Gubernamental',
    'B16': 'Comprobante para Exportaciones',
    'B17': 'Comprobante para Pagos al Exterior',
}

@login_required
@permission_required('catalogos.ver')
def facturacion_ars():
    """Lista de ARS - Filtrado por tenant"""
    
    tenant_id = get_current_tenant_id()
    ars_list = execute_query(
        'SELECT * FROM ars WHERE tenant_id = %s ORDER BY nombre', 
        (tenant_id,), fetch='all'
    ) or []
    return render_template('facturacion/ars.html', ars_list=ars_list)

@login_required
@permission_required('catalogos.crear')
def facturacion_ars_nuevo():
    """Crear nueva ARS"""
    
    if request.method == 'POST':
        nombre_ars = sanitize_input(request.form.get('nombre_ars', ''), 50)
        rnc = sanitize_input(request.form.get('rnc', ''), 50)
        activo = 1 if request.form.get('activo') == '1' else 0
        
        if not nombre_ars or not rnc:
            flash('El nombre y el RNC son obligatorios', 'error')
            return redirect(url_for('facturacion_ars_nuevo'))

        if not validate_digits(rnc, 9):
            flash('El RNC debe contener exactamente 9 números', 'error')
            return redirect(url_for('facturacion_ars_nuevo'))
        
        tenant_id = get_current_tenant_id()
        
        # Generar código automáticamente basado en el nombre (primeras letras + timestamp)
        import time
        codigo = ''.join(filter(str.isalnum, nombre_ars[:6].upper())) + str(int(time.time()))[-4:]
        
        # Asegurar que el código sea único
        contador = 1
        codigo_original = codigo
        while execute_query('SELECT id FROM ars WHERE codigo = %s AND tenant_id = %s', (codigo, tenant_id)):
            codigo = f"{codigo_original}{contador}"
            contador += 1
        
        execute_update('''
            INSERT INTO ars (tenant_id, codigo, nombre, rnc, activo)
            VALUES (%s, %s, %s, %s, %s)
        ''', (tenant_id, codigo, nombre_ars, rnc, activo))
        
        flash(f'ARS {nombre_ars} creada exitosamente', 'success')
        return redirect(url_for('facturacion_ars'))
    
    return render_template('facturacion/ars_form.html', ars=None)

@login_required
@permission_required('catalogos.editar')
def facturacion_ars_editar(ars_id):
    """Editar ARS"""
    
    tenant_id = get_current_tenant_id()
    ars = execute_query('SELECT * FROM ars WHERE id = %s AND tenant_id = %s', (ars_id, tenant_id))
    if not ars:
        flash('ARS no encontrada', 'error')
        return redirect(url_for('facturacion_ars'))
    
    if request.method == 'POST':
        nombre_ars = sanitize_input(request.form.get('nombre_ars', ''), 50)
        rnc = sanitize_input(request.form.get('rnc', ''), 50)
        activo = 1 if request.form.get('activo') == '1' else 0
        
        if not nombre_ars or not rnc:
            flash('El nombre y el RNC son obligatorios', 'error')
            return redirect(url_for('facturacion_ars_editar', ars_id=ars_id))

        if not validate_digits(rnc, 9):
            flash('El RNC debe contener exactamente 9 números', 'error')
            return redirect(url_for('facturacion_ars_editar', ars_id=ars_id))
        
        # Mantener el código existente (no se modifica en edición)
        
        execute_update('''
            UPDATE ars 
            SET nombre = %s, rnc = %s, activo = %s
            WHERE id = %s AND tenant_id = %s
        ''', (nombre_ars, rnc, activo, ars_id, tenant_id))
        
        flash(f'ARS {nombre_ars} actualizada exitosamente', 'success')
        return redirect(url_for('facturacion_ars'))
    
    return render_template('facturacion/ars_form.html', ars=ars)

@login_required
@permission_required('catalogos.eliminar')
def facturacion_ars_eliminar(ars_id):
    """Eliminar ARS"""
    
    tenant_id = get_current_tenant_id()
    # Validar que pertenece al tenant antes de eliminar
    if not validate_tenant_access('ars', ars_id):
        flash('No tienes acceso a esta ARS', 'error')
        return redirect(url_for('facturacion_ars'))
    
    execute_update('DELETE FROM ars WHERE id = %s AND tenant_id = %s', (ars_id, tenant_id))
    flash('ARS eliminada exitosamente', 'success')
    return redirect(url_for('facturacion_ars'))

@login_required  
@permission_required('catalogos.ver')
def facturacion_medicos():
    """Lista de médicos - Filtrado por tenant"""
    
    tenant_id = get_current_tenant_id()
    search = sanitize_input(request.args.get('search', ''), 100)

    if search:
        search_term = f'%{search}%'
        medicos_list = execute_query('''
            SELECT * FROM medicos
            WHERE tenant_id = %s
              AND (nombre LIKE %s OR especialidad LIKE %s OR telefono LIKE %s)
            ORDER BY nombre
        ''', (tenant_id, search_term, search_term, search_term), fetch='all') or []
    else:
        medicos_list = execute_query(
            'SELECT * FROM medicos WHERE tenant_id = %s ORDER BY nombre',
            (tenant_id,), fetch='all'
        ) or []

    return render_template(
        'facturacion/medicos.html',
        medicos_list=medicos_list,
        search=search
    )

@login_required
@permission_required('catalogos.crear')
def facturacion_medicos_nuevo():
    """Crear nuevo médico"""
    
    if request.method == 'POST':
        nombre = sanitize_input(request.form.get('nombre', ''), 200)
        exequatur = sanitize_input(request.form.get('exequatur', ''), 50)
        especialidad = get_especialidad_form(request.form)
        telefono = sanitize_input(request.form.get('telefono', ''), 20)
        email = request.form.get('email', '').strip()
        cedula = sanitize_input(request.form.get('cedula', ''), 20)
        factura = 1 if request.form.get('factura') == '1' else 0
        
        if not all([nombre, exequatur, especialidad, telefono, email, cedula]):
            flash('Todos los campos del médico son obligatorios', 'error')
            return redirect(url_for('facturacion_medicos_nuevo'))

        if not validate_digits(cedula, 11):
            flash('La cédula debe contener exactamente 11 números', 'error')
            return redirect(url_for('facturacion_medicos_nuevo'))

        if not validate_digits(telefono, 10):
            flash('El teléfono debe contener exactamente 10 números', 'error')
            return redirect(url_for('facturacion_medicos_nuevo'))

        if not validate_email(email):
            flash('Ingresa un correo electrónico válido', 'error')
            return redirect(url_for('facturacion_medicos_nuevo'))
        
        tenant_id = get_current_tenant_id()
        execute_update('''
            INSERT INTO medicos (tenant_id, nombre, exequatur, especialidad, telefono, email, cedula, activo, factura)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 1, %s)
        ''', (tenant_id, nombre, exequatur, especialidad, telefono, email, cedula, factura))
        
        flash(f'Médico {nombre} creado exitosamente', 'success')
        return redirect(url_for('facturacion_medicos'))
    
    return render_template(
        'facturacion/medicos_form.html',
        medico=None,
        especialidades=ESPECIALIDADES_MEDICAS
    )

@login_required
@permission_required('catalogos.editar')
def facturacion_medicos_editar(medico_id):
    """Editar médico"""
    
    tenant_id = get_current_tenant_id()
    medico = execute_query('SELECT * FROM medicos WHERE id = %s AND tenant_id = %s', (medico_id, tenant_id))
    if not medico:
        flash('Médico no encontrado', 'error')
        return redirect(url_for('facturacion_medicos'))
    
    if request.method == 'POST':
        nombre = sanitize_input(request.form.get('nombre', ''), 200)
        exequatur = sanitize_input(request.form.get('exequatur', ''), 50)
        especialidad = get_especialidad_form(request.form)
        telefono = sanitize_input(request.form.get('telefono', ''), 20)
        email = request.form.get('email', '').strip()
        cedula = sanitize_input(request.form.get('cedula', ''), 20)
        activo = 1 if request.form.get('activo') == '1' else 0
        factura = 1 if request.form.get('factura') == '1' else 0
        
        if not all([nombre, exequatur, especialidad, telefono, email, cedula]):
            flash('Todos los campos del médico son obligatorios', 'error')
            return redirect(url_for('facturacion_medicos_editar', medico_id=medico_id))

        if not validate_digits(cedula, 11):
            flash('La cédula debe contener exactamente 11 números', 'error')
            return redirect(url_for('facturacion_medicos_editar', medico_id=medico_id))

        if not validate_digits(telefono, 10):
            flash('El teléfono debe contener exactamente 10 números', 'error')
            return redirect(url_for('facturacion_medicos_editar', medico_id=medico_id))

        if not validate_email(email):
            flash('Ingresa un correo electrónico válido', 'error')
            return redirect(url_for('facturacion_medicos_editar', medico_id=medico_id))
        
        tenant_id = get_current_tenant_id()
        execute_update('''
            UPDATE medicos 
            SET nombre = %s, exequatur = %s, especialidad = %s, telefono = %s, email = %s, cedula = %s, activo = %s, factura = %s
            WHERE id = %s AND tenant_id = %s
        ''', (nombre, exequatur, especialidad, telefono, email, cedula, activo, factura, medico_id, tenant_id))
        
        flash(f'Médico {nombre} actualizado exitosamente', 'success')
        return redirect(url_for('facturacion_medicos'))
    
    return render_template(
        'facturacion/medicos_form.html',
        medico=medico,
        especialidades=ESPECIALIDADES_MEDICAS
    )

@login_required
@permission_required('catalogos.eliminar')
def facturacion_medicos_eliminar(medico_id):
    """Eliminar médico"""
    
    tenant_id = get_current_tenant_id()
    if not validate_tenant_access('medicos', medico_id):
        flash('No tienes acceso a este médico', 'error')
        return redirect(url_for('facturacion_medicos'))
    
    execute_update('DELETE FROM medicos WHERE id = %s AND tenant_id = %s', (medico_id, tenant_id))
    flash('Médico eliminado exitosamente', 'success')
    return redirect(url_for('facturacion_medicos'))

@login_required
@permission_required('catalogos.ver')
def facturacion_centros_medicos():
    """Lista de centros médicos - Filtrado por tenant"""
    
    tenant_id = get_current_tenant_id()
    search = request.args.get('search', '').strip()
    
    if search:
        centros_list = execute_query(
            '''SELECT * FROM centros_medicos 
               WHERE tenant_id = %s AND (nombre LIKE %s OR rnc LIKE %s OR direccion LIKE %s)
               ORDER BY nombre''', 
            (tenant_id, f'%{search}%', f'%{search}%', f'%{search}%'), fetch='all'
        ) or []
    else:
        centros_list = execute_query(
            'SELECT * FROM centros_medicos WHERE tenant_id = %s ORDER BY nombre', 
            (tenant_id,), fetch='all'
        ) or []
    
    return render_template('facturacion/centros_medicos.html', centros_list=centros_list, search=search)

@login_required
@permission_required('catalogos.crear')
def facturacion_centros_medicos_nuevo():
    """Crear nuevo centro médico"""
    
    if request.method == 'POST':
        nombre = sanitize_input(request.form.get('nombre', ''), 200)
        codigo = sanitize_input(request.form.get('codigo', ''), 50)
        direccion = sanitize_input(request.form.get('direccion', ''), 500)
        rnc = sanitize_input(request.form.get('rnc', ''), 20)
        telefono = sanitize_input(request.form.get('telefono', ''), 20)
        
        if not nombre or not telefono or not rnc:
            flash('El nombre, el teléfono y el RNC son obligatorios', 'error')
            return redirect(url_for('facturacion_centros_medicos_nuevo'))

        if not validate_digits(telefono, 10):
            flash('El teléfono debe contener exactamente 10 números', 'error')
            return redirect(url_for('facturacion_centros_medicos_nuevo'))

        if not validate_digits(rnc, 9):
            flash('El RNC debe contener exactamente 9 números', 'error')
            return redirect(url_for('facturacion_centros_medicos_nuevo'))
        
        tenant_id = get_current_tenant_id()
        execute_update('''
            INSERT INTO centros_medicos (tenant_id, nombre, codigo, direccion, rnc, telefono, activo)
            VALUES (%s, %s, %s, %s, %s, %s, 1)
        ''', (tenant_id, nombre, codigo, direccion, rnc, telefono))
        
        flash(f'Centro médico {nombre} creado exitosamente', 'success')
        return redirect(url_for('facturacion_centros_medicos'))
    
    return render_template('facturacion/centro_medico_form.html', centro=None)

@login_required
@permission_required('catalogos.editar')
def facturacion_centros_medicos_editar(centro_id):
    """Editar centro médico"""
    
    tenant_id = get_current_tenant_id()
    centro = execute_query('SELECT * FROM centros_medicos WHERE id = %s AND tenant_id = %s', (centro_id, tenant_id))
    if not centro:
        flash('Centro médico no encontrado', 'error')
        return redirect(url_for('facturacion_centros_medicos'))
    
    if request.method == 'POST':
        nombre = sanitize_input(request.form.get('nombre', ''), 200)
        codigo = sanitize_input(request.form.get('codigo', ''), 50)
        direccion = sanitize_input(request.form.get('direccion', ''), 500)
        rnc = sanitize_input(request.form.get('rnc', ''), 20)
        telefono = sanitize_input(request.form.get('telefono', ''), 20)
        activo = 1 if request.form.get('activo') == '1' else 0
        
        if not nombre or not telefono or not rnc:
            flash('El nombre, el teléfono y el RNC son obligatorios', 'error')
            return redirect(url_for('facturacion_centros_medicos_editar', centro_id=centro_id))

        if not validate_digits(telefono, 10):
            flash('El teléfono debe contener exactamente 10 números', 'error')
            return redirect(url_for('facturacion_centros_medicos_editar', centro_id=centro_id))

        if not validate_digits(rnc, 9):
            flash('El RNC debe contener exactamente 9 números', 'error')
            return redirect(url_for('facturacion_centros_medicos_editar', centro_id=centro_id))
        
        tenant_id = get_current_tenant_id()
        execute_update('''
            UPDATE centros_medicos 
            SET nombre = %s, codigo = %s, direccion = %s, rnc = %s, telefono = %s, activo = %s
            WHERE id = %s AND tenant_id = %s
        ''', (nombre, codigo, direccion, rnc, telefono, activo, centro_id, tenant_id))
        
        flash(f'Centro médico {nombre} actualizado exitosamente', 'success')
        return redirect(url_for('facturacion_centros_medicos'))
    
    return render_template('facturacion/centro_medico_form.html', centro=centro)

@login_required
@permission_required('catalogos.eliminar')
def facturacion_centros_medicos_eliminar(centro_id):
    """Eliminar centro médico"""
    
    tenant_id = get_current_tenant_id()
    if not validate_tenant_access('centros_medicos', centro_id):
        flash('No tienes acceso a este centro médico', 'error')
        return redirect(url_for('facturacion_centros_medicos'))
    
    execute_update('DELETE FROM centros_medicos WHERE id = %s AND tenant_id = %s', (centro_id, tenant_id))
    flash('Centro médico eliminado exitosamente', 'success')
    return redirect(url_for('facturacion_centros_medicos'))

@login_required
@permission_required('catalogos.ver')
def facturacion_servicios():
    """Lista de servicios - Filtrado por tenant"""
    
    tenant_id = get_current_tenant_id()
    servicios_list = execute_query(
        'SELECT * FROM servicios WHERE tenant_id = %s ORDER BY descripcion', 
        (tenant_id,), fetch='all'
    ) or []
    return render_template('facturacion/servicios.html', servicios_list=servicios_list)

@login_required
@permission_required('catalogos.crear')
def facturacion_servicios_nuevo():
    """Crear nuevo servicio"""
    
    if request.method == 'POST':
        descripcion = sanitize_input(request.form.get('descripcion', ''), 15)
        precio_base = request.form.get('precio_base', '0')
        
        if not descripcion:
            flash('La descripción es obligatoria', 'error')
            return redirect(url_for('facturacion_servicios_nuevo'))
        
        try:
            precio_base = float(precio_base)
        except:
            precio_base = 0.0
        
        tenant_id = get_current_tenant_id()
        execute_update('''
            INSERT INTO servicios (tenant_id, nombre, descripcion, precio_base, activo)
            VALUES (%s, %s, %s, %s, 1)
        ''', (tenant_id, descripcion, descripcion, precio_base))
        
        flash(f'Servicio {descripcion} creado exitosamente', 'success')
        return redirect(url_for('facturacion_servicios'))
    
    return render_template('facturacion/servicios_form.html', servicio=None)

@login_required
@permission_required('catalogos.editar')
def facturacion_servicios_editar(servicio_id):
    """Editar servicio"""
    
    tenant_id = get_current_tenant_id()
    servicio = execute_query('SELECT * FROM servicios WHERE id = %s AND tenant_id = %s', (servicio_id, tenant_id))
    if not servicio:
        flash('Servicio no encontrado', 'error')
        return redirect(url_for('facturacion_servicios'))
    
    if request.method == 'POST':
        descripcion = sanitize_input(request.form.get('descripcion', ''), 15)
        precio_base = request.form.get('precio_base', '0')
        activo = 1 if request.form.get('activo') == '1' else 0
        
        if not descripcion:
            flash('La descripción es obligatoria', 'error')
            return redirect(url_for('facturacion_servicios_editar', servicio_id=servicio_id))
        
        try:
            precio_base = float(precio_base)
        except:
            precio_base = 0.0
        
        tenant_id = get_current_tenant_id()
        execute_update('''
            UPDATE servicios 
            SET nombre = %s, descripcion = %s, precio_base = %s, activo = %s
            WHERE id = %s AND tenant_id = %s
        ''', (descripcion, descripcion, precio_base, activo, servicio_id, tenant_id))
        
        flash(f'Servicio {descripcion} actualizado exitosamente', 'success')
        return redirect(url_for('facturacion_servicios'))
    
    return render_template('facturacion/servicios_form.html', servicio=servicio)

@login_required
@permission_required('catalogos.eliminar')
def facturacion_servicios_eliminar(servicio_id):
    """Eliminar servicio"""
    
    tenant_id = get_current_tenant_id()
    if not validate_tenant_access('servicios', servicio_id):
        flash('No tienes acceso a este servicio', 'error')
        return redirect(url_for('facturacion_servicios'))
    
    execute_update('DELETE FROM servicios WHERE id = %s AND tenant_id = %s', (servicio_id, tenant_id))
    flash('Servicio eliminado exitosamente', 'success')
    return redirect(url_for('facturacion_servicios'))

def obtener_relacion_codigo_ars(tenant_id):
    """Configurar la entidad que se relaciona con ARS según la empresa."""
    empresa = get_empresa_info(tenant_id) or {}
    es_centro_salud = empresa.get('tipo_empresa') == 'centro_salud'
    if es_centro_salud:
        entidades = execute_query('''
            SELECT id, nombre
            FROM centros_medicos
            WHERE activo=1 AND tenant_id=%s
            ORDER BY nombre
        ''', (tenant_id,), fetch='all') or []
        return {
            'tipo_empresa': 'centro_salud',
            'es_centro_salud': True,
            'entidades': entidades,
            'campo': 'centro_medico_id',
            'etiqueta': 'Centro de salud',
            'etiqueta_plural': 'centros de salud',
        }

    entidades = execute_query('''
        SELECT id, nombre, especialidad
        FROM medicos
        WHERE activo=1 AND tenant_id=%s
        ORDER BY nombre
    ''', (tenant_id,), fetch='all') or []
    return {
        'tipo_empresa': 'medico',
        'es_centro_salud': False,
        'entidades': entidades,
        'campo': 'medico_id',
        'etiqueta': 'Médico',
        'etiqueta_plural': 'médicos',
    }

@login_required
@permission_required('catalogos.ver')
def facturacion_codigo_ars():
    """Lista de códigos ARS - Filtrado por tenant"""
    
    tenant_id = get_current_tenant_id()
    relacion = obtener_relacion_codigo_ars(tenant_id)
    search = request.args.get('search', '').strip()
    query = '''
        SELECT ca.*, a.nombre,
               m.nombre AS nombre_medico,
               c.nombre AS nombre_centro
        FROM codigo_ars ca
        JOIN ars a
          ON ca.ars_id = a.id AND a.tenant_id = ca.tenant_id
        LEFT JOIN medicos m
          ON ca.medico_id = m.id AND m.tenant_id = ca.tenant_id
        LEFT JOIN centros_medicos c
          ON ca.centro_medico_id = c.id AND c.tenant_id = ca.tenant_id
        WHERE ca.tenant_id = %s
    '''
    params = [tenant_id]
    if search:
        pattern = f'%{search}%'
        query += '''
            AND (
                a.nombre LIKE %s OR ca.codigo LIKE %s
                OR m.nombre LIKE %s OR c.nombre LIKE %s
            )
        '''
        params.extend([pattern, pattern, pattern, pattern])
    query += '''
        ORDER BY COALESCE(c.nombre, m.nombre), a.nombre, ca.codigo
    '''
    codigos_list = execute_query(
        query, tuple(params), fetch='all'
    ) or []
    return render_template(
        'facturacion/codigo_ars.html',
        codigos_list=codigos_list,
        relacion=relacion,
        search=search,
    )

@login_required
@permission_required('catalogos.crear')
def facturacion_codigo_ars_nuevo():
    """Crear nuevo código ARS"""
    
    tenant_id = get_current_tenant_id()
    relacion = obtener_relacion_codigo_ars(tenant_id)

    if request.method == 'POST':
        entidad_id = request.form.get('entidad_id')
        ars_id = request.form.get('ars_id')
        codigo = sanitize_input(request.form.get('codigo_ars', ''), 50)
        descripcion = sanitize_input(request.form.get('descripcion', ''), 500)
        precio = request.form.get('precio', '0')
        activo = 1 if request.form.get('activo') == '1' else 0
        
        if not entidad_id or not ars_id or not codigo:
            flash(
                f"{relacion['etiqueta']}, ARS y código son obligatorios",
                'error'
            )
            return redirect(url_for('facturacion_codigo_ars_nuevo'))
        
        entidad = execute_query(
            f"SELECT id FROM {'centros_medicos' if relacion['es_centro_salud'] else 'medicos'} "
            "WHERE id=%s AND tenant_id=%s AND activo=1",
            (entidad_id, tenant_id)
        )
        ars = execute_query(
            'SELECT id FROM ars WHERE id=%s AND tenant_id=%s AND activo=1',
            (ars_id, tenant_id)
        )
        if not entidad or not ars:
            flash('La relación seleccionada no es válida', 'error')
            return redirect(url_for('facturacion_codigo_ars_nuevo'))

        try:
            precio = float(precio) if precio else 0.0
        except (TypeError, ValueError):
            precio = 0.0
        
        existe = execute_query(
            f'SELECT id FROM codigo_ars WHERE {relacion["campo"]}=%s '
            'AND ars_id=%s AND tenant_id=%s',
            (entidad_id, ars_id, tenant_id)
        )
        if existe:
            flash(
                f"Ya existe un código para este "
                f"{relacion['etiqueta'].lower()} y ARS",
                'error'
            )
            return redirect(url_for('facturacion_codigo_ars_nuevo'))
        
        medico_id = None if relacion['es_centro_salud'] else entidad_id
        centro_medico_id = entidad_id if relacion['es_centro_salud'] else None
        execute_update('''
            INSERT INTO codigo_ars
                (tenant_id, medico_id, centro_medico_id, ars_id, codigo,
                 descripcion, precio, activo)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ''', (
            tenant_id, medico_id, centro_medico_id, ars_id, codigo,
            descripcion or '', precio, activo
        ))
        
        flash(f'Código ARS {codigo} creado exitosamente', 'success')
        return redirect(url_for('facturacion_codigo_ars'))
    
    ars_list = execute_query('SELECT * FROM ars WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    return render_template(
        'facturacion/codigo_ars_form.html',
        codigo=None,
        ars_list=ars_list,
        relacion=relacion,
    )

@login_required
@permission_required('catalogos.editar')
def facturacion_codigo_ars_editar(codigo_id):
    """Editar código ARS"""
    
    tenant_id = get_current_tenant_id()
    codigo = execute_query('SELECT * FROM codigo_ars WHERE id = %s AND tenant_id = %s', (codigo_id, tenant_id))
    if not codigo:
        flash('Código ARS no encontrado', 'error')
        return redirect(url_for('facturacion_codigo_ars'))
    
    relacion = obtener_relacion_codigo_ars(tenant_id)

    if request.method == 'POST':
        entidad_id = request.form.get('entidad_id')
        ars_id = request.form.get('ars_id')
        codigo_texto = sanitize_input(request.form.get('codigo_ars', ''), 50)
        descripcion = sanitize_input(request.form.get('descripcion', ''), 500)
        precio = request.form.get('precio', '0')
        activo = 1 if request.form.get('activo') == '1' else 0
        
        if not entidad_id or not ars_id or not codigo_texto:
            flash(
                f"{relacion['etiqueta']}, ARS y código son obligatorios",
                'error'
            )
            return redirect(url_for('facturacion_codigo_ars_editar', codigo_id=codigo_id))
        
        entidad = execute_query(
            f"SELECT id FROM {'centros_medicos' if relacion['es_centro_salud'] else 'medicos'} "
            "WHERE id=%s AND tenant_id=%s AND activo=1",
            (entidad_id, tenant_id)
        )
        ars = execute_query(
            'SELECT id FROM ars WHERE id=%s AND tenant_id=%s AND activo=1',
            (ars_id, tenant_id)
        )
        if not entidad or not ars:
            flash('La relación seleccionada no es válida', 'error')
            return redirect(url_for(
                'facturacion_codigo_ars_editar', codigo_id=codigo_id
            ))

        try:
            precio = float(precio) if precio else 0.0
        except (TypeError, ValueError):
            precio = 0.0
        
        existe = execute_query(
            f'SELECT id FROM codigo_ars WHERE {relacion["campo"]}=%s '
            'AND ars_id=%s AND id!=%s AND tenant_id=%s',
            (entidad_id, ars_id, codigo_id, tenant_id)
        )
        if existe:
            flash(
                f"Ya existe un código para este "
                f"{relacion['etiqueta'].lower()} y ARS",
                'error'
            )
            return redirect(url_for('facturacion_codigo_ars_editar', codigo_id=codigo_id))
        
        medico_id = None if relacion['es_centro_salud'] else entidad_id
        centro_medico_id = entidad_id if relacion['es_centro_salud'] else None
        execute_update('''
            UPDATE codigo_ars 
            SET medico_id=%s, centro_medico_id=%s, ars_id=%s, codigo=%s,
                descripcion=%s, precio=%s, activo=%s
            WHERE id = %s AND tenant_id = %s
        ''', (
            medico_id, centro_medico_id, ars_id, codigo_texto,
            descripcion or '', precio, activo, codigo_id, tenant_id
        ))
        
        flash(f'Código ARS actualizado exitosamente', 'success')
        return redirect(url_for('facturacion_codigo_ars'))
    
    ars_list = execute_query('SELECT * FROM ars WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    return render_template(
        'facturacion/codigo_ars_form.html',
        codigo=codigo,
        ars_list=ars_list,
        relacion=relacion,
    )

@login_required
@permission_required('catalogos.eliminar')
def facturacion_codigo_ars_eliminar(codigo_id):
    """Eliminar código ARS"""
    
    tenant_id = get_current_tenant_id()
    if not validate_tenant_access('codigo_ars', codigo_id):
        flash('No tienes acceso a este código ARS', 'error')
        return redirect(url_for('facturacion_codigo_ars'))
    
    execute_update('DELETE FROM codigo_ars WHERE id = %s AND tenant_id = %s', (codigo_id, tenant_id))
    flash('Código ARS eliminado exitosamente', 'success')
    return redirect(url_for('facturacion_codigo_ars'))

@login_required
@permission_required('catalogos.ver')
def facturacion_medico_centro():
    """Relación médico-centro - Filtrado por tenant"""
    
    tenant_id = get_current_tenant_id()
    relaciones_list = execute_query('''
        SELECT mc.*, m.nombre as medico_nombre, m.especialidad, c.nombre as centro_nombre
        FROM medico_centro mc
        JOIN medicos m
          ON mc.medico_id = m.id AND m.tenant_id = mc.tenant_id
        JOIN centros_medicos c
          ON mc.centro_medico_id = c.id AND c.tenant_id = mc.tenant_id
        WHERE mc.tenant_id = %s
        ORDER BY m.nombre, c.nombre
    ''', (tenant_id,), fetch='all') or []
    return render_template('facturacion/medico_centro.html', relaciones_list=relaciones_list)

@login_required
@transactional_methods('POST')
@permission_required('catalogos.crear')
def facturacion_medico_centro_nuevo():
    """Crear nueva relación médico-centro"""
    
    if request.method == 'POST':
        medico_id = request.form.get('medico_id')
        centro_medico_id = request.form.get('centro_medico_id')
        es_defecto = 1 if request.form.get('es_defecto') == '1' else 0
        
        if not medico_id or not centro_medico_id:
            flash('Médico y centro médico son obligatorios', 'error')
            return redirect(url_for('facturacion_medico_centro_nuevo'))
        
        tenant_id = get_current_tenant_id()
        medico = execute_query(
            '''
            SELECT id FROM medicos
            WHERE id = %s AND tenant_id = %s AND activo = 1
            ''',
            (medico_id, tenant_id),
        )
        centro = execute_query(
            '''
            SELECT id FROM centros_medicos
            WHERE id = %s AND tenant_id = %s AND activo = 1
            ''',
            (centro_medico_id, tenant_id),
        )
        if not medico or not centro:
            flash('El médico o centro seleccionado no pertenece a tu empresa', 'error')
            return redirect(url_for('facturacion_medico_centro_nuevo'))

        existe = execute_query('SELECT id FROM medico_centro WHERE medico_id = %s AND centro_medico_id = %s AND tenant_id = %s', 
                              (medico_id, centro_medico_id, tenant_id))
        if existe:
            flash('Esta relación ya existe', 'error')
            return redirect(url_for('facturacion_medico_centro_nuevo'))
        
        # Si se marca como por defecto, desmarcar otros centros por defecto de este médico
        if es_defecto:
            execute_update('''
                UPDATE medico_centro 
                SET es_defecto = 0 
                WHERE medico_id = %s AND tenant_id = %s
            ''', (medico_id, tenant_id))
        
        execute_update('''
            INSERT INTO medico_centro (tenant_id, medico_id, centro_medico_id, es_defecto)
            VALUES (%s, %s, %s, %s)
        ''', (tenant_id, medico_id, centro_medico_id, es_defecto))
        
        flash('Relación médico-centro creada exitosamente', 'success')
        return redirect(url_for('facturacion_medico_centro'))
    
    tenant_id = get_current_tenant_id()
    
    # Cargar médicos y centros ACTIVOS del tenant
    medicos = execute_query('SELECT * FROM medicos WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    centros = execute_query('SELECT * FROM centros_medicos WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    
    # Si no hay médicos, verificar si hay inactivos
    if not medicos:
        medicos_inactivos = execute_query('SELECT nombre FROM medicos WHERE activo = 0 AND tenant_id = %s', (tenant_id,), fetch='all') or []
        if medicos_inactivos:
            nombres = ', '.join([m['nombre'] for m in medicos_inactivos])
            flash(f'No hay médicos ACTIVOS. Tienes médicos INACTIVOS: {nombres}. Ve a la lista de médicos para activarlos.', 'warning')
        else:
            flash('No hay médicos registrados. Por favor, crea un médico primero.', 'warning')
    
    if not centros:
        centros_inactivos = execute_query('SELECT nombre FROM centros_medicos WHERE activo = 0 AND tenant_id = %s', (tenant_id,), fetch='all') or []
        if centros_inactivos:
            nombres = ', '.join([c['nombre'] for c in centros_inactivos])
            flash(f'No hay centros médicos ACTIVOS. Tienes centros INACTIVOS: {nombres}. Ve a la lista de centros para activarlos.', 'warning')
        else:
            flash('No hay centros médicos registrados. Por favor, crea un centro médico primero.', 'warning')
    
    return render_template('facturacion/medico_centro_form.html', relacion=None, medicos=medicos, centros=centros)

@login_required
@transactional_methods('POST')
@permission_required('catalogos.editar')
def facturacion_medico_centro_editar(relacion_id):
    """Editar relación médico-centro"""
    
    tenant_id = get_current_tenant_id()
    
    # Obtener la relación actual
    relacion = execute_query('SELECT * FROM medico_centro WHERE id = %s AND tenant_id = %s', (relacion_id, tenant_id))
    if not relacion:
        flash('Relación no encontrada', 'error')
        return redirect(url_for('facturacion_medico_centro'))
    
    if request.method == 'POST':
        medico_id = request.form.get('medico_id')
        centro_medico_id = request.form.get('centro_medico_id')
        es_defecto = 1 if request.form.get('es_defecto') == '1' else 0
        
        if not medico_id or not centro_medico_id:
            flash('Médico y centro médico son obligatorios', 'error')
            return redirect(url_for('facturacion_medico_centro_editar', relacion_id=relacion_id))

        medico = execute_query(
            '''
            SELECT id FROM medicos
            WHERE id = %s AND tenant_id = %s AND activo = 1
            ''',
            (medico_id, tenant_id),
        )
        centro = execute_query(
            '''
            SELECT id FROM centros_medicos
            WHERE id = %s AND tenant_id = %s AND activo = 1
            ''',
            (centro_medico_id, tenant_id),
        )
        if not medico or not centro:
            flash('El médico o centro seleccionado no pertenece a tu empresa', 'error')
            return redirect(url_for(
                'facturacion_medico_centro_editar',
                relacion_id=relacion_id,
            ))

        # Verificar si ya existe otra relación con estos valores (excluyendo la actual)
        existe = execute_query('''
            SELECT id FROM medico_centro 
            WHERE medico_id = %s AND centro_medico_id = %s AND tenant_id = %s AND id != %s
        ''', (medico_id, centro_medico_id, tenant_id, relacion_id))
        
        if existe:
            flash('Ya existe otra relación con este médico y centro médico', 'error')
            return redirect(url_for('facturacion_medico_centro_editar', relacion_id=relacion_id))
        
        # Si se marca como por defecto, desmarcar otros centros por defecto de este médico
        if es_defecto:
            execute_update('''
                UPDATE medico_centro 
                SET es_defecto = 0 
                WHERE medico_id = %s AND tenant_id = %s AND id != %s
            ''', (medico_id, tenant_id, relacion_id))
        
        # Actualizar la relación
        execute_update('''
            UPDATE medico_centro 
            SET medico_id = %s, centro_medico_id = %s, es_defecto = %s
            WHERE id = %s AND tenant_id = %s
        ''', (medico_id, centro_medico_id, es_defecto, relacion_id, tenant_id))
        
        flash('Relación actualizada exitosamente', 'success')
        return redirect(url_for('facturacion_medico_centro'))
    
    # Cargar médicos y centros ACTIVOS del tenant
    medicos = execute_query('SELECT * FROM medicos WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    centros = execute_query('SELECT * FROM centros_medicos WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    
    return render_template('facturacion/medico_centro_form.html', relacion=relacion, medicos=medicos, centros=centros)

@login_required
@permission_required('catalogos.eliminar')
def facturacion_medico_centro_eliminar(relacion_id):
    """Eliminar relación médico-centro"""
    
    tenant_id = get_current_tenant_id()
    if not validate_tenant_access('medico_centro', relacion_id):
        flash('No tienes acceso a esta relación', 'error')
        return redirect(url_for('facturacion_medico_centro'))
    
    execute_update('DELETE FROM medico_centro WHERE id = %s AND tenant_id = %s', (relacion_id, tenant_id))
    flash('Relación eliminada exitosamente', 'success')
    return redirect(url_for('facturacion_medico_centro'))

def obtener_tipo_ncf_formulario():
    selector = request.form.get('tipo', '').strip().upper()
    if selector == 'OTRO':
        tipo = request.form.get('tipo_personalizado', '').strip().upper()
        descripcion = sanitize_input(
            request.form.get('descripcion_personalizada', ''), 150
        )
    else:
        tipo = selector
        descripcion = NCF_TIPOS_TRADICIONALES.get(tipo, '')
        if not descripcion and re.fullmatch(r'B\d{2}', tipo):
            existente = execute_query('''
                SELECT descripcion
                FROM ncf
                WHERE tenant_id=%s AND tipo=%s
                ORDER BY id DESC
                LIMIT 1
            ''', (get_current_tenant_id(), tipo))
            descripcion = (existente or {}).get('descripcion', '')

    if not re.fullmatch(r'B\d{2}', tipo):
        return None, None, 'El código debe tener formato B seguido de dos números'
    if not descripcion:
        return None, None, 'La descripción del tipo de NCF es obligatoria'
    return tipo, descripcion, None

def obtener_catalogo_ncf_tenant(tenant_id):
    catalogo = dict(NCF_TIPOS_TRADICIONALES)
    tipos_propios = execute_query('''
        SELECT tipo, MAX(descripcion) AS descripcion
        FROM ncf
        WHERE tenant_id=%s
        GROUP BY tipo
        ORDER BY tipo
    ''', (tenant_id,), fetch='all') or []
    for item in tipos_propios:
        tipo = str(item.get('tipo') or '').upper()
        descripcion = str(item.get('descripcion') or '').strip()
        if re.fullmatch(r'B\d{2}', tipo) and descripcion:
            catalogo[tipo] = descripcion
    return dict(sorted(catalogo.items()))

def obtener_catalogo_ecf_tenant(tenant_id):
    """Combinar tipos oficiales con tipos registrados por la empresa."""
    catalogo = dict(ECF_TYPE_CATALOG)
    personalizados = execute_query('''
        SELECT tipo_ecf, MAX(descripcion_tipo) AS descripcion
        FROM ecf_secuencias
        WHERE tenant_id=%s
          AND descripcion_tipo IS NOT NULL
          AND TRIM(descripcion_tipo)<>''
        GROUP BY tipo_ecf
        ORDER BY tipo_ecf
    ''', (tenant_id,), fetch='all') or []
    for item in personalizados:
        codigo = str(item.get('tipo_ecf') or '').strip()
        descripcion = str(item.get('descripcion') or '').strip()
        if re.fullmatch(r'\d{2}', codigo) and codigo != '00' and descripcion:
            catalogo[codigo] = descripcion
    return dict(sorted(catalogo.items()))

def obtener_tipo_ecf_formulario(catalogo):
    selector = request.form.get('tipo_ecf', '').strip()
    if selector == 'OTRO':
        codigo = request.form.get('tipo_ecf_personalizado', '').strip()
        descripcion = sanitize_input(
            request.form.get('descripcion_tipo_ecf', ''), 150
        )
        if codigo in catalogo:
            return None, None, (
                f'El tipo E{codigo} ya existe; selecciónalo en la lista'
            )
    else:
        codigo = selector
        descripcion = catalogo.get(codigo, '')

    if not re.fullmatch(r'\d{2}', codigo or '') or codigo == '00':
        return None, None, 'El tipo e-CF debe contener dos dígitos distintos de 00'
    if not descripcion:
        return None, None, 'La descripción del tipo e-CF es obligatoria'
    return codigo, descripcion, None

def build_ncf_number(tipo, numero, tamano):
    """Construir el NCF completo usando el tipo y el tamaño de secuencia."""
    return f"{tipo}{numero:0{tamano}d}"

def invoice_has_ncf(tenant_id, tipo, numero, tamano):
    """Comprobar si una factura de la empresa ya utiliza ese número NCF."""
    ncf_completo = build_ncf_number(tipo, numero, tamano)
    factura = execute_query(
        'SELECT id FROM facturas WHERE tenant_id = %s AND ncf = %s LIMIT 1',
        (tenant_id, ncf_completo)
    )
    return bool(factura), ncf_completo

@login_required
@permission_required('catalogos.ver')
def facturacion_ncf_verificar_numero():
    """Validar en tiempo real si un número NCF ya figura en facturas."""
    tipo = request.args.get('tipo', '')
    try:
        numero = int(request.args.get('numero', ''))
        tamano = int(request.args.get('tamano', '8'))
    except (TypeError, ValueError):
        return jsonify({'exists': False, 'valid': False}), 400

    if not re.fullmatch(r'B\d{2}', tipo) or numero < 0 or not 1 <= tamano <= 20:
        return jsonify({'exists': False, 'valid': False}), 400

    exists, ncf_completo = invoice_has_ncf(
        get_current_tenant_id(), tipo, numero, tamano
    )
    return jsonify({
        'exists': exists,
        'valid': True,
        'ncf': ncf_completo
    })

@login_required
@permission_required('catalogos.ver')
def facturacion_ncf():
    """Lista de NCF - Filtrado por tenant"""
    
    tenant_id = get_current_tenant_id()
    ncf_list = execute_query(
        'SELECT * FROM ncf WHERE tenant_id = %s ORDER BY tipo, id DESC',
        (tenant_id,),
        fetch='all',
    ) or []
    ecf_secuencias = execute_query('''
        SELECT *,
               GREATEST(ultimo_numero, secuencia_inicial - 1) + 1 AS proximo_numero
        FROM ecf_secuencias
        WHERE tenant_id = %s
        ORDER BY tipo_ecf, activo DESC, fecha_vencimiento DESC, id DESC
    ''', (tenant_id,), fetch='all') or []
    ecf_types = obtener_catalogo_ecf_tenant(tenant_id)
    return render_template(
        'facturacion/ncf.html',
        ncf_list=ncf_list,
        ecf_secuencias=ecf_secuencias,
        ecf_types=ecf_types,
    )

@login_required
@permission_required('catalogos.crear')
def facturacion_ecf_secuencia_nueva():
    """Registrar un rango e-NCF autorizado por la DGII."""

    tenant_id = get_current_tenant_id()
    ecf_types = obtener_catalogo_ecf_tenant(tenant_id)
    if request.method == 'POST':
        tipo_ecf, descripcion_tipo, tipo_error = (
            obtener_tipo_ecf_formulario(ecf_types)
        )
        fecha_autorizacion = request.form.get('fecha_autorizacion') or None
        fecha_vencimiento = request.form.get('fecha_vencimiento', '').strip()
        activo = 1 if request.form.get('activo') == '1' else 0
        try:
            if tipo_error:
                raise ValueError(tipo_error)
            secuencia_inicial = int(request.form.get('secuencia_inicial', ''))
            secuencia_final = int(request.form.get('secuencia_final', ''))
            ultimo_numero = int(
                request.form.get('ultimo_numero', str(secuencia_inicial - 1))
            )
            if not 1 <= secuencia_inicial <= 9999999999:
                raise ValueError('La secuencia inicial no es válida')
            if not secuencia_inicial <= secuencia_final <= 9999999999:
                raise ValueError('La secuencia final no es válida')
            if not secuencia_inicial - 1 <= ultimo_numero <= secuencia_final:
                raise ValueError('El último número utilizado está fuera del rango')
            if not fecha_vencimiento:
                raise ValueError('La fecha de vencimiento es obligatoria')
            fecha_fin = datetime.strptime(fecha_vencimiento, '%Y-%m-%d').date()
            fecha_inicio = (
                datetime.strptime(fecha_autorizacion, '%Y-%m-%d').date()
                if fecha_autorizacion else None
            )
            if fecha_inicio and fecha_fin < fecha_inicio:
                raise ValueError(
                    'La fecha de vencimiento no puede ser anterior a la autorización'
                )
        except (TypeError, ValueError) as error:
            flash(str(error) or 'Los datos de la secuencia no son válidos', 'error')
            return render_template(
                'facturacion/ncf_electronico_form.html',
                form=request.form,
                ecf_types=ecf_types,
            )

        overlapping = execute_query('''
            SELECT id
            FROM ecf_secuencias
            WHERE tenant_id=%s AND tipo_ecf=%s
              AND NOT (secuencia_final < %s OR secuencia_inicial > %s)
            LIMIT 1
        ''', (
            tenant_id,
            tipo_ecf,
            secuencia_inicial,
            secuencia_final
        ))
        if overlapping:
            flash('El rango indicado se solapa con otra secuencia e-NCF', 'error')
            return render_template(
                'facturacion/ncf_electronico_form.html',
                form=request.form,
                ecf_types=ecf_types,
            )

        execute_update('''
            INSERT INTO ecf_secuencias
            (tenant_id, tipo_ecf, descripcion_tipo, serie, secuencia_inicial,
             secuencia_final, ultimo_numero, fecha_autorizacion,
             fecha_vencimiento, activo)
            VALUES (%s, %s, %s, 'E', %s, %s, %s, %s, %s, %s)
        ''', (
            tenant_id,
            tipo_ecf,
            descripcion_tipo,
            secuencia_inicial,
            secuencia_final,
            ultimo_numero,
            fecha_autorizacion,
            fecha_vencimiento,
            activo
        ))
        flash(f'Secuencia E{tipo_ecf} registrada correctamente', 'success')
        return redirect(url_for('facturacion_ncf'))

    return render_template(
        'facturacion/ncf_electronico_form.html',
        form={},
        ecf_types=ecf_types,
    )

@login_required
@permission_required('catalogos.editar')
def facturacion_ecf_secuencia_estado(secuencia_id):
    """Activar o desactivar un rango e-NCF sin eliminar su historial."""

    tenant_id = get_current_tenant_id()
    secuencia = execute_query(
        'SELECT * FROM ecf_secuencias WHERE id=%s AND tenant_id=%s',
        (secuencia_id, tenant_id)
    )
    if not secuencia:
        flash('Secuencia electrónica no encontrada', 'error')
        return redirect(url_for('facturacion_ncf'))

    nuevo_estado = 0 if secuencia.get('activo') else 1
    if nuevo_estado:
        if secuencia['fecha_vencimiento'] < datetime.now().date():
            flash('No se puede activar una secuencia vencida', 'error')
            return redirect(url_for('facturacion_ncf'))
        if int(secuencia['ultimo_numero']) >= int(secuencia['secuencia_final']):
            flash('No se puede activar una secuencia agotada', 'error')
            return redirect(url_for('facturacion_ncf'))

    execute_update(
        'UPDATE ecf_secuencias SET activo=%s WHERE id=%s AND tenant_id=%s',
        (nuevo_estado, secuencia_id, tenant_id)
    )
    flash(
        f"Secuencia E31 {'activada' if nuevo_estado else 'desactivada'}",
        'success'
    )
    return redirect(url_for('facturacion_ncf'))

@login_required
@permission_required('catalogos.crear')
def facturacion_ncf_nuevo():
    """Crear nuevo NCF"""
    
    if request.method == 'POST':
        tipo, descripcion, tipo_error = obtener_tipo_ncf_formulario()
        if tipo_error:
            flash(tipo_error, 'error')
            return redirect(url_for('facturacion_ncf_nuevo'))
        prefijo = tipo or ''
        tamano_secuencia = request.form.get('tamano_secuencia', '8')
        ultimo_numero = request.form.get('ultimo_numero', '0')
        fecha_fin = request.form.get('fecha_fin')
        
        if not all([tipo, prefijo, tamano_secuencia]):
            flash('Tipo, Prefijo y Tamaño son obligatorios', 'error')
            return redirect(url_for('facturacion_ncf_nuevo'))
        
        try:
            ultimo_numero_int = int(ultimo_numero or 0)
            tamano_secuencia_int = int(tamano_secuencia)
            if ultimo_numero_int < 0 or not 1 <= tamano_secuencia_int <= 20:
                raise ValueError
        except (TypeError, ValueError):
            flash('El último número y el tamaño de secuencia no son válidos', 'error')
            return redirect(url_for('facturacion_ncf_nuevo'))

        tenant_id = get_current_tenant_id()
        exists, ncf_completo = invoice_has_ncf(
            tenant_id, tipo, ultimo_numero_int, tamano_secuencia_int
        )
        if exists:
            flash(
                f'No se puede usar el último número: la factura {ncf_completo} ya existe',
                'error'
            )
            return redirect(url_for('facturacion_ncf_nuevo'))

        proximo_numero = ultimo_numero_int + 1
        execute_update('''
            INSERT INTO ncf
                (tenant_id, tipo, descripcion, prefijo, ultimo_numero,
                 proximo_numero, tamano_secuencia, fecha_fin, activo)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 1)
        ''', (
            tenant_id, tipo, descripcion, prefijo, ultimo_numero_int,
            proximo_numero, tamano_secuencia_int, fecha_fin
        ))
        
        flash(f'NCF {tipo} creado exitosamente', 'success')
        return redirect(url_for('facturacion_ncf'))
    
    return render_template(
        'facturacion/ncf_form.html',
        ncf=None,
        ncf_tipos=obtener_catalogo_ncf_tenant(get_current_tenant_id()),
    )

@login_required
@permission_required('catalogos.editar')
def facturacion_ncf_editar(ncf_id):
    """Editar NCF"""
    
    tenant_id = get_current_tenant_id()
    ncf = execute_query(
        'SELECT * FROM ncf WHERE id = %s AND tenant_id = %s',
        (ncf_id, tenant_id),
    )
    if not ncf:
        flash('NCF no encontrado', 'error')
        return redirect(url_for('facturacion_ncf'))
    
    if request.method == 'POST':
        tipo, descripcion, tipo_error = obtener_tipo_ncf_formulario()
        if tipo_error:
            flash(tipo_error, 'error')
            return redirect(url_for('facturacion_ncf_editar', ncf_id=ncf_id))
        prefijo = tipo or ''
        tamano_secuencia = request.form.get('tamano_secuencia', '8')
        ultimo_numero = request.form.get('ultimo_numero', '0')
        fecha_fin = request.form.get('fecha_fin')
        activo = 1 if request.form.get('activo') == '1' else 0
        
        if not all([tipo, prefijo, tamano_secuencia]):
            flash('Tipo, Prefijo y Tamaño son obligatorios', 'error')
            return redirect(url_for('facturacion_ncf_editar', ncf_id=ncf_id))
        
        try:
            ultimo_numero_int = int(ultimo_numero or 0)
            tamano_secuencia_int = int(tamano_secuencia)
            if ultimo_numero_int < 0 or not 1 <= tamano_secuencia_int <= 20:
                raise ValueError
        except (TypeError, ValueError):
            flash('El último número y el tamaño de secuencia no son válidos', 'error')
            return redirect(url_for('facturacion_ncf_editar', ncf_id=ncf_id))

        tenant_id = get_current_tenant_id()
        sequence_changed = (
            tipo != ncf['tipo']
            or ultimo_numero_int != ncf['ultimo_numero']
            or tamano_secuencia_int != ncf['tamano_secuencia']
        )
        if sequence_changed:
            exists, ncf_completo = invoice_has_ncf(
                tenant_id, tipo, ultimo_numero_int, tamano_secuencia_int
            )
            if exists:
                flash(
                    f'No se puede usar el último número: la factura {ncf_completo} ya existe',
                    'error'
                )
                return redirect(url_for('facturacion_ncf_editar', ncf_id=ncf_id))

        proximo_numero = ultimo_numero_int + 1
        execute_update('''
            UPDATE ncf 
            SET tipo = %s, descripcion = %s, prefijo = %s,
                ultimo_numero = %s, proximo_numero = %s,
                tamano_secuencia = %s, fecha_fin = %s, activo = %s
            WHERE id = %s AND tenant_id = %s
        ''', (
            tipo, descripcion, prefijo, ultimo_numero_int, proximo_numero,
            tamano_secuencia_int, fecha_fin, activo, ncf_id, tenant_id
        ))
        
        flash(f'NCF actualizado exitosamente', 'success')
        return redirect(url_for('facturacion_ncf'))
    
    return render_template(
        'facturacion/ncf_form.html',
        ncf=ncf,
        ncf_tipos=obtener_catalogo_ncf_tenant(tenant_id),
    )

@login_required
@permission_required('catalogos.eliminar')
def facturacion_ncf_eliminar(ncf_id):
    """Eliminar NCF"""
    
    tenant_id = get_current_tenant_id()
    if not validate_tenant_access('ncf', ncf_id):
        flash('No tienes acceso a este NCF', 'error')
        return redirect(url_for('facturacion_ncf'))
    
    execute_update('DELETE FROM ncf WHERE id = %s AND tenant_id = %s', (ncf_id, tenant_id))
    flash('NCF eliminado exitosamente', 'success')
    return redirect(url_for('facturacion_ncf'))

def register_catalog_routes(app):
    app.add_url_rule('/facturacion/ars', endpoint='facturacion_ars', view_func=facturacion_ars)
    app.add_url_rule('/facturacion/ars/nuevo', endpoint='facturacion_ars_nuevo', view_func=facturacion_ars_nuevo, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/ars/<int:ars_id>/editar', endpoint='facturacion_ars_editar', view_func=facturacion_ars_editar, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/ars/<int:ars_id>/eliminar', endpoint='facturacion_ars_eliminar', view_func=facturacion_ars_eliminar, methods=['POST'])
    app.add_url_rule('/facturacion/medicos', endpoint='facturacion_medicos', view_func=facturacion_medicos)
    app.add_url_rule('/facturacion/medicos/nuevo', endpoint='facturacion_medicos_nuevo', view_func=facturacion_medicos_nuevo, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/medicos/<int:medico_id>/editar', endpoint='facturacion_medicos_editar', view_func=facturacion_medicos_editar, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/medicos/<int:medico_id>/eliminar', endpoint='facturacion_medicos_eliminar', view_func=facturacion_medicos_eliminar, methods=['POST'])
    app.add_url_rule('/facturacion/centros-medicos', endpoint='facturacion_centros_medicos', view_func=facturacion_centros_medicos)
    app.add_url_rule('/facturacion/centros-medicos/nuevo', endpoint='facturacion_centros_medicos_nuevo', view_func=facturacion_centros_medicos_nuevo, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/centros-medicos/<int:centro_id>/editar', endpoint='facturacion_centros_medicos_editar', view_func=facturacion_centros_medicos_editar, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/centros-medicos/<int:centro_id>/eliminar', endpoint='facturacion_centros_medicos_eliminar', view_func=facturacion_centros_medicos_eliminar, methods=['POST'])
    app.add_url_rule('/facturacion/servicios', endpoint='facturacion_servicios', view_func=facturacion_servicios)
    app.add_url_rule('/facturacion/servicios/nuevo', endpoint='facturacion_servicios_nuevo', view_func=facturacion_servicios_nuevo, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/servicios/<int:servicio_id>/editar', endpoint='facturacion_servicios_editar', view_func=facturacion_servicios_editar, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/servicios/<int:servicio_id>/eliminar', endpoint='facturacion_servicios_eliminar', view_func=facturacion_servicios_eliminar, methods=['POST'])
    app.add_url_rule('/facturacion/codigo-ars', endpoint='facturacion_codigo_ars', view_func=facturacion_codigo_ars)
    app.add_url_rule('/facturacion/codigo-ars/nuevo', endpoint='facturacion_codigo_ars_nuevo', view_func=facturacion_codigo_ars_nuevo, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/codigo-ars/<int:codigo_id>/editar', endpoint='facturacion_codigo_ars_editar', view_func=facturacion_codigo_ars_editar, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/codigo-ars/<int:codigo_id>/eliminar', endpoint='facturacion_codigo_ars_eliminar', view_func=facturacion_codigo_ars_eliminar, methods=['POST'])
    app.add_url_rule('/facturacion/medico-centro', endpoint='facturacion_medico_centro', view_func=facturacion_medico_centro)
    app.add_url_rule('/facturacion/medico-centro/nuevo', endpoint='facturacion_medico_centro_nuevo', view_func=facturacion_medico_centro_nuevo, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/medico-centro/<int:relacion_id>/editar', endpoint='facturacion_medico_centro_editar', view_func=facturacion_medico_centro_editar, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/medico-centro/<int:relacion_id>/eliminar', endpoint='facturacion_medico_centro_eliminar', view_func=facturacion_medico_centro_eliminar, methods=['POST'])
    app.add_url_rule('/facturacion/ncf/verificar-numero', endpoint='facturacion_ncf_verificar_numero', view_func=facturacion_ncf_verificar_numero)
    app.add_url_rule('/facturacion/ncf', endpoint='facturacion_ncf', view_func=facturacion_ncf)
    app.add_url_rule('/facturacion/ncf/electronico/nuevo', endpoint='facturacion_ecf_secuencia_nueva', view_func=facturacion_ecf_secuencia_nueva, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/ncf/electronico/<int:secuencia_id>/estado', endpoint='facturacion_ecf_secuencia_estado', view_func=facturacion_ecf_secuencia_estado, methods=['POST'])
    app.add_url_rule('/facturacion/ncf/nuevo', endpoint='facturacion_ncf_nuevo', view_func=facturacion_ncf_nuevo, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/ncf/<int:ncf_id>/editar', endpoint='facturacion_ncf_editar', view_func=facturacion_ncf_editar, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/ncf/<int:ncf_id>/eliminar', endpoint='facturacion_ncf_eliminar', view_func=facturacion_ncf_eliminar, methods=['POST'])
