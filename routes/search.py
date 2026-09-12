"""Búsqueda global y detección de teléfonos repetidos."""

import re

from flask import jsonify, request, url_for
from flask_login import current_user, login_required

from core.database import execute_query
from core.presentation import hora_input
from core.tenant import get_current_tenant_id


@login_required
def api_busqueda_global():
    termino = request.args.get('q', '').strip()
    if len(termino) < 2:
        return jsonify({'resultados': []})
    tenant_id = get_current_tenant_id()
    patron = f'%{termino}%'
    digits = re.sub(r'\D', '', termino)
    phone_pattern = f'%{digits}%' if len(digits) >= 3 else patron
    results = []
    pacientes = execute_query(
        """
        SELECT id, nombre, cedula, nss, telefono FROM pacientes
        WHERE tenant_id=%s
          AND (nombre LIKE %s OR cedula LIKE %s OR nss LIKE %s
               OR telefono LIKE %s OR telefono_pariente LIKE %s OR email LIKE %s)
        ORDER BY nombre LIMIT 6
        """,
        (
            tenant_id, patron, patron, patron, phone_pattern, phone_pattern,
            patron,
        ),
        fetch='all',
    ) or []
    patient_endpoint = (
        'facturacion_paciente_acciones'
        if current_user.perfil == 'Registro de Facturas'
        else 'facturacion_historia_clinica_expediente'
    )
    for patient in pacientes:
        references = [
            value for value in (
                f"Cédula: {patient.get('cedula')}" if patient.get('cedula') else None,
                f"NSS: {patient.get('nss')}" if patient.get('nss') else None,
                patient.get('telefono'),
            ) if value
        ]
        results.append({
            'tipo': 'Paciente',
            'titulo': patient['nombre'],
            'detalle': ' · '.join(references) or 'Expediente del paciente',
            'icono': 'fas fa-user-injured',
            'url': url_for(patient_endpoint, paciente_id=patient['id']),
        })
    invoices = execute_query(
        """
        SELECT id, numero_factura, ncf, nombre_paciente, cedula_paciente,
               nss_paciente, nombre_ars, estado FROM facturas
        WHERE tenant_id=%s
          AND (numero_factura LIKE %s OR ncf LIKE %s OR nombre_paciente LIKE %s
               OR cedula_paciente LIKE %s OR nss_paciente LIKE %s
               OR nombre_ars LIKE %s)
        ORDER BY fecha_emision DESC, id DESC LIMIT 6
        """,
        (tenant_id, patron, patron, patron, patron, patron, patron),
        fetch='all',
    ) or []
    for invoice in invoices:
        results.append({
            'tipo': 'Factura',
            'titulo': invoice.get('numero_factura') or f"Factura {invoice['id']}",
            'detalle': (
                f"NCF: {invoice.get('ncf') or 'N/D'} · "
                f"{invoice.get('nombre_paciente') or 'Sin paciente'} · "
                f"{invoice.get('estado') or ''}"
            ),
            'icono': 'fas fa-file-invoice-dollar',
            'url': url_for('facturacion_ver_factura', factura_id=invoice['id']),
        })
    if current_user.perfil == 'Registro de Facturas':
        return jsonify({'resultados': results[:30]})
    _add_clinical_results(results, tenant_id, patron)
    if current_user.perfil in ('Administrador', 'Nivel 2'):
        _add_catalog_results(results, tenant_id, patron, phone_pattern)
    return jsonify({'resultados': results[:30]})


def _add_clinical_results(results, tenant_id, patron):
    consultations = execute_query(
        """
        SELECT c.id, c.fecha, c.motivo_consulta, c.diagnostico_principal,
               c.codigo_cie10, p.nombre AS paciente_nombre
        FROM consultas_clinicas c
        JOIN pacientes p ON p.id=c.paciente_id AND p.tenant_id=c.tenant_id
        WHERE c.tenant_id=%s
          AND (p.nombre LIKE %s OR p.cedula LIKE %s OR p.nss LIKE %s
               OR c.motivo_consulta LIKE %s OR c.diagnostico_principal LIKE %s
               OR c.codigo_cie10 LIKE %s)
        ORDER BY c.fecha DESC, c.id DESC LIMIT 6
        """,
        (tenant_id, patron, patron, patron, patron, patron, patron),
        fetch='all',
    ) or []
    for item in consultations:
        results.append({
            'tipo': 'Consulta clínica',
            'titulo': item['paciente_nombre'],
            'detalle': (
                f"{item['fecha']} · "
                f"{item.get('codigo_cie10') or item.get('diagnostico_principal') or item.get('motivo_consulta')}"
            ),
            'icono': 'fas fa-notes-medical',
            'url': url_for('facturacion_historia_clinica_ver', consulta_id=item['id']),
        })
    licenses = execute_query(
        """
        SELECT l.id, l.codigo, l.diagnostico, l.codigo_cie10, l.estado,
               p.nombre AS paciente_nombre, p.cedula
        FROM licencias_medicas l
        JOIN pacientes p ON p.id=l.paciente_id AND p.tenant_id=l.tenant_id
        WHERE l.tenant_id=%s
          AND (l.codigo LIKE %s OR p.nombre LIKE %s OR p.cedula LIKE %s
               OR l.diagnostico LIKE %s OR l.codigo_cie10 LIKE %s)
        ORDER BY l.fecha_emision DESC, l.id DESC LIMIT 6
        """,
        (tenant_id, patron, patron, patron, patron, patron),
        fetch='all',
    ) or []
    for item in licenses:
        results.append({
            'tipo': 'Licencia médica',
            'titulo': item['codigo'],
            'detalle': (
                f"{item['paciente_nombre']} · "
                f"{item.get('codigo_cie10') or item['diagnostico']} · "
                f"{item['estado']}"
            ),
            'icono': 'fas fa-file-medical',
            'url': url_for('facturacion_licencia_medica_ver', licencia_id=item['id']),
        })
    appointments = execute_query(
        """
        SELECT c.id, c.fecha, c.hora, c.motivo, c.estado,
               p.nombre AS paciente_nombre, m.nombre AS medico_nombre
        FROM citas_medicas c
        JOIN pacientes p ON p.id=c.paciente_id AND p.tenant_id=c.tenant_id
        JOIN medicos m ON m.id=c.medico_id AND m.tenant_id=c.tenant_id
        WHERE c.tenant_id=%s
          AND (p.nombre LIKE %s OR p.cedula LIKE %s
               OR m.nombre LIKE %s OR c.motivo LIKE %s)
        ORDER BY c.fecha DESC, c.hora DESC LIMIT 6
        """,
        (tenant_id, patron, patron, patron, patron),
        fetch='all',
    ) or []
    for item in appointments:
        results.append({
            'tipo': 'Cita médica',
            'titulo': item['paciente_nombre'],
            'detalle': (
                f"{item['fecha']} {hora_input(item['hora'])} · "
                f"{item['medico_nombre']} · {item['estado']}"
            ),
            'icono': 'fas fa-calendar-days',
            'url': url_for('facturacion_cita_editar', cita_id=item['id']),
        })
    prescriptions = execute_query(
        """
        SELECT DISTINCT r.id, r.codigo, r.fecha, r.estado,
               p.nombre AS paciente_nombre
        FROM recetas_medicas r
        JOIN pacientes p ON p.id=r.paciente_id AND p.tenant_id=r.tenant_id
        LEFT JOIN receta_medicamentos rm
          ON rm.receta_id=r.id AND rm.tenant_id=r.tenant_id
        WHERE r.tenant_id=%s
          AND (r.codigo LIKE %s OR p.nombre LIKE %s OR p.cedula LIKE %s
               OR r.diagnostico LIKE %s OR rm.medicamento LIKE %s)
        ORDER BY r.fecha DESC, r.id DESC LIMIT 6
        """,
        (tenant_id, patron, patron, patron, patron, patron),
        fetch='all',
    ) or []
    for item in prescriptions:
        results.append({
            'tipo': 'Receta médica',
            'titulo': item['paciente_nombre'],
            'detalle': f"{item['codigo']} · {item['fecha']} · {item['estado']}",
            'icono': 'fas fa-prescription',
            'url': url_for('facturacion_receta_medica_ver', receta_id=item['id']),
        })


def _add_catalog_results(results, tenant_id, patron, phone_pattern):
    specs = (
        (
            'Médico',
            """
            SELECT id, nombre, cedula, exequatur, especialidad, telefono
            FROM medicos WHERE tenant_id=%s
              AND (nombre LIKE %s OR cedula LIKE %s OR exequatur LIKE %s
                   OR especialidad LIKE %s OR telefono LIKE %s)
            ORDER BY nombre LIMIT 5
            """,
            (tenant_id, patron, patron, patron, patron, phone_pattern),
            'facturacion_medicos_editar',
            'medico_id',
            'fas fa-user-doctor',
            lambda x: (
                f"{x.get('especialidad') or 'Sin especialidad'} · "
                f"Exequátur: {x.get('exequatur') or 'N/D'}"
            ),
        ),
        (
            'ARS',
            """
            SELECT id, nombre, codigo, rnc, telefono FROM ars
            WHERE tenant_id=%s AND
              (nombre LIKE %s OR codigo LIKE %s OR rnc LIKE %s OR telefono LIKE %s)
            ORDER BY nombre LIMIT 5
            """,
            (tenant_id, patron, patron, patron, phone_pattern),
            'facturacion_ars_editar',
            'ars_id',
            'fas fa-shield-heart',
            lambda x: (
                f"Código: {x.get('codigo') or 'N/D'} · "
                f"RNC: {x.get('rnc') or 'N/D'} · "
                f"{x.get('telefono') or 'Sin teléfono'}"
            ),
        ),
        (
            'Centro médico',
            """
            SELECT id, nombre, codigo, rnc, telefono FROM centros_medicos
            WHERE tenant_id=%s AND
              (nombre LIKE %s OR codigo LIKE %s OR rnc LIKE %s OR telefono LIKE %s)
            ORDER BY nombre LIMIT 5
            """,
            (tenant_id, patron, patron, patron, phone_pattern),
            'facturacion_centros_medicos_editar',
            'centro_id',
            'fas fa-hospital',
            lambda x: (
                f"Código: {x.get('codigo') or 'N/D'} · "
                f"RNC: {x.get('rnc') or 'N/D'}"
            ),
        ),
        (
            'Servicio',
            """
            SELECT id, codigo, nombre, categoria FROM servicios
            WHERE tenant_id=%s AND
              (codigo LIKE %s OR nombre LIKE %s OR descripcion LIKE %s
               OR categoria LIKE %s)
            ORDER BY nombre LIMIT 5
            """,
            (tenant_id, patron, patron, patron, patron),
            'facturacion_servicios_editar',
            'servicio_id',
            'fas fa-list-check',
            lambda x: (
                f"Código: {x.get('codigo') or 'N/D'} · "
                f"{x.get('categoria') or 'Sin categoría'}"
            ),
        ),
    )
    for kind, query, params, endpoint, id_name, icon, detail in specs:
        for item in execute_query(query, params, fetch='all') or []:
            results.append({
                'tipo': kind,
                'titulo': item['nombre'],
                'detalle': detail(item),
                'icono': icon,
                'url': url_for(endpoint, **{id_name: item['id']}),
            })
    sequences = execute_query(
        """
        SELECT id, tipo, prefijo, ultimo_numero, activo FROM ncf
        WHERE tenant_id=%s
          AND (tipo LIKE %s OR prefijo LIKE %s
               OR CONCAT(prefijo, LPAD(ultimo_numero, 8, '0')) LIKE %s)
        ORDER BY tipo LIMIT 5
        """,
        (tenant_id, patron, patron, patron),
        fetch='all',
    ) or []
    for item in sequences:
        results.append({
            'tipo': 'Secuencia NCF',
            'titulo': f"{item['tipo']} · {item['prefijo']}",
            'detalle': f"Último número: {item.get('ultimo_numero') or 0}",
            'icono': 'fas fa-receipt',
            'url': url_for('facturacion_ncf_editar', ncf_id=item['id']),
        })


@login_required
def api_verificar_telefono():
    telefono = re.sub(r'\D', '', request.args.get('telefono', ''))
    if len(telefono) != 10:
        return jsonify({'coincidencias': []})
    tenant_id = get_current_tenant_id()
    matches = []
    patients = execute_query(
        'SELECT id, nombre, telefono, telefono_pariente FROM pacientes '
        'WHERE tenant_id=%s AND (telefono=%s OR telefono_pariente=%s) LIMIT 10',
        (tenant_id, telefono, telefono),
        fetch='all',
    ) or []
    for item in patients:
        matches.append({
            'tipo': (
                'paciente' if item.get('telefono') == telefono
                else 'pariente del paciente'
            ),
            'nombre': item['nombre'],
            'url': url_for('facturacion_pacientes_editar', paciente_id=item['id']),
        })
    if current_user.perfil == 'Registro de Facturas':
        return jsonify({'coincidencias': matches})
    tables = (
        ('medicos', 'médico', 'facturacion_medicos_editar', 'medico_id'),
        ('ars', 'ARS', 'facturacion_ars_editar', 'ars_id'),
        (
            'centros_medicos', 'centro médico',
            'facturacion_centros_medicos_editar', 'centro_id',
        ),
    )
    for table, kind, endpoint, parameter in tables:
        rows = execute_query(
            f'SELECT id, nombre FROM {table} '
            'WHERE tenant_id=%s AND telefono=%s LIMIT 10',
            (tenant_id, telefono),
            fetch='all',
        ) or []
        for item in rows:
            matches.append({
                'tipo': kind,
                'nombre': item['nombre'],
                'url': url_for(endpoint, **{parameter: item['id']}),
            })
    if tenant_id is not None:
        company = execute_query(
            'SELECT id, nombre FROM empresas WHERE id=%s AND telefono=%s',
            (tenant_id, telefono),
        )
        if company:
            matches.append({
                'tipo': 'empresa',
                'nombre': company['nombre'],
                'url': url_for(
                    'admin_empresas_editar', empresa_id=company['id'],
                ),
            })
    return jsonify({'coincidencias': matches})


def register_search_routes(app):
    app.add_url_rule(
        '/api/busqueda-global', 'api_busqueda_global', api_busqueda_global,
    )
    app.add_url_rule(
        '/api/verificar-telefono',
        'api_verificar_telefono',
        api_verificar_telefono,
    )
