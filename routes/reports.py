"""Histórico unificado de facturación y actividad clínica."""

import re

from flask import render_template, request
from flask_login import current_user

from auth import user_has_permission
from core.database import execute_query
from core.tenant import get_current_tenant_id
from routes.appointments import medico_id_agenda_restringida
from routes.clinical_history import medico_id_historias_restringido
from routes.emergency import medico_id_emergencias_restringido
from routes.licenses import medico_id_licencias_restringido
from routes.prescriptions import medico_id_recetas_restringido
from routes.support import execute_paginated_query, sanitize_input, validate_int

SECCIONES_HISTORICO = (
    {
        'id': 'facturas',
        'label': 'Facturas',
        'permiso': 'facturacion.ver',
        'icono': 'fa-file-invoice-dollar',
    },
    {
        'id': 'consultas',
        'label': 'Historia clínica',
        'permiso': 'historia_clinica.ver',
        'icono': 'fa-notes-medical',
    },
    {
        'id': 'emergencias',
        'label': 'Emergencias',
        'permiso': 'emergencia.ver',
        'icono': 'fa-truck-medical',
    },
    {
        'id': 'licencias',
        'label': 'Licencias',
        'permiso': 'licencias.ver',
        'icono': 'fa-file-medical',
    },
    {
        'id': 'citas',
        'label': 'Citas',
        'permiso': 'citas.ver',
        'icono': 'fa-calendar-check',
    },
    {
        'id': 'recetas',
        'label': 'Recetas',
        'permiso': 'recetas.ver',
        'icono': 'fa-prescription',
    },
    {
        'id': 'enfermeria',
        'label': 'Enfermería',
        'permiso': 'enfermeria.ver',
        'icono': 'fa-user-nurse',
    },
    {
        'id': 'reclamaciones',
        'label': 'Reclamaciones',
        'permiso': 'facturacion.ver',
        'icono': 'fa-triangle-exclamation',
    },
    {
        'id': 'pagos',
        'label': 'Pagos',
        'permiso': 'facturacion.ver',
        'icono': 'fa-money-check-dollar',
    },
)


def _secciones_visibles():
    return [
        seccion
        for seccion in SECCIONES_HISTORICO
        if user_has_permission(current_user, seccion['permiso'])
    ]


def _filtros_comunes():
    return {
        'buscar': sanitize_input(request.args.get('buscar', ''), 120),
        'ars_id': validate_int(request.args.get('ars_id'), min_value=1, default=None),
        'medico_id': validate_int(
            request.args.get('medico_id'), min_value=1, default=None
        ),
        'ncf': sanitize_input(request.args.get('ncf', ''), 20),
        'numero': sanitize_input(request.args.get('numero', ''), 40),
        'estado': sanitize_input(request.args.get('estado', ''), 40),
        'metodo_pago': sanitize_input(request.args.get('metodo_pago', ''), 40),
        'fecha_desde': sanitize_input(request.args.get('fecha_desde', ''), 10),
        'fecha_hasta': sanitize_input(request.args.get('fecha_hasta', ''), 10),
    }


def _aplicar_rango_fecha(query, params, columna, filtros):
    if filtros['fecha_desde']:
        query += f' AND {columna} >= %s'
        params.append(filtros['fecha_desde'])
    if filtros['fecha_hasta']:
        query += f' AND {columna} <= %s'
        params.append(filtros['fecha_hasta'])
    return query, params


def _patron_busqueda(texto):
    patron = f'%{texto}%'
    digits = re.sub(r'\D', '', texto)
    return patron, f'%{digits}%' if digits else patron


def _listar_medicos(tenant_id, restringido=None):
    return execute_query(
        '''
        SELECT id, nombre FROM medicos
        WHERE tenant_id=%s AND activo=1 AND (%s IS NULL OR id=%s)
        ORDER BY nombre
        ''',
        (tenant_id, restringido, restringido),
        fetch='all',
    ) or []


def _listar_ars(tenant_id):
    return execute_query(
        'SELECT id, nombre FROM ars WHERE activo=1 AND tenant_id=%s ORDER BY nombre',
        (tenant_id,),
        fetch='all',
    ) or []


def _consultar_facturas(tenant_id, filtros):
    query = '''
        SELECT f.id, f.fecha_emision AS fecha, f.numero_factura, f.ncf,
               f.nombre_ars, COALESCE(m.nombre, f.nombre_medico) AS medico,
               f.total, f.estado
        FROM facturas f
        LEFT JOIN medicos m
          ON m.id=f.medico_id AND m.tenant_id=f.tenant_id
        WHERE f.tenant_id=%s
    '''
    params = [tenant_id]
    if filtros['ars_id']:
        query += ' AND f.ars_id=%s'
        params.append(filtros['ars_id'])
    if filtros['medico_id']:
        query += ' AND f.medico_id=%s'
        params.append(filtros['medico_id'])
    if filtros['ncf']:
        query += ' AND f.ncf LIKE %s'
        params.append(f"%{filtros['ncf']}%")
    if filtros['estado'] in ('Pendiente', 'Pagada', 'Vencida', 'Anulada'):
        query += ' AND f.estado=%s'
        params.append(filtros['estado'])
    query, params = _aplicar_rango_fecha(query, params, 'f.fecha_emision', filtros)
    filas, pagination = execute_paginated_query(
        query, params, 'f.fecha_emision DESC, f.id DESC', default_per_page=50
    )
    return {
        'filas': filas,
        'pagination': pagination,
        'columnas': (
            ('fecha', 'Fecha'),
            ('numero_factura', 'Factura'),
            ('ncf', 'NCF'),
            ('nombre_ars', 'ARS'),
            ('medico', 'Médico'),
            ('total', 'Monto'),
            ('estado', 'Estado'),
        ),
        'ver_endpoint': 'facturacion_ver_factura',
        'ver_param': 'factura_id',
        'filtros': ('ars_id', 'medico_id', 'ncf', 'estado', 'fecha_desde', 'fecha_hasta'),
        'estados': ('Pendiente', 'Pagada', 'Vencida', 'Anulada'),
        'moneda': ('total',),
    }


def _consultar_consultas(tenant_id, filtros):
    restringido = medico_id_historias_restringido()
    medico_id = restringido or filtros['medico_id']
    query = '''
        SELECT c.id, c.fecha, c.hora, p.nombre AS paciente,
               m.nombre AS medico, c.motivo_consulta, c.diagnostico_principal
        FROM consultas_clinicas c
        JOIN pacientes p ON p.id=c.paciente_id AND p.tenant_id=c.tenant_id
        JOIN medicos m ON m.id=c.medico_id AND m.tenant_id=c.tenant_id
        WHERE c.tenant_id=%s
    '''
    params = [tenant_id]
    if medico_id:
        query += ' AND c.medico_id=%s'
        params.append(medico_id)
    if filtros['buscar']:
        patron, telefono = _patron_busqueda(filtros['buscar'])
        query += '''
            AND (
                p.nombre LIKE %s OR p.cedula LIKE %s OR p.nss LIKE %s
                OR REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(
                    COALESCE(p.telefono,''),'-',''),' ',''),'(',''),')',''),'+','')
                    LIKE %s
                OR c.motivo_consulta LIKE %s OR c.diagnostico_principal LIKE %s
            )
        '''
        params.extend([patron, patron, patron, telefono, patron, patron])
    query, params = _aplicar_rango_fecha(query, params, 'c.fecha', filtros)
    filas, pagination = execute_paginated_query(
        query, params, 'c.fecha DESC, c.id DESC'
    )
    return {
        'filas': filas,
        'pagination': pagination,
        'columnas': (
            ('fecha', 'Fecha'),
            ('hora', 'Hora'),
            ('paciente', 'Paciente'),
            ('medico', 'Médico'),
            ('motivo_consulta', 'Motivo'),
            ('diagnostico_principal', 'Diagnóstico'),
        ),
        'ver_endpoint': 'facturacion_historia_clinica_ver',
        'ver_param': 'consulta_id',
        'filtros': ('buscar', 'medico_id', 'fecha_desde', 'fecha_hasta'),
        'medico_restringido': restringido,
    }


def _consultar_emergencias(tenant_id, filtros):
    restringido = medico_id_emergencias_restringido()
    medico_id = restringido or filtros['medico_id']
    query = '''
        SELECT e.id, e.fecha, e.hora_servicio, e.nombre_paciente AS paciente,
               e.motivo_emergencia, e.estatus_paciente, e.medico_nombre AS medico
        FROM historias_emergencia e
        WHERE e.tenant_id=%s
    '''
    params = [tenant_id]
    if medico_id:
        query += ' AND e.medico_id=%s'
        params.append(medico_id)
    if filtros['estado']:
        query += ' AND e.estatus_paciente=%s'
        params.append(filtros['estado'])
    if filtros['buscar']:
        patron = f"%{filtros['buscar']}%"
        query += ' AND (e.nombre_paciente LIKE %s OR e.motivo_emergencia LIKE %s)'
        params.extend([patron, patron])
    query, params = _aplicar_rango_fecha(query, params, 'e.fecha', filtros)
    filas, pagination = execute_paginated_query(
        query, params, 'e.fecha DESC, e.id DESC'
    )
    return {
        'filas': filas,
        'pagination': pagination,
        'columnas': (
            ('fecha', 'Fecha'),
            ('hora_servicio', 'Hora'),
            ('paciente', 'Paciente'),
            ('medico', 'Médico'),
            ('motivo_emergencia', 'Motivo'),
            ('estatus_paciente', 'Estatus'),
        ),
        'ver_endpoint': 'facturacion_historia_emergencia_ver',
        'ver_param': 'historia_id',
        'filtros': ('buscar', 'medico_id', 'estado', 'fecha_desde', 'fecha_hasta'),
        'estados': (
            'Dado de alta', 'Referido', 'Alta a petición', 'Admitido', 'Fallecido',
        ),
        'medico_restringido': restringido,
    }


def _consultar_licencias(tenant_id, filtros):
    restringido = medico_id_licencias_restringido()
    medico_id = restringido or filtros['medico_id']
    query = '''
        SELECT l.id, l.codigo, l.fecha_emision AS fecha, l.fecha_inicio,
               l.fecha_termino, l.estado, p.nombre AS paciente,
               m.nombre AS medico, t.nombre AS tipo_licencia
        FROM licencias_medicas l
        JOIN pacientes p ON p.id=l.paciente_id AND p.tenant_id=l.tenant_id
        JOIN medicos m ON m.id=l.medico_id AND m.tenant_id=l.tenant_id
        JOIN tipos_licencia_medica t
          ON t.id=l.tipo_licencia_id AND t.tenant_id=l.tenant_id
        WHERE l.tenant_id=%s
    '''
    params = [tenant_id]
    if medico_id:
        query += ' AND l.medico_id=%s'
        params.append(medico_id)
    if filtros['estado'] in ('Borrador', 'Emitida', 'Anulada', 'Vencida'):
        query += ' AND l.estado=%s'
        params.append(filtros['estado'])
    if filtros['buscar']:
        patron, telefono = _patron_busqueda(filtros['buscar'])
        query += '''
            AND (
                l.codigo LIKE %s OR p.nombre LIKE %s OR p.cedula LIKE %s
                OR REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(
                    COALESCE(p.telefono,''),'-',''),' ',''),'(',''),')',''),'+','')
                    LIKE %s
                OR l.diagnostico LIKE %s
            )
        '''
        params.extend([patron, patron, patron, telefono, patron])
    query, params = _aplicar_rango_fecha(query, params, 'l.fecha_emision', filtros)
    filas, pagination = execute_paginated_query(
        query, params, 'l.fecha_emision DESC, l.id DESC'
    )
    return {
        'filas': filas,
        'pagination': pagination,
        'columnas': (
            ('fecha', 'Emisión'),
            ('codigo', 'Código'),
            ('paciente', 'Paciente'),
            ('medico', 'Médico'),
            ('tipo_licencia', 'Tipo'),
            ('fecha_inicio', 'Inicio'),
            ('fecha_termino', 'Término'),
            ('estado', 'Estado'),
        ),
        'ver_endpoint': 'facturacion_licencia_medica_ver',
        'ver_param': 'licencia_id',
        'filtros': ('buscar', 'medico_id', 'estado', 'fecha_desde', 'fecha_hasta'),
        'estados': ('Borrador', 'Emitida', 'Anulada', 'Vencida'),
        'medico_restringido': restringido,
    }


def _consultar_citas(tenant_id, filtros):
    restringido = medico_id_agenda_restringida()
    medico_id = restringido or filtros['medico_id']
    query = '''
        SELECT c.id, c.fecha, c.hora, c.estado, c.motivo,
               p.nombre AS paciente, m.nombre AS medico
        FROM citas_medicas c
        JOIN pacientes p ON p.id=c.paciente_id AND p.tenant_id=c.tenant_id
        JOIN medicos m ON m.id=c.medico_id AND m.tenant_id=c.tenant_id
        WHERE c.tenant_id=%s
    '''
    params = [tenant_id]
    if medico_id:
        query += ' AND c.medico_id=%s'
        params.append(medico_id)
    if filtros['estado'] in (
        'Programada', 'Confirmada', 'Completada', 'Cancelada', 'No asistió', 'Vencida',
    ):
        query += ' AND c.estado=%s'
        params.append(filtros['estado'])
    if filtros['buscar']:
        patron, telefono = _patron_busqueda(filtros['buscar'])
        query += '''
            AND (
                p.nombre LIKE %s OR p.cedula LIKE %s OR p.nss LIKE %s
                OR REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(
                    COALESCE(p.telefono,''),'-',''),' ',''),'(',''),')',''),'+','')
                    LIKE %s
                OR m.nombre LIKE %s OR c.motivo LIKE %s
            )
        '''
        params.extend([patron, patron, patron, telefono, patron, patron])
    query, params = _aplicar_rango_fecha(query, params, 'c.fecha', filtros)
    filas, pagination = execute_paginated_query(
        query, params, 'c.fecha DESC, c.hora DESC, c.id DESC'
    )
    return {
        'filas': filas,
        'pagination': pagination,
        'columnas': (
            ('fecha', 'Fecha'),
            ('hora', 'Hora'),
            ('paciente', 'Paciente'),
            ('medico', 'Médico'),
            ('motivo', 'Motivo'),
            ('estado', 'Estado'),
        ),
        'ver_endpoint': 'facturacion_cita_editar',
        'ver_param': 'cita_id',
        'filtros': ('buscar', 'medico_id', 'estado', 'fecha_desde', 'fecha_hasta'),
        'estados': (
            'Programada', 'Confirmada', 'Completada',
            'Cancelada', 'No asistió', 'Vencida',
        ),
        'medico_restringido': restringido,
    }


def _consultar_recetas(tenant_id, filtros):
    restringido = medico_id_recetas_restringido()
    medico_id = restringido or filtros['medico_id']
    query = '''
        SELECT r.id, r.codigo, r.fecha, r.diagnostico, r.estado,
               p.nombre AS paciente, m.nombre AS medico
        FROM recetas_medicas r
        JOIN pacientes p ON p.id=r.paciente_id AND p.tenant_id=r.tenant_id
        JOIN medicos m ON m.id=r.medico_id AND m.tenant_id=r.tenant_id
        WHERE r.tenant_id=%s
    '''
    params = [tenant_id]
    if medico_id:
        query += ' AND r.medico_id=%s'
        params.append(medico_id)
    if filtros['estado'] in ('Emitida', 'Anulada'):
        query += ' AND r.estado=%s'
        params.append(filtros['estado'])
    if filtros['buscar']:
        patron, telefono = _patron_busqueda(filtros['buscar'])
        query += '''
            AND (
                r.codigo LIKE %s OR p.nombre LIKE %s OR p.cedula LIKE %s
                OR REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(
                    COALESCE(p.telefono,''),'-',''),' ',''),'(',''),')',''),'+','')
                    LIKE %s
                OR r.diagnostico LIKE %s
            )
        '''
        params.extend([patron, patron, patron, telefono, patron])
    query, params = _aplicar_rango_fecha(query, params, 'r.fecha', filtros)
    filas, pagination = execute_paginated_query(
        query, params, 'r.fecha DESC, r.id DESC'
    )
    return {
        'filas': filas,
        'pagination': pagination,
        'columnas': (
            ('fecha', 'Fecha'),
            ('codigo', 'Código'),
            ('paciente', 'Paciente'),
            ('medico', 'Médico'),
            ('diagnostico', 'Diagnóstico'),
            ('estado', 'Estado'),
        ),
        'ver_endpoint': 'facturacion_receta_medica_ver',
        'ver_param': 'receta_id',
        'filtros': ('buscar', 'medico_id', 'estado', 'fecha_desde', 'fecha_hasta'),
        'estados': ('Emitida', 'Anulada'),
        'medico_restringido': restringido,
    }


def _consultar_enfermeria(tenant_id, filtros):
    query = '''
        SELECT h.id, h.fecha_servicio AS fecha, h.hora_servicio,
               h.nombre_paciente AS paciente, h.responsable
        FROM hojas_enfermeria h
        LEFT JOIN pacientes p
          ON p.id=h.paciente_id AND p.tenant_id=h.tenant_id
        WHERE h.tenant_id=%s
    '''
    params = [tenant_id]
    if filtros['buscar']:
        patron, telefono = _patron_busqueda(filtros['buscar'])
        query += '''
            AND (
                h.nombre_paciente LIKE %s OR p.cedula LIKE %s OR p.nss LIKE %s
                OR REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(
                    COALESCE(p.telefono,''),'-',''),' ',''),'(',''),')',''),'+','')
                    LIKE %s
            )
        '''
        params.extend([patron, patron, patron, telefono])
    query, params = _aplicar_rango_fecha(query, params, 'h.fecha_servicio', filtros)
    filas, pagination = execute_paginated_query(
        query, params, 'h.fecha_servicio DESC, h.id DESC'
    )
    return {
        'filas': filas,
        'pagination': pagination,
        'columnas': (
            ('fecha', 'Fecha'),
            ('hora_servicio', 'Hora'),
            ('paciente', 'Paciente'),
            ('responsable', 'Responsable'),
        ),
        'ver_endpoint': 'facturacion_hoja_enfermeria_ver',
        'ver_param': 'hoja_id',
        'filtros': ('buscar', 'fecha_desde', 'fecha_hasta'),
    }


def _consultar_reclamaciones(tenant_id, filtros):
    query = '''
        SELECT r.id, r.fecha_reclamacion AS fecha, r.monto_reclamado,
               r.estado, r.observaciones, f.numero_factura, f.nombre_ars
        FROM reclamaciones r
        JOIN facturas f ON f.id=r.factura_id AND f.tenant_id=r.tenant_id
        WHERE r.tenant_id=%s
    '''
    params = [tenant_id]
    if filtros['ars_id']:
        query += ' AND f.ars_id=%s'
        params.append(filtros['ars_id'])
    if filtros['estado'] in ('Pendiente', 'Procesada', 'Rechazada'):
        query += ' AND r.estado=%s'
        params.append(filtros['estado'])
    query, params = _aplicar_rango_fecha(query, params, 'r.fecha_reclamacion', filtros)
    filas, pagination = execute_paginated_query(
        query, params, 'r.fecha_reclamacion DESC, r.id DESC'
    )
    return {
        'filas': filas,
        'pagination': pagination,
        'columnas': (
            ('fecha', 'Fecha'),
            ('numero_factura', 'Factura'),
            ('nombre_ars', 'ARS'),
            ('monto_reclamado', 'Monto'),
            ('observaciones', 'Observación'),
            ('estado', 'Estado'),
        ),
        'ver_endpoint': 'facturacion_reclamacion_detalle',
        'ver_param': 'reclamacion_id',
        'filtros': ('ars_id', 'estado', 'fecha_desde', 'fecha_hasta'),
        'estados': ('Pendiente', 'Procesada', 'Rechazada'),
        'moneda': ('monto_reclamado',),
    }


def _consultar_pagos(tenant_id, filtros):
    query = '''
        SELECT p.id, p.fecha_pago AS fecha, p.metodo_pago, p.referencia,
               COALESCE(
                   (SELECT SUM(pf.monto_aplicado)
                    FROM pago_facturas pf
                    WHERE pf.pago_id=p.id AND pf.tenant_id=p.tenant_id),
                   p.monto,
                   0
               ) AS monto_total,
               CONCAT('PAGO-', LPAD(p.id, 6, '0')) AS numero_pago
        FROM pagos p
        WHERE p.tenant_id=%s
    '''
    params = [tenant_id]
    if filtros['metodo_pago'] in (
        'Transferencia', 'Efectivo', 'Cheque', 'Tarjeta', 'Otro',
    ):
        query += ' AND p.metodo_pago=%s'
        params.append(filtros['metodo_pago'])
    if filtros['numero']:
        query += ' AND p.referencia LIKE %s'
        params.append(f"%{filtros['numero']}%")
    query, params = _aplicar_rango_fecha(query, params, 'p.fecha_pago', filtros)
    filas, pagination = execute_paginated_query(
        query, params, 'p.fecha_pago DESC, p.id DESC'
    )
    return {
        'filas': filas,
        'pagination': pagination,
        'columnas': (
            ('fecha', 'Fecha'),
            ('numero_pago', 'Pago'),
            ('metodo_pago', 'Método'),
            ('referencia', 'Referencia'),
            ('monto_total', 'Monto'),
        ),
        'ver_endpoint': 'facturacion_pago_detalle',
        'ver_param': 'pago_id',
        'filtros': ('metodo_pago', 'numero', 'fecha_desde', 'fecha_hasta'),
        'metodos_pago': ('Transferencia', 'Efectivo', 'Cheque', 'Tarjeta', 'Otro'),
        'moneda': ('monto_total',),
    }


CONSULTORES = {
    'facturas': _consultar_facturas,
    'consultas': _consultar_consultas,
    'emergencias': _consultar_emergencias,
    'licencias': _consultar_licencias,
    'citas': _consultar_citas,
    'recetas': _consultar_recetas,
    'enfermeria': _consultar_enfermeria,
    'reclamaciones': _consultar_reclamaciones,
    'pagos': _consultar_pagos,
}


def renderizar_historico():
    tenant_id = get_current_tenant_id()
    secciones = _secciones_visibles()
    tipo = sanitize_input(request.args.get('tipo', ''), 30) or (
        secciones[0]['id'] if secciones else 'facturas'
    )
    if tipo not in {seccion['id'] for seccion in secciones}:
        tipo = secciones[0]['id'] if secciones else 'facturas'
    filtros = _filtros_comunes()
    consultor = CONSULTORES.get(tipo, _consultar_facturas)
    resultado = consultor(tenant_id, filtros)
    restringido = resultado.get('medico_restringido')
    return render_template(
        'facturacion/historico.html',
        tipo=tipo,
        secciones=secciones,
        filas=resultado.get('filas') or [],
        columnas=resultado.get('columnas') or (),
        pagination=resultado.get('pagination'),
        ver_endpoint=resultado.get('ver_endpoint'),
        ver_param=resultado.get('ver_param'),
        filtros_visibles=resultado.get('filtros') or (),
        estados=resultado.get('estados') or (),
        metodos_pago=resultado.get('metodos_pago') or (),
        campos_moneda=resultado.get('moneda') or (),
        filtros=filtros,
        ars_list=_listar_ars(tenant_id) if 'ars_id' in (resultado.get('filtros') or ()) else [],
        medicos_list=_listar_medicos(tenant_id, restringido)
        if 'medico_id' in (resultado.get('filtros') or ()) else [],
        medico_restringido=bool(restringido),
    )
