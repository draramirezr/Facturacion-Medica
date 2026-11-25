"""Dashboard de facturación."""
from flask import render_template, request
from flask_login import current_user, login_required
from auth import permission_required, user_has_permission
from core.database import execute_query
from core.tenant import get_current_tenant_id


def _render_dashboard_medico(tenant_id, medico_id, fecha_desde, fecha_hasta):
    """Mostrar exclusivamente la actividad asociada al médico autenticado."""
    alcance = (tenant_id, medico_id, fecha_desde, fecha_hasta)
    consultas = execute_query('''
        SELECT COUNT(*) AS total,
               COUNT(DISTINCT paciente_id) AS pacientes,
               COALESCE(SUM(fecha = CURDATE()), 0) AS hoy
        FROM consultas_clinicas
        WHERE tenant_id=%s AND medico_id=%s
          AND fecha BETWEEN %s AND %s
    ''', alcance) or {}
    citas = execute_query('''
        SELECT COUNT(*) AS total,
               COALESCE(SUM(
                   estado = 'Programada'
                   AND TIMESTAMP(fecha, hora) >= NOW()
               ), 0) AS proximas
        FROM citas_medicas
        WHERE tenant_id=%s AND medico_id=%s
          AND fecha BETWEEN %s AND %s
    ''', alcance) or {}
    recetas = execute_query('''
        SELECT COUNT(*) AS total
        FROM recetas_medicas
        WHERE tenant_id=%s AND medico_id=%s
          AND fecha BETWEEN %s AND %s
    ''', alcance) or {}
    turnos = execute_query('''
        SELECT COUNT(*) AS total
        FROM turnos_atencion
        WHERE tenant_id=%s AND medico_id=%s
          AND fecha BETWEEN %s AND %s
          AND estado='Finalizado'
    ''', alcance) or {}
    actividad_reciente = execute_query('''
        SELECT c.id, c.paciente_id, c.fecha, c.hora,
               c.motivo_consulta, c.diagnostico_principal,
               p.nombre AS paciente_nombre
        FROM consultas_clinicas c
        JOIN pacientes p
          ON p.id=c.paciente_id AND p.tenant_id=c.tenant_id
        WHERE c.tenant_id=%s AND c.medico_id=%s
          AND c.fecha BETWEEN %s AND %s
        ORDER BY c.fecha DESC, c.hora DESC, c.id DESC
        LIMIT 10
    ''', alcance, fetch='all') or []
    medico = execute_query(
        'SELECT nombre, especialidad FROM medicos '
        'WHERE id=%s AND tenant_id=%s',
        (medico_id, tenant_id),
    ) or {}
    return render_template(
        'facturacion/dashboard_medico.html',
        medico=medico,
        consultas=consultas,
        citas=citas,
        recetas=recetas,
        turnos=turnos,
        actividad_reciente=actividad_reciente,
        fecha_desde=fecha_desde,
        fecha_hasta=fecha_hasta,
    )


@login_required
@permission_required('dashboard.ver')
def facturacion_dashboard():
    """Dashboard de facturación"""
    from datetime import datetime, timedelta
    
    # Fechas por defecto (último mes)
    fecha_hasta = request.args.get('fecha_hasta', datetime.now().strftime('%Y-%m-%d'))
    fecha_desde = request.args.get('fecha_desde', (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d'))
    
    # Estadísticas básicas
    total_facturas = 0
    total_facturado = 0.0
    monto_pendiente = 0.0
    ars_pendientes_nombres = []
    
    tenant_id = get_current_tenant_id()
    medico_id = getattr(current_user, 'medico_id', None)
    roles_rbac = set(getattr(current_user, 'rbac_roles', ()))
    es_medico = (
        'Médico' in roles_rbac
        or getattr(current_user, 'perfil', None) == 'Médico'
    )
    es_administrador = (
        'Administrador' in roles_rbac
        or getattr(current_user, 'perfil', None) == 'Administrador'
    )
    if medico_id and es_medico and not es_administrador:
        return _render_dashboard_medico(
            tenant_id,
            medico_id,
            fecha_desde,
            fecha_hasta,
        )
        
    try:
        # Total de facturas
        result = execute_query('''
            SELECT COUNT(*) as total FROM facturas 
            WHERE tenant_id = %s
        ''', (tenant_id,))
        total_facturas = result['total'] if result else 0
        
        # Total facturado
        result = execute_query('''
            SELECT COALESCE(SUM(total), 0) as total FROM facturas 
            WHERE tenant_id = %s
        ''', (tenant_id,))
        total_facturado = float(result['total']) if result and result['total'] else 0.0
        
        # Monto pendiente (si existe tabla pacientes con monto)
        try:
            result = execute_query('''
                SELECT COALESCE(SUM(monto), 0) as total FROM pacientes 
                WHERE tenant_id = %s
            ''', (tenant_id,))
            monto_pendiente = float(result['total']) if result and result['total'] else 0.0
        except:
            monto_pendiente = 0.0
        
        # ARS pendientes
        result = execute_query('''
            SELECT DISTINCT a.nombre 
            FROM pacientes_pendientes pp 
            JOIN ars a
              ON pp.ars_id = a.id
             AND a.tenant_id = pp.tenant_id
            WHERE pp.estado = 'Pendiente'
              AND pp.tenant_id = %s
        ''', (tenant_id,), fetch='all')
        ars_pendientes_nombres = [r['nombre'] for r in result] if result else []
        
    except Exception as e:
        print(f"Error en dashboard: {e}")
    
    # Facturación por mes
    facturacion_por_mes = []
    try:
        result = execute_query('''
            SELECT DATE_FORMAT(fecha_emision, '%%Y-%%m') as mes, 
                   SUM(total) as total_monto
            FROM facturas
            WHERE fecha_emision BETWEEN %s AND %s
              AND tenant_id = %s
            GROUP BY DATE_FORMAT(fecha_emision, '%%Y-%%m')
            ORDER BY mes
        ''', (fecha_desde, fecha_hasta, tenant_id), fetch='all')
        facturacion_por_mes = [{'mes': r['mes'], 'total_monto': float(r['total_monto'])} for r in result] if result else []
    except:
        facturacion_por_mes = []
    
    # Facturación por ARS y mes
    facturacion_ars_mes = []
    try:
        result = execute_query('''
            SELECT DATE_FORMAT(f.fecha_emision, '%%Y-%%m') as mes,
                   a.nombre as nombre_ars,
                   SUM(f.total) as total_monto
            FROM facturas f
            JOIN ars a
              ON f.ars_id = a.id
             AND a.tenant_id = f.tenant_id
            WHERE f.fecha_emision BETWEEN %s AND %s
              AND f.tenant_id = %s
            GROUP BY DATE_FORMAT(f.fecha_emision, '%%Y-%%m'), a.nombre
            ORDER BY mes, a.nombre
        ''', (fecha_desde, fecha_hasta, tenant_id), fetch='all')
        facturacion_ars_mes = [{'mes': r['mes'], 'nombre_ars': r['nombre_ars'], 'total_monto': float(r['total_monto'])} for r in result] if result else []
    except:
        facturacion_ars_mes = []
    
    # Listas para filtros
    tenant_id = get_current_tenant_id()
    ars_list = execute_query('SELECT * FROM ars WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    medicos_factura_list = execute_query('SELECT * FROM medicos WHERE activo = 1 AND tenant_id = %s ORDER BY nombre', (tenant_id,), fetch='all') or []
    medicos_consulta_list = medicos_factura_list  # Usar la misma lista
    
    return render_template('facturacion/dashboard.html',
                          total_facturas=total_facturas,
                          total_facturado=total_facturado,
                          monto_pendiente=monto_pendiente,
                          ars_pendientes_nombres=ars_pendientes_nombres,
                          facturacion_por_mes=facturacion_por_mes,
                          facturacion_ars_mes=facturacion_ars_mes,
                          ars_list=ars_list,
                          medicos_factura_list=medicos_factura_list,
                          medicos_consulta_list=medicos_consulta_list,
                          fecha_desde=fecha_desde,
                          fecha_hasta=fecha_hasta,
                          es_administrador=user_has_permission(current_user, 'facturacion.editar'),
                          ars_ids_seleccionados=[],
                          medico_factura_ids_seleccionados=[],
                          medico_consulta_ids_seleccionados=[])
