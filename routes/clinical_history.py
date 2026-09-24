"""Rutas y helpers de historia cl?nica."""

import json
import re
from datetime import datetime

from flask import flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from auth import permission_required, user_has_permission
from clinical_specialties import get_specialty_schema, validate_specialty_data
from core.database import execute_query, execute_update, transactional_methods
from core.presentation import hora_input
from core.tenant import get_current_tenant_id
from routes.appointments import actualizar_citas_vencidas
from routes.licenses import actualizar_licencias_vencidas
from routes.patients import paciente_adulto_sin_cedula
from routes.support import (
    calcular_edad_clinica, execute_paginated_query, sanitize_input,
    url_historia_clinica, validate_int,
)
from routes.turnos_screens import obtener_turno_tenant, registrar_evento_turno
from turnos import EstadoTurno


def medico_id_historias_restringido():
    """Restringir historias al médico vinculado para el rol Médico."""
    roles_rbac = set(getattr(current_user, 'rbac_roles', ()))
    es_medico = (
        'Médico' in roles_rbac
        or getattr(current_user, 'perfil', None) == 'Médico'
    )
    es_administrador = (
        'Administrador' in roles_rbac
        or getattr(current_user, 'perfil', None) == 'Administrador'
    )
    medico_id = getattr(current_user, 'medico_id', None)
    return medico_id if medico_id and es_medico and not es_administrador else None


def es_usuario_medico_clinico():
    """Rol o perfil Médico que no administra la empresa."""
    if not getattr(current_user, 'is_authenticated', False):
        return False
    roles_rbac = set(getattr(current_user, 'rbac_roles', ()) or ())
    es_administrador = (
        'Administrador' in roles_rbac
        or (
            getattr(current_user, 'perfil', None) == 'Administrador'
            and not getattr(current_user, 'rbac_role_count', 0)
        )
    )
    if es_administrador:
        return False
    return (
        'Médico' in roles_rbac
        or getattr(current_user, 'perfil', None) == 'Médico'
    )


def puede_ver_facturacion_paciente():
    """El médico ve el 360 clínico, no facturas, pagos ni reclamaciones."""
    if medico_id_historias_restringido() or es_usuario_medico_clinico():
        return False
    return user_has_permission(current_user, 'facturacion.ver')


def cargar_json_clinico(valor):
    try:
        return json.loads(valor or '{}')
    except (TypeError, ValueError):
        return {}


def parsear_presion_arterial(texto):
    """Devolver (sistólica, diastólica) o None si está vacía."""
    valor = str(texto or '').strip()
    if not valor:
        return None
    match = re.match(r'^(\d{2,3})\s*[/\-]\s*(\d{2,3})$', valor)
    if not match:
        return 'invalido'
    sistolica, diastolica = int(match.group(1)), int(match.group(2))
    return sistolica, diastolica


def alertas_signos_vitales(signos):
    """Avisos cuando un signo vital sale del rango habitual (no impide guardar)."""
    alertas = []
    presion = parsear_presion_arterial((signos or {}).get('presion_arterial'))
    if presion == 'invalido':
        alertas.append('Presión arterial: use el formato 120/80')
    elif presion:
        sistolica, diastolica = presion
        if sistolica < 85 or sistolica > 160 or diastolica < 50 or diastolica > 100:
            alertas.append(f'Presión arterial {sistolica}/{diastolica} mmHg (habitual 90-140 / 60-90)')
        elif sistolica <= diastolica:
            alertas.append(f'Presión arterial {sistolica}/{diastolica}: la sistólica debe ser mayor')
    def _fuera(nombre, valor, minimo, maximo, unidad=''):
        if valor in (None, ''):
            return
        try:
            numero = float(valor)
        except (TypeError, ValueError):
            return
        if numero < minimo or numero > maximo:
            etiqueta = f'{minimo:g}-{maximo:g}{(" " + unidad) if unidad else ""}'
            alertas.append(f'{nombre} {numero:g} (habitual {etiqueta})')
    _fuera('Frecuencia cardíaca', signos.get('frecuencia_cardiaca'), 50, 120, 'lpm')
    _fuera('Frecuencia respiratoria', signos.get('frecuencia_respiratoria'), 10, 24, 'rpm')
    _fuera('Temperatura', signos.get('temperatura'), 35.5, 38.0, '°C')
    _fuera('Saturación de oxígeno', signos.get('saturacion_oxigeno'), 92, 100, '%')
    _fuera('Peso', signos.get('peso'), 2.5, 200, 'kg')
    _fuera('Talla', signos.get('talla'), 0.50, 2.10, 'm')
    _fuera('IMC', signos.get('imc'), 16, 35)
    return alertas


def obtener_consulta_clinica_formulario():
    fecha = request.form.get('fecha', '').strip()
    hora = request.form.get('hora', '').strip()
    medico_id = (
        str(medico_id_historias_restringido())
        if medico_id_historias_restringido()
        else request.form.get('medico_id', '').strip()
    )
    motivo = sanitize_input(request.form.get('motivo_consulta', ''), 5000)
    diagnostico_principal = sanitize_input(request.form.get('diagnostico_principal', ''), 5000)

    if not all([fecha, hora, medico_id, motivo, diagnostico_principal]):
        return None, 'Fecha, hora, médico, motivo y diagnóstico principal son obligatorios'
    try:
        fecha_consulta = datetime.strptime(fecha, '%Y-%m-%d').date()
        datetime.strptime(hora, '%H:%M')
        medico_id = int(medico_id)
    except (ValueError, TypeError):
        return None, 'La fecha, hora o médico no es válido'
    if fecha_consulta > datetime.now().date():
        return None, 'La fecha de la consulta no puede ser futura'

    def texto(nombre, limite=5000):
        return sanitize_input(request.form.get(nombre, ''), limite)

    def numero_decimal(nombre, minimo, maximo):
        valor = request.form.get(nombre, '').strip()
        if not valor:
            return None
        try:
            numero = float(valor)
            return numero if minimo <= numero <= maximo else 'invalido'
        except ValueError:
            return 'invalido'

    def numero_entero(nombre, minimo, maximo):
        valor = request.form.get(nombre, '').strip()
        if not valor:
            return None
        numero = validate_int(valor, min_value=minimo, max_value=maximo, default=None)
        return numero if numero is not None else 'invalido'

    peso = numero_decimal('peso', 0.5, 400)
    talla = numero_decimal('talla', 0.3, 2.5)
    temperatura = numero_decimal('temperatura', 30, 45)
    saturacion = numero_decimal('saturacion_oxigeno', 0, 100)
    frecuencia_cardiaca = numero_entero('frecuencia_cardiaca', 1, 300)
    frecuencia_respiratoria = numero_entero('frecuencia_respiratoria', 1, 100)
    if 'invalido' in [peso, talla, temperatura, saturacion,
                      frecuencia_cardiaca, frecuencia_respiratoria]:
        return None, 'Revise los valores numéricos de los signos vitales'

    imc = round(peso / (talla * talla), 2) if peso and talla else None
    datos = {
        'fecha': fecha,
        'hora': hora,
        'medico_id': medico_id,
        'motivo_consulta': motivo,
        'enfermedad_actual': {
            'inicio_sintomas': texto('inicio_sintomas', 1000),
            'evolucion': texto('evolucion', 3000),
            'intensidad': texto('intensidad', 100),
            'factores_agravan': texto('factores_agravan', 2000),
            'factores_alivian': texto('factores_alivian', 2000),
            'sintomas_asociados': texto('sintomas_asociados', 3000),
            'tratamientos_previos': texto('tratamientos_previos', 3000)
        },
        'antecedentes_personales': {
            'enfermedades_previas': texto('enfermedades_previas', 3000),
            'cirugias': texto('cirugias', 2000),
            'hospitalizaciones': texto('hospitalizaciones', 2000),
            'alergias': texto('alergias', 2000),
            'medicamentos_actuales': texto('medicamentos_actuales', 3000),
            'habitos': texto('habitos', 2000),
            'otros': texto('otros_antecedentes', 3000)
        },
        'antecedentes_familiares': {
            'diabetes': request.form.get('familiar_diabetes') == '1',
            'hipertension': request.form.get('familiar_hipertension') == '1',
            'cardiacas': request.form.get('familiar_cardiacas') == '1',
            'cancer': request.form.get('familiar_cancer') == '1',
            'hereditarias': texto('familiar_hereditarias', 2000),
            'otros': texto('otros_antecedentes_familiares', 2000)
        },
        'signos_vitales': {
            'presion_arterial': texto('presion_arterial', 30),
            'frecuencia_cardiaca': frecuencia_cardiaca,
            'frecuencia_respiratoria': frecuencia_respiratoria,
            'temperatura': temperatura,
            'saturacion_oxigeno': saturacion,
            'peso': peso,
            'talla': talla,
            'imc': imc
        },
        'examen_fisico': {
            'estado_general': texto('estado_general', 2000),
            'cabeza_cuello': texto('cabeza_cuello', 2000),
            'cardiovascular': texto('cardiovascular', 2000),
            'respiratorio': texto('respiratorio', 2000),
            'abdomen': texto('abdomen', 2000),
            'extremidades': texto('extremidades', 2000),
            'neurologico': texto('neurologico', 2000),
            'otros': texto('otros_hallazgos', 3000)
        },
        'diagnostico_principal': diagnostico_principal,
        'diagnosticos_secundarios': texto('diagnosticos_secundarios', 4000),
        'diagnostico_presuntivo': texto('diagnostico_presuntivo', 3000),
        'diagnostico_diferencial': texto('diagnostico_diferencial', 3000),
        'codigo_cie10': texto('codigo_cie10', 30).upper(),
        'plan_tratamiento': {
            'medicamentos': texto('plan_medicamentos', 4000),
            'dosis': texto('plan_dosis', 1000),
            'frecuencia': texto('plan_frecuencia', 1000),
            'duracion': texto('plan_duracion', 1000),
            'laboratorios': texto('estudios_laboratorio', 3000),
            'imagenes': texto('estudios_imagenes', 3000),
            'procedimientos': texto('procedimientos', 3000),
            'recomendaciones': texto('recomendaciones', 4000)
        },
        'nota_evolucion_inicial': texto('nota_evolucion_inicial', 5000),
        'proxima_cita': request.form.get('proxima_cita') or None,
        'proxima_hora': request.form.get('proxima_hora') or None,
        'proxima_especialidad': texto('proxima_especialidad', 150),
        'proxima_motivo': texto('proxima_motivo', 2000),
        'indicaciones_seguimiento': texto('indicaciones_seguimiento', 3000),
    }
    if datos['proxima_cita']:
        try:
            proxima_cita = datetime.strptime(datos['proxima_cita'], '%Y-%m-%d').date()
        except ValueError:
            return None, 'La fecha de próxima cita no es válida'
        if proxima_cita < fecha_consulta:
            return None, 'La próxima cita no puede ser anterior a la consulta'
        if not datos['proxima_hora']:
            return None, 'Indique la hora de la próxima cita'
        try:
            datetime.strptime(datos['proxima_hora'], '%H:%M')
        except ValueError:
            return None, 'La hora de próxima cita no es válida'
    if parsear_presion_arterial(datos['signos_vitales']['presion_arterial']) == 'invalido':
        return None, 'La presión arterial debe escribirse como 120/80'
    alertas = alertas_signos_vitales(datos['signos_vitales'])
    if alertas and request.form.get('confirmar_signos_fuera_rango') != '1':
        return None, (
            'Hay signos vitales fuera del rango habitual: '
            + '; '.join(alertas)
            + '. Confirme si está seguro de esos valores.'
        )
    return datos, None


def completar_datos_especialidad(datos, medico):
    """Validar la sección dinámica usando la especialidad real del médico."""
    especialidad = (medico.get('especialidad') or '').strip()
    esquema = get_specialty_schema(especialidad)
    valores, errores = validate_specialty_data(request.form, esquema)
    if errores:
        return ', '.join(errores[:5])
    datos['especialidad_consulta'] = especialidad or esquema['label']
    datos['plantilla_version'] = esquema['version']
    datos['datos_especialidad'] = valores
    return None


def obtener_consulta_clinica(
    consulta_id,
    tenant_id,
    medico_id_restringido=None,
):
    consulta = execute_query('''
        SELECT c.*, p.nombre AS paciente_nombre, p.fecha_nacimiento, p.cedula,
               p.telefono, p.email, p.direccion, p.ocupacion, p.sexo,
               m.nombre AS medico_nombre,
               m.especialidad AS medico_especialidad
        FROM consultas_clinicas c
        JOIN pacientes p ON c.paciente_id = p.id AND p.tenant_id = c.tenant_id
        JOIN medicos m ON c.medico_id = m.id AND m.tenant_id = c.tenant_id
        WHERE c.id = %s AND c.tenant_id = %s
          AND (%s IS NULL OR c.medico_id=%s)
    ''', (
        consulta_id, tenant_id,
        medico_id_restringido, medico_id_restringido,
    ))
    if consulta:
        for campo in ['enfermedad_actual', 'antecedentes_personales',
                      'antecedentes_familiares', 'signos_vitales',
                      'examen_fisico', 'plan_tratamiento',
                      'datos_especialidad']:
            consulta[campo] = cargar_json_clinico(consulta.get(campo))
        especialidad = (
            consulta.get('especialidad_consulta')
            or consulta.get('medico_especialidad')
            or ''
        )
        consulta['esquema_especialidad'] = get_specialty_schema(especialidad)
    return consulta


def sincronizar_cita_desde_historia(consulta_id, tenant_id):
    """Crear o actualizar en agenda la próxima cita registrada en la historia."""
    consulta = execute_query('''
        SELECT c.id, c.paciente_id, c.medico_id, c.proxima_cita,
               c.proxima_hora, c.proxima_especialidad, c.proxima_motivo,
               c.indicaciones_seguimiento
        FROM consultas_clinicas c
        WHERE c.id=%s AND c.tenant_id=%s
    ''', (consulta_id, tenant_id))
    if not consulta:
        return 'No se encontró la consulta para programar la cita'
    existente = execute_query(
        'SELECT id, estado FROM citas_medicas '
        'WHERE tenant_id=%s AND consulta_origen_id=%s',
        (tenant_id, consulta_id)
    )
    if not consulta.get('proxima_cita'):
        if existente and existente['estado'] not in ['Completada', 'Cancelada']:
            execute_update('''
                UPDATE citas_medicas
                SET estado='Cancelada', motivo_cancelacion=%s,
                    fecha_cancelacion=NOW(), cancelada_por=%s, updated_by=%s
                WHERE id=%s AND tenant_id=%s
            ''', (
                'Próxima cita retirada de la Historia Clínica',
                current_user.id, current_user.id, existente['id'], tenant_id
            ))
        return None
    hora = consulta.get('proxima_hora') or '09:00:00'
    parametros = [
        tenant_id, consulta['medico_id'], consulta['paciente_id'],
        consulta['proxima_cita'],
        hora, hora
    ]
    query = '''
        SELECT c.id, c.hora, c.medico_id, c.paciente_id,
               p.nombre AS paciente_nombre
        FROM citas_medicas c
        JOIN pacientes p
          ON p.id=c.paciente_id AND p.tenant_id=c.tenant_id
        WHERE c.tenant_id=%s
          AND (c.medico_id=%s OR c.paciente_id=%s) AND c.fecha=%s
          AND c.estado NOT IN ('Cancelada','Vencida','No asistió')
          AND c.hora<ADDTIME(%s, '00:30:00')
          AND ADDTIME(c.hora, SEC_TO_TIME(c.duracion_minutos * 60))>%s
    '''
    if existente:
        query += ' AND c.id<>%s'
        parametros.append(existente['id'])
    query += ' LIMIT 1'
    conflicto = execute_query(query, tuple(parametros))
    if conflicto:
        recurso = (
            'el médico' if conflicto['medico_id'] == consulta['medico_id']
            else 'el paciente'
        )
        return (
            f"No se agregó a la agenda: {recurso} ya tiene una cita a las "
            f"{hora_input(conflicto['hora'])} con {conflicto['paciente_nombre']}"
        )
    motivo = consulta.get('proxima_motivo') or 'Seguimiento médico'
    if existente:
        execute_update('''
            UPDATE citas_medicas SET
                paciente_id=%s, medico_id=%s, fecha=%s, hora=%s,
                especialidad=%s, motivo=%s, notas=%s,
                estado=CASE WHEN estado IN ('Cancelada','Vencida')
                            THEN 'Programada' ELSE estado END,
                updated_by=%s
            WHERE id=%s AND tenant_id=%s
        ''', (
            consulta['paciente_id'], consulta['medico_id'],
            consulta['proxima_cita'], hora,
            consulta.get('proxima_especialidad'), motivo,
            consulta.get('indicaciones_seguimiento'), current_user.id,
            existente['id'], tenant_id
        ))
    else:
        execute_update('''
            INSERT INTO citas_medicas (
                tenant_id, paciente_id, medico_id, consulta_origen_id,
                fecha, hora, duracion_minutos, especialidad, motivo,
                notas, estado, origen, created_by, updated_by
            ) VALUES (
                %s,%s,%s,%s,%s,%s,30,%s,%s,%s,
                'Programada','Historia clinica',%s,%s
            )
        ''', (
            tenant_id, consulta['paciente_id'], consulta['medico_id'],
            consulta_id, consulta['proxima_cita'], hora,
            consulta.get('proxima_especialidad'), motivo,
            consulta.get('indicaciones_seguimiento'),
            current_user.id, current_user.id
        ))
    return None


@login_required
@permission_required('historia_clinica.ver')
def facturacion_historia_clinica():
    tenant_id = get_current_tenant_id()
    medico_id_restringido = medico_id_historias_restringido()
    search = request.args.get('search', '').strip()
    query = '''
        SELECT p.id, p.nombre, p.cedula, p.telefono, p.fecha_nacimiento,
               MAX(c.fecha) AS ultima_consulta, COUNT(c.id) AS total_consultas
        FROM pacientes p
        LEFT JOIN consultas_clinicas c
          ON c.paciente_id = p.id AND c.tenant_id = p.tenant_id
         AND (%s IS NULL OR c.medico_id=%s)
        WHERE p.tenant_id = %s
          AND (%s IS NULL OR c.id IS NOT NULL)
    '''
    params = [
        medico_id_restringido,
        medico_id_restringido,
        tenant_id,
        medico_id_restringido,
    ]
    if search:
        query += '''
            AND (
                p.nombre LIKE %s OR p.cedula LIKE %s OR p.nss LIKE %s
                OR REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(
                    COALESCE(p.telefono,''),'-',''),' ',''),'(',''),')',''),'+','')
                    LIKE %s
            )
        '''
        patron = f'%{search}%'
        phone_digits = re.sub(r'\D', '', search)
        phone_pattern = f'%{phone_digits}%' if phone_digits else patron
        params.extend([patron, patron, patron, phone_pattern])
    query += ' GROUP BY p.id'
    pacientes, pagination = execute_paginated_query(
        query,
        params,
        'p.nombre, p.id',
    )
    sin_historias_propias = []
    if search and medico_id_restringido and not pacientes:
        sin_historias_propias = execute_query(
            '''
            SELECT p.id, p.nombre, p.cedula, p.telefono
            FROM pacientes p
            WHERE p.tenant_id=%s
              AND (
                  p.nombre LIKE %s OR p.cedula LIKE %s OR p.nss LIKE %s
                  OR REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(
                      COALESCE(p.telefono,''),'-',''),' ',''),'(',''),')',''),
                      '+','') LIKE %s
              )
            ORDER BY p.nombre, p.id
            LIMIT 10
            ''',
            (tenant_id, patron, patron, patron, phone_pattern),
            fetch='all',
        ) or []
    return render_template(
        'facturacion/historia_clinica.html',
        pacientes=pacientes,
        search=search,
        pagination=pagination,
        historias_restringidas=bool(medico_id_restringido),
        sin_historias_propias=sin_historias_propias,
    )


@login_required
@permission_required('historia_clinica.ver')
def facturacion_reporte_pacientes_360():
    """Listado de pacientes para acceder a su vista clínica integral."""

    tenant_id = get_current_tenant_id()
    search = request.args.get('search', '').strip()
    query = '''
        SELECT p.id, p.nombre, p.cedula, p.telefono, p.fecha_nacimiento,
               p.sexo, MAX(c.fecha) AS ultima_consulta,
               COUNT(DISTINCT c.id) AS total_consultas
        FROM pacientes p
        LEFT JOIN consultas_clinicas c
          ON c.paciente_id=p.id AND c.tenant_id=p.tenant_id
        WHERE p.tenant_id=%s
    '''
    params = [tenant_id]
    if search:
        query += '''
            AND (
                p.nombre LIKE %s OR p.cedula LIKE %s
                OR REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(
                    COALESCE(p.telefono,''),'-',''),' ',''),'(',''),')',''),'+','')
                    LIKE %s
            )
        '''
        pattern = f'%{search}%'
        phone_digits = re.sub(r'\D', '', search)
        phone_pattern = f'%{phone_digits}%' if phone_digits else pattern
        params.extend([pattern, pattern, phone_pattern])
    query += '''
        GROUP BY p.id, p.nombre, p.cedula, p.telefono,
                 p.fecha_nacimiento, p.sexo
        ORDER BY p.nombre
        LIMIT 200
    '''
    pacientes = execute_query(query, tuple(params), fetch='all') or []
    for paciente in pacientes:
        paciente['edad'] = calcular_edad_clinica(
            paciente.get('fecha_nacimiento')
        )

    return render_template(
        'facturacion/reporte_pacientes_360.html',
        pacientes=pacientes,
        search=search,
    )


@login_required
@permission_required('historia_clinica.ver')
def facturacion_historia_clinica_expediente(paciente_id):
    tenant_id = get_current_tenant_id()
    paciente = execute_query('''
        SELECT p.*, a.nombre AS ars_nombre
        FROM pacientes p
        LEFT JOIN ars a
          ON p.ars_id = a.id AND a.tenant_id = p.tenant_id
        WHERE p.id = %s AND p.tenant_id = %s
    ''', (paciente_id, tenant_id))
    if not paciente:
        flash('Paciente no encontrado', 'error')
        return redirect(url_for('facturacion_historia_clinica'))
    paciente['edad'] = calcular_edad_clinica(paciente.get('fecha_nacimiento'))
    consultas = execute_query('''
        SELECT c.id, c.medico_id, c.fecha, c.hora, c.motivo_consulta,
               c.diagnostico_principal, c.plan_tratamiento,
               c.nota_evolucion_inicial, c.proxima_cita, c.version,
               m.nombre AS medico_nombre,
               COUNT(e.id) AS total_evoluciones
        FROM consultas_clinicas c
        JOIN medicos m
          ON c.medico_id = m.id AND m.tenant_id = c.tenant_id
        LEFT JOIN evoluciones_clinicas e
          ON e.consulta_id = c.id AND e.tenant_id = c.tenant_id
        WHERE c.paciente_id = %s AND c.tenant_id = %s
        GROUP BY c.id
        ORDER BY c.fecha DESC, c.hora DESC, c.id DESC
    ''', (paciente_id, tenant_id), fetch='all') or []
    for consulta in consultas:
        consulta['plan'] = cargar_json_clinico(
            consulta.get('plan_tratamiento')
        )
    actualizar_licencias_vencidas(tenant_id)
    licencias = execute_query('''
        SELECT l.id, l.medico_id, l.codigo, l.fecha_emision,
               l.fecha_inicio, l.fecha_termino,
               l.cantidad_dias, l.diagnostico, l.estado,
               m.nombre AS medico_nombre
        FROM licencias_medicas l
        JOIN medicos m
          ON m.id=l.medico_id AND m.tenant_id=l.tenant_id
        WHERE l.paciente_id=%s AND l.tenant_id=%s
        ORDER BY l.fecha_emision DESC, l.id DESC
    ''', (paciente_id, tenant_id), fetch='all') or []
    emergencias = execute_query('''
        SELECT id, medico_id, fecha, hora_servicio, motivo_emergencia,
               diagnostico_impresion, estatus_paciente, medico_nombre
        FROM historias_emergencia
        WHERE paciente_id=%s AND tenant_id=%s
        ORDER BY fecha DESC, hora_servicio DESC, id DESC
    ''', (paciente_id, tenant_id), fetch='all') or []
    ver_facturacion = puede_ver_facturacion_paciente()
    consultas_registradas = []
    facturas = []
    if ver_facturacion:
        consultas_registradas = execute_query('''
            SELECT pp.id, pp.fecha_servicio, pp.monto_estimado, pp.estado,
                   pp.servicios_realizados, pp.medico_id,
                   COALESCE(m.nombre, 'Sin médico asignado') AS medico_nombre
            FROM pacientes_pendientes pp
            LEFT JOIN medicos m
              ON m.id=pp.medico_id AND m.tenant_id=pp.tenant_id
            WHERE pp.paciente_id=%s AND pp.tenant_id=%s
            ORDER BY pp.fecha_servicio DESC, pp.id DESC
        ''', (paciente_id, tenant_id), fetch='all') or []
        facturas = execute_query('''
            SELECT id, numero_factura, ncf, fecha_emision, total, estado
            FROM facturas
            WHERE paciente_id=%s AND tenant_id=%s
            ORDER BY fecha_emision DESC, id DESC
        ''', (paciente_id, tenant_id), fetch='all') or []
    actualizar_citas_vencidas(tenant_id)
    citas = execute_query('''
        SELECT c.id, c.medico_id, c.fecha, c.hora, c.motivo, c.estado,
               c.especialidad, m.nombre AS medico_nombre
        FROM citas_medicas c
        JOIN medicos m ON m.id=c.medico_id AND m.tenant_id=c.tenant_id
        WHERE c.paciente_id=%s AND c.tenant_id=%s
        ORDER BY c.fecha DESC, c.hora DESC, c.id DESC
    ''', (paciente_id, tenant_id), fetch='all') or []
    recetas = execute_query('''
        SELECT r.id, r.medico_id, r.codigo, r.fecha, r.diagnostico, r.estado,
               m.nombre AS medico_nombre, COUNT(rm.id) AS medicamentos
        FROM recetas_medicas r
        JOIN medicos m ON m.id=r.medico_id AND m.tenant_id=r.tenant_id
        LEFT JOIN receta_medicamentos rm
          ON rm.receta_id=r.id AND rm.tenant_id=r.tenant_id
        WHERE r.paciente_id=%s AND r.tenant_id=%s
        GROUP BY r.id ORDER BY r.fecha DESC, r.id DESC
    ''', (paciente_id, tenant_id), fetch='all') or []
    actividades = (
        (consultas, 'historias'),
        (citas, 'citas'),
        (recetas, 'recetas'),
        (emergencias, 'emergencias'),
        (consultas_registradas, 'consultas_registradas'),
        (licencias, 'licencias'),
    )
    actividad_por_medico = {}
    for registros, categoria in actividades:
        for registro in registros:
            nombre = registro.get('medico_nombre') or 'Sin médico asignado'
            actividad = actividad_por_medico.setdefault(nombre, {
                'medico_nombre': nombre,
                'historias': 0,
                'citas': 0,
                'recetas': 0,
                'emergencias': 0,
                'consultas_registradas': 0,
                'licencias': 0,
            })
            actividad[categoria] += 1
    resumen = {
        'consultas_clinicas': len(consultas),
        'emergencias': len(emergencias),
        'citas': len(citas),
        'recetas': len(recetas),
        'licencias': len(licencias),
        'consultas_registradas': len(consultas_registradas),
        'facturas': len(facturas),
        'pendientes_facturar': sum(
            1 for registro in consultas_registradas
            if str(registro.get('estado', '')).lower() == 'pendiente'
        )
    }
    return render_template(
        'facturacion/paciente_360.html',
        paciente=paciente,
        consultas=consultas,
        citas=citas,
        recetas=recetas,
        licencias=licencias,
        emergencias=emergencias,
        consultas_registradas=consultas_registradas,
        facturas=facturas,
        resumen=resumen,
        actividad_por_medico=sorted(
            actividad_por_medico.values(),
            key=lambda item: item['medico_nombre'],
        ),
        ver_facturacion=ver_facturacion,
        vista_restringida=not ver_facturacion,
    )


@login_required
@permission_required('historia_clinica.crear')
def api_historia_clinica_plantilla_especialidad(medico_id):
    """Entregar el esquema clínico del médico dentro del tenant actual."""
    medico_id_restringido = medico_id_historias_restringido()
    if medico_id_restringido and medico_id != medico_id_restringido:
        return jsonify({'error': 'Médico no disponible'}), 403
    medico = execute_query(
        'SELECT id, especialidad FROM medicos '
        'WHERE id=%s AND tenant_id=%s AND activo=1',
        (medico_id, get_current_tenant_id())
    )
    if not medico:
        return jsonify({'error': 'Médico no encontrado'}), 404
    return jsonify(get_specialty_schema(medico.get('especialidad')))


@login_required
@transactional_methods('POST')
@permission_required('historia_clinica.crear')
def facturacion_historia_clinica_nueva(paciente_id):
    tenant_id = get_current_tenant_id()
    medico_id_restringido = medico_id_historias_restringido()
    turno_id = request.values.get('turno_id', type=int)
    turno = None
    paciente = execute_query(
        'SELECT * FROM pacientes WHERE id = %s AND tenant_id = %s',
        (paciente_id, tenant_id)
    )
    if not paciente:
        flash('Paciente no encontrado', 'error')
        return redirect(url_for('facturacion_historia_clinica'))
    if paciente_adulto_sin_cedula(paciente):
        flash('Debe actualizar la cédula propia del paciente antes de registrar la consulta', 'warning')
        return redirect(url_for('facturacion_paciente_acciones', paciente_id=paciente_id))
    if turno_id:
        turno = obtener_turno_tenant(
            turno_id,
            tenant_id,
            bloquear=request.method == 'POST',
        )
        if (
            not turno
            or int(turno['paciente_id']) != int(paciente_id)
            or (
                medico_id_restringido
                and int(turno['medico_id']) != int(medico_id_restringido)
            )
            or turno['estado'] != EstadoTurno.EnConsulta.value
            or turno.get('consulta_id')
        ):
            flash('El turno no está disponible para iniciar esta historia', 'error')
            return redirect(url_for('turnos_mi_cola'))
    if request.method == 'POST':
        datos, error = obtener_consulta_clinica_formulario()
        if error:
            flash(error, 'error')
            return redirect(url_for('facturacion_historia_clinica_nueva', paciente_id=paciente_id))
        medico = execute_query(
            'SELECT id, especialidad FROM medicos '
            'WHERE id = %s AND tenant_id = %s AND activo = 1',
            (datos['medico_id'], tenant_id)
        )
        if not medico:
            flash('El médico seleccionado no es válido', 'error')
            return redirect(url_for('facturacion_historia_clinica_nueva', paciente_id=paciente_id))
        if turno and int(turno['medico_id']) != int(datos['medico_id']):
            flash('La historia debe registrarse con el médico del turno', 'error')
            return redirect(url_for(
                'facturacion_historia_clinica_nueva',
                paciente_id=paciente_id,
                turno_id=turno_id,
            ))
        if (
            user_has_permission(current_user, 'turnos.cola_propia')
            and not user_has_permission(current_user, 'turnos.administrar')
            and int(datos['medico_id']) != int(current_user.medico_id or 0)
        ):
            flash('Solo puedes registrar historias para tu médico vinculado', 'error')
            return redirect(url_for('turnos_mi_cola'))
        error_especialidad = completar_datos_especialidad(datos, medico)
        if error_especialidad:
            flash(error_especialidad, 'error')
            return redirect(url_for(
                'facturacion_historia_clinica_nueva',
                paciente_id=paciente_id
            ))
        consulta_id = execute_update('''
            INSERT INTO consultas_clinicas (
                tenant_id, paciente_id, medico_id, especialidad_consulta,
                plantilla_version, datos_especialidad,
                fecha, hora, motivo_consulta,
                enfermedad_actual, antecedentes_personales, antecedentes_familiares,
                signos_vitales, examen_fisico, diagnostico_principal,
                diagnosticos_secundarios, diagnostico_presuntivo,
                diagnostico_diferencial, codigo_cie10, plan_tratamiento,
                nota_evolucion_inicial, proxima_cita, proxima_hora, proxima_especialidad,
                proxima_motivo, indicaciones_seguimiento, created_by, updated_by,
                turno_id
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s
            )
        ''', (
            tenant_id, paciente_id, datos['medico_id'],
            datos['especialidad_consulta'], datos['plantilla_version'],
            json.dumps(datos['datos_especialidad'], ensure_ascii=False),
            datos['fecha'], datos['hora'],
            datos['motivo_consulta'], json.dumps(datos['enfermedad_actual'], ensure_ascii=False),
            json.dumps(datos['antecedentes_personales'], ensure_ascii=False),
            json.dumps(datos['antecedentes_familiares'], ensure_ascii=False),
            json.dumps(datos['signos_vitales'], ensure_ascii=False),
            json.dumps(datos['examen_fisico'], ensure_ascii=False),
            datos['diagnostico_principal'], datos['diagnosticos_secundarios'],
            datos['diagnostico_presuntivo'], datos['diagnostico_diferencial'],
            datos['codigo_cie10'] or None,
            json.dumps(datos['plan_tratamiento'], ensure_ascii=False),
            datos['nota_evolucion_inicial'] or None, datos['proxima_cita'],
            datos['proxima_hora'],
            datos['proxima_especialidad'] or None, datos['proxima_motivo'] or None,
            datos['indicaciones_seguimiento'] or None, current_user.id,
            current_user.id, turno_id
        ))
        error_agenda = sincronizar_cita_desde_historia(consulta_id, tenant_id)
        if turno:
            execute_update('''
                UPDATE turnos_atencion
                SET consulta_id=%s, estado='Atendido', finalizado_at=NOW(),
                    actor_id=%s, updated_by=%s
                WHERE id=%s AND tenant_id=%s AND estado='EnConsulta'
            ''', (
                consulta_id,
                current_user.id,
                current_user.id,
                turno_id,
                tenant_id,
            ))
            registrar_evento_turno(
                turno_id,
                tenant_id,
                EstadoTurno.EnConsulta.value,
                EstadoTurno.Atendido.value,
                datos={'consulta_id': consulta_id},
            )
        if error_agenda:
            flash(error_agenda, 'warning')
        else:
            flash('Consulta clínica registrada y seguimiento agregado a la agenda', 'success')
        return redirect(url_for('facturacion_historia_clinica_ver', consulta_id=consulta_id))
    medicos = execute_query(
        'SELECT id, nombre, especialidad FROM medicos '
        'WHERE tenant_id = %s AND activo = 1 '
        'AND (%s IS NULL OR id=%s) ORDER BY nombre',
        (
            tenant_id,
            medico_id_restringido,
            medico_id_restringido,
        ),
        fetch='all',
    ) or []
    return render_template(
        'facturacion/historia_clinica_form.html',
        paciente=paciente, medicos=medicos, consulta=None,
        fecha_actual=datetime.now().strftime('%Y-%m-%d'),
        hora_actual=datetime.now().strftime('%H:%M'),
        esquema_especialidad=get_specialty_schema(
            medicos[0].get('especialidad')
            if medico_id_restringido and medicos else ''
        ),
        datos_especialidad={},
        turno_id=turno_id,
        medico_preseleccionado=(
            turno['medico_id'] if turno
            else (
                medico_id_restringido
                or request.args.get('medico_id', type=int)
            )
        ),
        motivo_preseleccionado=turno.get('motivo', '') if turno else '',
        historias_restringidas=bool(medico_id_restringido),
    )


@login_required
@permission_required('historia_clinica.ver')
def facturacion_historia_clinica_ver(consulta_id):
    tenant_id = get_current_tenant_id()
    medico_id_restringido = medico_id_historias_restringido()
    consulta = obtener_consulta_clinica(consulta_id, tenant_id)
    if not consulta:
        flash('Consulta clínica no encontrada', 'error')
        return redirect(url_for('facturacion_historia_clinica'))
    consulta['edad'] = calcular_edad_clinica(consulta.get('fecha_nacimiento'), consulta['fecha'])
    evoluciones = execute_query('''
        SELECT e.*, m.nombre AS medico_nombre
        FROM evoluciones_clinicas e
        JOIN medicos m
          ON e.medico_id = m.id AND m.tenant_id = e.tenant_id
        WHERE e.consulta_id = %s AND e.tenant_id = %s
        ORDER BY e.fecha ASC, e.hora ASC, e.id ASC
    ''', (consulta_id, tenant_id), fetch='all') or []
    auditoria = execute_query('''
        SELECT a.version_anterior, a.created_at, u.nombre AS usuario_nombre
        FROM auditoria_historia_clinica a
        LEFT JOIN usuarios u
          ON a.usuario_id = u.id AND u.tenant_id = a.tenant_id
        WHERE a.consulta_id = %s AND a.tenant_id = %s
        ORDER BY a.created_at DESC
    ''', (consulta_id, tenant_id), fetch='all') or []
    medicos = execute_query(
        'SELECT id, nombre FROM medicos '
        'WHERE tenant_id = %s AND activo = 1 '
        'AND (%s IS NULL OR id=%s) ORDER BY nombre',
        (
            tenant_id,
            medico_id_restringido,
            medico_id_restringido,
        ),
        fetch='all',
    ) or []
    cita_agenda = execute_query(
        'SELECT id, estado FROM citas_medicas '
        'WHERE consulta_origen_id=%s AND tenant_id=%s',
        (consulta_id, tenant_id)
    )
    recetas = execute_query('''
        SELECT r.id, r.codigo, r.fecha, r.estado, COUNT(rm.id) AS medicamentos
        FROM recetas_medicas r
        LEFT JOIN receta_medicamentos rm
          ON rm.receta_id=r.id AND rm.tenant_id=r.tenant_id
        WHERE r.consulta_id=%s AND r.tenant_id=%s
        GROUP BY r.id ORDER BY r.fecha DESC, r.id DESC
    ''', (consulta_id, tenant_id), fetch='all') or []
    recetas_disponibles = execute_query('''
        SELECT r.id, r.codigo, r.fecha, r.estado
        FROM recetas_medicas r
        WHERE r.tenant_id=%s AND r.paciente_id=%s
          AND r.estado<>'Anulada' AND r.consulta_id IS NULL
        ORDER BY r.fecha DESC, r.id DESC
        LIMIT 50
    ''', (tenant_id, consulta['paciente_id']), fetch='all') or []
    licencias = execute_query('''
        SELECT l.id, l.codigo, l.fecha_emision, l.fecha_inicio, l.fecha_termino,
               l.estado, l.diagnostico, t.nombre AS tipo_nombre
        FROM licencias_medicas l
        LEFT JOIN tipos_licencia_medica t
          ON t.id=l.tipo_licencia_id AND t.tenant_id=l.tenant_id
        WHERE l.consulta_id=%s AND l.tenant_id=%s
        ORDER BY l.fecha_emision DESC, l.id DESC
    ''', (consulta_id, tenant_id), fetch='all') or []
    licencias_disponibles = execute_query('''
        SELECT l.id, l.codigo, l.fecha_emision, l.estado, l.diagnostico
        FROM licencias_medicas l
        WHERE l.tenant_id=%s AND l.paciente_id=%s
          AND l.estado<>'Anulada' AND l.consulta_id IS NULL
        ORDER BY l.fecha_emision DESC, l.id DESC
        LIMIT 50
    ''', (tenant_id, consulta['paciente_id']), fetch='all') or []
    tipos_licencia = execute_query(
        'SELECT id, nombre FROM tipos_licencia_medica '
        'WHERE tenant_id=%s AND activo=1 ORDER BY nombre',
        (tenant_id,), fetch='all'
    ) or []
    return render_template(
        'facturacion/historia_clinica_ver.html',
        consulta=consulta, evoluciones=evoluciones,
        auditoria=auditoria, medicos=medicos, cita_agenda=cita_agenda,
        recetas=recetas, recetas_disponibles=recetas_disponibles,
        licencias=licencias, licencias_disponibles=licencias_disponibles,
        tipos_licencia=tipos_licencia,
        fecha_actual=datetime.now().strftime('%Y-%m-%d'),
        hora_actual=datetime.now().strftime('%H:%M')
    )


@login_required
@transactional_methods('POST')
@permission_required('historia_clinica.ver')
def facturacion_historia_vincular_documento(consulta_id):
    """Relacionar o quitar una receta o licencia de esta consulta, de forma opcional."""
    tenant_id = get_current_tenant_id()
    medico_id_restringido = medico_id_historias_restringido()
    consulta = obtener_consulta_clinica(
        consulta_id, tenant_id, medico_id_restringido
    )
    if not consulta:
        flash('Consulta clínica no encontrada', 'error')
        return redirect(url_for('facturacion_historia_clinica'))
    tipo = (request.form.get('tipo') or '').strip()
    accion = (request.form.get('accion') or 'vincular').strip()
    documento_id = validate_int(
        request.form.get('documento_id'), min_value=1, default=None
    )
    pestana = 'recetas' if tipo == 'receta' else 'licencias'
    if tipo not in {'receta', 'licencia'} or not documento_id:
        flash('Seleccione un documento para relacionar', 'error')
        return redirect(url_historia_clinica(consulta_id, pestana))
    permiso = 'recetas.crear' if tipo == 'receta' else 'licencias.crear'
    if not user_has_permission(current_user, permiso):
        flash('No tiene permiso para relacionar este documento', 'error')
        return redirect(url_historia_clinica(consulta_id, pestana))
    if tipo == 'receta':
        fila = execute_query(
            'SELECT id, paciente_id, consulta_id, estado FROM recetas_medicas '
            'WHERE id=%s AND tenant_id=%s',
            (documento_id, tenant_id),
        )
        tabla = 'recetas_medicas'
        etiqueta = 'Receta'
    else:
        fila = execute_query(
            'SELECT id, paciente_id, consulta_id, estado FROM licencias_medicas '
            'WHERE id=%s AND tenant_id=%s',
            (documento_id, tenant_id),
        )
        tabla = 'licencias_medicas'
        etiqueta = 'Licencia'
    if not fila or fila['paciente_id'] != consulta['paciente_id']:
        flash(f'La {etiqueta.lower()} no pertenece a este paciente', 'error')
        return redirect(url_historia_clinica(consulta_id, pestana))
    if fila.get('estado') == 'Anulada':
        flash(f'No se puede relacionar una {etiqueta.lower()} anulada', 'error')
        return redirect(url_historia_clinica(consulta_id, pestana))
    if accion == 'desvincular':
        execute_update(
            f'UPDATE {tabla} SET consulta_id=NULL '
            'WHERE id=%s AND tenant_id=%s AND consulta_id=%s',
            (documento_id, tenant_id, consulta_id),
        )
        flash(f'{etiqueta} desvinculada de esta consulta', 'success')
    else:
        execute_update(
            f'UPDATE {tabla} SET consulta_id=%s '
            'WHERE id=%s AND tenant_id=%s',
            (consulta_id, documento_id, tenant_id),
        )
        flash(f'{etiqueta} relacionada con esta consulta', 'success')
    return redirect(url_historia_clinica(consulta_id, pestana))


@login_required
@transactional_methods('POST')
@permission_required('historia_clinica.editar')
def facturacion_historia_clinica_editar(consulta_id):
    tenant_id = get_current_tenant_id()
    medico_id_restringido = medico_id_historias_restringido()
    consulta = obtener_consulta_clinica(
        consulta_id,
        tenant_id,
        medico_id_restringido,
    )
    if not consulta:
        flash('Consulta clínica no encontrada', 'error')
        return redirect(url_for('facturacion_historia_clinica'))
    if request.method == 'POST':
        datos, error = obtener_consulta_clinica_formulario()
        if error:
            flash(error, 'error')
            return redirect(url_for('facturacion_historia_clinica_editar', consulta_id=consulta_id))
        medico = execute_query(
            'SELECT id, especialidad FROM medicos '
            'WHERE id = %s AND tenant_id = %s AND activo = 1',
            (datos['medico_id'], tenant_id)
        )
        if not medico:
            flash('El médico seleccionado no es válido', 'error')
            return redirect(url_for('facturacion_historia_clinica_editar', consulta_id=consulta_id))
        error_especialidad = completar_datos_especialidad(datos, medico)
        if error_especialidad:
            flash(error_especialidad, 'error')
            return redirect(url_for(
                'facturacion_historia_clinica_editar',
                consulta_id=consulta_id
            ))
        datos_anteriores = json.dumps(consulta, default=str, ensure_ascii=False)
        version_anterior = consulta['version']
        execute_update('''
            UPDATE consultas_clinicas SET
                medico_id=%s, especialidad_consulta=%s,
                plantilla_version=%s, datos_especialidad=%s,
                fecha=%s, hora=%s, motivo_consulta=%s,
                enfermedad_actual=%s, antecedentes_personales=%s,
                antecedentes_familiares=%s, signos_vitales=%s, examen_fisico=%s,
                diagnostico_principal=%s, diagnosticos_secundarios=%s,
                diagnostico_presuntivo=%s, diagnostico_diferencial=%s,
                codigo_cie10=%s, plan_tratamiento=%s, nota_evolucion_inicial=%s,
                proxima_cita=%s, proxima_hora=%s, proxima_especialidad=%s, proxima_motivo=%s,
                indicaciones_seguimiento=%s, version=version+1, updated_by=%s
            WHERE id=%s AND tenant_id=%s
        ''', (
            datos['medico_id'], datos['especialidad_consulta'],
            datos['plantilla_version'],
            json.dumps(datos['datos_especialidad'], ensure_ascii=False),
            datos['fecha'], datos['hora'], datos['motivo_consulta'],
            json.dumps(datos['enfermedad_actual'], ensure_ascii=False),
            json.dumps(datos['antecedentes_personales'], ensure_ascii=False),
            json.dumps(datos['antecedentes_familiares'], ensure_ascii=False),
            json.dumps(datos['signos_vitales'], ensure_ascii=False),
            json.dumps(datos['examen_fisico'], ensure_ascii=False),
            datos['diagnostico_principal'], datos['diagnosticos_secundarios'],
            datos['diagnostico_presuntivo'], datos['diagnostico_diferencial'],
            datos['codigo_cie10'] or None,
            json.dumps(datos['plan_tratamiento'], ensure_ascii=False),
            datos['nota_evolucion_inicial'] or None, datos['proxima_cita'],
            datos['proxima_hora'],
            datos['proxima_especialidad'] or None, datos['proxima_motivo'] or None,
            datos['indicaciones_seguimiento'] or None, current_user.id,
            consulta_id, tenant_id
        ))
        consulta_nueva = execute_query(
            'SELECT * FROM consultas_clinicas WHERE id=%s AND tenant_id=%s',
            (consulta_id, tenant_id)
        )
        execute_update('''
            INSERT INTO auditoria_historia_clinica (
                tenant_id, consulta_id, usuario_id, version_anterior,
                datos_anteriores, datos_nuevos, ip, user_agent
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ''', (
            tenant_id, consulta_id, current_user.id, version_anterior,
            datos_anteriores, json.dumps(consulta_nueva, default=str, ensure_ascii=False),
            request.remote_addr, (request.user_agent.string or '')[:500]
        ))
        error_agenda = sincronizar_cita_desde_historia(consulta_id, tenant_id)
        if error_agenda:
            flash(error_agenda, 'warning')
        else:
            flash('Consulta actualizada y próxima cita sincronizada con la agenda', 'success')
        return redirect(url_for('facturacion_historia_clinica_ver', consulta_id=consulta_id))
    medicos = execute_query(
        'SELECT id, nombre, especialidad FROM medicos '
        'WHERE tenant_id=%s AND activo=1 '
        'AND (%s IS NULL OR id=%s) ORDER BY nombre',
        (
            tenant_id,
            medico_id_restringido,
            medico_id_restringido,
        ),
        fetch='all',
    ) or []
    return render_template(
        'facturacion/historia_clinica_form.html',
        paciente=consulta, medicos=medicos, consulta=consulta,
        fecha_actual=consulta['fecha'], hora_actual=str(consulta['hora'])[:5],
        esquema_especialidad=consulta['esquema_especialidad'],
        datos_especialidad=consulta['datos_especialidad'],
        historias_restringidas=bool(medico_id_restringido),
    )


@login_required
@permission_required('historia_clinica.editar')
def facturacion_historia_clinica_evolucion(consulta_id):
    tenant_id = get_current_tenant_id()
    medico_id_restringido = medico_id_historias_restringido()
    consulta = execute_query(
        'SELECT id, paciente_id, fecha FROM consultas_clinicas '
        'WHERE id=%s AND tenant_id=%s '
        'AND (%s IS NULL OR medico_id=%s)',
        (
            consulta_id, tenant_id,
            medico_id_restringido, medico_id_restringido,
        )
    )
    nota = sanitize_input(request.form.get('nota_evolucion', ''), 5000)
    fecha = request.form.get('fecha_evolucion', '').strip()
    hora = request.form.get('hora_evolucion', '').strip()
    medico_id = (
        str(medico_id_restringido)
        if medico_id_restringido
        else request.form.get('medico_evolucion', '').strip()
    )
    if not consulta or not all([nota, fecha, hora, medico_id]):
        flash('Complete todos los datos de la evolución', 'error')
        return redirect(url_for('facturacion_historia_clinica_ver', consulta_id=consulta_id))
    try:
        fecha_evolucion = datetime.strptime(fecha, '%Y-%m-%d').date()
        datetime.strptime(hora, '%H:%M')
        medico_id = int(medico_id)
    except (ValueError, TypeError):
        flash('Los datos de la evolución no son válidos', 'error')
        return redirect(url_for('facturacion_historia_clinica_ver', consulta_id=consulta_id))
    if fecha_evolucion < consulta['fecha'] or fecha_evolucion > datetime.now().date():
        flash('La fecha de evolución debe estar entre la consulta y hoy', 'error')
        return redirect(url_for('facturacion_historia_clinica_ver', consulta_id=consulta_id))
    medico = execute_query(
        'SELECT id FROM medicos WHERE id=%s AND tenant_id=%s AND activo=1',
        (medico_id, tenant_id)
    )
    if not medico:
        flash('El médico seleccionado no es válido', 'error')
        return redirect(url_for('facturacion_historia_clinica_ver', consulta_id=consulta_id))
    execute_update('''
        INSERT INTO evoluciones_clinicas (
            tenant_id, consulta_id, paciente_id, medico_id, fecha, hora,
            nota_evolucion, diagnostico, tratamiento, created_by
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ''', (
        tenant_id, consulta_id, consulta['paciente_id'], medico_id, fecha, hora,
        nota, sanitize_input(request.form.get('diagnostico_evolucion', ''), 3000) or None,
        sanitize_input(request.form.get('tratamiento_evolucion', ''), 3000) or None,
        current_user.id
    ))
    flash('Nueva nota de evolución agregada al historial', 'success')
    return redirect(url_for('facturacion_historia_clinica_ver', consulta_id=consulta_id))


def register_clinical_history_routes(app):
    app.add_url_rule('/facturacion/historia-clinica', endpoint='facturacion_historia_clinica', view_func=facturacion_historia_clinica)
    app.add_url_rule('/facturacion/reportes/pacientes-360', endpoint='facturacion_reporte_pacientes_360', view_func=facturacion_reporte_pacientes_360)
    app.add_url_rule('/facturacion/historia-clinica/paciente/<int:paciente_id>', endpoint='facturacion_historia_clinica_expediente', view_func=facturacion_historia_clinica_expediente)
    app.add_url_rule('/api/facturacion/historia-clinica/plantilla-especialidad/<int:medico_id>', endpoint='api_historia_clinica_plantilla_especialidad', view_func=api_historia_clinica_plantilla_especialidad)
    app.add_url_rule('/facturacion/historia-clinica/paciente/<int:paciente_id>/nueva', endpoint='facturacion_historia_clinica_nueva', view_func=facturacion_historia_clinica_nueva, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/historia-clinica/consulta/<int:consulta_id>', endpoint='facturacion_historia_clinica_ver', view_func=facturacion_historia_clinica_ver)
    app.add_url_rule(
        '/facturacion/historia-clinica/consulta/<int:consulta_id>/vincular',
        endpoint='facturacion_historia_vincular_documento',
        view_func=facturacion_historia_vincular_documento,
        methods=['POST'],
    )
    app.add_url_rule('/facturacion/historia-clinica/consulta/<int:consulta_id>/editar', endpoint='facturacion_historia_clinica_editar', view_func=facturacion_historia_clinica_editar, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/historia-clinica/consulta/<int:consulta_id>/evolucion', endpoint='facturacion_historia_clinica_evolucion', view_func=facturacion_historia_clinica_evolucion, methods=['POST'])
