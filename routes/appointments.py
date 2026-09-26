"""Rutas y helpers de citas m?dicas."""

import calendar as calendar_module
import re
from collections import defaultdict
from datetime import datetime, timedelta

from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from auth import permission_required, user_has_permission
from core.config import IS_PRODUCTION, url_publica_base
from core.clock import ahora_clinica, fecha_clinica
from core.database import execute_query, execute_update
from core.security import rate_limit
from core.tenant import get_current_tenant_id
from core.presentation import hora_input
from markupsafe import escape
from routes.support import sanitize_input, validate_int
from services.tenant_mail import notificar_paciente
import hashlib
import logging
import secrets
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


ESTADOS_REAGENDABLES = frozenset({
    'Programada', 'Confirmada', 'No asistió', 'Vencida', 'Cancelada',
})
ESTADOS_AL_REVIVIR = frozenset({'Vencida', 'No asistió'})


COLUMNAS_CONFIRMACION_CITA = {
    'confirmacion_token_hash': 'VARCHAR(64) NULL',
    'confirmacion_token_expiracion': 'DATETIME NULL',
    'recordatorio_enviado': 'TINYINT(1) NOT NULL DEFAULT 0',
}


def cita_se_puede_reagendar(cita):
    """Permitir cambiar fecha y hora salvo que la cita ya se haya completado."""
    return bool(cita) and cita.get('estado') in ESTADOS_REAGENDABLES


def cita_horario_sigue_vigente(fecha, hora, duracion, ahora=None):
    """True si el bloque aún no termina (misma regla que al marcar Vencida)."""
    hora_t = hora_como_time(hora)
    if fecha is None or hora_t is None:
        return False
    if hasattr(fecha, 'year') and not hasattr(fecha, 'hour'):
        fecha_d = fecha
    elif hasattr(fecha, 'date'):
        fecha_d = fecha.date()
    else:
        try:
            fecha_d = datetime.strptime(str(fecha)[:10], '%Y-%m-%d').date()
        except ValueError:
            return False
    fin = datetime.combine(fecha_d, hora_t) + timedelta(minutes=int(duracion or 30))
    return fin > (ahora or ahora_clinica())


def estado_si_horario_vigente(estado, fecha, hora, duracion, ahora=None):
    """Vencida o No asistió vuelven a Programada si el nuevo horario no ha pasado."""
    if estado in ESTADOS_AL_REVIVIR and cita_horario_sigue_vigente(
        fecha, hora, duracion, ahora,
    ):
        return 'Programada'
    return estado


def asegurar_columnas_confirmacion_cita():
    for nombre, definicion in COLUMNAS_CONFIRMACION_CITA.items():
        if execute_query(f"SHOW COLUMNS FROM citas_medicas LIKE '{nombre}'"):
            continue
        execute_update(
            f'ALTER TABLE citas_medicas ADD COLUMN `{nombre}` {definicion}'
        )


def hashear_token_cita(token):
    return hashlib.sha256((token or '').encode('utf-8')).hexdigest()


def hora_como_time(valor):
    if valor is None:
        return None
    if hasattr(valor, 'hour') and not hasattr(valor, 'year'):
        return valor
    texto = str(valor).strip()
    texto_norm = texto.upper().replace('.', '')
    for formato in ('%H:%M:%S', '%H:%M', '%I:%M:%S %p', '%I:%M %p'):
        try:
            return datetime.strptime(texto_norm if '%p' in formato else texto, formato).time()
        except ValueError:
            continue
    if len(texto) >= 8 and texto[2] == ':':
        texto = texto[:8]
    elif len(texto) >= 5:
        texto = texto[:5]
    for formato in ('%H:%M:%S', '%H:%M'):
        try:
            return datetime.strptime(texto, formato).time()
        except ValueError:
            continue
    return None


def calcular_huecos(fecha, duracion, hora_inicio, hora_fin, ocupados, ahora=None):
    """Huecos de un día restando citas ya tomadas (sin tocar la base)."""
    inicio = hora_como_time(hora_inicio)
    fin = hora_como_time(hora_fin)
    if not fecha or not inicio or not fin or not duracion:
        return []
    paso = timedelta(minutes=int(duracion))
    cursor = datetime.combine(fecha, inicio)
    limite = datetime.combine(fecha, fin)
    umbral = ahora if ahora is not None else ahora_clinica()
    bloques = []
    for item in ocupados or []:
        hora = hora_como_time(item.get('hora') if isinstance(item, dict) else item[0])
        minutos = int(
            (item.get('duracion_minutos') if isinstance(item, dict) else item[1]) or duracion
        )
        if not hora:
            continue
        arranque = datetime.combine(fecha, hora)
        bloques.append((arranque, arranque + timedelta(minutes=minutos)))
    huecos = []
    while cursor + paso <= limite:
        if cursor >= umbral:
            choca = any(
                cursor < fin_ocupado and cursor + paso > inicio_ocupado
                for inicio_ocupado, fin_ocupado in bloques
            )
            if not choca:
                huecos.append(cursor.strftime('%H:%M'))
        cursor += paso
    return huecos


def ocupaciones_medico_dia(tenant_id, medico_id, fecha):
    return execute_query(
        '''
        SELECT hora, duracion_minutos
        FROM citas_medicas
        WHERE tenant_id=%s AND medico_id=%s AND fecha=%s
          AND estado NOT IN ('Cancelada', 'Vencida', 'No asistió')
        ''',
        (tenant_id, medico_id, fecha),
        fetch='all',
    ) or []


def conflicto_horario_cita(
    tenant_id, medico_id, paciente_id, fecha, hora, duracion, cita_id=None,
):
    parametros = [
        tenant_id, medico_id, paciente_id, fecha, hora, duracion, hora,
    ]
    conflicto_sql = '''
        SELECT c.id, c.hora, c.medico_id, c.paciente_id,
               c.duracion_minutos, p.nombre AS paciente_nombre
        FROM citas_medicas c
        JOIN pacientes p
          ON p.id=c.paciente_id AND p.tenant_id=c.tenant_id
        WHERE c.tenant_id=%s AND (c.medico_id=%s OR c.paciente_id=%s)
          AND c.fecha=%s
          AND c.estado NOT IN ('Cancelada', 'Vencida', 'No asistió')
          AND c.hora<ADDTIME(%s, SEC_TO_TIME(%s * 60))
          AND ADDTIME(c.hora, SEC_TO_TIME(c.duracion_minutos * 60))>%s
    '''
    if cita_id:
        conflicto_sql += ' AND c.id<>%s'
        parametros.append(cita_id)
    conflicto_sql += ' LIMIT 1'
    return execute_query(conflicto_sql, tuple(parametros))


def _datetime_cita(valor):
    if valor is None:
        return None
    if isinstance(valor, datetime):
        return valor
    if hasattr(valor, 'year') and hasattr(valor, 'hour'):
        return datetime(
            valor.year, valor.month, valor.day,
            valor.hour, valor.minute, getattr(valor, 'second', 0),
        )
    texto = str(valor).replace('T', ' ')[:19]
    try:
        return datetime.strptime(texto, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        try:
            return datetime.strptime(texto[:16], '%Y-%m-%d %H:%M')
        except ValueError:
            return None


def _url_absoluta_cita(token):
    base = url_publica_base().strip()
    ruta = url_for('cita_paciente_gestionar', token=token)
    if base:
        return urljoin(base.rstrip('/') + '/', ruta.lstrip('/'))
    if not IS_PRODUCTION:
        return url_for('cita_paciente_gestionar', token=token, _external=True)
    raise RuntimeError('APP_BASE_URL no está configurada')


def emitir_enlace_confirmacion(cita_id, tenant_id, fecha, hora):
    """Nuevo token por aviso; el anterior deja de servir."""
    asegurar_columnas_confirmacion_cita()
    token = secrets.token_urlsafe(32)
    if hasattr(fecha, 'strftime') and hasattr(hora, 'strftime'):
        vencimiento = datetime.combine(fecha, hora) + timedelta(hours=6)
    else:
        vencimiento = ahora_clinica() + timedelta(days=2)
    execute_update(
        '''
        UPDATE citas_medicas
        SET confirmacion_token_hash=%s,
            confirmacion_token_expiracion=%s,
            recordatorio_enviado=0
        WHERE id=%s AND tenant_id=%s
        ''',
        (hashear_token_cita(token), vencimiento, cita_id, tenant_id),
    )
    return token


def _avisar_cita_paciente(tenant_id, cita_id, paciente_id, fecha, hora, tipo):
    fecha_txt = fecha.strftime('%d/%m/%Y') if hasattr(fecha, 'strftime') else fecha
    hora_txt = hora.strftime('%H:%M') if hasattr(hora, 'strftime') else hora_input(hora)
    if tipo == 'reagendada':
        verbo = 'reagendó'
    elif tipo == 'recordatorio':
        verbo = 'recuerda'
    else:
        verbo = 'programó'
    try:
        token = emitir_enlace_confirmacion(cita_id, tenant_id, fecha, hora)
        enlace = _url_absoluta_cita(token)
    except Exception as error:
        logger.error('No se pudo armar el enlace de confirmación: %s', error)
        enlace = None
    html = (
        f'<p>Su cita se {verbo} para el <strong>{escape(str(fecha_txt))}</strong> '
        f'a las <strong>{escape(str(hora_txt))}</strong>.</p>'
    )
    if enlace:
        html += (
            '<p>Confirme o cancele con un toque (no hace falta llamar):</p>'
            f'<p><a href="{escape(enlace)}">Confirmar o cancelar mi cita</a></p>'
        )
    ok, detalle = notificar_paciente(
        tenant_id,
        paciente_id,
        'Confirme su cita',
        html,
    )
    if tipo == 'recordatorio':
        return ok
    if ok and getattr(current_user, 'is_authenticated', False):
        flash('Se envió un aviso al correo del paciente para confirmar o cancelar.', 'info')
    elif (
        getattr(current_user, 'is_authenticated', False)
        and 'no tiene correo' in (detalle or '').lower()
    ):
        flash('El paciente no tiene correo: la confirmación queda a mano en la cita.', 'info')
    return ok


def enviar_recordatorios_citas(tenant_id):
    """Recordatorio del día anterior; se dispara al abrir agenda o Mi cola."""
    if not tenant_id:
        return
    asegurar_columnas_confirmacion_cita()
    pendientes = execute_query(
        '''
        SELECT c.id, c.paciente_id, c.fecha, c.hora, c.estado
        FROM citas_medicas c
        JOIN pacientes p
          ON p.id=c.paciente_id AND p.tenant_id=c.tenant_id
        WHERE c.tenant_id=%s
          AND c.fecha=%s
          AND c.estado IN ('Programada', 'Confirmada')
          AND IFNULL(c.recordatorio_enviado, 0)=0
          AND p.email IS NOT NULL AND p.email<>''
        LIMIT 20
        ''',
        (tenant_id, fecha_clinica() + timedelta(days=1)),
        fetch='all',
    ) or []
    for cita in pendientes:
        if _avisar_cita_paciente(
            tenant_id,
            cita['id'],
            cita['paciente_id'],
            cita['fecha'],
            cita['hora'],
            'recordatorio',
        ):
            execute_update(
                'UPDATE citas_medicas SET recordatorio_enviado=1 '
                'WHERE id=%s AND tenant_id=%s',
                (cita['id'], tenant_id),
            )


def obtener_cita_por_token(token):
    if not token or not (20 <= len(token) <= 80):
        return None
    asegurar_columnas_confirmacion_cita()
    return execute_query(
        '''
        SELECT c.id, c.tenant_id, c.estado, c.fecha, c.hora, c.motivo,
               c.confirmacion_token_expiracion,
               p.nombre AS paciente_nombre,
               m.nombre AS medico_nombre,
               e.nombre AS empresa_nombre
        FROM citas_medicas c
        JOIN pacientes p ON p.id=c.paciente_id AND p.tenant_id=c.tenant_id
        JOIN medicos m ON m.id=c.medico_id AND m.tenant_id=c.tenant_id
        JOIN empresas e ON e.id=c.tenant_id
        WHERE c.confirmacion_token_hash=%s
        ''',
        (hashear_token_cita(token),),
    )


def fecha_prellenada_agenda(valor=None):
    """Aceptar solo una fecha ISO válida para prellenar el formulario."""
    candidato = (valor if valor is not None else request.args.get('fecha') or '').strip()
    try:
        return datetime.strptime(candidato, '%Y-%m-%d').date().isoformat()
    except ValueError:
        return ''


def medico_id_agenda_restringida():
    """Obtener el médico obligatorio para usuarios con el rol Médico."""
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


def puede_gestionar_qr_citas():
    """Solo recepción/administración genera el QR del consultorio."""
    return medico_id_agenda_restringida() is None


def actualizar_citas_vencidas(tenant_id):
    ahora = ahora_clinica()
    execute_update('''
        UPDATE citas_medicas
        SET estado='Vencida'
        WHERE tenant_id=%s
          AND estado IN ('Programada', 'Confirmada')
          AND (
              fecha<%s
              OR (
                  fecha=%s
                  AND ADDTIME(hora, SEC_TO_TIME(duracion_minutos * 60))<%s
              )
          )
    ''', (
        tenant_id,
        ahora.date(),
        ahora.date(),
        ahora.strftime('%H:%M:%S'),
    ))


def contexto_formulario_cita(tenant_id, medico_id_restringido=None):
    medicos_sql = (
        'SELECT id, nombre, especialidad FROM medicos '
        'WHERE tenant_id=%s AND activo=1'
    )
    medicos_params = [tenant_id]
    if medico_id_restringido:
        medicos_sql += ' AND id=%s'
        medicos_params.append(medico_id_restringido)
    medicos_sql += ' ORDER BY nombre'
    return {
        'pacientes': execute_query(
            'SELECT id, nombre, cedula, telefono FROM pacientes '
            'WHERE tenant_id=%s ORDER BY nombre',
            (tenant_id,), fetch='all'
        ) or [],
        'medicos': execute_query(
            medicos_sql, tuple(medicos_params), fetch='all'
        ) or [],
        'agenda_restringida': bool(medico_id_restringido),
    }


def validar_formulario_cita(tenant_id, cita_id=None):
    paciente_id = validate_int(request.form.get('paciente_id'), min_value=1, default=None)
    medico_id = (
        medico_id_agenda_restringida()
        or validate_int(request.form.get('medico_id'), min_value=1, default=None)
    )
    fecha = request.form.get('fecha', '').strip()
    hora = request.form.get('hora', '').strip()
    duracion = validate_int(
        request.form.get('duracion_minutos'), min_value=10,
        max_value=480, default=None
    )
    especialidad = sanitize_input(request.form.get('especialidad', ''), 150)
    motivo = sanitize_input(request.form.get('motivo', ''), 2000)
    notas = sanitize_input(request.form.get('notas', ''), 3000)
    estado = request.form.get('estado', 'Programada').strip()
    if request.form.get('accion') == 'reagendar':
        estado = 'Programada'
    estados_validos = [
        'Programada', 'Confirmada', 'Completada',
        'Cancelada', 'No asistió', 'Vencida'
    ]
    if not all([paciente_id, medico_id, fecha, hora, duracion, motivo]):
        return None, 'Complete todos los campos obligatorios'
    if estado not in estados_validos:
        return None, 'El estado de la cita no es válido'
    try:
        fecha_obj = datetime.strptime(fecha, '%Y-%m-%d').date()
        hora_obj = hora_como_time(hora)
        if hora_obj is None:
            raise ValueError('hora')
    except ValueError:
        return None, 'La fecha u hora no es válida'
    paciente = execute_query(
        'SELECT id FROM pacientes WHERE id=%s AND tenant_id=%s',
        (paciente_id, tenant_id)
    )
    medico = execute_query(
        'SELECT id, especialidad FROM medicos '
        'WHERE id=%s AND tenant_id=%s AND activo=1',
        (medico_id, tenant_id)
    )
    if not paciente or not medico:
        return None, 'El paciente o médico seleccionado no es válido'
    if estado in ['Programada', 'Confirmada']:
        inicio = datetime.combine(fecha_obj, hora_obj)
        fin = inicio + timedelta(minutes=duracion)
        if fin <= ahora_clinica():
            return None, 'No puede programar una cita en una fecha u hora pasada'
    conflicto = None
    if estado in ['Programada', 'Confirmada']:
        conflicto = conflicto_horario_cita(
            tenant_id, medico_id, paciente_id, fecha_obj, hora_obj,
            duracion, cita_id,
        )
    if conflicto:
        recurso = 'El médico' if conflicto['medico_id'] == medico_id else 'El paciente'
        return None, (
            f"{recurso} ya tiene una cita a las {hora_input(conflicto['hora'])} "
            f"con {conflicto['paciente_nombre']}"
        )
    return {
        'paciente_id': paciente_id,
        'medico_id': medico_id,
        'fecha': fecha_obj,
        'hora': hora_obj,
        'duracion': duracion,
        'especialidad': especialidad or medico.get('especialidad'),
        'motivo': motivo,
        'notas': notas or None,
        'estado': estado
    }, None


@login_required
@permission_required('citas.ver')
def facturacion_citas():
    tenant_id = get_current_tenant_id()
    medico_id_restringido = medico_id_agenda_restringida()
    actualizar_citas_vencidas(tenant_id)
    enviar_recordatorios_citas(tenant_id)
    vista = request.args.get('vista', 'mes')
    if vista not in ['mes', 'hoy', 'proximas', 'todas']:
        vista = 'mes'
    mes_texto = request.args.get('mes', ahora_clinica().strftime('%Y-%m'))
    try:
        primer_dia = datetime.strptime(mes_texto, '%Y-%m').date().replace(day=1)
    except ValueError:
        primer_dia = fecha_clinica().replace(day=1)
        mes_texto = primer_dia.strftime('%Y-%m')
    ultimo_dia_numero = calendar_module.monthrange(
        primer_dia.year, primer_dia.month
    )[1]
    ultimo_dia = primer_dia.replace(day=ultimo_dia_numero)
    mes_anterior = (primer_dia - timedelta(days=1)).replace(day=1)
    mes_siguiente = (ultimo_dia + timedelta(days=1)).replace(day=1)
    paciente_id = validate_int(
        request.args.get('paciente_id'), min_value=1, default=None
    )
    medico_id = medico_id_restringido or validate_int(
        request.args.get('medico_id'), min_value=1, default=None
    )
    estado = request.args.get('estado', '').strip()
    buscar = request.args.get('buscar', '').strip()
    query = '''
        SELECT c.*, p.nombre AS paciente_nombre, p.telefono,
               m.nombre AS medico_nombre, m.especialidad AS medico_especialidad
        FROM citas_medicas c
        JOIN pacientes p ON p.id=c.paciente_id AND p.tenant_id=c.tenant_id
        JOIN medicos m ON m.id=c.medico_id AND m.tenant_id=c.tenant_id
        WHERE c.tenant_id=%s
    '''
    params = [tenant_id]
    hoy = fecha_clinica()
    if vista == 'mes':
        query += ' AND c.fecha BETWEEN %s AND %s'
        params.extend([primer_dia, ultimo_dia])
    elif vista == 'hoy':
        query += ' AND c.fecha=%s'
        params.append(hoy)
    elif vista == 'proximas':
        query += " AND c.fecha>=%s AND c.estado NOT IN ('Cancelada','Completada','Vencida','No asistió')"
        params.append(hoy)
    if paciente_id:
        query += ' AND c.paciente_id=%s'
        params.append(paciente_id)
    if medico_id:
        query += ' AND c.medico_id=%s'
        params.append(medico_id)
    if estado in [
        'Programada', 'Confirmada', 'Completada',
        'Cancelada', 'No asistió', 'Vencida'
    ]:
        query += ' AND c.estado=%s'
        params.append(estado)
    if buscar:
        patron = f'%{buscar}%'
        phone_digits = re.sub(r'\D', '', buscar)
        phone_pattern = f'%{phone_digits}%' if phone_digits else patron
        query += """
            AND (
                p.nombre LIKE %s OR p.cedula LIKE %s OR p.nss LIKE %s
                OR REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(
                    COALESCE(p.telefono,''),'-',''),' ',''),'(',''),')',''),'+','')
                    LIKE %s
                OR m.nombre LIKE %s OR c.motivo LIKE %s
            )
        """
        params.extend([
            patron, patron, patron, phone_pattern, patron, patron
        ])
    query += ' ORDER BY c.fecha ASC, c.hora ASC'
    citas = execute_query(query, tuple(params), fetch='all') or []
    citas_por_fecha = defaultdict(list)
    for cita in citas:
        citas_por_fecha[cita['fecha'].isoformat()].append(cita)
    calendario = calendar_module.Calendar(firstweekday=0)
    semanas = calendario.monthdatescalendar(primer_dia.year, primer_dia.month)
    contexto = contexto_formulario_cita(tenant_id, medico_id_restringido)
    return render_template(
        'facturacion/citas.html',
        citas=citas, citas_por_fecha=dict(citas_por_fecha),
        semanas=semanas, vista=vista, mes=mes_texto,
        mes_numero=primer_dia.month, anio=primer_dia.year,
        mes_anterior=mes_anterior.strftime('%Y-%m'),
        mes_siguiente=mes_siguiente.strftime('%Y-%m'),
        hoy=hoy, filtros=request.args, **contexto
    )


@login_required
@permission_required('citas.crear')
def facturacion_citas_nueva():
    tenant_id = get_current_tenant_id()
    medico_id_restringido = medico_id_agenda_restringida()
    contexto = contexto_formulario_cita(tenant_id, medico_id_restringido)
    consulta_id = validate_int(
        request.args.get('consulta_id') or request.form.get('consulta_origen_id'),
        min_value=1, default=None
    )
    consulta_origen = None
    if consulta_id:
        consulta_origen = execute_query('''
            SELECT c.id, c.paciente_id, c.medico_id, c.proxima_cita,
                   c.proxima_hora, c.proxima_especialidad, c.proxima_motivo,
                   c.indicaciones_seguimiento
            FROM consultas_clinicas c
            WHERE c.id=%s AND c.tenant_id=%s
              AND (%s IS NULL OR c.medico_id=%s)
        ''', (
            consulta_id, tenant_id,
            medico_id_restringido, medico_id_restringido,
        ))
    if request.method == 'POST':
        datos, error = validar_formulario_cita(tenant_id)
        if error:
            flash(error, 'error')
            return render_template(
                'facturacion/cita_form.html', cita=None,
                consulta_origen=consulta_origen, form_data=request.form,
                **contexto
            )
        if consulta_id:
            existente = execute_query(
                'SELECT id FROM citas_medicas '
                'WHERE tenant_id=%s AND consulta_origen_id=%s',
                (tenant_id, consulta_id)
            )
            if existente:
                flash('Esta consulta ya tiene una próxima cita en la agenda', 'warning')
                return redirect(url_for(
                    'facturacion_cita_editar', cita_id=existente['id']
                ))
        cita_id = execute_update('''
            INSERT INTO citas_medicas (
                tenant_id, paciente_id, medico_id, consulta_origen_id,
                fecha, hora, duracion_minutos, especialidad, motivo,
                notas, estado, origen, created_by, updated_by
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
        ''', (
            tenant_id, datos['paciente_id'], datos['medico_id'], consulta_id,
            datos['fecha'], datos['hora'], datos['duracion'],
            datos['especialidad'], datos['motivo'], datos['notas'],
            datos['estado'], 'Historia clinica' if consulta_id else 'Manual',
            current_user.id, current_user.id
        ))
        flash('Cita programada exitosamente', 'success')
        _avisar_cita_paciente(
            tenant_id, cita_id, datos['paciente_id'], datos['fecha'],
            datos['hora'], 'programada',
        )
        return redirect(url_for(
            'facturacion_citas', vista='mes',
            mes=datos['fecha'].strftime('%Y-%m')
        ))
    return render_template(
        'facturacion/cita_form.html', cita=None,
        consulta_origen=consulta_origen, form_data={},
        fecha_actual=fecha_prellenada_agenda(),
        paciente_preseleccionado=request.args.get('paciente_id', ''),
        medico_preseleccionado=(
            medico_id_restringido or request.args.get('medico_id', '')
        ),
        **contexto
    )


@login_required
@permission_required('citas.editar')
def facturacion_cita_editar(cita_id):
    tenant_id = get_current_tenant_id()
    medico_id_restringido = medico_id_agenda_restringida()
    cita = execute_query(
        'SELECT * FROM citas_medicas WHERE id=%s AND tenant_id=%s',
        (cita_id, tenant_id)
    )
    if not cita:
        flash('Cita no encontrada', 'error')
        return redirect(url_for('facturacion_citas'))
    contexto = contexto_formulario_cita(tenant_id, medico_id_restringido)
    if request.method == 'POST':
        if (
            medico_id_restringido
            and cita.get('medico_id') != medico_id_restringido
        ):
            flash('Solo puedes modificar las citas de tu agenda', 'error')
            return redirect(url_for('facturacion_cita_editar', cita_id=cita_id))
        if request.form.get('accion') == 'reenviar_aviso':
            _avisar_cita_paciente(
                tenant_id, cita_id, cita['paciente_id'],
                cita['fecha'], cita['hora'], 'programada',
            )
            return redirect(url_for('facturacion_cita_editar', cita_id=cita_id))
        datos, error = validar_formulario_cita(tenant_id, cita_id)
        if error:
            flash(error, 'error')
            return render_template(
                'facturacion/cita_form.html', cita=cita,
                consulta_origen=None, form_data=request.form,
                puede_reagendar=cita_se_puede_reagendar(cita),
                modo_reagendar=request.form.get('accion') == 'reagendar',
                **contexto
            )
        notas = datos['notas'] or ''
        estado_previo = datos['estado']
        datos['estado'] = estado_si_horario_vigente(
            datos['estado'], datos['fecha'], datos['hora'], datos['duracion'],
        )
        if request.form.get('accion') == 'reagendar':
            if not cita_se_puede_reagendar(cita):
                flash('Esta cita no se puede reagendar', 'error')
                return redirect(url_for('facturacion_cita_editar', cita_id=cita_id))
            datos['estado'] = 'Programada'
            previa = (
                f"{cita.get('fecha')} {hora_input(cita.get('hora'))}".strip()
            )
            motivo_reagendar = sanitize_input(
                request.form.get('motivo_reagendar', ''), 1000
            )
            linea = f'Reagendada (antes {previa})'
            if motivo_reagendar:
                linea += f': {motivo_reagendar}'
            notas = f'{notas}\n{linea}'.strip() if notas else linea
        execute_update('''
            UPDATE citas_medicas SET
                paciente_id=%s, medico_id=%s, fecha=%s, hora=%s,
                duracion_minutos=%s, especialidad=%s, motivo=%s,
                notas=%s, estado=%s, updated_by=%s,
                cancelada_por=%s, fecha_cancelacion=%s, motivo_cancelacion=%s
            WHERE id=%s AND tenant_id=%s
        ''', (
            datos['paciente_id'], datos['medico_id'], datos['fecha'],
            datos['hora'], datos['duracion'], datos['especialidad'],
            datos['motivo'], notas or None, datos['estado'],
            current_user.id,
            None if request.form.get('accion') == 'reagendar' else cita.get('cancelada_por'),
            None if request.form.get('accion') == 'reagendar' else cita.get('fecha_cancelacion'),
            None if request.form.get('accion') == 'reagendar' else cita.get('motivo_cancelacion'),
            cita_id, tenant_id
        ))
        if request.form.get('accion') == 'reagendar':
            flash(
                f"Cita reagendada para el {datos['fecha'].strftime('%d/%m/%Y')} "
                f"a las {datos['hora'].strftime('%H:%M')}",
                'success',
            )
            _avisar_cita_paciente(
                tenant_id, cita_id, datos['paciente_id'], datos['fecha'],
                datos['hora'], 'reagendada',
            )
        else:
            if estado_previo in ESTADOS_AL_REVIVIR and datos['estado'] == 'Programada':
                flash(
                    'El horario sigue vigente: la cita pasó de %s a Programada.'
                    % estado_previo,
                    'success',
                )
            else:
                flash('Cita actualizada correctamente', 'success')
        return redirect(url_for(
            'facturacion_citas', vista='mes',
            mes=datos['fecha'].strftime('%Y-%m')
        ))
    return render_template(
        'facturacion/cita_form.html', cita=cita,
        consulta_origen=None, form_data=cita,
        puede_reagendar=cita_se_puede_reagendar(cita),
        modo_reagendar=request.args.get('reagendar') == '1',
        **contexto
    )


@login_required
@permission_required('citas.editar')
def facturacion_cita_estado(cita_id):
    tenant_id = get_current_tenant_id()
    medico_id_restringido = medico_id_agenda_restringida()
    estado = request.form.get('estado', '').strip()
    if estado not in [
        'Programada', 'Confirmada', 'Completada',
        'Cancelada', 'No asistió'
    ]:
        flash('Estado de cita no válido', 'error')
        return redirect(url_for('facturacion_citas'))
    if (
        estado == 'Cancelada'
        and not user_has_permission(current_user, 'citas.cancelar')
    ):
        flash('No tienes permisos para cancelar citas', 'error')
        return redirect(request.referrer or url_for('facturacion_citas'))
    cita = execute_query(
        'SELECT id FROM citas_medicas WHERE id=%s AND tenant_id=%s '
        'AND (%s IS NULL OR medico_id=%s)',
        (
            cita_id, tenant_id,
            medico_id_restringido, medico_id_restringido,
        )
    )
    if not cita:
        flash('Cita no encontrada', 'error')
        return redirect(url_for('facturacion_citas'))
    motivo_cancelacion = sanitize_input(
        request.form.get('motivo_cancelacion', ''), 1000
    )
    if estado == 'Cancelada' and not motivo_cancelacion:
        flash('Indique el motivo de cancelación', 'error')
        return redirect(request.referrer or url_for('facturacion_citas'))
    execute_update('''
        UPDATE citas_medicas SET estado=%s, updated_by=%s,
            cancelada_por=%s, fecha_cancelacion=%s, motivo_cancelacion=%s
        WHERE id=%s AND tenant_id=%s
    ''', (
        estado, current_user.id,
        current_user.id if estado == 'Cancelada' else None,
        ahora_clinica() if estado == 'Cancelada' else None,
        motivo_cancelacion if estado == 'Cancelada' else None,
        cita_id, tenant_id
    ))
    flash('Estado de la cita actualizado', 'success')
    return redirect(request.referrer or url_for('facturacion_citas'))


@rate_limit(max_requests=30, window=300, methods=('GET', 'POST'))
def cita_paciente_gestionar(token):
    """El paciente confirma o cancela sin iniciar sesión."""
    cita = obtener_cita_por_token(token)
    vencimiento = _datetime_cita(cita.get('confirmacion_token_expiracion') if cita else None)
    vencida = not cita or not vencimiento or vencimiento < ahora_clinica()
    if vencida or not cita:
        return render_template(
            'cita_paciente.html',
            resultado='invalido',
            cita=None,
        )
    if cita['estado'] in ('Completada', 'Vencida'):
        return render_template(
            'cita_paciente.html',
            resultado='cerrada',
            cita=cita,
        )
    if request.method == 'POST':
        decision = request.form.get('decision', '').strip()
        if decision == 'confirmar' and cita['estado'] != 'Cancelada':
            execute_update(
                '''
                UPDATE citas_medicas
                SET estado='Confirmada',
                    confirmacion_token_hash=NULL,
                    updated_at=NOW()
                WHERE id=%s AND tenant_id=%s
                ''',
                (cita['id'], cita['tenant_id']),
            )
            cita['estado'] = 'Confirmada'
            return render_template(
                'cita_paciente.html', resultado='confirmada', cita=cita,
            )
        if decision == 'cancelar':
            execute_update(
                '''
                UPDATE citas_medicas
                SET estado='Cancelada',
                    fecha_cancelacion=NOW(),
                    motivo_cancelacion=%s,
                    confirmacion_token_hash=NULL
                WHERE id=%s AND tenant_id=%s
                ''',
                (
                    'Cancelada por el paciente',
                    cita['id'],
                    cita['tenant_id'],
                ),
            )
            cita['estado'] = 'Cancelada'
            return render_template(
                'cita_paciente.html', resultado='cancelada', cita=cita,
            )
    return render_template(
        'cita_paciente.html', resultado='pendiente', cita=cita, token=token,
    )


def register_appointment_routes(app):
    app.add_url_rule('/facturacion/citas', endpoint='facturacion_citas', view_func=facturacion_citas)
    app.add_url_rule('/facturacion/citas/nueva', endpoint='facturacion_citas_nueva', view_func=facturacion_citas_nueva, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/citas/<int:cita_id>/editar', endpoint='facturacion_cita_editar', view_func=facturacion_cita_editar, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/citas/<int:cita_id>/estado', endpoint='facturacion_cita_estado', view_func=facturacion_cita_estado, methods=['POST'])
    app.add_url_rule('/cita/<token>', endpoint='cita_paciente_gestionar', view_func=cita_paciente_gestionar, methods=['GET', 'POST'])
