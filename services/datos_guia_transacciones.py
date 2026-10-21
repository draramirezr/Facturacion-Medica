"""Tres registros de ejemplo por módulo operativo (guía al usuario)."""

import json
import logging
from datetime import date, datetime, time, timedelta
from decimal import Decimal

from core.database import execute_query, execute_update

logger = logging.getLogger(__name__)

_MARCADOR = '[Guía]'
_CEDULAS = ('99990000001', '99990000002', '99990000003')


def _json(data):
    return json.dumps(data, ensure_ascii=False)


def _ya_sembrado(tenant_id):
    return bool(
        execute_query(
            'SELECT id FROM pacientes WHERE tenant_id=%s AND cedula=%s LIMIT 1',
            (tenant_id, _CEDULAS[0]),
        )
    )


def _usuario_id(tenant_id):
    fila = execute_query(
        '''
        SELECT id FROM usuarios
        WHERE tenant_id=%s AND activo=1
        ORDER BY id LIMIT 1
        ''',
        (tenant_id,),
    )
    return fila['id'] if fila else None


def _centro(tenant_id):
    return execute_query(
        '''
        SELECT id, nombre FROM centros_medicos
        WHERE tenant_id=%s AND activo=1
        ORDER BY CASE WHEN codigo='GUIA-DEMO' THEN 0 ELSE 1 END, id
        LIMIT 1
        ''',
        (tenant_id,),
    )


def _medico(tenant_id, centro_id, telefono, correo):
    fila = execute_query(
        '''
        SELECT id, nombre FROM medicos
        WHERE tenant_id=%s AND activo=1
        ORDER BY id LIMIT 1
        ''',
        (tenant_id,),
    )
    if fila:
        return fila
    medico_id = execute_update(
        '''
        INSERT INTO medicos (
            tenant_id, nombre, exequatur, especialidad, telefono, email,
            cedula, activo, factura
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, 1, 1)
        ''',
        (
            tenant_id,
            '(Ejemplo) Médico de muestra',
            '0000000002',
            'Medicina General',
            telefono,
            correo,
            '40212358440',
        ),
    )
    if medico_id and centro_id:
        execute_update(
            '''
            INSERT IGNORE INTO medico_centro (tenant_id, medico_id, centro_medico_id)
            VALUES (%s, %s, %s)
            ''',
            (tenant_id, medico_id, centro_id),
        )
    return {'id': medico_id, 'nombre': '(Ejemplo) Médico de muestra'}


def _ars(tenant_id):
    return execute_query(
        '''
        SELECT id, nombre FROM ars
        WHERE tenant_id=%s AND activo=1
        ORDER BY CASE WHEN codigo='HUMANO' THEN 0 ELSE 1 END, id
        LIMIT 1
        ''',
        (tenant_id,),
    )


def _tipo_licencia(tenant_id):
    fila = execute_query(
        '''
        SELECT id FROM tipos_licencia_medica
        WHERE tenant_id=%s AND activo=1
        ORDER BY id LIMIT 1
        ''',
        (tenant_id,),
    )
    if fila:
        return fila['id']
    return execute_update(
        '''
        INSERT INTO tipos_licencia_medica (tenant_id, nombre, activo)
        VALUES (%s, %s, 1)
        ''',
        (tenant_id, 'Reposo médico (ejemplo)'),
    )


def sembrar_transacciones_guia_tenant(tenant_id):
    if not tenant_id or _ya_sembrado(tenant_id):
        return False

    empresa = execute_query(
        'SELECT telefono, email FROM empresas WHERE id=%s',
        (tenant_id,),
    ) or {}
    telefono = ''.join(c for c in (empresa.get('telefono') or '8095550000') if c.isdigit())[:10]
    correo = (empresa.get('email') or 'ejemplo@clinicrd.com').strip().lower()
    usuario_id = _usuario_id(tenant_id)
    centro = _centro(tenant_id)
    medico = _medico(tenant_id, (centro or {}).get('id'), telefono, correo)
    ars = _ars(tenant_id)
    if not usuario_id or not medico or not medico.get('id') or not ars:
        logger.warning(
            'No se sembraron transacciones guía: faltan usuario, médico o ARS (tenant %s)',
            tenant_id,
        )
        return False

    medico_id = medico['id']
    medico_nombre = medico.get('nombre') or '(Ejemplo) Médico'
    centro_id = (centro or {}).get('id')
    centro_nombre = (centro or {}).get('nombre') or ''
    tipo_licencia_id = _tipo_licencia(tenant_id)
    hoy = date.today()

    nombres = (
        '(Ejemplo) Paciente Ana',
        '(Ejemplo) Paciente Luis',
        '(Ejemplo) Paciente Carla',
    )
    diagnosticos = (
        'Consulta general (ejemplo)',
        'Control de presión (ejemplo)',
        'Seguimiento clínico (ejemplo)',
    )

    for indice, (cedula, nombre, diagnostico) in enumerate(
        zip(_CEDULAS, nombres, diagnosticos), start=1,
    ):
        nss = f'465900000{indice}'
        paciente_id = execute_update(
            '''
            INSERT INTO pacientes (
                tenant_id, nombre, cedula, nss, telefono, email, direccion,
                fecha_nacimiento, sexo, ars_id
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''',
            (
                tenant_id, nombre, cedula, nss, f'809700000{indice}',
                f'guia.paciente{indice}@example.com',
                'Dirección de ejemplo, Santo Domingo',
                date(1990, indice, 15).isoformat(),
                'F' if indice % 2 else 'M',
                ars['id'],
            ),
        )

        fecha_cita = hoy + timedelta(days=indice)
        execute_update(
            '''
            INSERT INTO citas_medicas (
                tenant_id, paciente_id, medico_id, fecha, hora,
                duracion_minutos, especialidad, motivo, estado, origen,
                created_by, updated_by
            ) VALUES (%s, %s, %s, %s, %s, 30, %s, %s, %s, 'Manual', %s, %s)
            ''',
            (
                tenant_id, paciente_id, medico_id, fecha_cita,
                time(8 + indice, 30),
                'Medicina General',
                f'{_MARCADOR} Cita de ejemplo {indice}',
                'Programada' if indice < 3 else 'Confirmada',
                usuario_id, usuario_id,
            ),
        )

        turno_id = execute_update(
            '''
            INSERT INTO turnos_atencion (
                tenant_id, fecha, paciente_id, medico_id, especialidad_snapshot,
                numero, posicion, estado, motivo, registro_incompleto,
                created_by, updated_by
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 0, %s, %s)
            ''',
            (
                tenant_id, hoy, paciente_id, medico_id, 'Medicina General',
                indice, indice,
                ('EnEspera', 'Llamado', 'EnConsulta')[indice - 1],
                f'{_MARCADOR} Turno de ejemplo {indice}',
                usuario_id, usuario_id,
            ),
        )
        execute_update(
            '''
            INSERT INTO turnos_eventos (
                tenant_id, turno_id, estado_anterior, estado_nuevo,
                motivo, actor_id, datos
            ) VALUES (%s, %s, NULL, %s, %s, %s, %s)
            ''',
            (
                tenant_id, turno_id,
                ('EnEspera', 'Llamado', 'EnConsulta')[indice - 1],
                'Registro guía de ClinicRD',
                usuario_id,
                _json({'origen': 'guia'}),
            ),
        )

        fecha_clinica = hoy - timedelta(days=indice)
        motivo_historia = f'{_MARCADOR} Historia clínica {indice}'
        historia_id = execute_update(
            '''
            INSERT INTO consultas_clinicas (
                tenant_id, paciente_id, medico_id, fecha, hora,
                motivo_consulta, enfermedad_actual, antecedentes_personales,
                antecedentes_familiares, signos_vitales, examen_fisico,
                diagnostico_principal, codigo_cie10, plan_tratamiento,
                nota_evolucion_inicial, created_by, updated_by
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            ''',
            (
                tenant_id, paciente_id, medico_id, fecha_clinica,
                time(9 + indice, 0), motivo_historia,
                _json({'evolucion': 'Ejemplo para orientar al usuario'}),
                _json({'alergias': 'No conocidas'}),
                _json({'hereditarias': 'Sin datos relevantes'}),
                _json({
                    'presion_arterial': '120/80',
                    'frecuencia_cardiaca': 72,
                    'temperatura': 36.5,
                }),
                _json({'estado_general': 'Estable'}),
                diagnostico, 'Z00.0',
                _json({'recomendaciones': 'Seguimiento ambulatorio'}),
                'Registro de ejemplo. Puede editarlo o eliminarlo.',
                usuario_id, usuario_id,
            ),
        )

        motivo_emergencia = f'{_MARCADOR} Emergencia {indice}'
        emergencia_id = execute_update(
            '''
            INSERT INTO historias_emergencia (
                tenant_id, paciente_id, medico_id, fecha, hora_servicio,
                autorizacion, nombre_paciente, edad, sexo, ars_nombre,
                numero_afiliado, nss, motivo_emergencia, historia_enfermedad,
                datos_clinicos, diagnostico_impresion, estatus_paciente,
                origen_enfermedad, observaciones, medico_nombre, created_by
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s
            )
            ''',
            (
                tenant_id, paciente_id, medico_id, fecha_clinica,
                time(14 + indice, 0), f'GUIA-{indice:03d}', nombre, 30 + indice,
                'F' if indice % 2 else 'M', ars['nombre'], nss, nss,
                motivo_emergencia,
                'Evaluación inicial de ejemplo.',
                _json({'ta': '120/80', 'fc': '72', 'medicamentos': 'Sintomáticos'}),
                diagnostico, 'Dado de alta', 'Enfermedad común',
                'Dato de guía; no es un paciente real.',
                medico_nombre, usuario_id,
            ),
        )

        execute_update(
            '''
            INSERT INTO hojas_enfermeria (
                tenant_id, paciente_id, historia_emergencia_id,
                fecha_servicio, hora_servicio, nombre_paciente, edad, sexo,
                direccion, responsable, telefono_responsable, ars_nombre,
                medicamentos_materiales, observaciones, created_by
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''',
            (
                tenant_id, paciente_id, emergencia_id, fecha_clinica,
                time(14 + indice, 15), nombre, 30 + indice,
                'F' if indice % 2 else 'M',
                'Dirección de ejemplo',
                'Responsable de ejemplo', telefono, ars['nombre'],
                _json([{
                    'fecha': fecha_clinica.isoformat(),
                    'hora': '14:30',
                    'detalle': 'Medicamento de ejemplo',
                    'cantidad': '1',
                }]),
                f'{_MARCADOR} Hoja de enfermería {indice}',
                usuario_id,
            ),
        )

        codigo_receta = f'REC-GUIA-{indice:03d}'
        receta_id = execute_update(
            '''
            INSERT INTO recetas_medicas (
                tenant_id, codigo, paciente_id, medico_id, consulta_id,
                fecha, diagnostico, codigo_cie10, indicaciones_generales,
                estado, created_by
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'Emitida', %s)
            ''',
            (
                tenant_id, codigo_receta, paciente_id, medico_id, historia_id,
                fecha_clinica, diagnostico, 'Z00.0',
                'Receta de ejemplo para orientar al usuario.',
                usuario_id,
            ),
        )
        execute_update(
            '''
            INSERT INTO receta_medicamentos (
                tenant_id, receta_id, medicamento, presentacion, dosis, via,
                frecuencia, duracion, cantidad, indicaciones, orden
            ) VALUES (%s, %s, %s, 'Tableta', '1', 'Oral', 'Cada 8 h', '3 días', '9', %s, 1)
            ''',
            (
                tenant_id, receta_id, 'Medicamento de ejemplo',
                'Suspender si hay reacción adversa.',
            ),
        )

        if tipo_licencia_id:
            execute_update(
                '''
                INSERT INTO licencias_medicas (
                    tenant_id, codigo, paciente_id, medico_id, consulta_id,
                    tipo_licencia_id, diagnostico, motivo_condicion,
                    observaciones, fecha_emision, fecha_inicio, fecha_termino,
                    cantidad_dias, estado, created_by, updated_by
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    'Emitida', %s, %s
                )
                ''',
                (
                    tenant_id, f'LIC-GUIA-{indice:03d}', paciente_id, medico_id,
                    historia_id, tipo_licencia_id, diagnostico,
                    'Reposo en el hogar (ejemplo)',
                    'Licencia de muestra.',
                    fecha_clinica, fecha_clinica,
                    fecha_clinica + timedelta(days=2),
                    3, usuario_id, usuario_id,
                ),
            )

        pendiente_id = execute_update(
            '''
            INSERT INTO pacientes_pendientes (
                tenant_id, paciente_id, nombre_paciente, cedula, nss, ars_id,
                fecha_servicio, servicios_realizados, observaciones,
                monto_estimado, estado, medico_id, centro_medico_id, created_by
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'Pendiente', %s, %s, %s
            )
            ''',
            (
                tenant_id, paciente_id, nombre, cedula, nss, ars['id'],
                fecha_clinica,
                f'{_MARCADOR} Consulta para facturar {indice}',
                'Servicio pendiente de facturación (ejemplo).',
                Decimal('1500.00') + indice * 100,
                medico_id, centro_id, usuario_id,
            ),
        )

        ncf_numero = f'B02{indice:08d}'
        numero_factura = f'FAC-GUIA-{indice:04d}'
        total = Decimal('1500.00') + indice * 100
        factura_id = execute_update(
            '''
            INSERT INTO facturas (
                tenant_id, numero_factura, tipo_factura, ncf, fecha_emision,
                paciente_id, nombre_paciente, cedula_paciente, nss_paciente,
                ars_id, nombre_ars, medico_id, nombre_medico,
                centro_medico_id, nombre_centro_medico,
                subtotal, itbis, total, estado, created_by
            ) VALUES (
                %s, %s, 'Consumo', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, 0, %s, %s, %s
            )
            ''',
            (
                tenant_id, numero_factura, ncf_numero, fecha_clinica,
                paciente_id, nombre, cedula, nss, ars['id'], ars['nombre'],
                medico_id, medico_nombre, centro_id, centro_nombre,
                total, total, 'Pendiente', usuario_id,
            ),
        )
        execute_update(
            '''
            INSERT INTO factura_detalles (
                tenant_id, factura_id, paciente_pendiente_id, descripcion,
                cantidad, precio_unitario, subtotal
            ) VALUES (%s, %s, %s, %s, 1, %s, %s)
            ''',
            (
                tenant_id, factura_id, pendiente_id,
                f'{_MARCADOR} Servicio facturado {indice}',
                total, total,
            ),
        )

        execute_update(
            '''
            INSERT INTO reclamaciones (
                factura_id, monto_reclamado, fecha_reclamacion, observaciones,
                tenant_id, created_by, estado
            ) VALUES (%s, %s, %s, %s, %s, %s, 'Pendiente')
            ''',
            (
                factura_id, total, fecha_clinica,
                f'{_MARCADOR} Reclamación de ejemplo {indice}',
                tenant_id, usuario_id,
            ),
        )

        pago_id = execute_update(
            '''
            INSERT INTO pagos (
                numero_pago, monto_total, fecha_pago, metodo_pago,
                referencia, observaciones, tenant_id, created_by
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ''',
            (
                f'PAG-GUIA-{indice:03d}', total, fecha_clinica, 'Transferencia',
                f'REF-GUIA-{indice:03d}',
                f'{_MARCADOR} Pago de ejemplo {indice}',
                tenant_id, usuario_id,
            ),
        )
        execute_update(
            '''
            INSERT INTO pago_facturas (pago_id, factura_id, monto_aplicado, tenant_id)
            VALUES (%s, %s, %s, %s)
            ''',
            (pago_id, factura_id, total, tenant_id),
        )

    execute_update(
        '''
        INSERT INTO secuencias_turnos (tenant_id, fecha, medico_id, ultimo_numero)
        VALUES (%s, %s, %s, 3)
        ON DUPLICATE KEY UPDATE ultimo_numero=GREATEST(ultimo_numero, 3)
        ''',
        (tenant_id, hoy, medico_id),
    )
    return True
