"""Registros de ejemplo al crear una empresa (guía para el usuario)."""

import logging
from datetime import date, timedelta

from core.database import execute_query, execute_update
from services.datos_guia_transacciones import sembrar_transacciones_guia_tenant

logger = logging.getLogger(__name__)

_CODIGO_CENTRO = 'GUIA-DEMO'
_CODIGO_SERVICIO = 'GUIA-SRV'
_CODIGO_ARS = 'CONS-GUIA'
_RNC_CENTRO = '101850043'
_CEDULA_MEDICO = '00111956884'
_EXEQUATUR_MEDICO = '0000000001'


def _ya_sembrado(tenant_id):
    fila = execute_query(
        '''
        SELECT id FROM centros_medicos
        WHERE tenant_id=%s AND codigo=%s
        LIMIT 1
        ''',
        (tenant_id, _CODIGO_CENTRO),
    )
    return bool(fila)


def _empresa(tenant_id):
    return execute_query(
        'SELECT tipo_empresa, telefono, email, nombre FROM empresas WHERE id=%s',
        (tenant_id,),
    ) or {}


def _ars_humano(tenant_id):
    return execute_query(
        '''
        SELECT id FROM ars
        WHERE tenant_id=%s AND activo=1
        ORDER BY CASE WHEN codigo='HUMANO' THEN 0 ELSE 1 END, id
        LIMIT 1
        ''',
        (tenant_id,),
    )


def sembrar_datos_guia_tenant(tenant_id, tipo_empresa=None, telefono=None, email=None):
    """
    Crea un registro de muestra en centros, servicios, NCF y códigos ARS.
    En consultorios (tipo medico) también crea un médico de ejemplo.
    """
    if not tenant_id:
        return False
    if _ya_sembrado(tenant_id):
        sembrar_transacciones_guia_tenant(tenant_id)
        return False

    datos = _empresa(tenant_id)
    tipo = tipo_empresa or datos.get('tipo_empresa') or 'medico'
    tel = (telefono or datos.get('telefono') or '8095550000').strip()
    if len(''.join(c for c in tel if c.isdigit())) >= 10:
        tel = ''.join(c for c in tel if c.isdigit())[:10]
    correo = (email or datos.get('email') or 'ejemplo@clinicrd.com').strip().lower()

    centro_id = execute_update(
        '''
        INSERT INTO centros_medicos (
            tenant_id, nombre, codigo, direccion, rnc, telefono, activo
        ) VALUES (%s, %s, %s, %s, %s, %s, 1)
        ''',
        (
            tenant_id,
            '(Ejemplo) Consultorio / centro',
            _CODIGO_CENTRO,
            'Complete la dirección real de su consultorio o centro.',
            _RNC_CENTRO,
            tel,
        ),
    )
    if not centro_id:
        logger.warning('No se creó el centro guía para tenant %s', tenant_id)
        return False

    medico_id = None
    # Consultorios individuales registran su médico real en onboarding; no sembrar uno de guía.
    if tipo != 'medico':
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
                _EXEQUATUR_MEDICO,
                'Medicina General',
                tel,
                correo,
                _CEDULA_MEDICO,
            ),
        )
        if medico_id:
            execute_update(
                '''
                INSERT INTO medico_centro (tenant_id, medico_id, centro_medico_id)
                VALUES (%s, %s, %s)
                ''',
                (tenant_id, medico_id, centro_id),
            )

    execute_update(
        '''
        INSERT INTO servicios (tenant_id, codigo, nombre, descripcion, precio_base, activo)
        VALUES (%s, %s, %s, %s, %s, 1)
        ''',
        (
            tenant_id,
            _CODIGO_SERVICIO,
            'Consulta (ejemplo)',
            'Consulta (ejemplo)',
            1500.00,
        ),
    )

    execute_update(
        '''
        INSERT INTO ncf (
            tenant_id, tipo, descripcion, prefijo, ultimo_numero,
            proximo_numero, tamano_secuencia, fecha_fin, activo
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 1)
        ''',
        (
            tenant_id,
            'B02',
            'Factura de consumo (ejemplo)',
            'B02',
            0,
            1,
            8,
            (date.today() + timedelta(days=365)).isoformat(),
        ),
    )

    ars = _ars_humano(tenant_id)
    if ars:
        medico_codigo = None if tipo == 'centro_salud' else medico_id
        centro_codigo = centro_id if tipo == 'centro_salud' else None
        if tipo == 'medico' and not medico_codigo:
            medico_codigo = execute_query(
                '''
                SELECT id FROM medicos
                WHERE tenant_id=%s AND activo=1
                ORDER BY id LIMIT 1
                ''',
                (tenant_id,),
            )
            medico_codigo = (medico_codigo or {}).get('id')
        execute_update(
            '''
            INSERT INTO codigo_ars (
                tenant_id, medico_id, centro_medico_id, ars_id, codigo,
                descripcion, precio, activo
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, 1)
            ''',
            (
                tenant_id,
                medico_codigo,
                centro_codigo,
                ars['id'],
                _CODIGO_ARS,
                'Consulta médica (ejemplo)',
                1500.00,
            ),
        )

    sembrar_transacciones_guia_tenant(tenant_id)
    return True
