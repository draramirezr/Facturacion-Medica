"""Factura al paciente: diferencia/copago ARS, consulta privada u otros servicios.

Es distinta de la factura a la ARS (consolidada a fin de mes):
- Se emite en el momento de la atención y se cobra de inmediato.
- Comprobante B02 (consumo) por defecto; B01 (crédito fiscal) si el
  paciente da RNC o cédula. Usa las mismas secuencias NCF de la empresa.
- Queda marcada con destinatario='PACIENTE' para no mezclarse con
  pagos, reclamaciones ni cuentas por cobrar de ARS.

Preparado para e-CF: el tipo de comprobante es un dato aparte; E32/E31 se
agregan cuando la empresa esté certificada ante la DGII.
"""

import re
from datetime import date
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation

from core.database import database_transaction, execute_query, execute_update

CENTAVO = Decimal('0.01')
# Mismas reglas que el registro de consultas ARS (routes/billing_common.py).
_RE_NSS = re.compile(r'^[0-9\-]+$')
_RE_AUTORIZACION = re.compile(r'^[A-Z0-9\-]+$')
DESTINATARIO = 'PACIENTE'
TIPOS_COMPROBANTE = {
    'B02': 'Consumo',
    'B01': 'Crédito fiscal',
}
TIPO_POR_DEFECTO = 'B02'
METODOS_PAGO = ('Efectivo', 'Tarjeta', 'Transferencia', 'Cheque', 'Otro')
CONCEPTOS = (
    'Diferencia / copago ARS',
    'Consulta privada',
    'Otros servicios',
)
MAX_LINEAS = 30


class FacturaPacienteError(ValueError):
    """Error de validación o de emisión mostrado al usuario."""


def _monto(valor):
    try:
        numero = Decimal(str(valor if valor not in (None, '') else '0').replace(',', ''))
    except (InvalidOperation, TypeError, ValueError):
        raise FacturaPacienteError('Hay un monto inválido') from None
    if not numero.is_finite():
        raise FacturaPacienteError('Hay un monto inválido')
    return numero.quantize(CENTAVO, rounding=ROUND_HALF_UP)


def _digitos(valor):
    return ''.join(ch for ch in str(valor or '') if ch.isdigit())


def validar_factura_paciente(tenant_id, form, lineas):
    """Valida el formulario. `lineas` es una lista de dicts con
    descripcion, cantidad, precio y servicio_id opcional."""
    errores = []
    try:
        paciente_id = int(form.get('paciente_id') or 0)
    except (TypeError, ValueError):
        paciente_id = 0
    paciente = execute_query(
        'SELECT id, nombre, cedula, nss FROM pacientes WHERE id=%s AND tenant_id=%s',
        (paciente_id, tenant_id),
    ) if paciente_id else None
    if not paciente:
        errores.append('Seleccione el paciente')

    medico_id = form.get('medico_id') or None
    medico = None
    if medico_id:
        try:
            medico = execute_query(
                'SELECT id, nombre FROM medicos WHERE id=%s AND tenant_id=%s AND activo=1',
                (int(medico_id), tenant_id),
            )
        except (TypeError, ValueError):
            medico = None
        if not medico:
            errores.append('El médico seleccionado no es válido')

    tipo = (form.get('tipo_comprobante') or TIPO_POR_DEFECTO).strip().upper()
    if tipo not in TIPOS_COMPROBANTE:
        errores.append('Tipo de comprobante inválido')
    rnc = _digitos(form.get('rnc_comprador'))
    razon_social = (form.get('razon_social_comprador') or '').strip()[:200]
    if tipo == 'B01':
        if len(rnc) not in (9, 11):
            errores.append('Para crédito fiscal (B01) indique RNC (9 dígitos) o cédula (11)')
        if not razon_social:
            errores.append('Para crédito fiscal (B01) indique el nombre o razón social')

    metodo = (form.get('metodo_pago') or '').strip()
    referencia = (form.get('referencia_pago') or '').strip()[:100] or None

    detalle = []          # Lo que paga el paciente (va en su factura).
    consultas_ars = []    # Lo que cubre el seguro (va a Estado de Facturación).
    total = Decimal('0.00')
    autorizaciones = set()
    if not lineas:
        errores.append('Agregue al menos un servicio')
    for numero, linea in enumerate(lineas[:MAX_LINEAS], start=1):
        descripcion = (linea.get('descripcion') or '').strip()[:500]
        con_seguro = str(linea.get('seguro') or '').lower() in ('1', 'true', 'on', 'si', 'sí')
        try:
            cantidad = 1 if con_seguro else int(linea.get('cantidad') or 1)
            precio = _monto(linea.get('precio'))
        except (TypeError, ValueError):
            errores.append(f'Línea {numero}: cantidad o precio inválido')
            continue
        except FacturaPacienteError:
            errores.append(f'Línea {numero}: precio inválido')
            continue
        if not descripcion:
            errores.append(f'Línea {numero}: falta la descripción')
            continue
        if cantidad < 1 or cantidad > 999:
            errores.append(f'Línea {numero}: la cantidad debe estar entre 1 y 999')
            continue
        if precio <= 0:
            errores.append(f'Línea {numero}: el monto debe ser mayor que cero')
            continue
        servicio_id = linea.get('servicio_id') or None
        if servicio_id:
            try:
                servicio_id = int(servicio_id)
            except (TypeError, ValueError):
                servicio_id = None
            if servicio_id and not execute_query(
                'SELECT id FROM servicios WHERE id=%s AND tenant_id=%s',
                (servicio_id, tenant_id),
            ):
                servicio_id = None

        if con_seguro:
            autorizacion = (linea.get('autorizacion') or '').strip().upper()
            if not autorizacion:
                errores.append(f'Línea {numero}: la autorización de la ARS es obligatoria')
                continue
            if not _RE_AUTORIZACION.match(autorizacion) or len(autorizacion) > 50:
                errores.append(f'Línea {numero}: autorización inválida (solo letras, números y guiones)')
                continue
            if autorizacion in autorizaciones:
                errores.append(f'Línea {numero}: la autorización {autorizacion} está repetida')
                continue
            autorizaciones.add(autorizacion)
            try:
                cubre = _monto(linea.get('cubre'))
            except FacturaPacienteError:
                errores.append(f'Línea {numero}: el monto que cubre la ARS no es válido')
                continue
            if cubre <= 0:
                errores.append(f'Línea {numero}: indique cuánto cubre la ARS')
                continue
            if cubre > precio:
                errores.append(f'Línea {numero}: lo que cubre la ARS no puede ser mayor que el monto del servicio')
                continue
            diferencia = (precio - cubre).quantize(CENTAVO)
            consultas_ars.append({
                'servicio': descripcion,
                'autorizacion': autorizacion,
                'monto': cubre,
                'diferencia': diferencia,
            })
            if diferencia > 0:
                detalle.append({
                    'descripcion': f'Diferencia {descripcion} (Aut. {autorizacion})'[:500],
                    'cantidad': 1,
                    'precio_unitario': diferencia,
                    'subtotal': diferencia,
                    'servicio_id': servicio_id,
                })
                total += diferencia
            continue

        subtotal = (precio * cantidad).quantize(CENTAVO)
        detalle.append({
            'descripcion': descripcion,
            'cantidad': cantidad,
            'precio_unitario': precio,
            'subtotal': subtotal,
            'servicio_id': servicio_id,
        })
        total += subtotal

    # Datos de seguro (una sola vez para toda la atención).
    ars = None
    nss = None
    if consultas_ars:
        try:
            ars_id = int(form.get('ars_id') or 0)
        except (TypeError, ValueError):
            ars_id = 0
        ars = execute_query(
            'SELECT id, nombre FROM ars WHERE id=%s AND tenant_id=%s AND activo=1',
            (ars_id, tenant_id),
        ) if ars_id else None
        if not ars:
            errores.append('Seleccione la ARS del paciente')
        nss = (form.get('nss') or '').strip()
        if not nss or not _RE_NSS.match(nss) or len(nss) > 20:
            errores.append('Indique el NSS del paciente (solo números y guiones)')
        if not medico:
            errores.append('Para servicios con seguro indique el médico que atendió')

    if total > 0 and metodo not in METODOS_PAGO:
        errores.append('Seleccione la forma de pago')

    monto_recibido = None
    if total > 0 and metodo == 'Efectivo' and form.get('monto_recibido') not in (None, ''):
        try:
            monto_recibido = _monto(form.get('monto_recibido'))
        except FacturaPacienteError:
            errores.append('El monto recibido no es válido')
        else:
            if monto_recibido < total:
                errores.append('El monto recibido en efectivo es menor que el total')

    if errores:
        raise FacturaPacienteError(' · '.join(errores))
    return {
        'paciente': paciente,
        'medico': medico,
        'tipo_comprobante': tipo,
        'rnc_comprador': rnc or None,
        'razon_social_comprador': razon_social or None,
        'metodo_pago': metodo,
        'referencia_pago': referencia,
        'monto_recibido': monto_recibido,
        'lineas': detalle,
        'consultas_ars': consultas_ars,
        'ars': ars,
        'nss': nss,
        'total': total.quantize(CENTAVO),
        'observaciones': (form.get('observaciones') or '').strip()[:500] or None,
    }


def emitir_factura_paciente(tenant_id, datos, usuario_id, hoy=None):
    """Reserva el NCF, guarda la factura pagada y sus líneas. Retorna el id."""
    hoy = hoy or date.today()
    tipo = datos['tipo_comprobante']
    with database_transaction():
        # Bloquea la secuencia: dos cajeros a la vez no obtienen el mismo NCF.
        secuencia = execute_query(
            '''
            SELECT id, tipo, prefijo, ultimo_numero, tamano_secuencia, fecha_fin
            FROM ncf
            WHERE tenant_id=%s AND tipo=%s AND activo=1
            ORDER BY id
            LIMIT 1
            FOR UPDATE
            ''',
            (tenant_id, tipo),
        )
        if not secuencia:
            raise FacturaPacienteError(
                f'No hay una secuencia {tipo} activa. Regístrela en Administración → NCF.'
            )
        vence = secuencia.get('fecha_fin')
        if vence and hasattr(vence, 'year') and vence < hoy:
            raise FacturaPacienteError(
                f'La secuencia {tipo} venció el {vence.strftime("%d/%m/%Y")}. '
                'Registre una secuencia vigente.'
            )
        numero = int(secuencia.get('ultimo_numero') or 0) + 1
        tamano = int(secuencia.get('tamano_secuencia') or 8)
        ncf = f"{secuencia.get('prefijo') or tipo}{numero:0{tamano}d}"
        if execute_query(
            'SELECT id FROM facturas WHERE tenant_id=%s AND ncf=%s LIMIT 1',
            (tenant_id, ncf),
        ):
            raise FacturaPacienteError(
                f'El NCF {ncf} ya fue usado. Revise el último número de la secuencia {tipo}.'
            )
        paciente = datos['paciente']
        medico = datos.get('medico') or {}
        factura_id = execute_update(
            '''
            INSERT INTO facturas (
                tenant_id, numero_factura, tipo_factura, ncf, fecha_emision,
                paciente_id, nombre_paciente, cedula_paciente, nss_paciente,
                ars_id, nombre_ars, medico_id, nombre_medico,
                subtotal, itbis, total, estado, observaciones, created_by,
                destinatario, rnc_comprador, razon_social_comprador,
                metodo_pago, referencia_pago, monto_recibido
            ) VALUES (
                %s, %s, 'TRADICIONAL', %s, %s,
                %s, %s, %s, %s,
                NULL, NULL, %s, %s,
                %s, 0, %s, 'Pagada', %s, %s,
                %s, %s, %s,
                %s, %s, %s
            )
            ''',
            (
                tenant_id, f'FACP-{ncf}', ncf, hoy,
                paciente['id'], paciente.get('nombre') or '', paciente.get('cedula'),
                paciente.get('nss'),
                medico.get('id'), medico.get('nombre'),
                datos['total'], datos['total'], datos.get('observaciones'), usuario_id,
                DESTINATARIO, datos.get('rnc_comprador'), datos.get('razon_social_comprador'),
                datos['metodo_pago'], datos.get('referencia_pago'), datos.get('monto_recibido'),
            ),
        )
        for linea in datos['lineas']:
            execute_update(
                '''
                INSERT INTO factura_detalles (
                    tenant_id, factura_id, servicio_id, descripcion,
                    cantidad, precio_unitario, subtotal
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                ''',
                (
                    tenant_id, factura_id, linea.get('servicio_id'), linea['descripcion'],
                    linea['cantidad'], linea['precio_unitario'], linea['subtotal'],
                ),
            )
        execute_update(
            'UPDATE ncf SET ultimo_numero=%s, proximo_numero=%s WHERE id=%s AND tenant_id=%s',
            (numero, numero + 1, secuencia['id'], tenant_id),
        )
    return int(factura_id)


def cargar_factura_paciente(tenant_id, factura_id):
    factura = execute_query(
        '''
        SELECT f.*, n.fecha_fin AS ncf_vence
        FROM facturas f
        LEFT JOIN ncf n
          ON n.tenant_id = f.tenant_id
         AND n.tipo = LEFT(f.ncf, 3)
         AND n.activo = 1
        WHERE f.id=%s AND f.tenant_id=%s AND f.destinatario=%s
        LIMIT 1
        ''',
        (factura_id, tenant_id, DESTINATARIO),
    )
    if not factura:
        return None
    factura['lineas'] = execute_query(
        '''
        SELECT descripcion, cantidad, precio_unitario, subtotal
        FROM factura_detalles
        WHERE factura_id=%s AND tenant_id=%s
        ORDER BY id
        ''',
        (factura_id, tenant_id),
        fetch='all',
    ) or []
    total = Decimal(str(factura.get('total') or 0))
    recibido = factura.get('monto_recibido')
    factura['cambio'] = (
        (Decimal(str(recibido)) - total).quantize(CENTAVO) if recibido is not None else None
    )
    return factura


def anular_factura_paciente(tenant_id, factura_id, motivo, usuario_id):
    motivo = (motivo or '').strip()[:500]
    if not motivo:
        raise FacturaPacienteError('Indique el motivo de la anulación')
    with database_transaction():
        factura = execute_query(
            '''
            SELECT id, estado FROM facturas
            WHERE id=%s AND tenant_id=%s AND destinatario=%s
            FOR UPDATE
            ''',
            (factura_id, tenant_id, DESTINATARIO),
        )
        if not factura:
            raise FacturaPacienteError('Factura no encontrada')
        if factura['estado'] == 'Anulada':
            raise FacturaPacienteError('La factura ya está anulada')
        execute_update(
            '''
            UPDATE facturas
            SET estado='Anulada', motivo_anulacion=%s, anulado_por=%s,
                fecha_anulacion=NOW()
            WHERE id=%s AND tenant_id=%s
            ''',
            (motivo, usuario_id, factura_id, tenant_id),
        )


def _autorizaciones_existentes(tenant_id, ars_id, autorizaciones):
    """Autorizaciones ya registradas para esa ARS (en cualquier fecha)."""
    if not autorizaciones:
        return set()
    condiciones = ' OR '.join(['servicios_realizados LIKE %s'] * len(autorizaciones))
    filas = execute_query(
        f"""
        SELECT servicios_realizados FROM pacientes_pendientes
        WHERE tenant_id=%s AND ars_id=%s AND ({condiciones})
        FOR UPDATE
        """,
        (tenant_id, ars_id, *[f'%- Autorización: {a}' for a in autorizaciones]),
        fetch='all',
    ) or []
    usadas = set()
    for fila in filas:
        texto = fila.get('servicios_realizados') or ''
        for autorizacion in autorizaciones:
            if texto.endswith(f'- Autorización: {autorizacion}'):
                usadas.add(autorizacion)
    return usadas


def registrar_atencion(tenant_id, datos, usuario_id, hoy=None):
    """Factura al paciente lo que le toca y envía a la ARS lo que cubre el seguro.

    Todo o nada: si una autorización ya existe o falla el NCF, no se guarda nada.
    Retorna (factura_id o None, cantidad de consultas enviadas a la ARS).
    """
    hoy = hoy or date.today()
    consultas = datos.get('consultas_ars') or []
    with database_transaction():
        if consultas:
            ars = datos['ars']
            repetidas = _autorizaciones_existentes(
                tenant_id, ars['id'], [c['autorizacion'] for c in consultas],
            )
            if repetidas:
                raise FacturaPacienteError(
                    'Estas autorizaciones ya fueron registradas para '
                    f"{ars['nombre']}: {', '.join(sorted(repetidas))}"
                )

        factura_id = None
        ncf = None
        if datos['total'] > 0:
            factura_id = emitir_factura_paciente(tenant_id, datos, usuario_id, hoy=hoy)
            fila = execute_query(
                'SELECT ncf FROM facturas WHERE id=%s AND tenant_id=%s',
                (factura_id, tenant_id),
            ) or {}
            ncf = fila.get('ncf')

        if consultas:
            paciente = datos['paciente']
            # Completa NSS y ARS del paciente si no los tenía.
            execute_update(
                """
                UPDATE pacientes
                SET nss = COALESCE(NULLIF(nss, ''), %s),
                    ars_id = COALESCE(ars_id, %s)
                WHERE id=%s AND tenant_id=%s
                """,
                (datos['nss'], datos['ars']['id'], paciente['id'], tenant_id),
            )
            medico = datos.get('medico') or {}
            for consulta in consultas:
                nota = (
                    f"Diferencia RD$ {consulta['diferencia']} cobrada al paciente"
                    + (f' (factura {ncf})' if ncf else '')
                    if consulta['diferencia'] > 0 else 'Sin diferencia para el paciente'
                )
                execute_update(
                    """
                    INSERT INTO pacientes_pendientes
                    (tenant_id, paciente_id, nombre_paciente, nss, ars_id,
                     fecha_servicio, servicios_realizados, monto_estimado,
                     estado, medico_id, observaciones, created_by)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'Pendiente', %s, %s, %s)
                    """,
                    (
                        tenant_id, paciente['id'], paciente.get('nombre') or '',
                        datos['nss'], datos['ars']['id'], hoy,
                        f"{consulta['servicio']} - Autorización: {consulta['autorizacion']}",
                        consulta['monto'], medico.get('id'), nota, usuario_id,
                    ),
                )
    return factura_id, len(consultas)
