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

from datetime import date
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation

from core.database import database_transaction, execute_query, execute_update

CENTAVO = Decimal('0.01')
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
    if metodo not in METODOS_PAGO:
        errores.append('Seleccione la forma de pago')
    referencia = (form.get('referencia_pago') or '').strip()[:100] or None

    detalle = []
    total = Decimal('0.00')
    if not lineas:
        errores.append('Agregue al menos un servicio')
    for numero, linea in enumerate(lineas[:MAX_LINEAS], start=1):
        descripcion = (linea.get('descripcion') or '').strip()[:500]
        try:
            cantidad = int(linea.get('cantidad') or 1)
            precio = _monto(linea.get('precio'))
        except (TypeError, ValueError):
            errores.append(f'Línea {numero}: cantidad o precio inválido')
            continue
        if not descripcion:
            errores.append(f'Línea {numero}: falta la descripción')
            continue
        if cantidad < 1 or cantidad > 999:
            errores.append(f'Línea {numero}: la cantidad debe estar entre 1 y 999')
            continue
        if precio <= 0:
            errores.append(f'Línea {numero}: el precio debe ser mayor que cero')
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
        subtotal = (precio * cantidad).quantize(CENTAVO)
        detalle.append({
            'descripcion': descripcion,
            'cantidad': cantidad,
            'precio_unitario': precio,
            'subtotal': subtotal,
            'servicio_id': servicio_id,
        })
        total += subtotal

    monto_recibido = None
    if metodo == 'Efectivo' and form.get('monto_recibido') not in (None, ''):
        try:
            monto_recibido = _monto(form.get('monto_recibido'))
        except FacturaPacienteError:
            errores.append('El monto recibido no es válido')
        else:
            if detalle and monto_recibido < total:
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
