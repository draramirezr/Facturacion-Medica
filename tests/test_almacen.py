"""Almacén: códigos, validación, existencia bajo bloqueo, aislamiento por
empresa, conciliación del consumo en emergencias, permisos y reporte."""

import re
import unittest
from contextlib import contextmanager
from datetime import date
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from werkzeug.datastructures import MultiDict

import app as app_module
import core.database as database_module
import routes.almacen as alm
import routes.emergency as emergency
from rbac_catalog import PERMISOS_ROLES_SISTEMA, TODOS_LOS_PERMISOS

TENANT_ID = 9
USUARIO = SimpleNamespace(id=5, tenant_id=TENANT_ID)

PERMISOS_ESPERADOS = {
    'facturacion_almacen': 'almacen.ver',
    'facturacion_almacen_nuevo': 'almacen.gestionar',
    'facturacion_almacen_editar': 'almacen.gestionar',
    'facturacion_almacen_estado': 'almacen.gestionar',
    'facturacion_almacen_entrada': 'almacen.movimientos',
    'facturacion_almacen_salida': 'almacen.movimientos',
    'facturacion_almacen_movimientos': 'almacen.ver',
    'facturacion_reporte_almacen': 'almacen.ver',
    # El consumo en emergencias lo autoriza el permiso de emergencias.
    'facturacion_historias_emergencia_nueva': 'emergencia.crear',
    'facturacion_historia_emergencia_almacen': 'emergencia.crear',
}


def _sin_decoradores(vista):
    while hasattr(vista, '__wrapped__'):
        vista = vista.__wrapped__
    return vista


def _articulo(**cambios):
    fila = {
        'id': 1, 'codigo': 'MED-0001', 'descripcion': 'Diclofenac 75mg',
        'unidad': 'Ampolla', 'tipo': 'MEDICAMENTO', 'activo': 1,
        'existencia': Decimal('5.00'),
    }
    fila.update(cambios)
    return fila


class _Registro:
    """Captura las llamadas a execute_query / execute_update."""

    def __init__(self, respuestas=None, lastrowid=100):
        self.consultas = []
        self.escrituras = []
        self.respuestas = respuestas or []
        self.lastrowid = lastrowid

    def query(self, sql, params=None, fetch='one'):
        self.consultas.append((sql, params))
        for patron, valor in self.respuestas:
            if patron in sql:
                return valor(sql, params) if callable(valor) else valor
        return [] if fetch == 'all' else None

    def update(self, sql, params=None):
        self.escrituras.append((sql, params))
        self.lastrowid += 1
        return self.lastrowid

    def assert_tenant(self, caso):
        for sql, params in self.consultas + self.escrituras:
            with caso.subTest(sql=sql[:80]):
                caso.assertIn('tenant_id', sql)
                caso.assertIn(TENANT_ID, tuple(params or ()))


class CodigoArticuloTests(unittest.TestCase):
    def test_codigo_por_tipo_con_bloqueo_y_tenant(self):
        for tipo, esperado in (('MEDICAMENTO', 'MED-0007'), ('MATERIAL', 'MAT-0007')):
            with self.subTest(tipo=tipo), \
                    patch.object(alm, 'execute_query', return_value={'siguiente': 7}) as query:
                numero, codigo = alm.siguiente_codigo_articulo(TENANT_ID, tipo)
            sql, params = query.call_args.args
            self.assertEqual((numero, codigo), (7, esperado))
            self.assertIn('FOR UPDATE', sql)
            self.assertIn('MAX(numero)', sql)
            self.assertIn('tenant_id=%s AND tipo=%s', sql)
            self.assertEqual(params, (TENANT_ID, tipo))

    def test_primer_codigo_de_la_empresa(self):
        with patch.object(alm, 'execute_query', return_value=None):
            self.assertEqual(
                alm.siguiente_codigo_articulo(TENANT_ID, 'MEDICAMENTO'),
                (1, 'MED-0001'),
            )

    def test_insertar_articulo_usa_codigo_generado(self):
        datos = {'tipo': 'MATERIAL', 'descripcion': 'Jeringa 5cc', 'unidad': 'Unidad'}
        with patch.object(alm, 'execute_query', return_value={'siguiente': 3}), \
                patch.object(alm, 'execute_update', return_value=40) as update, \
                patch.object(alm, 'current_user', USUARIO):
            articulo_id, codigo = alm.insertar_articulo(TENANT_ID, datos)
        self.assertEqual((articulo_id, codigo), (40, 'MAT-0003'))
        params = update.call_args.args[1]
        self.assertEqual(params[:4], (TENANT_ID, 'MATERIAL', 3, 'MAT-0003'))

    def test_validacion_de_articulo(self):
        with app_module.app.test_request_context('/'), \
                patch.object(alm, 'execute_query', return_value=None) as query:
            datos, error = alm.validar_datos_articulo(TENANT_ID, {'tipo': 'OTRO', 'descripcion': 'X'})
            self.assertIsNone(datos)
            self.assertIn('medicamento o material', error)
            datos, error = alm.validar_datos_articulo(TENANT_ID, {'tipo': 'MEDICAMENTO', 'descripcion': ' '})
            self.assertIn('descripción', error)
            datos, error = alm.validar_datos_articulo(
                TENANT_ID, {'tipo': 'material', 'descripcion': 'Gasas <b>4x4</b>', 'unidad': ''},
            )
        self.assertIsNone(error)
        self.assertEqual(datos, {'tipo': 'MATERIAL', 'descripcion': 'Gasas 4x4', 'unidad': 'Unidad'})
        sql, params = query.call_args.args
        self.assertIn('tenant_id=%s', sql)
        self.assertEqual(params[0], TENANT_ID)

    def test_edicion_no_cambia_tipo(self):
        with app_module.app.test_request_context('/'), \
                patch.object(alm, 'execute_query', return_value=None):
            datos, error = alm.validar_datos_articulo(
                TENANT_ID, {'tipo': 'MATERIAL', 'descripcion': 'Otro'},
                articulo={'id': 1, 'tipo': 'MEDICAMENTO'},
            )
        self.assertIsNone(error)
        self.assertEqual(datos['tipo'], 'MEDICAMENTO')

    def test_descripcion_duplicada(self):
        with app_module.app.test_request_context('/'), \
                patch.object(alm, 'execute_query', return_value={'id': 3}):
            datos, error = alm.validar_datos_articulo(
                TENANT_ID, {'tipo': 'MEDICAMENTO', 'descripcion': 'Diclofenac'},
            )
        self.assertIsNone(datos)
        self.assertIn('Ya existe', error)


class CantidadTests(unittest.TestCase):
    def test_cantidades_invalidas(self):
        for valor in ('', None, '0', '-1', '-0.01', 'abc', 'NaN', 'Infinity',
                      '-Infinity', '1e400', '100000000', '1.234', '1,5'):
            with self.subTest(valor=valor):
                cantidad, error = alm.parsear_cantidad(valor)
                self.assertIsNone(cantidad)
                self.assertTrue(error)

    def test_cantidades_validas(self):
        self.assertEqual(alm.parsear_cantidad('2.5'), (Decimal('2.50'), None))
        self.assertEqual(alm.parsear_cantidad(' 3 '), (Decimal('3.00'), None))
        self.assertEqual(alm.parsear_cantidad('99999999.99')[0], Decimal('99999999.99'))

    def test_fecha_futura_rechazada(self):
        with patch.object(alm, 'fecha_clinica', return_value=date(2026, 11, 24)):
            self.assertEqual(
                alm.parsear_fecha_movimiento('2026-11-20'), (date(2026, 11, 20), None),
            )
            self.assertIsNone(alm.parsear_fecha_movimiento('2026-11-25')[0])
            self.assertIsNone(alm.parsear_fecha_movimiento('20/11/2026')[0])
            self.assertEqual(alm.parsear_fecha_movimiento('')[0], date(2026, 11, 24))

    def test_formato_cantidad(self):
        self.assertEqual(alm.formato_cantidad(Decimal('2.00')), '2')
        self.assertEqual(alm.formato_cantidad(Decimal('1.50')), '1.5')
        self.assertEqual(alm.formato_cantidad(Decimal('1250.25')), '1,250.25')
        self.assertEqual(alm.formato_cantidad(None), '0')


class MovimientosTests(unittest.TestCase):
    def _planificar(self, cambios, articulos):
        registro = _Registro([('FROM almacen_articulos', articulos)])
        with patch.object(alm, 'execute_query', side_effect=registro.query):
            plan, error = alm.planificar_movimientos(TENANT_ID, cambios)
        return plan, error, registro

    def test_bloquea_filas_del_tenant_en_orden(self):
        plan, error, registro = self._planificar(
            [(3, alm.MOV_SALIDA, Decimal('-1')), (1, alm.MOV_SALIDA, Decimal('-1'))],
            [_articulo(id=1), _articulo(id=3, codigo='MED-0003')],
        )
        self.assertIsNone(error)
        sql, params = registro.consultas[0]
        self.assertIn('FOR UPDATE', sql)
        self.assertIn('tenant_id=%s', sql)
        self.assertEqual(params, (TENANT_ID, 1, 3))
        self.assertEqual([m['saldo_resultante'] for m in plan], [Decimal('4.00')] * 2)

    def test_salida_nunca_deja_existencia_negativa(self):
        plan, error, _ = self._planificar(
            [(1, alm.MOV_SALIDA, Decimal('-5.01'))], [_articulo()],
        )
        self.assertIsNone(plan)
        self.assertIn('Existencia insuficiente', error)
        # Llevarla exactamente a cero sí se permite.
        plan, error, _ = self._planificar(
            [(1, alm.MOV_SALIDA, Decimal('-5'))], [_articulo()],
        )
        self.assertIsNone(error)
        self.assertEqual(plan[0]['saldo_resultante'], Decimal('0.00'))

    def test_consumo_acumulado_del_mismo_articulo(self):
        plan, error, _ = self._planificar(
            [
                (1, alm.MOV_CONSUMO_EMERGENCIA, Decimal('-3')),
                (1, alm.MOV_CONSUMO_EMERGENCIA, Decimal('-3')),
            ],
            [_articulo()],
        )
        self.assertIsNone(plan)
        self.assertIn('insuficiente', error)

    def test_articulo_inactivo_rechazado(self):
        for tipo, delta in (
            (alm.MOV_ENTRADA, Decimal('1')),
            (alm.MOV_SALIDA, Decimal('-1')),
            (alm.MOV_CONSUMO_EMERGENCIA, Decimal('-1')),
            (alm.MOV_AJUSTE_EMERGENCIA, Decimal('-1')),
        ):
            with self.subTest(tipo=tipo):
                plan, error, _ = self._planificar([(1, tipo, delta)], [_articulo(activo=0)])
                self.assertIsNone(plan)
                self.assertIn('desactivado', error)
        # Devolver al almacén lo consumido en una emergencia sí se permite.
        plan, error, _ = self._planificar(
            [(1, alm.MOV_AJUSTE_EMERGENCIA, Decimal('2'))], [_articulo(activo=0)],
        )
        self.assertIsNone(error)
        self.assertEqual(plan[0]['saldo_resultante'], Decimal('7.00'))

    def test_articulo_de_otra_empresa_no_existe(self):
        plan, error, _ = self._planificar([(99, alm.MOV_ENTRADA, Decimal('1'))], [])
        self.assertIsNone(plan)
        self.assertIn('no existe', error)

    def test_aplicar_actualiza_existencia_con_incremento_y_tenant(self):
        plan = [{
            'articulo_id': 1, 'tipo': alm.MOV_SALIDA,
            'cantidad': Decimal('-2.00'), 'saldo_resultante': Decimal('3.00'),
        }]
        registro = _Registro()
        with patch.object(alm, 'execute_update', side_effect=registro.update), \
                patch.object(alm, 'current_user', USUARIO):
            alm.aplicar_movimientos(TENANT_ID, plan, date(2026, 11, 24), 'Vencido')
        (sql_upd, p_upd), (sql_ins, p_ins) = registro.escrituras
        self.assertIn('existencia = existencia + %s', sql_upd)
        self.assertEqual(p_upd, (Decimal('-2.00'), 1, TENANT_ID))
        self.assertIn('INSERT INTO almacen_movimientos', sql_ins)
        self.assertEqual(p_ins[:6], (
            TENANT_ID, 1, alm.MOV_SALIDA, date(2026, 11, 24),
            Decimal('-2.00'), Decimal('3.00'),
        ))
        registro.assert_tenant(self)

    def test_registrar_salida_insuficiente_no_escribe(self):
        with patch.object(alm, 'execute_query', return_value=[_articulo(existencia=Decimal('1'))]), \
                patch.object(alm, 'execute_update') as update:
            movimiento, error = alm.registrar_movimiento(
                TENANT_ID, alm.MOV_SALIDA, 1, Decimal('2'), date(2026, 11, 24),
            )
        self.assertIsNone(movimiento)
        self.assertIn('insuficiente', error)
        update.assert_not_called()

    def test_vista_entrada_registra_y_redirige(self):
        registro = _Registro([('FROM almacen_articulos', [_articulo()])])
        with app_module.app.test_request_context(
            '/facturacion/almacen/entrada', method='POST',
            data={'articulo_id': '1', 'cantidad': '10', 'fecha': '2026-11-20', 'nota': 'Compra'},
        ), patch.object(alm, 'get_current_tenant_id', return_value=TENANT_ID), \
                patch.object(alm, 'execute_query', side_effect=registro.query), \
                patch.object(alm, 'execute_update', side_effect=registro.update), \
                patch.object(alm, 'fecha_clinica', return_value=date(2026, 11, 24)), \
                patch.object(alm, 'current_user', USUARIO), \
                patch.object(alm, 'flash') as flash:
            respuesta = _sin_decoradores(alm.facturacion_almacen_entrada)()
        self.assertEqual(respuesta.status_code, 302)
        self.assertIn('Existencia actual: 15', flash.call_args.args[0])
        insert = registro.escrituras[1][1]
        self.assertEqual(insert[2:6], (alm.MOV_ENTRADA, date(2026, 11, 20), Decimal('10.00'), Decimal('15.00')))
        registro.assert_tenant(self)

    def test_vista_salida_exige_motivo(self):
        with app_module.app.test_request_context(
            '/facturacion/almacen/salida', method='POST',
            data={'articulo_id': '1', 'cantidad': '1'},
        ), patch.object(alm, 'get_current_tenant_id', return_value=TENANT_ID), \
                patch.object(alm, 'execute_query', return_value=[]), \
                patch.object(alm, 'execute_update') as update, \
                patch.object(alm, 'render_template', side_effect=lambda t, **c: c), \
                patch.object(alm, 'flash') as flash:
            _sin_decoradores(alm.facturacion_almacen_salida)()
        update.assert_not_called()
        self.assertIn('motivo', flash.call_args.args[0])

    def test_toggle_estado_bloquea_y_filtra_tenant(self):
        registro = _Registro([('FROM almacen_articulos', _articulo())])
        with app_module.app.test_request_context(
            '/facturacion/almacen/1/estado', method='POST',
        ), patch.object(alm, 'get_current_tenant_id', return_value=TENANT_ID), \
                patch.object(alm, 'execute_query', side_effect=registro.query), \
                patch.object(alm, 'execute_update', side_effect=registro.update), \
                patch.object(alm, 'current_user', USUARIO), \
                patch.object(alm, 'flash'):
            respuesta = _sin_decoradores(alm.facturacion_almacen_estado)(1)
        self.assertEqual(respuesta.status_code, 302)
        self.assertIn('FOR UPDATE', registro.consultas[0][0])
        sql, params = registro.escrituras[0]
        self.assertIn('activo=%s', sql)
        self.assertEqual(params, (0, USUARIO.id, 1, TENANT_ID))
        registro.assert_tenant(self)


class AislamientoTenantAlmacenTests(unittest.TestCase):
    def _listado(self, vista, url):
        capturado = {}

        def fake_paginated(query, params, order_by):
            capturado['query'] = query
            capturado['params'] = list(params)
            return [], {'page': 1}

        registro = _Registro()
        with app_module.app.test_request_context(url), \
                patch.object(alm, 'get_current_tenant_id', return_value=TENANT_ID), \
                patch.object(alm, 'execute_paginated_query', side_effect=fake_paginated), \
                patch.object(alm, 'execute_query', side_effect=registro.query), \
                patch.object(alm, 'render_template', side_effect=lambda t, **c: c):
            contexto = _sin_decoradores(vista)()
        self.assertIn('tenant_id=%s', capturado['query'])
        self.assertEqual(capturado['params'][0], TENANT_ID)
        registro.assert_tenant(self)
        return capturado, contexto

    def test_listado_de_articulos(self):
        capturado, _ = self._listado(
            alm.facturacion_almacen,
            '/facturacion/almacen?buscar=dic&tipo=MEDICAMENTO&estado=inactivos&existencia=sin',
        )
        self.assertIn('MEDICAMENTO', capturado['params'])
        self.assertIn('a.activo=0', capturado['query'])
        self.assertIn('a.existencia<=0', capturado['query'])

    def test_kardex(self):
        capturado, _ = self._listado(
            alm.facturacion_almacen_movimientos,
            '/facturacion/almacen/movimientos?articulo_id=4&tipo=SALIDA&desde=2026-11-30&hasta=2026-11-01',
        )
        self.assertEqual(
            capturado['params'],
            [TENANT_ID, 4, 'SALIDA', date(2026, 11, 1), date(2026, 11, 30)],
        )
        self.assertIn('a.tenant_id=m.tenant_id', capturado['query'])

    def test_consultas_de_emergencia_filtran_por_tenant(self):
        registro = _Registro()
        with patch.object(alm, 'execute_query', side_effect=registro.query):
            alm.consumo_registrado_historia(TENANT_ID, 30)
            alm.detalle_consumo_historia(TENANT_ID, 30)
            alm.articulos_para_consumo(TENANT_ID, {4: Decimal('1')})
            alm.articulos_activos(TENANT_ID)
            alm.obtener_articulo(4, TENANT_ID, bloquear=True)
        registro.assert_tenant(self)
        self.assertIn('FOR UPDATE', registro.consultas[-1][0])

    def test_reporte_filtra_por_tenant(self):
        registro = _Registro()
        with patch.object(alm, 'execute_query', side_effect=registro.query):
            alm.consultar_reporte_almacen(
                TENANT_ID, date(2026, 11, 1), date(2026, 11, 30), 'MATERIAL', 'activos',
            )
        registro.assert_tenant(self)
        sql, params = registro.consultas[0]
        self.assertIn('m.tenant_id=a.tenant_id', sql)
        self.assertEqual(params, (date(2026, 11, 1), date(2026, 11, 30), TENANT_ID, 'MATERIAL'))


class ConsumoEmergenciaTests(unittest.TestCase):
    def test_leer_formulario(self):
        form = MultiDict([
            ('almacen_articulo_id', '1'), ('almacen_cantidad', '2'),
            ('almacen_articulo_id', ''), ('almacen_cantidad', ''),
            ('almacen_articulo_id', '1'), ('almacen_cantidad', '0.5'),
            ('almacen_articulo_id', '4'), ('almacen_cantidad', '1'),
        ])
        consumo, error = alm.leer_consumo_formulario(form)
        self.assertIsNone(error)
        self.assertEqual(consumo, {1: Decimal('2.50'), 4: Decimal('1.00')})

    def test_leer_formulario_rechaza_filas_incompletas(self):
        for filas in (
            [('almacen_articulo_id', ''), ('almacen_cantidad', '2')],
            [('almacen_articulo_id', '1'), ('almacen_cantidad', '')],
            [('almacen_articulo_id', '1'), ('almacen_cantidad', 'inf')],
            [('almacen_articulo_id', '1'), ('almacen_cantidad', '-3')],
        ):
            with self.subTest(filas=filas):
                consumo, error = alm.leer_consumo_formulario(MultiDict(filas))
                self.assertIsNone(consumo)
                self.assertIn('Almacén', error)

    def test_diferencias_de_conciliacion(self):
        cambios = alm.cambios_consumo_emergencia(
            {1: Decimal('3'), 2: Decimal('1'), 5: Decimal('4')},
            {1: Decimal('5'), 3: Decimal('2'), 5: Decimal('4')},
            es_edicion=True,
        )
        self.assertEqual(cambios, [
            (1, alm.MOV_AJUSTE_EMERGENCIA, Decimal('2')),   # devuelve 2
            (2, alm.MOV_AJUSTE_EMERGENCIA, Decimal('-1')),  # consume 1 más
            (3, alm.MOV_AJUSTE_EMERGENCIA, Decimal('2')),   # quitado: devuelve todo
        ])
        creacion = alm.cambios_consumo_emergencia({1: Decimal('2')}, {}, es_edicion=False)
        self.assertEqual(creacion, [(1, alm.MOV_CONSUMO_EMERGENCIA, Decimal('-2'))])

    def _post_edicion(self, data, articulos, previo):
        registro = _Registro([
            ('-SUM(cantidad) AS consumido', previo),
            ('FROM almacen_articulos', articulos),
        ])
        historia = {'id': 30, 'fecha': date(2026, 11, 20), 'nombre_paciente': 'Ana',
                    'medico_id': 2, 'medico_nombre': 'Dr. Luis'}
        consultas_historia = []

        def fake_historia(sql, params=None, fetch='one'):
            consultas_historia.append((sql, params))
            return historia

        with app_module.app.test_request_context(
            '/facturacion/historias-emergencia/30/almacen', method='POST',
            data=MultiDict(data),
        ), patch.object(emergency, 'get_current_tenant_id', return_value=TENANT_ID), \
                patch.object(emergency, 'medico_id_emergencias_restringido', return_value=None), \
                patch.object(emergency, 'execute_query', side_effect=fake_historia), \
                patch.object(emergency, 'fecha_clinica', return_value=date(2026, 11, 24)), \
                patch.object(alm, 'execute_query', side_effect=registro.query), \
                patch.object(alm, 'execute_update', side_effect=registro.update), \
                patch.object(alm, 'current_user', USUARIO), \
                patch.object(emergency, 'flash') as flash:
            respuesta = _sin_decoradores(emergency.facturacion_historia_emergencia_almacen)(30)
        self.assertEqual(respuesta.status_code, 302)
        sql, params = consultas_historia[0]
        self.assertIn('FOR UPDATE', sql)
        self.assertIn('tenant_id=%s', sql)
        self.assertEqual(params[:2], (30, TENANT_ID))
        registro.assert_tenant(self)
        return registro, flash

    def test_edicion_registra_solo_diferencias(self):
        registro, _ = self._post_edicion(
            [('almacen_articulo_id', '1'), ('almacen_cantidad', '3'),
             ('almacen_articulo_id', '2'), ('almacen_cantidad', '1')],
            [_articulo(id=1, existencia=Decimal('10')),
             _articulo(id=2, codigo='MAT-0001', existencia=Decimal('4'))],
            [{'articulo_id': 1, 'consumido': Decimal('5')}],
        )
        inserts = [p for sql, p in registro.escrituras if 'INSERT INTO almacen_movimientos' in sql]
        self.assertEqual(
            [(p[1], p[2], p[4], p[5], p[7]) for p in inserts],
            [
                (1, alm.MOV_AJUSTE_EMERGENCIA, Decimal('2'), Decimal('12'), 30),
                (2, alm.MOV_AJUSTE_EMERGENCIA, Decimal('-1'), Decimal('3'), 30),
            ],
        )
        self.assertTrue(all(p[3] == date(2026, 11, 24) for p in inserts))

    def test_edicion_sin_existencia_no_escribe(self):
        registro, flash = self._post_edicion(
            [('almacen_articulo_id', '1'), ('almacen_cantidad', '9')],
            [_articulo(id=1, existencia=Decimal('3'))],
            [{'articulo_id': 1, 'consumido': Decimal('5')}],
        )
        self.assertEqual(registro.escrituras, [])
        self.assertIn('insuficiente', flash.call_args.args[0])

    def test_edicion_sin_cambios(self):
        registro, flash = self._post_edicion(
            [('almacen_articulo_id', '1'), ('almacen_cantidad', '5')],
            [_articulo(id=1)],
            [{'articulo_id': 1, 'consumido': Decimal('5')}],
        )
        self.assertEqual(registro.escrituras, [])
        self.assertIn('No hubo cambios', flash.call_args.args[0])

    def _post_creacion(self, existencia):
        data = MultiDict({
            'paciente_id': '1', 'medico_id': '2', 'fecha': '2026-11-20',
            'hora_servicio': '08:30', 'edad': '30', 'sexo_historia': 'F',
            'motivo_emergencia': 'Dolor', 'historia_enfermedad': 'Inicio súbito',
            'diagnostico_impresion': 'Lumbalgia', 'estatus_paciente': 'Dado de alta',
            'origen_enfermedad': 'Enfermedad común',
        })
        data.add('almacen_articulo_id', '1')
        data.add('almacen_cantidad', '2')

        def fake_emergencia(sql, params=None, fetch='one'):
            if 'FROM pacientes p' in sql:
                return {'id': 1, 'nombre': 'Ana', 'nss': None, 'ars_nombre': None}
            if 'FROM medicos' in sql:
                return {'id': 2, 'nombre': 'Dr. Luis'}
            return None

        registro = _Registro([('FROM almacen_articulos', [_articulo(existencia=existencia)])])
        with app_module.app.test_request_context(
            '/facturacion/historias-emergencia/nueva', method='POST', data=data,
        ), patch.object(emergency, 'get_current_tenant_id', return_value=TENANT_ID), \
                patch.object(emergency, 'medico_id_emergencias_restringido', return_value=None), \
                patch.object(emergency, 'paciente_adulto_sin_cedula', return_value=False), \
                patch.object(emergency, 'execute_query', side_effect=fake_emergencia), \
                patch.object(emergency, 'execute_update', return_value=77) as insert_historia, \
                patch.object(emergency, 'current_user', USUARIO), \
                patch.object(alm, 'execute_query', side_effect=registro.query), \
                patch.object(alm, 'execute_update', side_effect=registro.update), \
                patch.object(alm, 'current_user', USUARIO), \
                patch.object(emergency, 'flash') as flash:
            respuesta = _sin_decoradores(emergency.facturacion_historias_emergencia_nueva)()
        self.assertEqual(respuesta.status_code, 302)
        return registro, insert_historia, flash

    def test_creacion_descuenta_en_la_misma_operacion(self):
        registro, insert_historia, _ = self._post_creacion(Decimal('5'))
        insert_historia.assert_called_once()
        self.assertIn('FOR UPDATE', registro.consultas[0][0])
        inserts = [p for sql, p in registro.escrituras if 'INSERT INTO almacen_movimientos' in sql]
        self.assertEqual(len(inserts), 1)
        self.assertEqual(
            (inserts[0][2], inserts[0][3], inserts[0][4], inserts[0][5], inserts[0][7]),
            (alm.MOV_CONSUMO_EMERGENCIA, '2026-11-20', Decimal('-2.00'), Decimal('3.00'), 77),
        )
        registro.assert_tenant(self)

    def test_creacion_sin_existencia_no_guarda_historia(self):
        registro, insert_historia, flash = self._post_creacion(Decimal('1'))
        insert_historia.assert_not_called()
        self.assertEqual(registro.escrituras, [])
        self.assertIn('insuficiente', flash.call_args.args[0])

    def test_creacion_es_transaccional(self):
        for endpoint in (
            'facturacion_historias_emergencia_nueva',
            'facturacion_historia_emergencia_almacen',
        ):
            with self.subTest(endpoint=endpoint):
                vista = app_module.app.view_functions[endpoint]
                while vista and not hasattr(vista, 'transactional_methods'):
                    vista = getattr(vista, '__wrapped__', None)
                self.assertIsNotNone(vista)
                self.assertEqual(vista.transactional_methods, frozenset({'POST'}))


class PermisosAlmacenTests(unittest.TestCase):
    def test_vistas_exigen_permiso_especifico(self):
        for endpoint, permiso in PERMISOS_ESPERADOS.items():
            with self.subTest(endpoint=endpoint):
                vista = app_module.app.view_functions[endpoint]
                self.assertEqual(getattr(vista, 'required_permission', None), permiso)

    def test_vistas_requieren_login(self):
        cliente = app_module.app.test_client()
        for url in (
            '/facturacion/almacen', '/facturacion/almacen/nuevo',
            '/facturacion/almacen/3/editar', '/facturacion/almacen/entrada',
            '/facturacion/almacen/salida', '/facturacion/almacen/movimientos',
            '/facturacion/reportes/almacen',
            '/facturacion/historias-emergencia/3/almacen',
        ):
            with self.subTest(url=url):
                respuesta = cliente.get(url)
                self.assertEqual(respuesta.status_code, 302)
                self.assertIn('login', respuesta.location)

    def test_escrituras_son_transaccionales(self):
        for endpoint in (
            'facturacion_almacen_nuevo', 'facturacion_almacen_editar',
            'facturacion_almacen_estado', 'facturacion_almacen_entrada',
            'facturacion_almacen_salida',
        ):
            with self.subTest(endpoint=endpoint):
                vista = app_module.app.view_functions[endpoint]
                while vista and not hasattr(vista, 'transactional_methods'):
                    vista = getattr(vista, '__wrapped__', None)
                self.assertIsNotNone(vista)
                self.assertEqual(vista.transactional_methods, frozenset({'POST'}))

    def test_estado_solo_acepta_post(self):
        reglas = [
            regla for regla in app_module.app.url_map.iter_rules()
            if regla.endpoint == 'facturacion_almacen_estado'
        ]
        self.assertEqual(len(reglas), 1)
        self.assertEqual(reglas[0].methods - {'HEAD', 'OPTIONS'}, {'POST'})

    def test_no_hay_rutas_para_borrar_movimientos(self):
        for regla in app_module.app.url_map.iter_rules():
            if 'almacen' in regla.rule:
                self.assertNotIn('eliminar', regla.rule)
                self.assertNotIn('DELETE', regla.methods)

    def test_roles_de_sistema(self):
        for codigo in ('almacen.ver', 'almacen.gestionar', 'almacen.movimientos'):
            self.assertIn(codigo, TODOS_LOS_PERMISOS)
        for rol, permisos in PERMISOS_ROLES_SISTEMA.items():
            with self.subTest(rol=rol):
                if 'emergencia.crear' in permisos:
                    self.assertIn('almacen.ver', permisos)
                    self.assertIn('almacen.movimientos', permisos)
                self.assertEqual(
                    'almacen.gestionar' in permisos, 'catalogos.editar' in permisos,
                )
        self.assertNotIn('almacen.gestionar', PERMISOS_ROLES_SISTEMA['Médico'])


class _CursorRegistro:
    def __init__(self):
        self.sentencias = []

    def execute(self, sql, params=None):
        self.sentencias.append((sql, params))

    def fetchone(self):
        return {'1': 1}

    def fetchall(self):
        return []


class EsquemaAlmacenTests(unittest.TestCase):
    def setUp(self):
        self.esquema = (
            Path(app_module.__file__).resolve().parent / 'database_schema.sql'
        ).read_text(encoding='utf-8')

    def _cuerpo(self, tabla):
        match = re.search(
            rf'CREATE TABLE IF NOT EXISTS {tabla}\s*\((.*?)\)\s*ENGINE=',
            self.esquema, re.DOTALL,
        )
        self.assertIsNotNone(match)
        return match.group(1)

    def test_tablas_con_tenant_claves_e_indices(self):
        articulos = self._cuerpo('almacen_articulos')
        self.assertRegex(articulos, r'(^|\s)tenant_id\s+INT NOT NULL')
        self.assertIn('(tenant_id, codigo)', articulos)
        self.assertIn('existencia DECIMAL(12,2)', articulos)
        self.assertIn('REFERENCES empresas(id) ON DELETE RESTRICT', articulos)
        movimientos = self._cuerpo('almacen_movimientos')
        self.assertIn('cantidad DECIMAL(10,2)', movimientos)
        self.assertIn('saldo_resultante', movimientos)
        self.assertIn('(tenant_id, articulo_id, fecha)', movimientos)
        self.assertIn('(tenant_id, historia_emergencia_id)', movimientos)
        self.assertIn('REFERENCES almacen_articulos(id)', movimientos)
        self.assertNotIn('REFERENCES historias_emergencia', movimientos)
        self.assertLess(
            self.esquema.index('CREATE TABLE IF NOT EXISTS almacen_articulos'),
            self.esquema.index('CREATE TABLE IF NOT EXISTS almacen_movimientos'),
        )

    def test_arranque_crea_tablas_en_orden_y_hereda_permisos(self):
        import core.schema_bootstrap as bootstrap

        cursor = _CursorRegistro()
        bootstrap._asegurar_tablas_modulos(cursor)
        creadas = [
            sql.split()[5] for sql, _p in cursor.sentencias
            if sql.startswith('CREATE TABLE IF NOT EXISTS almacen_')
        ]
        self.assertEqual(creadas, ['almacen_articulos', 'almacen_movimientos'])

        cursor = _CursorRegistro()
        bootstrap._heredar_permisos_nuevos(cursor, 'db', set())
        herencias = {p for sql, p in cursor.sentencias if 'INSERT IGNORE' in sql}
        self.assertTrue({
            ('emergencia.crear', 'almacen.ver'),
            ('emergencia.crear', 'almacen.movimientos'),
            ('catalogos.editar', 'almacen.gestionar'),
        }.issubset(herencias))

    def test_limpieza_y_backup_incluyen_almacen(self):
        from services import tenant_backup, tenant_cleanup

        opcionales = tenant_cleanup._TABLAS_OPCIONALES
        self.assertLess(
            opcionales.index('almacen_movimientos'),
            opcionales.index('almacen_articulos'),
        )
        self.assertIn('almacen_articulos', tenant_backup.TABLAS_PERMITIDAS)
        self.assertIn('almacen_movimientos', tenant_backup.TABLAS_PERMITIDAS)


class ReporteAlmacenTests(unittest.TestCase):
    FILAS = [
        {'id': 1, 'codigo': 'MED-0001', 'descripcion': 'Diclofenac', 'tipo': 'MEDICAMENTO',
         'unidad': 'Ampolla', 'activo': 1, 'existencia': Decimal('0.00'),
         'entradas': Decimal('10.00'), 'salidas': Decimal('1.00'),
         'consumo_emergencias': Decimal('9.00')},
        {'id': 2, 'codigo': 'MAT-0001', 'descripcion': 'Jeringa 5cc', 'tipo': 'MATERIAL',
         'unidad': 'Unidad', 'activo': 1, 'existencia': Decimal('20.00'),
         'entradas': Decimal('20.00'), 'salidas': Decimal('0.00'),
         'consumo_emergencias': Decimal('2.50')},
    ]

    def test_totales(self):
        with patch.object(alm, 'execute_query', return_value=self.FILAS):
            filas, totales = alm.consultar_reporte_almacen(
                TENANT_ID, date(2026, 11, 1), date(2026, 11, 30),
            )
        self.assertEqual(totales['articulos'], 2)
        self.assertEqual(totales['sin_existencia'], 1)
        self.assertEqual(totales['entradas'], Decimal('30.00'))
        self.assertEqual(totales['salidas'], Decimal('1.00'))
        self.assertEqual(totales['consumo_emergencias'], Decimal('11.50'))
        self.assertTrue(filas[0]['sin_existencia'])

    def test_csv_con_bom_y_totales(self):
        with app_module.app.test_request_context(
            '/facturacion/reportes/almacen?formato=csv&desde=2026-11-01&hasta=2026-11-30'
        ), patch.object(alm, 'get_current_tenant_id', return_value=TENANT_ID), \
                patch.object(alm, 'execute_query', return_value=self.FILAS) as query:
            respuesta = _sin_decoradores(alm.facturacion_reporte_almacen)()
        self.assertIn('text/csv', respuesta.mimetype)
        self.assertIn('almacen_2026-11-01_2026-11-30.csv', respuesta.headers['Content-Disposition'])
        texto = respuesta.get_data().decode('utf-8')
        self.assertTrue(texto.startswith('﻿'))
        self.assertIn('Código,Descripción,Tipo', texto)
        self.assertIn('MED-0001,Diclofenac,Medicamento,Ampolla,Activo,10.00,1.00,9.00,0.00', texto)
        self.assertIn('TOTAL,2 artículos,,,,30.00,1.00,11.50,', texto)
        _sql, params = query.call_args.args
        self.assertIn(TENANT_ID, params)


class _Cursor:
    lastrowid = None

    def execute(self, *args, **kwargs):
        pass

    def fetchone(self):
        return None

    def fetchall(self):
        return []

    def close(self):
        pass


class _Conexion:
    def cursor(self):
        return _Cursor()

    def begin(self):
        pass

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


class RenderizadoAlmacenTests(unittest.TestCase):
    def setUp(self):
        self.user = app_module.User(
            5, 'Admin', 'admin@example.test', 'Administrador',
            tenant_id=TENANT_ID, permissions=set(),
            rbac_roles={'Administrador'}, rbac_role_count=1,
        )

    @contextmanager
    def _contexto(self, url):
        with app_module.app.test_request_context(url), \
                patch('flask_login.utils._get_user', return_value=self.user), \
                patch.object(database_module, 'get_db_connection', return_value=_Conexion()), \
                patch.object(alm, 'get_current_tenant_id', return_value=TENANT_ID):
            yield

    def test_listado_renderiza_con_acciones(self):
        filas = [_articulo(existencia=Decimal('0')), _articulo(id=2, activo=0, codigo='MAT-0001', tipo='MATERIAL')]
        with self._contexto('/facturacion/almacen'), \
                patch.object(alm, 'execute_paginated_query', return_value=(filas, {'page': 1, 'total_pages': 1})), \
                patch.object(alm, 'execute_query', return_value={'total': 2, 'activos': 1, 'sin_existencia': 1}):
            html = alm.facturacion_almacen()
        for texto in ('MED-0001', 'Registrar entrada', 'Registrar salida', 'Movimientos',
                      'data-confirm-submit', 'alm-cero', 'Desactivado'):
            self.assertIn(texto, html)
        self.assertIn('href="/facturacion/almacen"', html)  # enlace del menú

    def test_formularios_y_kardex_renderizan(self):
        with self._contexto('/facturacion/almacen/nuevo'), \
                patch.object(alm, 'execute_query', return_value=[_articulo()]):
            html = alm.facturacion_almacen_nuevo()
            self.assertIn('MED-0001', html)
            self.assertIn('name="descripcion"', html)
        with self._contexto('/facturacion/almacen/salida?articulo_id=1'), \
                patch.object(alm, 'execute_query', return_value=[_articulo()]), \
                patch.object(alm, 'fecha_clinica', return_value=date(2026, 11, 24)):
            html = alm.facturacion_almacen_salida()
            self.assertIn('Registrar salida', html)
            self.assertIn('existencia 5 Ampolla', html)
        movimiento = {
            'id': 1, 'articulo_id': 1, 'tipo': 'CONSUMO_EMERGENCIA',
            'fecha': date(2026, 11, 20), 'cantidad': Decimal('-2.00'),
            'saldo_resultante': Decimal('3.00'), 'nota': 'Emergencia #30 · Ana',
            'historia_emergencia_id': 30, 'created_at': None, 'codigo': 'MED-0001',
            'descripcion': 'Diclofenac', 'unidad': 'Ampolla', 'usuario_nombre': 'Admin',
        }
        with self._contexto('/facturacion/almacen/movimientos?articulo_id=1'), \
                patch.object(alm, 'execute_paginated_query', return_value=([movimiento], {'page': 1, 'total_pages': 1})), \
                patch.object(alm, 'execute_query', return_value=[_articulo()]):
            html = alm.facturacion_almacen_movimientos()
        self.assertIn('Consumo en emergencia', html)
        self.assertIn('Emergencia #30', html)
        self.assertIn('−2', html)

    def test_reporte_renderiza_y_resalta_sin_existencia(self):
        with self._contexto('/facturacion/reportes/almacen'), \
                patch.object(alm, 'execute_query', return_value=ReporteAlmacenTests.FILAS):
            html = alm.facturacion_reporte_almacen()
        self.assertIn('almrep-cero', html)
        self.assertIn('Descargar CSV', html)
        self.assertIn('11.5', html)

    def test_historia_muestra_linea_compacta_del_almacen(self):
        historia = {
            'id': 30, 'fecha': date(2026, 11, 20), 'hora_servicio': '08:30',
            'autorizacion': None, 'nombre_paciente': 'Ana', 'edad': 30, 'sexo': 'F',
            'ars_nombre': None, 'numero_afiliado': None, 'nss': None,
            'motivo_emergencia': 'Dolor', 'historia_enfermedad': 'X',
            'datos_clinicos': '{"medicamentos": "Texto libre"}',
            'diagnostico_impresion': 'Y', 'estatus_paciente': 'Dado de alta',
            'origen_enfermedad': 'Enfermedad común', 'observaciones': None,
            'medico_nombre': 'Dr. Luis', 'medico_id': 2,
        }
        consumo = [
            {'descripcion': 'Diclofenac 75mg', 'cantidad': Decimal('2'), 'unidad': 'Unidad'},
            {'descripcion': 'Jeringa 5cc', 'cantidad': Decimal('1'), 'unidad': 'Unidad'},
        ]
        with self._contexto('/facturacion/historias-emergencia/30/imprimir'), \
                patch.object(emergency, 'get_current_tenant_id', return_value=TENANT_ID), \
                patch.object(emergency, 'execute_query', return_value=historia), \
                patch.object(emergency, 'detalle_consumo_historia', return_value=consumo):
            html = _sin_decoradores(emergency.facturacion_historia_emergencia_imprimir)(30)
        self.assertIn('Del almacén:', html)
        self.assertIn('Diclofenac 75mg × 2 · Jeringa 5cc × 1', html)
        self.assertIn('Texto libre', html)
        self.assertNotIn('Ajustar lo usado del almacén', html)

    def test_formulario_de_emergencia_tiene_filas_del_almacen(self):
        articulos = [dict(_articulo(), disponible=Decimal('5'))]
        with self._contexto('/facturacion/historias-emergencia/30/almacen'), \
                patch.object(emergency, 'get_current_tenant_id', return_value=TENANT_ID), \
                patch.object(emergency, 'medico_id_emergencias_restringido', return_value=None), \
                patch.object(emergency, 'execute_query', return_value={
                    'id': 30, 'fecha': date(2026, 11, 20), 'nombre_paciente': 'Ana',
                    'medico_id': 2, 'medico_nombre': 'Dr. Luis'}), \
                patch.object(emergency, 'consumo_registrado_historia', return_value={1: Decimal('2.00')}), \
                patch.object(emergency, 'articulos_para_consumo', return_value=articulos):
            html = _sin_decoradores(emergency.facturacion_historia_emergencia_almacen)(30)
        self.assertIn('name="almacen_articulo_id"', html)
        self.assertIn('data-alm-plantilla', html)
        self.assertIn('value="2.00"', html)
        self.assertIn('js/almacen-consumo.js', html)
        self.assertIn('data-confirm-submit', html)

    def test_nueva_emergencia_muestra_seccion_del_almacen(self):
        articulos = [
            dict(_articulo(), disponible=Decimal('5')),
            dict(_articulo(id=2, codigo='MAT-0001', existencia=Decimal('0')), disponible=Decimal('0')),
        ]
        with self._contexto('/facturacion/historias-emergencia/nueva'), \
                patch.object(emergency, 'get_current_tenant_id', return_value=TENANT_ID), \
                patch.object(emergency, 'medico_id_emergencias_restringido', return_value=None), \
                patch.object(emergency, 'execute_query', return_value=[]), \
                patch('services.catalogos_ars.sembrar_ars_tenant'), \
                patch.object(emergency, 'articulos_para_consumo', return_value=articulos) as consulta:
            html = _sin_decoradores(emergency.facturacion_historias_emergencia_nueva)()
        consulta.assert_called_once_with(TENANT_ID)
        self.assertIn('Medicamentos y materiales del almacén', html)
        self.assertIn('name="medicamentos"', html)  # el texto libre se conserva
        self.assertIn('disponible 5 Ampolla', html)
        self.assertRegex(html, r'value="2"[^>]*\s+disabled')


if __name__ == '__main__':
    unittest.main()
