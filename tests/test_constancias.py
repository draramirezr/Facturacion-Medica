"""Constancias médicas: validación, aislamiento por empresa y permisos."""

import unittest
from contextlib import contextmanager
from datetime import date, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import patch

import app as app_module
import core.database as database_module
import routes.certificates as cert
from rbac_catalog import PERMISOS_ROLES_SISTEMA, TODOS_LOS_PERMISOS

TENANT_ID = 9

PERMISOS_ESPERADOS = {
    'facturacion_constancias_medicas': 'constancias.ver',
    'facturacion_constancias_medicas_nueva': 'constancias.crear',
    'facturacion_constancia_medica_ver': 'constancias.ver',
    'facturacion_constancia_medica_editar': 'constancias.editar',
    'facturacion_constancia_medica_anular': 'constancias.anular',
    'facturacion_constancia_medica_imprimir': 'constancias.imprimir',
}


def _sin_decoradores(vista):
    while hasattr(vista, '__wrapped__'):
        vista = vista.__wrapped__
    return vista


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
    """Conexión simulada para los context processors de base.html."""

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


def _fila_constancia(**cambios):
    fila = {
        'id': 3, 'tenant_id': TENANT_ID, 'numero': 3, 'codigo': 'CM-000003',
        'paciente_id': 1, 'medico_id': 2, 'consulta_id': None,
        'fecha_atencion': date(2026, 11, 20),
        'hora_entrada': timedelta(hours=8),
        'hora_salida': timedelta(hours=9, minutes=30),
        'dirigida_a': 'Colegio San Juan', 'motivo': None, 'estado': 'Activa',
        'paciente_nombre': 'Ana Pérez', 'cedula': '001-0000000-1',
        'fecha_nacimiento': None, 'medico_nombre': 'Dr. Luis',
        'especialidad': 'Pediatría', 'exequatur': '123',
        'consulta_fecha': None, 'creado_por_nombre': 'Admin',
        'anulado_por_nombre': None,
        'created_at': datetime(2026, 11, 20, 9, 0),
        'fecha_anulacion': None, 'motivo_anulacion': None,
    }
    fila.update(cambios)
    return fila


class ValidacionConstanciaTests(unittest.TestCase):
    def setUp(self):
        self.consultas = []

    def _fake_query(self, query, params=None, fetch='one'):
        self.consultas.append((query, params))
        if 'FROM pacientes' in query:
            return {'id': 1}
        if 'FROM medicos' in query:
            return {'id': 2}
        if 'FROM consultas_clinicas' in query:
            return {'id': 7, 'paciente_id': 1}
        return None

    def _validar(self, datos):
        with app_module.app.test_request_context('/'), \
                patch.object(cert, 'execute_query', side_effect=self._fake_query), \
                patch.object(cert, 'medico_id_constancias_restringido', return_value=None):
            return cert.validar_datos_constancia(TENANT_ID, datos)

    def test_campos_obligatorios(self):
        for faltante in ('paciente_id', 'medico_id', 'fecha_atencion'):
            datos = {
                'paciente_id': '1', 'medico_id': '2',
                'fecha_atencion': '2026-11-20',
            }
            datos[faltante] = ''
            with self.subTest(faltante=faltante):
                resultado, error = self._validar(datos)
                self.assertIsNone(resultado)
                self.assertIn('obligatorios', error)

    def test_fecha_invalida(self):
        resultado, error = self._validar({
            'paciente_id': '1', 'medico_id': '2', 'fecha_atencion': '20/11/2026',
        })
        self.assertIsNone(resultado)
        self.assertIn('fecha', error.lower())

    def test_horas_invalidas_o_invertidas(self):
        base = {'paciente_id': '1', 'medico_id': '2', 'fecha_atencion': '2026-11-20'}
        _, error = self._validar({**base, 'hora_entrada': '25:00'})
        self.assertIn('hora', error.lower())
        _, error = self._validar({**base, 'hora_entrada': 'abc'})
        self.assertIn('hora', error.lower())
        _, error = self._validar({
            **base, 'hora_entrada': '10:00', 'hora_salida': '09:00',
        })
        self.assertIn('salida', error.lower())

    def test_datos_validos_y_valores_por_defecto(self):
        datos, error = self._validar({
            'paciente_id': '1', 'medico_id': '2',
            'fecha_atencion': '2026-11-20', 'hora_entrada': '08:00',
            'consulta_id': '7',
        })
        self.assertIsNone(error)
        self.assertEqual(datos['fecha_atencion'], date(2026, 11, 20))
        self.assertEqual(datos['dirigida_a'], cert.DIRIGIDA_A_PREDETERMINADA)
        self.assertIsNone(datos['motivo'])
        self.assertIsNone(datos['hora_salida'])
        self.assertEqual(datos['consulta_id'], 7)
        for query, params in self.consultas:
            with self.subTest(query=query):
                self.assertIn('tenant_id=%s', query)
                self.assertIn(TENANT_ID, params)

    def test_no_exige_diagnostico(self):
        datos, error = self._validar({
            'paciente_id': '1', 'medico_id': '2', 'fecha_atencion': '2026-11-20',
        })
        self.assertIsNone(error)
        self.assertNotIn('diagnostico', datos)

    def test_consulta_de_otro_paciente_se_rechaza(self):
        def fake(query, params=None, fetch='one'):
            if 'FROM consultas_clinicas' in query:
                return {'id': 7, 'paciente_id': 99}
            return self._fake_query(query, params, fetch)

        with app_module.app.test_request_context('/'), \
                patch.object(cert, 'execute_query', side_effect=fake), \
                patch.object(cert, 'medico_id_constancias_restringido', return_value=None):
            datos, error = cert.validar_datos_constancia(TENANT_ID, {
                'paciente_id': '1', 'medico_id': '2',
                'fecha_atencion': '2026-11-20', 'consulta_id': '7',
            })
        self.assertIsNone(datos)
        self.assertIn('consulta', error)


class AislamientoTenantConstanciaTests(unittest.TestCase):
    def test_listado_filtra_por_tenant(self):
        capturado = {}

        def fake_paginated(query, params, order_by):
            capturado['query'] = query
            capturado['params'] = list(params)
            return [], {'page': 1}

        consultas = []

        def fake_query(query, params=None, fetch='one'):
            consultas.append((query, params))
            return []

        with app_module.app.test_request_context(
            '/facturacion/constancias-medicas?buscar=ana&estado=Activa'
        ), patch.object(cert, 'get_current_tenant_id', return_value=TENANT_ID), \
                patch.object(cert, 'medico_id_constancias_restringido', return_value=None), \
                patch.object(cert, 'execute_paginated_query', side_effect=fake_paginated), \
                patch.object(cert, 'execute_query', side_effect=fake_query), \
                patch.object(cert, 'render_template', side_effect=lambda t, **c: c):
            contexto = _sin_decoradores(cert.facturacion_constancias_medicas)()

        self.assertIn('cm.tenant_id=%s', capturado['query'])
        self.assertEqual(capturado['params'][0], TENANT_ID)
        self.assertIn('Activa', capturado['params'])
        for query, params in consultas:
            self.assertIn('tenant_id=%s', query)
            self.assertEqual(params[0], TENANT_ID)
        self.assertFalse(contexto['constancias_restringidas'])

    def test_medico_operativo_solo_ve_sus_constancias(self):
        capturado = {}

        def fake_paginated(query, params, order_by):
            capturado['query'] = query
            capturado['params'] = list(params)
            return [], {'page': 1}

        with app_module.app.test_request_context(
            '/facturacion/constancias-medicas?medico_id=55'
        ), patch.object(cert, 'get_current_tenant_id', return_value=TENANT_ID), \
                patch.object(cert, 'medico_id_constancias_restringido', return_value=4), \
                patch.object(cert, 'execute_paginated_query', side_effect=fake_paginated), \
                patch.object(cert, 'execute_query', return_value=[]), \
                patch.object(cert, 'render_template', side_effect=lambda t, **c: c):
            contexto = _sin_decoradores(cert.facturacion_constancias_medicas)()

        self.assertIn('cm.medico_id=%s', capturado['query'])
        self.assertIn(4, capturado['params'])
        self.assertNotIn(55, capturado['params'])
        self.assertTrue(contexto['constancias_restringidas'])

    def test_obtener_constancia_filtra_por_tenant(self):
        with patch.object(cert, 'execute_query', return_value=None) as query:
            cert.obtener_constancia_medica(3, TENANT_ID)
        sql, params = query.call_args.args
        self.assertIn('cm.tenant_id=%s', sql)
        self.assertEqual(params[:2], (3, TENANT_ID))

    def test_correlativo_bloquea_y_filtra_por_tenant(self):
        with patch.object(cert, 'execute_query', return_value={'siguiente': 12}) as query:
            numero = cert.siguiente_numero_constancia(TENANT_ID)
        sql, params = query.call_args.args
        self.assertEqual(numero, 12)
        self.assertIn('FOR UPDATE', sql)
        self.assertIn('tenant_id=%s', sql)
        self.assertEqual(params, (TENANT_ID,))

    def test_insertar_genera_codigo_correlativo(self):
        user = SimpleNamespace(id=5, tenant_id=TENANT_ID)
        datos = {
            'paciente_id': 1, 'medico_id': 2, 'consulta_id': None,
            'fecha_atencion': date(2026, 11, 20), 'hora_entrada': None,
            'hora_salida': None, 'dirigida_a': 'A quien pueda interesar',
            'motivo': None,
        }
        with patch.object(cert, 'execute_query', return_value={'siguiente': 7}), \
                patch.object(cert, 'execute_update', return_value=40) as update, \
                patch.object(cert, 'current_user', user):
            constancia_id = cert.insertar_constancia_medica(TENANT_ID, datos)
        self.assertEqual(constancia_id, 40)
        params = update.call_args.args[1]
        self.assertEqual(params[:3], (TENANT_ID, 7, 'CM-000007'))

    def test_anular_actualiza_solo_dentro_del_tenant(self):
        user = SimpleNamespace(id=5, tenant_id=TENANT_ID)
        with app_module.app.test_request_context(
            '/facturacion/constancias-medicas/3/anular',
            method='POST', data={'motivo_anulacion': 'Error de fecha'},
        ), patch.object(cert, 'get_current_tenant_id', return_value=TENANT_ID), \
                patch.object(cert, 'medico_id_constancias_restringido', return_value=None), \
                patch.object(cert, 'execute_query', return_value=_fila_constancia()), \
                patch.object(cert, 'execute_update') as update, \
                patch.object(cert, 'current_user', user), \
                patch.object(cert, 'flash'):
            respuesta = _sin_decoradores(cert.facturacion_constancia_medica_anular)(3)
        self.assertEqual(respuesta.status_code, 302)
        sql, params = update.call_args.args
        self.assertIn("estado='Anulada'", sql)
        self.assertIn('tenant_id=%s', sql)
        self.assertEqual(params[-2:], (3, TENANT_ID))

    def test_anular_exige_motivo(self):
        with app_module.app.test_request_context(
            '/facturacion/constancias-medicas/3/anular', method='POST', data={},
        ), patch.object(cert, 'get_current_tenant_id', return_value=TENANT_ID), \
                patch.object(cert, 'medico_id_constancias_restringido', return_value=None), \
                patch.object(cert, 'execute_query', return_value=_fila_constancia()), \
                patch.object(cert, 'execute_update') as update, \
                patch.object(cert, 'flash'):
            _sin_decoradores(cert.facturacion_constancia_medica_anular)(3)
        update.assert_not_called()


class PermisosConstanciaTests(unittest.TestCase):
    def test_vistas_exigen_permiso_especifico(self):
        for endpoint, permiso in PERMISOS_ESPERADOS.items():
            with self.subTest(endpoint=endpoint):
                vista = app_module.app.view_functions[endpoint]
                self.assertEqual(getattr(vista, 'required_permission', None), permiso)

    def test_vistas_requieren_login(self):
        cliente = app_module.app.test_client()
        app_module.app.config.update(TESTING=True)
        for url in (
            '/facturacion/constancias-medicas',
            '/facturacion/constancias-medicas/nueva',
            '/facturacion/constancias-medicas/3',
            '/facturacion/constancias-medicas/3/editar',
            '/facturacion/constancias-medicas/3/imprimir',
        ):
            with self.subTest(url=url):
                respuesta = cliente.get(url)
                self.assertEqual(respuesta.status_code, 302)
                self.assertIn('login', respuesta.location)

    def test_anular_solo_acepta_post(self):
        reglas = [
            regla for regla in app_module.app.url_map.iter_rules()
            if regla.endpoint == 'facturacion_constancia_medica_anular'
        ]
        self.assertEqual(len(reglas), 1)
        self.assertEqual(reglas[0].methods - {'HEAD', 'OPTIONS'}, {'POST'})
        respuesta = app_module.app.test_client().get(
            '/facturacion/constancias-medicas/3/anular'
        )
        self.assertEqual(respuesta.status_code, 405)

    def test_escrituras_son_transaccionales(self):
        for endpoint in (
            'facturacion_constancias_medicas_nueva',
            'facturacion_constancia_medica_editar',
            'facturacion_constancia_medica_anular',
        ):
            with self.subTest(endpoint=endpoint):
                vista = app_module.app.view_functions[endpoint]
                while vista and not hasattr(vista, 'transactional_methods'):
                    vista = getattr(vista, '__wrapped__', None)
                self.assertIsNotNone(vista)
                self.assertEqual(vista.transactional_methods, frozenset({'POST'}))

    def test_roles_con_licencias_reciben_constancias(self):
        accion_equivalente = ('ver', 'crear', 'editar', 'anular', 'imprimir')
        for accion in accion_equivalente:
            self.assertIn(f'constancias.{accion}', TODOS_LOS_PERMISOS)
            for rol, permisos in PERMISOS_ROLES_SISTEMA.items():
                with self.subTest(rol=rol, accion=accion):
                    self.assertEqual(
                        f'constancias.{accion}' in permisos,
                        f'licencias.{accion}' in permisos,
                    )

    def test_emision_desde_consulta_requiere_permiso_y_casilla(self):
        sin_permiso = SimpleNamespace(id=1, tenant_id=TENANT_ID, has_permission=lambda c: False)
        con_permiso = SimpleNamespace(id=1, tenant_id=TENANT_ID, has_permission=lambda c: True)
        with app_module.app.test_request_context(
            '/', method='POST', data={'emitir_constancia': '1'},
        ), patch.object(cert, 'current_user', sin_permiso), \
                patch.object(cert, 'insertar_constancia_medica') as insertar:
            self.assertIsNone(cert.emitir_constancia_desde_consulta(
                TENANT_ID, 1, 2, 7, '2026-11-20', '08:00',
            ))
        insertar.assert_not_called()
        with app_module.app.test_request_context(
            '/', method='POST', data={},
        ), patch.object(cert, 'current_user', con_permiso), \
                patch.object(cert, 'insertar_constancia_medica') as insertar:
            self.assertIsNone(cert.emitir_constancia_desde_consulta(
                TENANT_ID, 1, 2, 7, '2026-11-20', '08:00',
            ))
        insertar.assert_not_called()

    def test_emision_desde_consulta_usa_fecha_y_hora_de_la_consulta(self):
        con_permiso = SimpleNamespace(id=1, tenant_id=TENANT_ID, has_permission=lambda c: True)
        with app_module.app.test_request_context(
            '/', method='POST',
            data={'emitir_constancia': '1', 'constancia_dirigida_a': 'Empresa ABC'},
        ), patch.object(cert, 'current_user', con_permiso), \
                patch.object(cert, 'medico_id_constancias_restringido', return_value=None), \
                patch.object(cert, 'execute_query', side_effect=lambda q, p=None, fetch='one': (
                    {'id': 7, 'paciente_id': 1} if 'consultas_clinicas' in q else {'id': 1}
                )), \
                patch.object(cert, 'insertar_constancia_medica', return_value=50) as insertar, \
                patch.object(cert, 'flash'):
            constancia_id = cert.emitir_constancia_desde_consulta(
                TENANT_ID, 1, 2, 7, '2026-11-20', '08:15',
            )
        self.assertEqual(constancia_id, 50)
        datos = insertar.call_args.args[1]
        self.assertEqual(datos['fecha_atencion'], date(2026, 11, 20))
        self.assertEqual(datos['hora_entrada'].strftime('%H:%M'), '08:15')
        self.assertEqual(datos['consulta_id'], 7)
        self.assertEqual(datos['dirigida_a'], 'Empresa ABC')


class RenderizadoConstanciaTests(unittest.TestCase):
    def setUp(self):
        self.user = app_module.User(
            5, 'Admin', 'admin@example.test', 'Administrador',
            tenant_id=TENANT_ID, permissions=set(),
            rbac_roles={'Administrador'}, rbac_role_count=1,
        )

    @contextmanager
    def _contexto(self, url, fila):
        with app_module.app.test_request_context(url), \
                patch('flask_login.utils._get_user', return_value=self.user), \
                patch.object(database_module, 'get_db_connection', return_value=_Conexion()), \
                patch.object(cert, 'get_current_tenant_id', return_value=TENANT_ID), \
                patch.object(cert, 'execute_query', return_value=fila), \
                patch.object(cert, 'get_empresa_info', return_value={'nombre': 'Centro Norte'}):
            yield

    def test_vista_de_impresion_renderiza(self):
        with self._contexto('/facturacion/constancias-medicas/3/imprimir', _fila_constancia()):
            html = cert.facturacion_constancia_medica_imprimir(3)
        self.assertIn('Constancia Médica', html)
        self.assertIn('CM-000003', html)
        self.assertIn('Colegio San Juan', html)
        self.assertIn('20/11/2026', html)
        self.assertIn('08:00', html)
        self.assertIn('09:30', html)
        self.assertIn('window.print', html)
        self.assertNotIn('cancelModal', html)

    def test_vista_detalle_renderiza_con_anulacion(self):
        with self._contexto('/facturacion/constancias-medicas/3', _fila_constancia()):
            html = cert.facturacion_constancia_medica_ver(3)
        self.assertIn('cancelModal', html)
        self.assertIn('data-confirm-submit', html)
        self.assertNotIn('window.print', html)

    def test_constancia_anulada_muestra_marca(self):
        fila = _fila_constancia(
            estado='Anulada', motivo_anulacion='Duplicada',
            fecha_anulacion=datetime(2026, 11, 21, 10, 0),
        )
        with self._contexto('/facturacion/constancias-medicas/3', fila):
            html = cert.facturacion_constancia_medica_ver(3)
        self.assertIn('ANULADA', html)
        self.assertIn('Duplicada', html)
        self.assertNotIn('cancelModal', html)

    def test_formulario_nuevo_renderiza(self):
        with self._contexto('/facturacion/constancias-medicas/nueva?paciente_id=1', []), \
                patch.object(cert, 'medico_id_constancias_restringido', return_value=None):
            html = cert.facturacion_constancias_medicas_nueva()
        self.assertIn('fecha_atencion', html)
        self.assertIn('dirigida_a', html)
        self.assertNotIn('name="diagnostico"', html)



class _CursorRegistro:
    def __init__(self, existentes=()):
        self.sentencias = []
        self.existentes = existentes

    def execute(self, sql, params=None):
        self.sentencias.append((sql, params))

    def fetchone(self):
        return {'1': 1}

    def fetchall(self):
        return [{'codigo': codigo} for codigo in self.existentes]


class EsquemaConstanciaTests(unittest.TestCase):
    def test_esquema_define_tabla_con_tenant_e_indices(self):
        import re
        from pathlib import Path

        esquema = (
            Path(app_module.__file__).resolve().parent / 'database_schema.sql'
        ).read_text(encoding='utf-8')
        match = re.search(
            r'CREATE TABLE IF NOT EXISTS constancias_medicas\s*\((.*?)\)\s*ENGINE=',
            esquema, re.DOTALL,
        )
        self.assertIsNotNone(match)
        cuerpo = match.group(1)
        self.assertRegex(cuerpo, r'(^|\s)tenant_id\s+INT NOT NULL')
        self.assertIn('UNIQUE KEY uq_constancia_codigo (tenant_id, codigo)', cuerpo)
        self.assertIn('(tenant_id, paciente_id)', cuerpo)
        self.assertIn('(tenant_id, fecha_atencion)', cuerpo)
        self.assertIn('REFERENCES empresas(id)', cuerpo)

    def test_arranque_crea_tabla_y_hereda_permisos_una_vez(self):
        import core.schema_bootstrap as bootstrap

        cursor = _CursorRegistro()
        bootstrap._asegurar_tablas_modulos(cursor)
        self.assertTrue(any(
            sql.startswith('CREATE TABLE IF NOT EXISTS constancias_medicas ')
            for sql, _params in cursor.sentencias
        ))

        cursor = _CursorRegistro()
        bootstrap._heredar_permisos_nuevos(cursor, 'db', set())
        herencias = [p for sql, p in cursor.sentencias if 'INSERT IGNORE' in sql]
        self.assertIn(('licencias.ver', 'constancias.ver'), herencias)
        self.assertEqual(
            len([h for h in herencias if h[1].startswith('constancias.')]), 5,
        )

        cursor = _CursorRegistro()
        bootstrap._heredar_permisos_nuevos(
            cursor, 'db', set(bootstrap.PERMISOS_HEREDADOS),
        )
        self.assertFalse(any('INSERT IGNORE' in sql for sql, _p in cursor.sentencias))

    def test_consulta_redirige_a_imprimir_constancia(self):
        import routes.clinical_history as clinical_history

        with app_module.app.test_request_context('/'):
            url = clinical_history.url_consulta_para_impresion(
                10, constancia_id=4,
            )
        self.assertIn('imprimir_constancia=4', url)


if __name__ == '__main__':
    unittest.main()
