"""Factura al paciente con seguro: el paciente paga la diferencia y lo que
cubre la ARS pasa a Estado de Facturación (pacientes_pendientes)."""

import unittest
from contextlib import nullcontext
from datetime import date
from decimal import Decimal as D
from unittest.mock import patch

import services.factura_paciente as fp

PACIENTE = {'id': 5, 'nombre': 'Ana Pérez', 'cedula': '00100000009', 'nss': ''}


def _query(sql, params=None, fetch='one'):
    if 'FROM pacientes' in sql:
        return PACIENTE if params == (5, 12) else None
    if 'FROM medicos' in sql:
        return {'id': 7, 'nombre': 'Dra. Ruiz'} if params[1] == 12 else None
    if 'FROM ars' in sql:
        return {'id': 3, 'nombre': 'ARS Humano'} if params == (3, 12) else None
    return None


BASE = {'paciente_id': '5', 'medico_id': '7', 'ars_id': '3', 'nss': '4659000001',
        'tipo_comprobante': 'B02', 'metodo_pago': 'Efectivo'}


def _validar(form=None, lineas=None):
    with patch.object(fp, 'execute_query', side_effect=_query):
        return fp.validar_factura_paciente(12, form or BASE, lineas)


class ValidacionSeguroTests(unittest.TestCase):
    def test_paciente_paga_solo_la_diferencia(self):
        datos = _validar(lineas=[
            {'descripcion': 'Consulta', 'seguro': '1', 'precio': '2000', 'cubre': '1600', 'autorizacion': 'ab-123'},
            {'descripcion': 'Certificado', 'seguro': '0', 'cantidad': '1', 'precio': '300'},
        ])
        self.assertEqual(datos['total'], D('700.00'))
        self.assertEqual(datos['consultas_ars'][0]['monto'], D('1600.00'))
        self.assertEqual(datos['consultas_ars'][0]['autorizacion'], 'AB-123')
        self.assertEqual(datos['lineas'][0]['subtotal'], D('400.00'))
        self.assertIn('Diferencia Consulta (Aut. AB-123)', datos['lineas'][0]['descripcion'])

    def test_seguro_cubre_todo_sin_cobro_ni_forma_de_pago(self):
        datos = _validar(dict(BASE, metodo_pago=''), [
            {'descripcion': 'Consulta', 'seguro': '1', 'precio': '1600', 'cubre': '1600', 'autorizacion': 'A1'},
        ])
        self.assertEqual(datos['total'], D('0.00'))
        self.assertEqual(datos['lineas'], [])
        self.assertEqual(len(datos['consultas_ars']), 1)

    def test_autorizacion_obligatoria_y_sin_repetir(self):
        with self.assertRaises(fp.FacturaPacienteError) as ctx:
            _validar(lineas=[{'descripcion': 'C', 'seguro': '1', 'precio': '100', 'cubre': '50'}])
        self.assertIn('autorización', str(ctx.exception))
        with self.assertRaises(fp.FacturaPacienteError) as ctx:
            _validar(lineas=[
                {'descripcion': 'C', 'seguro': '1', 'precio': '100', 'cubre': '50', 'autorizacion': 'X1'},
                {'descripcion': 'D', 'seguro': '1', 'precio': '100', 'cubre': '50', 'autorizacion': 'x1'},
            ])
        self.assertIn('repetida', str(ctx.exception))

    def test_cubre_no_puede_superar_el_monto(self):
        with self.assertRaises(fp.FacturaPacienteError):
            _validar(lineas=[{'descripcion': 'C', 'seguro': '1', 'precio': '100', 'cubre': '150', 'autorizacion': 'A'}])

    def test_seguro_exige_ars_nss_y_medico(self):
        linea = [{'descripcion': 'C', 'seguro': '1', 'precio': '100', 'cubre': '50', 'autorizacion': 'A'}]
        for faltante, texto in (('ars_id', 'ARS'), ('nss', 'NSS'), ('medico_id', 'médico')):
            with self.assertRaises(fp.FacturaPacienteError) as ctx:
                _validar(dict(BASE, **{faltante: ''}), linea)
            self.assertIn(texto, str(ctx.exception))

    def test_ars_de_otra_empresa_se_rechaza(self):
        with self.assertRaises(fp.FacturaPacienteError):
            _validar(dict(BASE, ars_id='99'),
                     [{'descripcion': 'C', 'seguro': '1', 'precio': '100', 'cubre': '50', 'autorizacion': 'A'}])


class RegistroAtencionTests(unittest.TestCase):
    def _registrar(self, datos, autorizaciones_usadas=()):
        consultas, escrituras = [], []

        def fake_query(sql, params=None, fetch='one'):
            consultas.append((sql, params))
            if 'FROM pacientes_pendientes' in sql:
                return [{'servicios_realizados': f'Consulta - Autorización: {a}'} for a in autorizaciones_usadas]
            if 'SELECT ncf FROM facturas' in sql:
                return {'ncf': 'B0200000042'}
            return None

        def fake_update(sql, params=None):
            escrituras.append((sql, params))
            return 1

        with patch.object(fp, 'execute_query', side_effect=fake_query), \
                patch.object(fp, 'execute_update', side_effect=fake_update), \
                patch.object(fp, 'database_transaction', return_value=nullcontext()), \
                patch.object(fp, 'emitir_factura_paciente', return_value=99) as emitir:
            resultado = fp.registrar_atencion(12, datos, 3, hoy=date(2026, 11, 26))
        return resultado, consultas, escrituras, emitir

    def _datos(self, total, diferencia):
        return {
            'paciente': PACIENTE, 'medico': {'id': 7, 'nombre': 'Dra. Ruiz'},
            'ars': {'id': 3, 'nombre': 'ARS Humano'}, 'nss': '4659000001',
            'total': D(total), 'lineas': [],
            'consultas_ars': [{'servicio': 'Consulta', 'autorizacion': 'AB-1',
                               'monto': D('1600.00'), 'diferencia': D(diferencia)}],
        }

    def test_envia_lo_del_seguro_a_estado_de_facturacion(self):
        (factura_id, enviadas), consultas, escrituras, emitir = self._registrar(self._datos('400.00', '400.00'))
        self.assertEqual((factura_id, enviadas), (99, 1))
        emitir.assert_called_once()
        insert = [e for e in escrituras if 'INSERT INTO pacientes_pendientes' in e[0]][0]
        params = insert[1]
        self.assertEqual(params[0], 12)
        self.assertIn('Consulta - Autorización: AB-1', params)
        self.assertIn(D('1600.00'), params)
        self.assertIn('factura B0200000042', params[-2])
        # La búsqueda de autorizaciones repetidas es por empresa y ARS, con bloqueo.
        busqueda = [c for c in consultas if 'FROM pacientes_pendientes' in c[0]][0]
        self.assertIn('FOR UPDATE', busqueda[0])
        self.assertEqual(busqueda[1][:2], (12, 3))

    def test_sin_diferencia_no_emite_factura_ni_gasta_ncf(self):
        (factura_id, enviadas), _c, escrituras, emitir = self._registrar(self._datos('0.00', '0.00'))
        self.assertIsNone(factura_id)
        self.assertEqual(enviadas, 1)
        emitir.assert_not_called()
        self.assertTrue(any('INSERT INTO pacientes_pendientes' in e[0] for e in escrituras))

    def test_autorizacion_ya_registrada_no_guarda_nada(self):
        with self.assertRaises(fp.FacturaPacienteError) as ctx:
            self._registrar(self._datos('400.00', '400.00'), autorizaciones_usadas=('AB-1',))
        self.assertIn('AB-1', str(ctx.exception))


if __name__ == '__main__':
    unittest.main()
