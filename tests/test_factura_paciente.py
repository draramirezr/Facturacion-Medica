"""Factura al paciente: validación, NCF y aislamiento por empresa."""

import unittest
from contextlib import nullcontext
from datetime import date
from decimal import Decimal as D
from unittest.mock import patch

import services.factura_paciente as fp

PACIENTE = {'id': 5, 'nombre': 'Ana Pérez', 'cedula': '00100000009', 'nss': '123'}


def _query_validacion(sql, params=None, fetch='one'):
    if 'FROM pacientes' in sql:
        return PACIENTE if params == (5, 12) else None
    if 'FROM medicos' in sql:
        return {'id': 7, 'nombre': 'Dra. Ruiz'} if params[1] == 12 else None
    if 'FROM servicios' in sql:
        return {'id': params[0]} if params[1] == 12 else None
    return None


FORM = {'paciente_id': '5', 'tipo_comprobante': 'B02', 'metodo_pago': 'Efectivo', 'monto_recibido': '2000'}
LINEAS = [
    {'descripcion': 'Diferencia consulta ARS Humano', 'cantidad': '1', 'precio': '500'},
    {'descripcion': 'Certificado', 'cantidad': '2', 'precio': '250.50'},
]


class ValidacionTests(unittest.TestCase):
    def _validar(self, form=None, lineas=None):
        with patch.object(fp, 'execute_query', side_effect=_query_validacion):
            return fp.validar_factura_paciente(12, form or FORM, LINEAS if lineas is None else lineas)

    def test_valida_y_calcula_total(self):
        datos = self._validar()
        self.assertEqual(datos['total'], D('1001.00'))
        self.assertEqual(datos['tipo_comprobante'], 'B02')
        self.assertEqual(len(datos['lineas']), 2)

    def test_paciente_de_otra_empresa_se_rechaza(self):
        with patch.object(fp, 'execute_query', side_effect=lambda s, p=None, fetch='one': None):
            with self.assertRaises(fp.FacturaPacienteError):
                fp.validar_factura_paciente(12, FORM, LINEAS)

    def test_b01_exige_rnc_y_razon_social(self):
        with self.assertRaises(fp.FacturaPacienteError) as ctx:
            self._validar(dict(FORM, tipo_comprobante='B01'))
        self.assertIn('B01', str(ctx.exception))
        datos = self._validar(dict(FORM, tipo_comprobante='B01', rnc_comprador='131-12345-6',
                                   razon_social_comprador='Empresa SRL'))
        self.assertEqual(datos['rnc_comprador'], '131123456')

    def test_precio_invalido_o_cero_se_rechaza(self):
        for precio in ('0', '-5', 'nan', 'abc'):
            with self.assertRaises(fp.FacturaPacienteError):
                self._validar(lineas=[{'descripcion': 'X', 'cantidad': 1, 'precio': precio}])

    def test_efectivo_insuficiente_se_rechaza(self):
        with self.assertRaises(fp.FacturaPacienteError) as ctx:
            self._validar(dict(FORM, monto_recibido='100'))
        self.assertIn('menor que el total', str(ctx.exception))

    def test_sin_lineas_se_rechaza(self):
        with self.assertRaises(fp.FacturaPacienteError):
            self._validar(lineas=[])


class EmisionTests(unittest.TestCase):
    def _emitir(self, secuencia, ncf_usado=False):
        consultas, escrituras = [], []

        def fake_query(sql, params=None, fetch='one'):
            consultas.append((sql, params))
            if 'FROM ncf' in sql:
                return secuencia
            if 'FROM facturas' in sql:
                return {'id': 1} if ncf_usado else None
            return None

        def fake_update(sql, params=None):
            escrituras.append((sql, params))
            return 99

        datos = {
            'paciente': PACIENTE, 'medico': None, 'tipo_comprobante': 'B02',
            'rnc_comprador': None, 'razon_social_comprador': None,
            'metodo_pago': 'Efectivo', 'referencia_pago': None,
            'monto_recibido': D('2000.00'), 'observaciones': None, 'total': D('1001.00'),
            'lineas': [{'descripcion': 'Diferencia', 'cantidad': 1,
                        'precio_unitario': D('1001.00'), 'subtotal': D('1001.00'), 'servicio_id': None}],
        }
        with patch.object(fp, 'execute_query', side_effect=fake_query), patch.object(
            fp, 'execute_update', side_effect=fake_update,
        ), patch.object(fp, 'database_transaction', return_value=nullcontext()):
            factura_id = fp.emitir_factura_paciente(12, datos, 3, hoy=date(2026, 11, 24))
        return factura_id, consultas, escrituras

    def test_reserva_ncf_bloqueando_la_secuencia(self):
        secuencia = {'id': 4, 'tipo': 'B02', 'prefijo': 'B02', 'ultimo_numero': 41,
                     'tamano_secuencia': 8, 'fecha_fin': date(2027, 12, 31)}
        factura_id, consultas, escrituras = self._emitir(secuencia)
        self.assertEqual(factura_id, 99)
        self.assertIn('FOR UPDATE', consultas[0][0])
        self.assertEqual(consultas[0][1], (12, 'B02'))
        insert = escrituras[0]
        self.assertIn('INSERT INTO facturas', insert[0])
        self.assertIn('B0200000042', insert[1])
        self.assertIn('PACIENTE', insert[1])
        self.assertIn("'Pagada'", insert[0])
        actualizacion = escrituras[-1]
        self.assertIn('UPDATE ncf', actualizacion[0])
        self.assertEqual(actualizacion[1], (42, 43, 4, 12))

    def test_secuencia_vencida_no_emite(self):
        secuencia = {'id': 4, 'tipo': 'B02', 'prefijo': 'B02', 'ultimo_numero': 1,
                     'tamano_secuencia': 8, 'fecha_fin': date(2026, 1, 1)}
        with self.assertRaises(fp.FacturaPacienteError) as ctx:
            self._emitir(secuencia)
        self.assertIn('venció', str(ctx.exception))

    def test_sin_secuencia_no_emite(self):
        with self.assertRaises(fp.FacturaPacienteError) as ctx:
            self._emitir(None)
        self.assertIn('No hay una secuencia B02', str(ctx.exception))

    def test_ncf_ya_usado_no_emite(self):
        secuencia = {'id': 4, 'tipo': 'B02', 'prefijo': 'B02', 'ultimo_numero': 1,
                     'tamano_secuencia': 8, 'fecha_fin': None}
        with self.assertRaises(fp.FacturaPacienteError):
            self._emitir(secuencia, ncf_usado=True)


class AnulacionTests(unittest.TestCase):
    def test_anular_exige_motivo_y_filtra_por_empresa(self):
        with self.assertRaises(fp.FacturaPacienteError):
            fp.anular_factura_paciente(12, 1, '  ', 3)
        consultas = []

        def fake_query(sql, params=None, fetch='one'):
            consultas.append((sql, params))
            return {'id': 1, 'estado': 'Pagada'}

        with patch.object(fp, 'execute_query', side_effect=fake_query), patch.object(
            fp, 'execute_update',
        ) as update, patch.object(fp, 'database_transaction', return_value=nullcontext()):
            fp.anular_factura_paciente(12, 1, 'Error en el monto', 3)
        self.assertEqual(consultas[0][1], (1, 12, 'PACIENTE'))
        self.assertIn("estado='Anulada'", update.call_args.args[0])


if __name__ == '__main__':
    unittest.main()
