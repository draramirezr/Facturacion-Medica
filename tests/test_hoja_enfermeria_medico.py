"""La hoja de enfermería exige el médico que atendió, de la misma empresa."""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

import app as app_module
import routes.nursing as nursing

FORM = {
    'paciente_id': '5', 'fecha_servicio': '2026-11-24', 'hora_servicio': '10:30',
    'responsable': 'María', 'telefono_responsable': '8095551234',
    'firma_responsable': 'María', 'detalle[]': 'Suero', 'fecha_linea[]': '2026-11-24',
    'hora_linea[]': '10:30', 'cantidad[]': '1', 'dosis_via[]': 'IV',
}


class HojaEnfermeriaMedicoTests(unittest.TestCase):
    def _guardar(self, form, medico_valido=True):
        def fake_query(sql, params=None, fetch='one'):
            if 'FROM medicos' in sql and 'WHERE id=%s' in sql:
                return {'id': 7, 'nombre': 'Dra. Ruiz'} if medico_valido and params == (7, 12) else None
            if 'FROM pacientes p' in sql and fetch == 'one':
                return {'id': 5, 'nombre': 'Ana', 'fecha_nacimiento': None, 'sexo': 'F',
                        'direccion': '', 'ars_nombre': None}
            return [] if fetch == 'all' else None

        handler = nursing.facturacion_hojas_enfermeria_nueva
        while hasattr(handler, '__wrapped__'):
            handler = handler.__wrapped__
        with app_module.app.test_request_context('/facturacion/hojas-enfermeria/nueva', method='POST', data=form), \
                patch.object(nursing, 'get_current_tenant_id', return_value=12), \
                patch.object(nursing, 'current_user', SimpleNamespace(id=3, medico_id=None)), \
                patch.object(nursing, 'execute_query', side_effect=fake_query), \
                patch.object(nursing, 'execute_update', return_value=44) as update, \
                patch.object(nursing, 'render_template', return_value='form'), \
                patch.object(nursing, 'flash'), \
                patch('services.catalogos_ars.sembrar_ars_tenant'):
            handler()
        return update

    def test_sin_medico_no_guarda(self):
        self._guardar(FORM).assert_not_called()

    def test_medico_de_otra_empresa_no_guarda(self):
        self._guardar(dict(FORM, medico_id='7'), medico_valido=False).assert_not_called()

    def test_guarda_medico_que_atendio(self):
        update = self._guardar(dict(FORM, medico_id='7'))
        sql, params = update.call_args.args
        self.assertIn('nombre_medico', sql)
        self.assertEqual(params[-2:], (7, 'Dra. Ruiz'))


if __name__ == '__main__':
    unittest.main()
