import unittest
from types import SimpleNamespace
from unittest.mock import patch

import app as app_module
import routes.prescriptions as prescriptions


class PrescriptionMedicineNameTests(unittest.TestCase):
    def test_duplicate_names_ignore_case_and_spacing(self):
        self.assertEqual(
            prescriptions.clave_nombre_medicamento('  AmoxiCILINA  500  '),
            'amoxicilina 500',
        )

    def test_new_prescription_rejects_duplicate_medicines(self):
        handler = prescriptions.facturacion_recetas_medicas_nueva
        while hasattr(handler, '__wrapped__'):
            handler = handler.__wrapped__
        user = SimpleNamespace(id=3, tenant_id=9, is_authenticated=True)
        flashes = []

        def execute_query(query, params=None, fetch=None):
            if 'FROM pacientes' in query and 'ORDER BY' in query:
                return [{'id': 1, 'nombre': 'Ana', 'cedula': '', 'fecha_nacimiento': None}]
            if 'FROM medicos' in query and 'ORDER BY' in query:
                return [{'id': 2, 'nombre': 'Luis', 'especialidad': 'MG'}]
            if 'FROM consultas_clinicas' in query:
                return []
            if 'FROM pacientes WHERE id' in query:
                return {'id': 1}
            if 'FROM medicos WHERE id' in query:
                return {'id': 2}
            return None

        with app_module.app.test_request_context(
            '/facturacion/recetas/nueva',
            method='POST',
            data={
                'paciente_id': '1',
                'medico_id': '2',
                'fecha': '2026-09-23',
                'medicamento[]': ['Amoxicilina', ' amoxicilina '],
                'presentacion[]': ['Tabletas', 'Tabletas'],
                'dosis[]': ['1 tableta', '1 tableta'],
                'via[]': ['Oral', 'Oral'],
                'frecuencia[]': ['Cada 8 horas', 'Cada 8 horas'],
                'duracion[]': ['7 días', '7 días'],
                'cantidad[]': ['21', '21'],
                'indicaciones[]': ['', ''],
            },
        ), patch.object(
            prescriptions, 'current_user', user
        ), patch.object(
            prescriptions, 'get_current_tenant_id', return_value=9
        ), patch.object(
            prescriptions, 'medico_id_recetas_restringido', return_value=None
        ), patch.object(
            prescriptions, 'execute_query', side_effect=execute_query
        ), patch.object(
            prescriptions, 'execute_update'
        ) as execute_update, patch.object(
            prescriptions, 'flash', side_effect=lambda msg, cat=None: flashes.append(msg)
        ), patch.object(
            prescriptions, 'render_template', return_value='form'
        ):
            response = handler()

        self.assertEqual(response, 'form')
        execute_update.assert_not_called()
        self.assertTrue(
            any('ya está en la receta' in message for message in flashes)
        )
