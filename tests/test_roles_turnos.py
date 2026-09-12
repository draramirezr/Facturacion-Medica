import unittest
from unittest.mock import patch

import app as app_module
import routes.turnos_screens as turnos_routes
from rbac_catalog import PERMISOS_ROLES_SISTEMA, TODOS_LOS_PERMISOS
from turnos import EstadoTurno, transicion_permitida, validar_transicion


class RbacCatalogTests(unittest.TestCase):
    def test_system_roles_reference_only_known_permissions(self):
        for permissions in PERMISOS_ROLES_SISTEMA.values():
            self.assertTrue(set(permissions).issubset(TODOS_LOS_PERMISOS))

    def test_user_prefers_assigned_rbac_permissions(self):
        user = app_module.User(
            7,
            'Prueba',
            'prueba@example.com',
            'Administrador',
            permissions={'pacientes.ver'},
            rbac_roles={'Rol limitado'},
            rbac_role_count=1,
        )
        self.assertTrue(user.has_permission('pacientes.ver'))
        self.assertFalse(user.has_permission('roles.editar'))

    def test_legacy_user_keeps_profile_permissions_until_migrated(self):
        user = app_module.User(
            8,
            'Legacy',
            'legacy@example.com',
            'Administrador',
        )
        self.assertTrue(user.has_permission('roles.editar'))


class QueueDomainTests(unittest.TestCase):
    def test_expected_transitions(self):
        self.assertTrue(transicion_permitida('EnEspera', 'Llamado'))
        self.assertTrue(transicion_permitida('Llamado', 'EnConsulta'))
        self.assertTrue(transicion_permitida('EnConsulta', 'Atendido'))
        self.assertTrue(transicion_permitida('NoPresente', 'EnEspera'))

    def test_skipping_call_is_rejected(self):
        with self.assertRaises(ValueError):
            validar_transicion('EnEspera', 'EnConsulta')

    def test_terminal_turn_cannot_restart(self):
        for status in (EstadoTurno.Atendido, EstadoTurno.Anulado):
            with self.assertRaises(ValueError):
                validar_transicion(status, EstadoTurno.EnEspera)

    def test_doctor_cannot_open_reception_queue_directly(self):
        doctor = app_module.User(
            10,
            'Doctora',
            'doctora@example.com',
            'Registro de Facturas',
            permissions=PERMISOS_ROLES_SISTEMA['Médico'],
            rbac_roles={'Médico'},
            rbac_role_count=1,
            medico_id=22,
        )
        handler = turnos_routes.turnos_recepcion.__wrapped__.__wrapped__
        with app_module.app.test_request_context('/turnos'):
            with patch.object(turnos_routes, 'current_user', doctor):
                response = handler()
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith('/turnos/mi-cola'))


class PublicDisplayTests(unittest.TestCase):
    def setUp(self):
        app_module.app.config.update(TESTING=True)
        self.client = app_module.app.test_client()

    @patch('routes.turnos_screens.execute_query')
    @patch('routes.turnos_screens.resolver_pantalla_por_token')
    def test_feed_never_exposes_patient_data(self, resolve_screen, query):
        resolve_screen.return_value = {'tenant_id': 9, 'medico_id': None}
        query.return_value = [
            {
                'numero': 12,
                'estado': 'Llamado',
                'posicion': 1,
                'medico': 'Dra. Rivera',
                'especialidad': 'Cardiología',
            },
            {
                'numero': 13,
                'estado': 'EnEspera',
                'posicion': 2,
                'medico': 'Dra. Rivera',
                'especialidad': 'Cardiología',
            },
        ]
        response = self.client.get('/api/sala/token-de-prueba')
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload['colas'][0]['actual'], '012')
        self.assertEqual(payload['colas'][0]['siguiente'], '013')
        self.assertNotIn('paciente', response.get_data(as_text=True).lower())
        self.assertEqual(query.call_args.args[1], [9])

    @patch('routes.turnos_screens.resolver_pantalla_por_token', return_value=None)
    def test_revoked_token_returns_not_found(self, _resolve_screen):
        response = self.client.get('/api/sala/revocado')
        self.assertEqual(response.status_code, 404)


if __name__ == '__main__':
    unittest.main()
