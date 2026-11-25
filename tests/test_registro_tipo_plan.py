"""Un centro de salud no puede registrarse con el plan Independiente."""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

import app as app_module
import auth.routes as auth_routes


class _PasoValidaciones(Exception):
    """Se lanza al llegar a la creación de tablas: las validaciones pasaron."""


class RegistroTipoPlanTests(unittest.TestCase):
    def _registrar(self, tipo, plan):
        handler = auth_routes.registro
        while hasattr(handler, '__wrapped__'):
            handler = handler.__wrapped__
        with app_module.app.test_request_context(
            '/registro',
            method='POST',
            data={
                'nombre_empresa': 'Centro Prueba',
                'tipo_empresa': tipo,
                'plan': plan,
                'nombre': 'Usuario Prueba',
                'email': 'centro@example.com',
                'telefono': '8095551234',
                'password': 'Segura123!',
                'password_confirm': 'Segura123!',
            },
        ), patch.object(
            auth_routes, 'current_user', SimpleNamespace(is_authenticated=False),
        ), patch.object(auth_routes, 'flash') as flash, patch.object(
            auth_routes, 'render_template', return_value='form',
        ), patch.object(auth_routes, 'execute_query', return_value=None), patch.object(
            auth_routes, 'execute_update',
        ) as update, patch.object(
            auth_routes, 'asegurar_tablas_plataforma', side_effect=_PasoValidaciones,
        ):
            try:
                handler()
                paso = False
            except _PasoValidaciones:
                paso = True
        return flash, update, paso

    def test_centro_salud_con_plan_independiente_se_rechaza(self):
        flash, update, paso = self._registrar('centro_salud', 'basico')
        self.assertFalse(paso)
        update.assert_not_called()
        self.assertIn('Independiente', flash.call_args.args[0])

    def test_medico_con_plan_independiente_sigue_permitido(self):
        _flash, _update, paso = self._registrar('medico', 'basico')
        self.assertTrue(paso)


if __name__ == '__main__':
    unittest.main()
