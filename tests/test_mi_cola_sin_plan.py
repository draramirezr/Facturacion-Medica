"""Un médico sin plan Centro médico no debe quedar en un bucle de redirecciones."""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

import auth.helpers as helpers


def _medico():
    return SimpleNamespace(
        tenant_id=7,
        medico_id=3,
        perfil='Registro de Facturas',
        rbac_roles={'Médico'},
        has_permission=lambda codigo: codigo == 'turnos.cola_propia',
    )


class MiColaSegunPlanTests(unittest.TestCase):
    def test_medico_sin_plan_centro_no_va_a_mi_cola(self):
        with patch(
            'services.plan_features.tenant_plan_centro_medico',
            return_value=False,
        ):
            self.assertFalse(helpers.usuario_usa_mi_cola(_medico()))

    def test_medico_con_plan_centro_va_a_mi_cola(self):
        with patch(
            'services.plan_features.tenant_plan_centro_medico',
            return_value=True,
        ):
            self.assertTrue(helpers.usuario_usa_mi_cola(_medico()))

    def test_menu_no_redirige_a_mi_cola_sin_plan(self):
        import app as app_module
        import routes.billing_common as billing_common

        handler = billing_common.facturacion_menu
        while hasattr(handler, '__wrapped__'):
            handler = handler.__wrapped__
        with app_module.app.test_request_context('/facturacion'), patch.object(
            billing_common, 'current_user', _medico(),
        ), patch.object(
            billing_common, 'usuario_es_dueno_software', return_value=False,
        ), patch(
            'services.plan_features.tenant_plan_centro_medico',
            return_value=False,
        ), patch.object(
            billing_common, 'render_template', return_value='menu',
        ):
            self.assertEqual(handler(), 'menu')


if __name__ == '__main__':
    unittest.main()
