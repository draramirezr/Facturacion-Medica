"""Un centro de salud siempre usa el plan Centro médico."""

import unittest
from unittest.mock import patch

from services.plan_features import (
    error_plan_para_tipo,
    plan_requerido_para_tipo,
    planes_permitidos_para_tipo,
)


class PlanPorTipoTests(unittest.TestCase):
    def test_centro_salud_exige_centro_medico(self):
        self.assertEqual(plan_requerido_para_tipo('centro_salud'), 'empresarial')
        for plan in ('basico', 'profesional'):
            self.assertTrue(error_plan_para_tipo('centro_salud', plan))
        self.assertIsNone(error_plan_para_tipo('centro_salud', 'empresarial'))

    def test_medico_puede_cualquier_plan(self):
        for plan in ('basico', 'profesional', 'empresarial'):
            self.assertIsNone(error_plan_para_tipo('medico', plan))

    def test_planes_permitidos(self):
        todos = ['basico', 'profesional', 'empresarial']
        self.assertEqual(planes_permitidos_para_tipo('centro_salud', todos), ['empresarial'])
        self.assertEqual(planes_permitidos_para_tipo('medico', todos), todos)
        self.assertEqual(planes_permitidos_para_tipo('centro_salud', ['profesional']), [])

    def test_demo_de_centro_nace_con_plan_centro_medico(self):
        import services.platform as platform

        with patch.object(platform, 'execute_update', return_value=9) as update:
            platform._crear_empresa_demo('Centro X', 'c@x.com', '8095550000', 'centro_salud')
        params = update.call_args.args[1]
        self.assertIn('empresarial', params)
        self.assertIn(5, params)

    def test_demo_de_medico_sigue_en_basico(self):
        import services.platform as platform

        with patch.object(platform, 'execute_update', return_value=9) as update:
            platform._crear_empresa_demo('Dr X', 'd@x.com', '8095550000', 'medico')
        self.assertIn('basico', update.call_args.args[1])

    def test_mejora_de_plan_de_centro_a_consultorio_se_rechaza(self):
        import services.plan_upgrades as upgrades

        empresa = {'id': 3, 'plan': 'basico', 'es_demo': 0, 'estado': 'activo',
                   'tipo_empresa': 'centro_salud'}
        with patch.object(upgrades, 'asegurar_tabla_upgrades'), patch.object(
            upgrades, 'execute_query', return_value=empresa,
        ), patch.object(upgrades, 'execute_update') as update:
            ok, mensaje, _ = upgrades.solicitar_upgrade_plan(3, 'profesional')
        self.assertFalse(ok)
        self.assertIn('Centro médico', mensaje)
        update.assert_not_called()


if __name__ == '__main__':
    unittest.main()
