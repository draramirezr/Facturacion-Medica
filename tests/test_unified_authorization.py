import unittest

import app as app_module


class UnifiedAuthorizationTests(unittest.TestCase):
    def test_routes_expose_action_specific_permissions(self):
        expected = {
            'facturacion_pacientes': 'pacientes.ver',
            'facturacion_pacientes_nuevo': 'pacientes.crear',
            'facturacion_pacientes_editar': 'pacientes.editar',
            'facturacion_pacientes_eliminar': 'pacientes.eliminar',
            'facturacion_ars': 'catalogos.ver',
            'facturacion_ars_nuevo': 'catalogos.crear',
            'facturacion_ars_editar': 'catalogos.editar',
            'facturacion_ars_eliminar': 'catalogos.eliminar',
            'facturacion_historia_clinica': 'historia_clinica.ver',
            'facturacion_historia_clinica_nueva': 'historia_clinica.crear',
            'facturacion_historia_clinica_editar': 'historia_clinica.editar',
            'facturacion_citas': 'citas.ver',
            'facturacion_citas_nueva': 'citas.crear',
            'facturacion_citas_qr': 'citas.crear',
            'facturacion_citas_qr_imagen': 'citas.crear',
            'facturacion_cita_editar': 'citas.editar',
            'facturacion_cita_estado': 'citas.editar',
            'turnos_mi_cola': 'turnos.cola_propia',
            'turnos_mi_cola_estado': 'turnos.cola_propia',
            'facturacion_recetas_medicas': 'recetas.ver',
            'facturacion_recetas_medicas_nueva': 'recetas.crear',
            'facturacion_receta_medica_anular': 'recetas.anular',
            'facturacion_licencias_medicas': 'licencias.ver',
            'facturacion_licencias_medicas_nueva': 'licencias.crear',
            'facturacion_licencia_medica_editar': 'licencias.editar',
            'facturacion_licencia_medica_anular': 'licencias.anular',
            'facturacion_historico': 'facturacion.ver',
            'facturacion_generar_final': 'facturacion.crear',
            'facturacion_editar_factura': 'facturacion.editar',
            'facturacion_reclamacion_editar': 'facturacion.editar',
            'facturacion_pago_editar': 'facturacion.editar',
            'facturacion_descargar_pdf': 'facturacion.imprimir',
            'perfil_descargar_backup': 'configuracion.backup',
            'facturacion_historia_vincular_documento': 'historia_clinica.ver',
        }

        for endpoint, permission in expected.items():
            with self.subTest(endpoint=endpoint):
                view = app_module.app.view_functions[endpoint]
                self.assertEqual(
                    getattr(view, 'required_permission', None),
                    permission,
                )

    def test_rbac_user_does_not_inherit_legacy_profile_permissions(self):
        user = app_module.User(
            1,
            'Usuario limitado',
            'limitado@example.test',
            'Administrador',
            permissions={'pacientes.ver'},
            rbac_roles={'Rol limitado'},
            rbac_role_count=1,
        )

        self.assertTrue(user.has_permission('pacientes.ver'))
        self.assertFalse(user.has_permission('pacientes.eliminar'))


if __name__ == '__main__':
    unittest.main()
