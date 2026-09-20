import hashlib
import json
import unittest
from unittest.mock import patch

import app as app_module
import auth.decorators as auth_decorators
from rbac_catalog import PERMISOS_ROLES_SISTEMA


SYSTEM_ROLES = (
    'Administrador',
    'Nivel 2',
    'Registro de Facturas',
    'Oficial de servicios',
    'Médico',
)

# Snapshot deliberadamente ordenado por permiso para que cada cambio de política
# sea visible y revisable. Los permisos provienen del catálogo estable de RBAC.
REPRESENTATIVE_ACCESS = {
    'dashboard.ver': frozenset({
        'Administrador', 'Nivel 2', 'Registro de Facturas', 'Médico',
    }),
    'pacientes.ver': frozenset(SYSTEM_ROLES),
    'pacientes.crear': frozenset({
        'Administrador', 'Nivel 2', 'Registro de Facturas',
        'Oficial de servicios', 'Médico',
    }),
    'pacientes.editar': frozenset({
        'Administrador', 'Nivel 2', 'Registro de Facturas',
        'Oficial de servicios', 'Médico',
    }),
    'pacientes.eliminar': frozenset({'Administrador'}),
    'facturacion.ver': frozenset({
        'Administrador', 'Nivel 2', 'Registro de Facturas',
    }),
    'facturacion.crear': frozenset({
        'Administrador', 'Nivel 2', 'Registro de Facturas',
    }),
    'facturacion.anular': frozenset({'Administrador'}),
    'turnos.ver': frozenset({
        'Administrador', 'Nivel 2', 'Oficial de servicios', 'Médico',
    }),
    'turnos.crear': frozenset({
        'Administrador', 'Nivel 2', 'Oficial de servicios',
    }),
    'turnos.administrar': frozenset({
        'Administrador', 'Nivel 2', 'Oficial de servicios',
    }),
    'turnos.cola_propia': frozenset({
        'Administrador', 'Nivel 2', 'Médico',
    }),
    'historia_clinica.ver': frozenset({
        'Administrador', 'Nivel 2', 'Médico',
    }),
    'historia_clinica.crear': frozenset({
        'Administrador', 'Nivel 2', 'Médico',
    }),
    'citas.ver': frozenset({
        'Administrador', 'Nivel 2', 'Oficial de servicios', 'Médico',
    }),
    'citas.crear': frozenset({
        'Administrador', 'Nivel 2', 'Oficial de servicios', 'Médico',
    }),
    'citas.cancelar': frozenset({
        'Administrador', 'Nivel 2', 'Oficial de servicios',
    }),
    'usuarios.ver': frozenset({'Administrador'}),
    'roles.editar': frozenset({'Administrador'}),
    'configuracion.ver': frozenset({
        'Administrador', 'Nivel 2', 'Registro de Facturas',
        'Oficial de servicios',
    }),
    'configuracion.editar': frozenset({
        'Administrador', 'Nivel 2', 'Registro de Facturas',
        'Oficial de servicios',
    }),
}

# Contrato normalizado de las rutas de aplicación (se excluye la ruta
# ``static`` que Flask agrega). El hash incluye endpoint, URL y métodos.
ENDPOINT_CONTRACT_COUNT = 170
ENDPOINT_CONTRACT_SHA256 = (
    '2ac23bbc10ac0a52c5aa7d4743bb4b171e02f3759109c6b2a0a8aa3548733481'
)

# Subconjunto legible que hace accionables las pérdidas en las áreas críticas.
IMPORTANT_ENDPOINTS = {
    ('activar_cuenta', '/activar-cuenta/<token>', ('GET',)),
    ('facturacion_pacientes', '/facturacion/pacientes', ('GET',)),
    (
        'facturacion_pacientes_nuevo',
        '/facturacion/pacientes/nuevo',
        ('GET', 'POST'),
    ),
    (
        'facturacion_pacientes_editar',
        '/facturacion/pacientes/<int:paciente_id>/editar',
        ('GET', 'POST'),
    ),
    (
        'facturacion_pacientes_eliminar',
        '/facturacion/pacientes/<int:paciente_id>/eliminar',
        ('POST',),
    ),
    (
        'facturacion_facturas_nueva',
        '/facturacion/facturas/nueva',
        ('GET', 'POST'),
    ),
    (
        'facturacion_ver_factura',
        '/facturacion/facturas/<int:factura_id>/ver',
        ('GET',),
    ),
    ('turnos_recepcion', '/turnos', ('GET',)),
    ('turnos_nuevo', '/turnos/nuevo', ('POST',)),
    (
        'turnos_accion',
        '/turnos/<int:turno_id>/accion',
        ('POST',),
    ),
    ('turnos_mi_cola', '/turnos/mi-cola', ('GET',)),
    (
        'facturacion_historia_clinica',
        '/facturacion/historia-clinica',
        ('GET',),
    ),
    (
        'facturacion_historia_clinica_nueva',
        '/facturacion/historia-clinica/paciente/<int:paciente_id>/nueva',
        ('GET', 'POST'),
    ),
    ('facturacion_citas', '/facturacion/citas', ('GET',)),
    (
        'facturacion_citas_nueva',
        '/facturacion/citas/nueva',
        ('GET', 'POST'),
    ),
    ('admin_usuarios', '/admin/usuarios', ('GET',)),
    ('admin_roles', '/admin/roles', ('GET',)),
    (
        'perfil_configuracion',
        '/perfil/configuracion',
        ('GET', 'POST'),
    ),
    (
        'cambiar_mi_password',
        '/mi-cuenta/cambiar-password',
        ('GET', 'POST'),
    ),
    ('api_buscar_pacientes', '/api/pacientes/buscar', ('GET',)),
}


def normalized_endpoint_contract():
    """Representar las rutas como un conjunto estable, independiente del orden."""
    return {
        (
            rule.endpoint,
            rule.rule,
            tuple(sorted(rule.methods - {'HEAD', 'OPTIONS'})),
        )
        for rule in app_module.app.url_map.iter_rules()
        if rule.endpoint != 'static'
    }


class EndpointContractTests(unittest.TestCase):
    def test_complete_endpoint_contract_snapshot(self):
        contract = normalized_endpoint_contract()
        canonical = sorted(contract)
        payload = json.dumps(
            canonical,
            ensure_ascii=False,
            separators=(',', ':'),
        )

        self.assertEqual(len(contract), ENDPOINT_CONTRACT_COUNT)
        self.assertEqual(
            hashlib.sha256(payload.encode('utf-8')).hexdigest(),
            ENDPOINT_CONTRACT_SHA256,
        )

    def test_important_endpoint_signatures_remain_available(self):
        contract = normalized_endpoint_contract()
        self.assertEqual(IMPORTANT_ENDPOINTS - contract, set())


class SystemRoleAuthorizationMatrixTests(unittest.TestCase):
    def test_matrix_matches_the_stable_rbac_catalog(self):
        self.assertEqual(tuple(PERMISOS_ROLES_SISTEMA), SYSTEM_ROLES)

        for permission, expected_roles in REPRESENTATIVE_ACCESS.items():
            with self.subTest(permission=permission):
                actual_roles = frozenset(
                    role
                    for role, permissions in PERMISOS_ROLES_SISTEMA.items()
                    if permission in permissions
                )
                self.assertEqual(actual_roles, expected_roles)

    def test_permission_guard_enforces_every_matrix_cell(self):
        sentinel = object()

        for permission, allowed_roles in REPRESENTATIVE_ACCESS.items():
            protected_view = app_module.permission_required(permission)(
                lambda: sentinel
            )
            for index, role in enumerate(SYSTEM_ROLES, start=1):
                user = app_module.User(
                    index,
                    role,
                    f'role-{index}@example.test',
                    role,
                    permissions=PERMISOS_ROLES_SISTEMA[role],
                    rbac_roles={role},
                    rbac_role_count=1,
                )
                with self.subTest(permission=permission, role=role):
                    with app_module.app.test_request_context(
                        '/authorization-probe'
                    ):
                        with patch.object(
                            auth_decorators,
                            'current_user',
                            user,
                        ):
                            result = protected_view()

                    if role in allowed_roles:
                        self.assertIs(result, sentinel)
                    else:
                        self.assertEqual(result.status_code, 302)


if __name__ == '__main__':
    unittest.main()
