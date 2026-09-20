"""Modelo de sesión de usuario."""

from flask_login import UserMixin

from rbac_catalog import PERMISOS_ROLES_SISTEMA

ALLOWED_UI_FONTS = frozenset({'arsflow', 'inter', 'manrope', 'jakarta'})


class User(UserMixin):
    def __init__(
        self, id, nombre, email, perfil, tema_color='cyan',
        fuente_ui='arsflow', tenant_id=1, empresa_nombre='',
        mostrar_chat=True, idioma_correccion='es',
        permissions=None, rbac_roles=None,
        rbac_role_count=0, medico_id=None,
    ):
        self.id = id
        self.nombre = nombre
        self.email = email
        self.perfil = perfil
        self.tema_color = tema_color or 'cyan'
        self.fuente_ui = (
            fuente_ui if fuente_ui in ALLOWED_UI_FONTS else 'arsflow'
        )
        self.tenant_id = tenant_id
        self.empresa_nombre = empresa_nombre
        self.mostrar_chat = bool(mostrar_chat)
        self.idioma_correccion = (
            idioma_correccion
            if idioma_correccion in {'es', 'en', 'fr', 'none'}
            else 'es'
        )
        self.permissions = frozenset(permissions or ())
        self.rbac_roles = tuple(rbac_roles or ())
        self.rbac_role_count = int(rbac_role_count or 0)
        self.medico_id = medico_id

    def has_permission(self, codigo):
        """Autorizar por RBAC con fallback para usuarios aún no migrados."""
        if self.tenant_id is None and self.perfil == 'Administrador':
            return True
        if 'Administrador' in (self.rbac_roles or ()):
            return True
        if self.rbac_role_count:
            return codigo in self.permissions
        return codigo in PERMISOS_ROLES_SISTEMA.get(self.perfil, frozenset())
