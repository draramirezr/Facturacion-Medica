"""Fachada WSGI de ClinicRD.

La lógica vive en sus paquetes propietarios. Este módulo crea la aplicación,
registra sus rutas y conserva únicamente las exportaciones de compatibilidad
que siguen usando pruebas y utilidades externas.
"""

import os

from flask import Flask

from auth import User, load_user, permission_required, roles_required, user_has_permission
from auth.routes import register_auth_routes
from core.config import (
    DATABASE_CONFIG,
    ENVIRONMENT,
    IS_PRODUCTION,
    REQUIRED_TENANT_TABLES,
    configure_app,
    validate_production_startup,
    validate_required_tenant_schema,
)
from core.database import (
    database_transaction,
    execute_query,
    execute_update,
    init_database,
    transactional_methods,
)
from core.errors import init_error_handlers
from core.extensions import init_extensions, login_manager
from core.presentation import init_presentation
from core.security import (
    init_security,
    request_counts,
)
from core.tenant import (
    ALLOWED_TABLES as _ALLOWED_TABLES,
    validate_tenant_access,
)
from routes import register_operation_routes
from routes.admin_companies import register_admin_company_routes
from routes.public import register_public_routes
from routes.search import register_search_routes
from services.notifications import init_notifications


def create_app():
    flask_app = Flask(__name__)
    configure(flask_app)
    return flask_app


def configure(flask_app):
    configure_app(flask_app)
    init_extensions(flask_app)
    init_database(flask_app)
    init_security(flask_app)
    init_error_handlers(flask_app)
    init_presentation(flask_app)
    init_notifications(flask_app)
    login_manager.user_loader(load_user)
    register_public_routes(flask_app)
    register_auth_routes(flask_app)
    register_admin_company_routes(flask_app)
    register_search_routes(flask_app)
    register_operation_routes(flask_app)


app = create_app()

if IS_PRODUCTION:
    validate_production_startup()


__all__ = [
    'app',
    'create_app',
    'User',
    'permission_required',
    'roles_required',
    'user_has_permission',
    'DATABASE_CONFIG',
    'REQUIRED_TENANT_TABLES',
    'validate_required_tenant_schema',
    'execute_query',
    'execute_update',
    'database_transaction',
    'transactional_methods',
    'validate_tenant_access',
    'request_counts',
    '_ALLOWED_TABLES',
]


if __name__ == '__main__':
    if IS_PRODUCTION:
        raise RuntimeError(
            'No uses el servidor de desarrollo en producción. '
            'Inicia la aplicación con Waitress u otro servidor WSGI.'
        )
    app.run(
        host=os.getenv('HOST', '127.0.0.1'),
        port=int(os.getenv('PORT', 5000)),
        debug=ENVIRONMENT == 'development',
    )
