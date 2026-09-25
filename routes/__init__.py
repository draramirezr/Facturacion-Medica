"""Registro de rutas extra?das de la aplicaci?n monol?tica."""

from routes.appointments import register_appointment_routes
from routes.cita_qr import register_cita_qr_routes
from routes.billing import register_billing_routes
from routes.catalogs import register_catalog_routes
from routes.clinical_history import register_clinical_history_routes
from routes.emergency import register_emergency_routes
from routes.licenses import register_license_routes
from routes.messaging import register_messaging_routes
from routes.nursing import register_nursing_routes
from routes.patients import register_patient_routes
from routes.prescriptions import register_prescription_routes
from routes.turnos_screens import register_turnos_routes
from routes.users_roles import register_user_role_routes


def register_operation_routes(app):
    register_billing_routes(app)
    register_catalog_routes(app)
    register_patient_routes(app)
    register_appointment_routes(app)
    register_cita_qr_routes(app)
    register_license_routes(app)
    register_prescription_routes(app)
    register_emergency_routes(app)
    register_nursing_routes(app)
    register_clinical_history_routes(app)
    register_messaging_routes(app)
    register_turnos_routes(app)
    register_user_role_routes(app)
