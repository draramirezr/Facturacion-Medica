"""Crea médicos y usuarios demo para revisar cada formulario clínico."""

from app import app
from core.database import database_transaction, execute_update
from crear_datos_prueba_turnos import (
    CLAVE_MEDICO,
    asegurar_medico,
    asegurar_usuario,
    obtener_rol,
    obtener_tenant_demo,
)


MEDICOS_ESPECIALIDADES = (
    {
        "nombre": "Dr. Alejandro Ruiz",
        "exequatur": "DEMO-ESP-001",
        "especialidad": "Medicina General",
        "email": "medico.general@arsflow.local",
    },
    {
        "nombre": "Dr. Carlos Peña",
        "exequatur": "DEMO-TURNO-002",
        "especialidad": "Pediatría",
        "email": "medico.pediatria@arsflow.local",
    },
    {
        "nombre": "Dra. Elena Vargas",
        "exequatur": "DEMO-ESP-003",
        "especialidad": "Ginecología",
        "email": "medico.ginecologia@arsflow.local",
    },
    {
        "nombre": "Dra. Laura Méndez",
        "exequatur": "DEMO-TURNO-001",
        "especialidad": "Cardiología",
        "email": "medico.cardio@arsflow.local",
    },
    {
        "nombre": "Dr. Miguel Torres",
        "exequatur": "DEMO-ESP-005",
        "especialidad": "Ortopedia",
        "email": "medico.ortopedia@arsflow.local",
    },
    {
        "nombre": "Dra. Isabel Cruz",
        "exequatur": "DEMO-ESP-006",
        "especialidad": "Dermatología",
        "email": "medico.dermatologia@arsflow.local",
    },
    {
        "nombre": "Dr. Roberto Salas",
        "exequatur": "DEMO-ESP-007",
        "especialidad": "Oftalmología",
        "email": "medico.oftalmologia@arsflow.local",
    },
    {
        "nombre": "Dra. Patricia León",
        "exequatur": "DEMO-ESP-008",
        "especialidad": "Otorrinolaringología",
        "email": "medico.otorrino@arsflow.local",
    },
    {
        "nombre": "Dr. Fernando Díaz",
        "exequatur": "DEMO-ESP-009",
        "especialidad": "Neurología",
        "email": "medico.neurologia@arsflow.local",
    },
    {
        "nombre": "Dra. Natalia Reyes",
        "exequatur": "DEMO-ESP-010",
        "especialidad": "Psiquiatría",
        "email": "medico.psiquiatria@arsflow.local",
    },
    {
        "nombre": "Dra. Adriana Soto",
        "exequatur": "DEMO-ESP-011",
        "especialidad": "Nutrición",
        "email": "medico.nutricion@arsflow.local",
    },
)


def crear_usuarios_especialidades():
    with app.app_context():
        with database_transaction():
            tenant_id = obtener_tenant_demo()
            rol_medico = obtener_rol(tenant_id, "Médico")
            for datos in MEDICOS_ESPECIALIDADES:
                medico_id = asegurar_medico(tenant_id, datos)
                usuario_id = asegurar_usuario(
                    tenant_id,
                    datos["nombre"],
                    datos["email"],
                    CLAVE_MEDICO,
                    rol_medico,
                )
                execute_update(
                    "DELETE FROM usuario_medico "
                    "WHERE tenant_id=%s AND "
                    "(usuario_id=%s OR medico_id=%s)",
                    (tenant_id, usuario_id, medico_id),
                )
                execute_update(
                    "INSERT INTO usuario_medico "
                    "(tenant_id, usuario_id, medico_id) VALUES (%s,%s,%s)",
                    (tenant_id, usuario_id, medico_id),
                )

    print("Usuarios demo por especialidad creados o actualizados:")
    for datos in MEDICOS_ESPECIALIDADES:
        print(
            f"- {datos['especialidad']}: {datos['email']} "
            f"/ {CLAVE_MEDICO}"
        )


if __name__ == "__main__":
    crear_usuarios_especialidades()
