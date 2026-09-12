"""Crea una agenda médica demostrativa con varios días y estados."""

from datetime import date, datetime, timedelta

from app import app
from core.database import database_transaction, execute_query, execute_update
from crear_datos_prueba_turnos import (
    MEDICOS,
    PACIENTES,
    asegurar_medico,
    asegurar_paciente,
    obtener_tenant_demo,
)


# médico, paciente, días desde hoy, hora, duración, estado, motivo
CITAS_DEMO = (
    (0, 0, -2, "09:00:00", 30, "Completada", "Control cardiovascular"),
    (1, 1, -1, "10:00:00", 30, "No asistió", "Control pediátrico"),
    (0, 2, 0, "08:30:00", 30, "Confirmada", "Evaluación de presión arterial"),
    (1, 3, 0, "09:30:00", 30, "Programada", "Fiebre recurrente"),
    (0, 4, 0, "11:00:00", 45, "Programada", "Primera consulta cardiológica"),
    (1, 5, 0, "11:30:00", 30, "Confirmada", "Seguimiento de crecimiento"),
    (0, 6, 1, "08:00:00", 30, "Confirmada", "Revisión de estudios"),
    (1, 7, 1, "09:00:00", 30, "Programada", "Consulta pediátrica general"),
    (0, 8, 1, "10:30:00", 45, "Programada", "Palpitaciones ocasionales"),
    (1, 0, 1, "14:00:00", 30, "Programada", "Seguimiento ambulatorio"),
    (0, 1, 2, "09:30:00", 30, "Programada", "Chequeo preventivo"),
    (1, 2, 2, "10:30:00", 30, "Programada", "Alergia estacional"),
    (0, 3, 3, "08:30:00", 45, "Programada", "Evaluación preoperatoria"),
    (1, 4, 3, "11:00:00", 30, "Programada", "Control posterior a tratamiento"),
    (0, 5, 5, "09:00:00", 30, "Cancelada", "Consulta cancelada por paciente"),
    (1, 6, 7, "15:00:00", 30, "Programada", "Control mensual"),
)


def crear_datos():
    hoy = date.today()
    with app.app_context():
        with database_transaction():
            tenant_id = obtener_tenant_demo()
            actor = execute_query(
                "SELECT id FROM usuarios "
                "WHERE email=%s AND tenant_id=%s AND activo=1",
                ("demo@arsflow.local", tenant_id),
            )
            actor_id = actor["id"] if actor else None

            medicos = [
                asegurar_medico(tenant_id, datos)
                for datos in MEDICOS
            ]
            pacientes = [
                asegurar_paciente(tenant_id, *datos)
                for datos in PACIENTES
            ]

            execute_update(
                "DELETE FROM citas_medicas "
                "WHERE tenant_id=%s AND motivo LIKE '[DEMO AGENDA]%%'",
                (tenant_id,),
            )

            for (
                medico_idx,
                paciente_idx,
                dias,
                hora,
                duracion,
                estado,
                motivo,
            ) in CITAS_DEMO:
                cancelada = estado == "Cancelada"
                execute_update(
                    """
                    INSERT INTO citas_medicas (
                        tenant_id, paciente_id, medico_id, fecha, hora,
                        duracion_minutos, especialidad, motivo, notas,
                        estado, origen, created_by, updated_by,
                        cancelada_por, fecha_cancelacion, motivo_cancelacion
                    ) VALUES (
                        %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'Manual',%s,%s,
                        %s,%s,%s
                    )
                    """,
                    (
                        tenant_id,
                        pacientes[paciente_idx],
                        medicos[medico_idx],
                        hoy + timedelta(days=dias),
                        hora,
                        duracion,
                        MEDICOS[medico_idx]["especialidad"],
                        f"[DEMO AGENDA] {motivo}",
                        "Registro creado para probar filtros y estados.",
                        estado,
                        actor_id,
                        actor_id,
                        actor_id if cancelada else None,
                        datetime.now() if cancelada else None,
                        "Reprogramación solicitada" if cancelada else None,
                    ),
                )

    print("[OK] Agenda médica demo creada")
    print(f"Citas generadas: {len(CITAS_DEMO)}")
    print("Incluye citas pasadas, de hoy y de los próximos 7 días")


if __name__ == "__main__":
    crear_datos()
