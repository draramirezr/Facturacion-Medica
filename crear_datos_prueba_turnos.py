"""Crea datos reutilizables para probar recepción, colas y pantalla de turnos."""

from datetime import date

from werkzeug.security import generate_password_hash

from app import app
from core.database import database_transaction, execute_query, execute_update


CLAVE_MEDICO = "MedicoDemo#2026"
CLAVE_RECEPCION = "RecepcionDemo#2026"

MEDICOS = (
    {
        "nombre": "Dra. Laura Méndez",
        "exequatur": "DEMO-TURNO-001",
        "especialidad": "Cardiología",
        "email": "medico.cardio@arsflow.local",
    },
    {
        "nombre": "Dr. Carlos Peña",
        "exequatur": "DEMO-TURNO-002",
        "especialidad": "Pediatría",
        "email": "medico.pediatria@arsflow.local",
    },
)

PACIENTES = (
    ("Ana Martínez", "DEMO-T-001", "809-555-0101"),
    ("José Ramírez", "DEMO-T-002", "809-555-0102"),
    ("María Santos", "DEMO-T-003", "809-555-0103"),
    ("Pedro Castillo", "DEMO-T-004", "809-555-0104"),
    ("Sofía Rodríguez", "DEMO-T-005", "809-555-0105"),
    ("Luis Hernández", "DEMO-T-006", "809-555-0106"),
    ("Camila García", "DEMO-T-007", "809-555-0107"),
    ("Diego Fernández", "DEMO-T-008", "809-555-0108"),
    ("Valentina Cruz", "DEMO-T-009", "809-555-0109"),
)

TURNOS = (
    # Índice de médico, índice de paciente, número, estado, motivo.
    (0, 0, 1, "Llamado", "Dolor torácico y evaluación cardiovascular"),
    (0, 1, 2, "EnEspera", "Control de presión arterial"),
    (0, 2, 3, "EnEspera", "Seguimiento de resultados"),
    (0, 3, 4, "NoPresente", "Consulta cardiológica inicial"),
    (1, 4, 1, "EnConsulta", "Fiebre y malestar general"),
    (1, 5, 2, "EnEspera", "Control pediátrico"),
    (1, 6, 3, "EnEspera", "Tos persistente"),
)


def obtener_tenant_demo():
    usuario = execute_query(
        "SELECT tenant_id FROM usuarios WHERE email=%s AND activo=1",
        ("demo@arsflow.local",),
    )
    if usuario and usuario.get("tenant_id"):
        return usuario["tenant_id"]
    empresa = execute_query("SELECT id FROM empresas ORDER BY id LIMIT 1")
    if not empresa:
        raise RuntimeError("No existe una empresa donde crear los datos demo")
    return empresa["id"]


def obtener_rol(tenant_id, nombre):
    rol = execute_query(
        "SELECT id FROM roles "
        "WHERE tenant_id=%s AND nombre=%s AND activo=1",
        (tenant_id, nombre),
    )
    if not rol:
        raise RuntimeError(
            f"No existe el rol {nombre}. Ejecuta crear_modulo_roles.py."
        )
    return rol["id"]


def asegurar_usuario(tenant_id, nombre, email, clave, rol_id):
    usuario = execute_query(
        "SELECT id FROM usuarios WHERE email=%s",
        (email,),
    )
    password_hash = generate_password_hash(clave)
    if usuario:
        usuario_id = usuario["id"]
        execute_update(
            """
            UPDATE usuarios
            SET tenant_id=%s, nombre=%s, password_hash=%s,
                perfil='Registro de Facturas', activo=1,
                password_temporal=0
            WHERE id=%s
            """,
            (tenant_id, nombre, password_hash, usuario_id),
        )
        execute_update(
            "DELETE FROM usuario_roles WHERE usuario_id=%s",
            (usuario_id,),
        )
    else:
        usuario_id = execute_update(
            """
            INSERT INTO usuarios (
                tenant_id, nombre, email, password_hash, perfil,
                activo, password_temporal, mostrar_chat
            ) VALUES (
                %s,%s,%s,%s,'Registro de Facturas',1,0,1
            )
            """,
            (tenant_id, nombre, email, password_hash),
        )
    execute_update(
        "INSERT INTO usuario_roles (tenant_id, usuario_id, rol_id) "
        "VALUES (%s,%s,%s)",
        (tenant_id, usuario_id, rol_id),
    )
    return usuario_id


def asegurar_medico(tenant_id, datos):
    medico = execute_query(
        "SELECT id FROM medicos WHERE tenant_id=%s AND exequatur=%s",
        (tenant_id, datos["exequatur"]),
    )
    if medico:
        medico_id = medico["id"]
        execute_update(
            """
            UPDATE medicos
            SET nombre=%s, especialidad=%s, email=%s, activo=1
            WHERE id=%s AND tenant_id=%s
            """,
            (
                datos["nombre"],
                datos["especialidad"],
                datos["email"],
                medico_id,
                tenant_id,
            ),
        )
    else:
        medico_id = execute_update(
            """
            INSERT INTO medicos (
                tenant_id, nombre, exequatur, especialidad, email, activo
            ) VALUES (%s,%s,%s,%s,%s,1)
            """,
            (
                tenant_id,
                datos["nombre"],
                datos["exequatur"],
                datos["especialidad"],
                datos["email"],
            ),
        )
    return medico_id


def asegurar_paciente(tenant_id, nombre, cedula, telefono):
    paciente = execute_query(
        "SELECT id FROM pacientes WHERE tenant_id=%s AND cedula=%s",
        (tenant_id, cedula),
    )
    if paciente:
        paciente_id = paciente["id"]
        execute_update(
            """
            UPDATE pacientes
            SET nombre=%s, telefono=%s, registro_incompleto=0
            WHERE id=%s AND tenant_id=%s
            """,
            (nombre, telefono, paciente_id, tenant_id),
        )
        return paciente_id
    return execute_update(
        """
        INSERT INTO pacientes (
            tenant_id, nombre, cedula, telefono, registro_incompleto
        ) VALUES (%s,%s,%s,%s,0)
        """,
        (tenant_id, nombre, cedula, telefono),
    )


def crear_datos():
    hoy = date.today()
    with app.app_context():
        with database_transaction():
            tenant_id = obtener_tenant_demo()
            rol_medico = obtener_rol(tenant_id, "Médico")
            rol_recepcion = obtener_rol(tenant_id, "Oficial de servicios")
            actor = execute_query(
                "SELECT id FROM usuarios WHERE email=%s AND tenant_id=%s",
                ("demo@arsflow.local", tenant_id),
            )
            actor_id = actor["id"] if actor else None

            medicos = []
            for datos in MEDICOS:
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
                    "WHERE tenant_id=%s AND (usuario_id=%s OR medico_id=%s)",
                    (tenant_id, usuario_id, medico_id),
                )
                execute_update(
                    "INSERT INTO usuario_medico "
                    "(tenant_id, usuario_id, medico_id) VALUES (%s,%s,%s)",
                    (tenant_id, usuario_id, medico_id),
                )
                medicos.append(medico_id)

            asegurar_usuario(
                tenant_id,
                "Recepción Demo",
                "recepcion@arsflow.local",
                CLAVE_RECEPCION,
                rol_recepcion,
            )

            pacientes = [
                asegurar_paciente(tenant_id, *paciente)
                for paciente in PACIENTES
            ]

            # Limpiar únicamente los turnos demo de hoy para que sea idempotente.
            placeholders = ",".join(["%s"] * len(pacientes))
            turnos_demo = execute_query(
                f"""
                SELECT id FROM turnos_atencion
                WHERE tenant_id=%s AND fecha=%s
                  AND paciente_id IN ({placeholders})
                """,
                (tenant_id, hoy, *pacientes),
                fetch="all",
            ) or []
            if turnos_demo:
                ids = [turno["id"] for turno in turnos_demo]
                ids_sql = ",".join(["%s"] * len(ids))
                execute_update(
                    f"DELETE FROM turnos_eventos "
                    f"WHERE tenant_id=%s AND turno_id IN ({ids_sql})",
                    (tenant_id, *ids),
                )
                execute_update(
                    f"DELETE FROM turnos_atencion "
                    f"WHERE tenant_id=%s AND id IN ({ids_sql})",
                    (tenant_id, *ids),
                )

            execute_update(
                "DELETE FROM secuencias_turnos "
                "WHERE tenant_id=%s AND fecha=%s "
                f"AND medico_id IN ({','.join(['%s'] * len(medicos))})",
                (tenant_id, hoy, *medicos),
            )

            for medico_idx, paciente_idx, numero, estado, motivo in TURNOS:
                medico_id = medicos[medico_idx]
                paciente_id = pacientes[paciente_idx]
                turno_id = execute_update(
                    """
                    INSERT INTO turnos_atencion (
                        tenant_id, fecha, paciente_id, medico_id,
                        especialidad_snapshot, numero, posicion, estado,
                        motivo, registro_incompleto, llegada_at, llamado_at,
                        consulta_iniciada_at, actor_id, created_by, updated_by
                    ) VALUES (
                        %s,%s,%s,%s,%s,%s,%s,%s,%s,0,NOW(),
                        CASE WHEN %s='Llamado' THEN NOW() ELSE NULL END,
                        CASE WHEN %s='EnConsulta' THEN NOW() ELSE NULL END,
                        %s,%s,%s
                    )
                    """,
                    (
                        tenant_id,
                        hoy,
                        paciente_id,
                        medico_id,
                        MEDICOS[medico_idx]["especialidad"],
                        numero,
                        numero,
                        estado,
                        motivo,
                        estado,
                        estado,
                        actor_id,
                        actor_id,
                        actor_id,
                    ),
                )
                execute_update(
                    """
                    INSERT INTO turnos_eventos (
                        tenant_id, turno_id, estado_anterior,
                        estado_nuevo, motivo, actor_id, datos
                    ) VALUES (%s,%s,NULL,%s,'Datos de demostración',%s,%s)
                    """,
                    (
                        tenant_id,
                        turno_id,
                        estado,
                        actor_id,
                        '{"origen":"Demo"}',
                    ),
                )

            for medico_idx, medico_id in enumerate(medicos):
                ultimo = max(
                    item[2] for item in TURNOS if item[0] == medico_idx
                )
                execute_update(
                    """
                    INSERT INTO secuencias_turnos (
                        tenant_id, fecha, medico_id, ultimo_numero
                    ) VALUES (%s,%s,%s,%s)
                    ON DUPLICATE KEY UPDATE
                        ultimo_numero=VALUES(ultimo_numero)
                    """,
                    (tenant_id, hoy, medico_id, ultimo),
                )

            execute_update(
                """
                DELETE FROM citas_medicas
                WHERE tenant_id=%s AND fecha=%s
                  AND paciente_id IN (%s,%s)
                  AND motivo LIKE '[DEMO TURNOS]%%'
                """,
                (tenant_id, hoy, pacientes[7], pacientes[8]),
            )
            for indice, hora in ((7, "14:30:00"), (8, "15:00:00")):
                medico_idx = indice - 7
                execute_update(
                    """
                    INSERT INTO citas_medicas (
                        tenant_id, paciente_id, medico_id, fecha, hora,
                        duracion_minutos, especialidad, motivo, estado,
                        origen, created_by, updated_by
                    ) VALUES (
                        %s,%s,%s,%s,%s,30,%s,%s,'Programada',
                        'Manual',%s,%s
                    )
                    """,
                    (
                        tenant_id,
                        pacientes[indice],
                        medicos[medico_idx],
                        hoy,
                        hora,
                        MEDICOS[medico_idx]["especialidad"],
                        "[DEMO TURNOS] Cita pendiente de llegada",
                        actor_id,
                        actor_id,
                    ),
                )

    print("[OK] Datos demo de turnos creados")
    print("Recepción: recepcion@arsflow.local / " + CLAVE_RECEPCION)
    print("Cardiología: medico.cardio@arsflow.local / " + CLAVE_MEDICO)
    print("Pediatría: medico.pediatria@arsflow.local / " + CLAVE_MEDICO)


if __name__ == "__main__":
    crear_datos()
