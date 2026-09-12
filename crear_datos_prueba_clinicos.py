"""Crea cinco pacientes con datos clínicos y consultas de prueba."""

import json
from datetime import date, time, timedelta

from app import app, execute_query, execute_update


PACIENTES = [
    ("PACIENTE PRUEBA ANA MARTÍNEZ", "00190000001", "8097000001", "4659000001", "F", "1992-03-15", "Contadora", "Migraña sin aura", "G43.0"),
    ("PACIENTE PRUEBA LUIS GÓMEZ", "00190000002", "8097000002", "4659000002", "M", "1985-07-22", "Ingeniero", "Hipertensión esencial", "I10"),
    ("PACIENTE PRUEBA CARLA PÉREZ", "00190000003", "8097000003", "4659000003", "F", "1998-11-08", "Docente", "Gastritis aguda", "K29.7"),
    ("PACIENTE PRUEBA JOSÉ RAMÍREZ", "00190000004", "8097000004", "4659000004", "M", "1979-01-30", "Comerciante", "Lumbalgia", "M54.5"),
    ("PACIENTE PRUEBA ELENA SANTOS", "00190000005", "8097000005", "4659000005", "F", "1990-05-19", "Enfermera", "Infección respiratoria aguda", "J06.9"),
]


def crear_datos():
    with app.app_context():
        usuario = execute_query(
            "SELECT id, tenant_id FROM usuarios "
            "WHERE email=%s AND activo=1 LIMIT 1",
            ("admin@facturacion.com",)
        )
        if not usuario or not usuario.get("tenant_id"):
            raise RuntimeError("No se encontró el administrador con empresa asignada")

        tenant_id = usuario["tenant_id"]
        usuario_id = usuario["id"]
        medico = execute_query(
            "SELECT id, nombre FROM medicos "
            "WHERE tenant_id=%s AND activo=1 ORDER BY id LIMIT 1",
            (tenant_id,)
        )
        ars = execute_query(
            "SELECT id, nombre FROM ars "
            "WHERE tenant_id=%s AND activo=1 ORDER BY id LIMIT 1",
            (tenant_id,)
        )
        if not medico or not ars:
            raise RuntimeError("Se necesita al menos un médico y una ARS activos")

        hoy = date.today()
        creados = {"pacientes": 0, "historias": 0, "emergencias": 0, "consultas": 0}

        for indice, datos in enumerate(PACIENTES, start=1):
            nombre, cedula, telefono, nss, sexo, nacimiento, ocupacion, diagnostico, cie10 = datos
            paciente = execute_query(
                "SELECT id FROM pacientes WHERE tenant_id=%s AND cedula=%s",
                (tenant_id, cedula)
            )
            if paciente:
                paciente_id = paciente["id"]
            else:
                paciente_id = execute_update(
                    """
                    INSERT INTO pacientes (
                        tenant_id, nombre, cedula, nss, telefono, email, direccion,
                        ocupacion, fecha_nacimiento, sexo, ars_id
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        tenant_id, nombre, cedula, nss, telefono,
                        f"paciente.prueba{indice}@example.com",
                        f"Calle Prueba #{indice}, Santo Domingo",
                        ocupacion, nacimiento, sexo, ars["id"]
                    )
                )
                creados["pacientes"] += 1

            motivo_clinico = f"CONSULTA CLÍNICA DE PRUEBA {indice}"
            existe_historia = execute_query(
                "SELECT id FROM consultas_clinicas "
                "WHERE tenant_id=%s AND paciente_id=%s AND motivo_consulta=%s",
                (tenant_id, paciente_id, motivo_clinico)
            )
            if not existe_historia:
                signos = {
                    "presion_arterial": f"{110 + indice * 2}/{70 + indice}",
                    "frecuencia_cardiaca": 70 + indice,
                    "frecuencia_respiratoria": 16 + indice,
                    "temperatura": 36.5,
                    "saturacion_oxigeno": 98,
                    "peso": 60 + indice * 3,
                    "talla": 1.60 + indice * 0.02,
                    "imc": round((60 + indice * 3) / ((1.60 + indice * 0.02) ** 2), 2)
                }
                execute_update(
                    """
                    INSERT INTO consultas_clinicas (
                        tenant_id, paciente_id, medico_id, fecha, hora,
                        motivo_consulta, enfermedad_actual, antecedentes_personales,
                        antecedentes_familiares, signos_vitales, examen_fisico,
                        diagnostico_principal, diagnosticos_secundarios,
                        diagnostico_presuntivo, diagnostico_diferencial, codigo_cie10,
                        plan_tratamiento, nota_evolucion_inicial, proxima_cita,
                        proxima_especialidad, proxima_motivo,
                        indicaciones_seguimiento, created_by, updated_by
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        tenant_id, paciente_id, medico["id"], hoy - timedelta(days=indice),
                        time(9 + indice, 0), motivo_clinico,
                        json.dumps({
                            "inicio_sintomas": "Tres días antes de la consulta",
                            "evolucion": "Progresiva",
                            "intensidad": f"{4 + indice}/10",
                            "factores_agravan": "Actividad física",
                            "factores_alivian": "Reposo",
                            "sintomas_asociados": "Malestar general",
                            "tratamientos_previos": "Ninguno"
                        }, ensure_ascii=False),
                        json.dumps({
                            "enfermedades_previas": "Sin antecedentes de importancia",
                            "cirugias": "Ninguna",
                            "hospitalizaciones": "Ninguna",
                            "alergias": "No conocidas",
                            "medicamentos_actuales": "Ninguno",
                            "habitos": "Niega tabaco y alcohol",
                            "otros": ""
                        }, ensure_ascii=False),
                        json.dumps({
                            "diabetes": False, "hipertension": indice == 2,
                            "cardiacas": False, "cancer": False,
                            "hereditarias": "", "otros": ""
                        }, ensure_ascii=False),
                        json.dumps(signos, ensure_ascii=False),
                        json.dumps({
                            "estado_general": "Consciente, orientado y colaborador",
                            "cabeza_cuello": "Sin alteraciones",
                            "cardiovascular": "Ruidos cardíacos rítmicos",
                            "respiratorio": "Murmullo vesicular conservado",
                            "abdomen": "Blando y depresible",
                            "extremidades": "Sin edema",
                            "neurologico": "Sin déficit focal",
                            "otros": ""
                        }, ensure_ascii=False),
                        diagnostico, "", diagnostico, "", cie10,
                        json.dumps({
                            "medicamentos": "Tratamiento sintomático",
                            "dosis": "Según indicación médica",
                            "frecuencia": "Cada 8 horas",
                            "duracion": "5 días",
                            "laboratorios": "Hemograma",
                            "imagenes": "",
                            "procedimientos": "",
                            "recomendaciones": "Hidratación y reposo"
                        }, ensure_ascii=False),
                        "Paciente estable al finalizar la consulta",
                        hoy + timedelta(days=30), "Medicina Interna",
                        "Seguimiento clínico", "Regresar antes si empeoran los síntomas",
                        usuario_id, usuario_id
                    )
                )
                creados["historias"] += 1

            motivo_emergencia = f"EMERGENCIA DE PRUEBA {indice}"
            existe_emergencia = execute_query(
                "SELECT id FROM historias_emergencia "
                "WHERE tenant_id=%s AND paciente_id=%s AND motivo_emergencia=%s",
                (tenant_id, paciente_id, motivo_emergencia)
            )
            if not existe_emergencia:
                edad = hoy.year - int(nacimiento[:4])
                execute_update(
                    """
                    INSERT INTO historias_emergencia (
                        tenant_id, paciente_id, medico_id, fecha, hora_servicio,
                        autorizacion, nombre_paciente, edad, sexo, ars_nombre,
                        numero_afiliado, nss, motivo_emergencia, historia_enfermedad,
                        datos_clinicos, diagnostico_impresion, estatus_paciente,
                        origen_enfermedad, observaciones, medico_nombre, created_by
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        tenant_id, paciente_id, medico["id"], hoy - timedelta(days=indice),
                        time(14 + indice, 0), f"AUT-PRUEBA-{indice}", nombre, edad,
                        sexo, ars["nombre"], nss, nss, motivo_emergencia,
                        "Paciente acude por síntomas de inicio reciente.",
                        json.dumps({
                            "atenciones_previas": False, "alergias": False,
                            "antecedentes": "Sin antecedentes relevantes",
                            "hallazgos_examen": "Paciente estable",
                            "ta": f"{110 + indice * 2}/{70 + indice}",
                            "fc": str(70 + indice), "fr": str(16 + indice),
                            "temperatura": "36.5", "pruebas": ["Hemograma"],
                            "otras_pruebas": "", "manejos": ["Hidratación"],
                            "oxigeno_inicio": "", "oxigeno_final": "",
                            "oxigeno_total_hora": "",
                            "medicamentos": "Tratamiento sintomático"
                        }, ensure_ascii=False),
                        diagnostico, "Dado de alta", "Enfermedad común",
                        "Registro generado para pruebas", medico["nombre"], usuario_id
                    )
                )
                creados["emergencias"] += 1

            consulta_marcador = f"CONSULTA FACTURABLE DE PRUEBA {indice}"
            existe_consulta = execute_query(
                "SELECT id FROM pacientes_pendientes "
                "WHERE tenant_id=%s AND paciente_id=%s AND servicios_realizados=%s",
                (tenant_id, paciente_id, consulta_marcador)
            )
            if not existe_consulta:
                execute_update(
                    """
                    INSERT INTO pacientes_pendientes (
                        tenant_id, paciente_id, nombre_paciente, cedula, nss, ars_id,
                        fecha_servicio, servicios_realizados, observaciones,
                        monto_estimado, estado, medico_id, centro_medico_id, created_by
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        'Pendiente', %s, NULL, %s
                    )
                    """,
                    (
                        tenant_id, paciente_id, nombre, cedula, nss, ars["id"],
                        hoy - timedelta(days=indice), consulta_marcador,
                        "Consulta creada como dato de prueba", 1500 + indice * 100,
                        medico["id"], usuario_id
                    )
                )
                creados["consultas"] += 1

        print(
            "[OK] Creados: "
            f"{creados['pacientes']} pacientes, "
            f"{creados['historias']} historias clínicas, "
            f"{creados['emergencias']} emergencias y "
            f"{creados['consultas']} consultas"
        )


if __name__ == "__main__":
    crear_datos()
