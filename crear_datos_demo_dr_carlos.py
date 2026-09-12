"""Crea tres expedientes clínicos demo para el Dr. Carlos Peña.

El script es idempotente: puede ejecutarse varias veces sin duplicar registros.
"""

import json
from datetime import date, time, timedelta

from app import app
from core.database import database_transaction, execute_query, execute_update


CASOS = (
    {
        "cedula": "DEMO-T-005",
        "fecha_nacimiento": "2018-05-14",
        "sexo": "F",
        "motivo": "Control pediátrico de crecimiento y desarrollo",
        "diagnostico": "Examen de salud rutinario del niño",
        "cie10": "Z00.1",
        "medicamento": "Multivitamínico pediátrico",
        "dosis": "5 ml",
        "frecuencia": "Una vez al día",
    },
    {
        "cedula": "DEMO-T-006",
        "fecha_nacimiento": "2016-09-03",
        "sexo": "M",
        "motivo": "Fiebre, congestión nasal y tos",
        "diagnostico": "Infección aguda de vías respiratorias superiores",
        "cie10": "J06.9",
        "medicamento": "Acetaminofén suspensión",
        "dosis": "10 ml",
        "frecuencia": "Cada 8 horas si presenta fiebre",
    },
    {
        "cedula": "DEMO-T-007",
        "fecha_nacimiento": "2020-02-18",
        "sexo": "F",
        "motivo": "Erupción cutánea con prurito",
        "diagnostico": "Dermatitis atópica",
        "cie10": "L20.9",
        "medicamento": "Cetirizina solución oral",
        "dosis": "2.5 ml",
        "frecuencia": "Una vez al día",
    },
)


def _edad(fecha_nacimiento, fecha_servicio):
    nacimiento = date.fromisoformat(fecha_nacimiento)
    return (
        fecha_servicio.year
        - nacimiento.year
        - (
            (fecha_servicio.month, fecha_servicio.day)
            < (nacimiento.month, nacimiento.day)
        )
    )


def _crear_historia(
    tenant_id, paciente_id, medico_id, usuario_id, caso, indice, fecha
):
    marcador = f"DEMO DR CARLOS {indice:02d} - {caso['motivo']}"
    existente = execute_query(
        "SELECT id FROM consultas_clinicas "
        "WHERE tenant_id=%s AND paciente_id=%s AND medico_id=%s "
        "AND motivo_consulta=%s",
        (tenant_id, paciente_id, medico_id, marcador),
    )
    if existente:
        return existente["id"], False
    historia_id = execute_update(
        """
        INSERT INTO consultas_clinicas (
            tenant_id, paciente_id, medico_id, especialidad_consulta,
            plantilla_version, datos_especialidad, fecha, hora,
            motivo_consulta, enfermedad_actual, antecedentes_personales,
            antecedentes_familiares, signos_vitales, examen_fisico,
            diagnostico_principal, diagnosticos_secundarios,
            diagnostico_presuntivo, diagnostico_diferencial, codigo_cie10,
            plan_tratamiento, nota_evolucion_inicial, proxima_cita,
            proxima_especialidad, proxima_motivo,
            indicaciones_seguimiento, created_by, updated_by
        ) VALUES (
            %s,%s,%s,'Pediatría','1.0',%s,%s,%s,%s,%s,%s,%s,%s,%s,
            %s,%s,%s,%s,%s,%s,%s,%s,'Pediatría',%s,%s,%s,%s
        )
        """,
        (
            tenant_id,
            paciente_id,
            medico_id,
            json.dumps({
                "tipo_consulta": "Control pediátrico",
                "desarrollo": "Acorde con la edad",
                "vacunacion": "Esquema revisado",
            }, ensure_ascii=False),
            fecha,
            time(9 + indice, 0),
            marcador,
            json.dumps({
                "inicio_sintomas": "Evolución reciente",
                "evolucion": "Estable",
                "sintomas_asociados": caso["motivo"],
            }, ensure_ascii=False),
            json.dumps({
                "alergias": "No conocidas",
                "hospitalizaciones": "Ninguna",
                "medicamentos_actuales": "Ninguno",
            }, ensure_ascii=False),
            json.dumps({
                "hereditarias": "Sin antecedentes relevantes",
            }, ensure_ascii=False),
            json.dumps({
                "presion_arterial": f"{100 + indice * 2}/{60 + indice}",
                "frecuencia_cardiaca": 82 + indice,
                "frecuencia_respiratoria": 18 + indice,
                "temperatura": 36.5 + indice / 10,
                "saturacion_oxigeno": 98,
                "peso": 19 + indice * 4,
                "talla": 1.10 + indice * 0.08,
            }, ensure_ascii=False),
            json.dumps({
                "estado_general": "Paciente activo y colaborador",
                "cabeza_cuello": "Sin hallazgos de alarma",
                "respiratorio": "Buena entrada de aire bilateral",
                "cardiovascular": "Ritmo regular",
                "abdomen": "Blando y depresible",
            }, ensure_ascii=False),
            caso["diagnostico"],
            "",
            caso["diagnostico"],
            "",
            caso["cie10"],
            json.dumps({
                "medicamentos": caso["medicamento"],
                "dosis": caso["dosis"],
                "frecuencia": caso["frecuencia"],
                "duracion": "5 días",
                "recomendaciones": "Hidratación, vigilancia y signos de alarma",
            }, ensure_ascii=False),
            "Paciente estable al finalizar la consulta demo.",
            fecha + timedelta(days=30),
            "Seguimiento pediátrico",
            "Acudir antes si presenta signos de alarma.",
            usuario_id,
            usuario_id,
        ),
    )
    return historia_id, True


def _crear_emergencia(
    tenant_id, paciente, medico, usuario_id, caso, indice, fecha
):
    marcador = f"DEMO DR CARLOS {indice:02d} - URGENCIA PEDIÁTRICA"
    existente = execute_query(
        "SELECT id FROM historias_emergencia "
        "WHERE tenant_id=%s AND paciente_id=%s AND medico_id=%s "
        "AND motivo_emergencia=%s",
        (tenant_id, paciente["id"], medico["id"], marcador),
    )
    if existente:
        return existente["id"], False
    emergencia_id = execute_update(
        """
        INSERT INTO historias_emergencia (
            tenant_id, paciente_id, medico_id, fecha, hora_servicio,
            autorizacion, nombre_paciente, edad, sexo, ars_nombre,
            numero_afiliado, nss, motivo_emergencia, historia_enfermedad,
            datos_clinicos, diagnostico_impresion, estatus_paciente,
            origen_enfermedad, observaciones, medico_nombre, created_by
        ) VALUES (
            %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s
        )
        """,
        (
            tenant_id,
            paciente["id"],
            medico["id"],
            fecha,
            time(14 + indice, 0),
            f"AUT-DEMO-CARLOS-{indice:02d}",
            paciente["nombre"],
            _edad(caso["fecha_nacimiento"], fecha),
            caso["sexo"],
            paciente.get("ars_nombre") or "Sin ARS",
            paciente.get("nss"),
            paciente.get("nss"),
            marcador,
            "Paciente evaluado en emergencia con síntomas de inicio reciente.",
            json.dumps({
                "antecedentes": "Sin antecedentes de alarma",
                "hallazgos_examen": "Paciente consciente y estable",
                "ta": f"{100 + indice * 2}/{60 + indice}",
                "fc": str(82 + indice),
                "fr": str(18 + indice),
                "temperatura": str(36.5 + indice / 10),
                "pruebas": ["Evaluación clínica"],
                "manejos": ["Observación", "Hidratación"],
                "medicamentos": caso["medicamento"],
            }, ensure_ascii=False),
            caso["diagnostico"],
            "Dado de alta",
            "Enfermedad común",
            "Registro clínico generado exclusivamente para demostración.",
            medico["nombre"],
            usuario_id,
        ),
    )
    return emergencia_id, True


def _crear_licencia(
    tenant_id, paciente_id, medico_id, usuario_id, historia_id,
    tipo_id, caso, indice, fecha
):
    codigo = f"LIC-DEMO-CARLOS-{indice:02d}"
    if execute_query(
        "SELECT id FROM licencias_medicas WHERE tenant_id=%s AND codigo=%s",
        (tenant_id, codigo),
    ):
        return False
    execute_update(
        """
        INSERT INTO licencias_medicas (
            tenant_id, codigo, paciente_id, medico_id, consulta_id,
            tipo_licencia_id, diagnostico, motivo_condicion,
            observaciones, fecha_emision, fecha_inicio, fecha_termino,
            cantidad_dias, estado, created_by, updated_by
        ) VALUES (
            %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'Emitida',%s,%s
        )
        """,
        (
            tenant_id,
            codigo,
            paciente_id,
            medico_id,
            historia_id,
            tipo_id,
            caso["diagnostico"],
            "Reposo y recuperación en el hogar",
            "Licencia pediátrica generada como dato de demostración.",
            fecha,
            fecha,
            fecha + timedelta(days=2 + indice),
            3 + indice,
            usuario_id,
            usuario_id,
        ),
    )
    return True


def _crear_receta(
    tenant_id, paciente_id, medico_id, usuario_id, historia_id,
    caso, indice, fecha
):
    codigo = f"REC-DEMO-CARLOS-{indice:02d}"
    existente = execute_query(
        "SELECT id FROM recetas_medicas WHERE tenant_id=%s AND codigo=%s",
        (tenant_id, codigo),
    )
    if existente:
        return False
    receta_id = execute_update(
        """
        INSERT INTO recetas_medicas (
            tenant_id, codigo, paciente_id, medico_id, consulta_id,
            fecha, diagnostico, codigo_cie10, indicaciones_generales,
            estado, created_by
        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,'Emitida',%s)
        """,
        (
            tenant_id,
            codigo,
            paciente_id,
            medico_id,
            historia_id,
            fecha,
            caso["diagnostico"],
            caso["cie10"],
            "Administrar bajo supervisión de un adulto responsable.",
            usuario_id,
        ),
    )
    execute_update(
        """
        INSERT INTO receta_medicamentos (
            tenant_id, receta_id, medicamento, presentacion, dosis, via,
            frecuencia, duracion, cantidad, indicaciones, orden
        ) VALUES (%s,%s,%s,'Solución oral',%s,'Oral',%s,'5 días','1 frasco',%s,1)
        """,
        (
            tenant_id,
            receta_id,
            caso["medicamento"],
            caso["dosis"],
            caso["frecuencia"],
            "Suspender y consultar si presenta reacción adversa.",
        ),
    )
    return True


def _crear_hoja_enfermeria(
    tenant_id, paciente, usuario_id, emergencia_id, caso, indice, fecha
):
    marcador = f"DEMO DR CARLOS {indice:02d} - HOJA DE ENFERMERÍA"
    if execute_query(
        "SELECT id FROM hojas_enfermeria "
        "WHERE tenant_id=%s AND paciente_id=%s AND observaciones=%s",
        (tenant_id, paciente["id"], marcador),
    ):
        return False
    suministros = [{
        "fecha": fecha.isoformat(),
        "hora": f"{14 + indice:02d}:15",
        "detalle": caso["medicamento"],
        "cantidad": "1 dosis",
        "dosis_via": f"{caso['dosis']} vía oral",
    }]
    telefono = "".join(
        character
        for character in (paciente.get("telefono") or "8095550100")
        if character.isdigit()
    )[:10]
    execute_update(
        """
        INSERT INTO hojas_enfermeria (
            tenant_id, paciente_id, historia_emergencia_id,
            fecha_servicio, hora_servicio, nombre_paciente, edad, sexo,
            direccion, responsable, telefono_responsable, ars_nombre,
            medicamentos_materiales, observaciones, firma_responsable,
            created_by
        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """,
        (
            tenant_id,
            paciente["id"],
            emergencia_id,
            fecha,
            time(14 + indice, 15),
            paciente["nombre"],
            _edad(caso["fecha_nacimiento"], fecha),
            caso["sexo"],
            paciente.get("direccion") or "Dirección demo",
            "Responsable del paciente",
            telefono,
            paciente.get("ars_nombre") or "Sin ARS",
            json.dumps(suministros, ensure_ascii=False),
            marcador,
            "Enfermería Demo",
            usuario_id,
        ),
    )
    return True


def crear_datos():
    with app.app_context(), database_transaction():
        medico = execute_query(
            """
            SELECT m.id, m.tenant_id, m.nombre, u.id AS usuario_id
            FROM medicos m
            JOIN usuario_medico um
              ON um.medico_id=m.id AND um.tenant_id=m.tenant_id
            JOIN usuarios u
              ON u.id=um.usuario_id AND u.tenant_id=m.tenant_id
            WHERE m.exequatur=%s AND m.activo=1 AND u.activo=1
            LIMIT 1
            """,
            ("DEMO-TURNO-002",),
        )
        if not medico:
            raise RuntimeError(
                "No se encontró el Dr. Carlos Peña demo. "
                "Ejecuta primero crear_datos_prueba_turnos.py."
            )
        tenant_id = medico["tenant_id"]
        tipo = execute_query(
            "SELECT id FROM tipos_licencia_medica "
            "WHERE tenant_id=%s AND activo=1 ORDER BY id LIMIT 1",
            (tenant_id,),
        )
        if not tipo:
            raise RuntimeError("No existe un tipo de licencia médica activo.")

        pacientes = execute_query(
            """
            SELECT p.*, a.nombre AS ars_nombre
            FROM pacientes p
            LEFT JOIN ars a
              ON a.id=p.ars_id AND a.tenant_id=p.tenant_id
            WHERE p.tenant_id=%s AND p.cedula IN (%s,%s,%s)
            ORDER BY FIELD(p.cedula,%s,%s,%s)
            """,
            (
                tenant_id,
                *(caso["cedula"] for caso in CASOS),
                *(caso["cedula"] for caso in CASOS),
            ),
            fetch="all",
        ) or []
        if len(pacientes) != len(CASOS):
            raise RuntimeError(
                "Faltan pacientes demo. "
                "Ejecuta primero crear_datos_prueba_turnos.py."
            )

        creados = {
            "historias": 0,
            "licencias": 0,
            "recetas": 0,
            "emergencias": 0,
            "hojas_enfermeria": 0,
        }
        hoy = date.today()
        for indice, (caso, paciente) in enumerate(
            zip(CASOS, pacientes), start=1
        ):
            execute_update(
                """
                UPDATE pacientes
                SET fecha_nacimiento=COALESCE(fecha_nacimiento,%s),
                    sexo=COALESCE(sexo,%s)
                WHERE id=%s AND tenant_id=%s
                """,
                (
                    caso["fecha_nacimiento"],
                    caso["sexo"],
                    paciente["id"],
                    tenant_id,
                ),
            )
            fecha = hoy - timedelta(days=indice * 2)
            historia_id, creado = _crear_historia(
                tenant_id,
                paciente["id"],
                medico["id"],
                medico["usuario_id"],
                caso,
                indice,
                fecha,
            )
            creados["historias"] += int(creado)
            emergencia_id, creado = _crear_emergencia(
                tenant_id,
                paciente,
                medico,
                medico["usuario_id"],
                caso,
                indice,
                fecha,
            )
            creados["emergencias"] += int(creado)
            creados["licencias"] += int(_crear_licencia(
                tenant_id,
                paciente["id"],
                medico["id"],
                medico["usuario_id"],
                historia_id,
                tipo["id"],
                caso,
                indice,
                fecha,
            ))
            creados["recetas"] += int(_crear_receta(
                tenant_id,
                paciente["id"],
                medico["id"],
                medico["usuario_id"],
                historia_id,
                caso,
                indice,
                fecha,
            ))
            creados["hojas_enfermeria"] += int(_crear_hoja_enfermeria(
                tenant_id,
                paciente,
                medico["usuario_id"],
                emergencia_id,
                caso,
                indice,
                fecha,
            ))

        print(
            f"[OK] Datos demo del {medico['nombre']}: "
            + ", ".join(f"{cantidad} {nombre}" for nombre, cantidad in creados.items())
        )


if __name__ == "__main__":
    crear_datos()
