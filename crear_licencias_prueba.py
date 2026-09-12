"""Genera licencias de prueba para pacientes con historias de emergencia."""

import json
import secrets
from datetime import timedelta

from app import app, execute_query, execute_update


def crear_licencias(tenant_id=1):
    with app.app_context():
        usuario = execute_query(
            """
            SELECT id FROM usuarios
            WHERE tenant_id=%s AND activo=1
            ORDER BY (perfil='Administrador') DESC, id
            LIMIT 1
            """,
            (tenant_id,),
        )
        tipos = execute_query(
            """
            SELECT id FROM tipos_licencia_medica
            WHERE tenant_id=%s AND activo=1
            ORDER BY id
            """,
            (tenant_id,),
            fetch="all",
        ) or []
        emergencias = execute_query(
            """
            SELECT h.paciente_id, h.medico_id, h.fecha,
                   h.diagnostico_impresion, h.motivo_emergencia
            FROM historias_emergencia h
            JOIN pacientes p
              ON p.id=h.paciente_id AND p.tenant_id=h.tenant_id
            WHERE h.tenant_id=%s
            GROUP BY h.paciente_id, h.medico_id, h.fecha,
                     h.diagnostico_impresion, h.motivo_emergencia
            ORDER BY h.fecha DESC, h.paciente_id DESC
            LIMIT 5
            """,
            (tenant_id,),
            fetch="all",
        ) or []

        if not usuario or not tipos or len(emergencias) < 5:
            raise RuntimeError(
                "Se requieren un usuario, tipos de licencia y cinco pacientes "
                "con historias de emergencia."
            )

        creadas = 0
        for indice, emergencia in enumerate(emergencias):
            existente = execute_query(
                """
                SELECT id FROM licencias_medicas
                WHERE tenant_id=%s AND paciente_id=%s
                  AND diagnostico=%s AND fecha_emision=%s
                LIMIT 1
                """,
                (
                    tenant_id,
                    emergencia["paciente_id"],
                    emergencia["diagnostico_impresion"],
                    emergencia["fecha"],
                ),
            )
            if existente:
                continue

            duracion = 3 + indice
            fecha_inicio = emergencia["fecha"]
            fecha_termino = fecha_inicio + timedelta(days=duracion - 1)
            codigo = (
                f"LM-{emergencia['fecha'].strftime('%Y%m%d')}-"
                f"{secrets.token_hex(3).upper()}"
            )
            datos_auditoria = {
                "origen": "historia de emergencia de prueba",
                "paciente_id": emergencia["paciente_id"],
                "diagnostico": emergencia["diagnostico_impresion"],
                "fecha_inicio": str(fecha_inicio),
                "fecha_termino": str(fecha_termino),
                "cantidad_dias": duracion,
                "estado": "Emitida",
            }
            licencia_id = execute_update(
                """
                INSERT INTO licencias_medicas (
                    tenant_id, codigo, paciente_id, medico_id,
                    tipo_licencia_id, diagnostico, motivo_condicion,
                    observaciones, fecha_emision, fecha_inicio,
                    fecha_termino, cantidad_dias, estado,
                    created_by, updated_by
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, 'Emitida', %s, %s
                )
                """,
                (
                    tenant_id,
                    codigo,
                    emergencia["paciente_id"],
                    emergencia["medico_id"],
                    tipos[indice % len(tipos)]["id"],
                    emergencia["diagnostico_impresion"],
                    emergencia["motivo_emergencia"],
                    "Licencia generada a partir de la historia de emergencia.",
                    emergencia["fecha"],
                    fecha_inicio,
                    fecha_termino,
                    duracion,
                    usuario["id"],
                    usuario["id"],
                ),
            )
            execute_update(
                """
                INSERT INTO auditoria_licencias_medicas (
                    tenant_id, licencia_id, usuario_id, accion,
                    datos_nuevos, motivo
                ) VALUES (%s, %s, %s, 'Creación', %s, %s)
                """,
                (
                    tenant_id,
                    licencia_id,
                    usuario["id"],
                    json.dumps(datos_auditoria, ensure_ascii=False),
                    "Datos clínicos de prueba",
                ),
            )
            creadas += 1

        total = execute_query(
            """
            SELECT COUNT(DISTINCT l.paciente_id) AS total
            FROM licencias_medicas l
            JOIN historias_emergencia h
              ON h.paciente_id=l.paciente_id AND h.tenant_id=l.tenant_id
            WHERE l.tenant_id=%s
            """,
            (tenant_id,),
        )
        print(
            f"[OK] Licencias creadas: {creadas}. "
            f"Pacientes de emergencia con licencia: {total['total']}."
        )


if __name__ == "__main__":
    crear_licencias()
