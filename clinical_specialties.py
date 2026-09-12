"""Esquemas versionados para la sección especializada de la historia clínica."""

from copy import deepcopy
from datetime import date
import re
import unicodedata


SCHEMA_VERSION = 1
FIELD_PREFIX = "especialidad_"


def _field(name, label, field_type="textarea", **options):
    field = {
        "name": name,
        "label": label,
        "type": field_type,
        "required": options.pop("required", False),
    }
    field.update(options)
    return field


YES_NO = ["No", "Sí"]
LATERALITY = ["No aplica", "Derecha", "Izquierda", "Bilateral"]


SPECIALTY_SCHEMAS = {
    "medicina-general": {
        "label": "Medicina General",
        "sections": [
            {
                "title": "Evaluación integral",
                "fields": [
                    _field("revision_sistemas", "Revisión por sistemas"),
                    _field("estado_funcional", "Estado funcional y autonomía"),
                    _field("riesgo_cardiovascular", "Factores de riesgo cardiovascular"),
                    _field("vacunacion", "Estado de vacunación"),
                    _field("tamizajes", "Tamizajes preventivos realizados o pendientes"),
                    _field("adherencia", "Adherencia al tratamiento"),
                ],
            },
        ],
    },
    "pediatria": {
        "label": "Pediatría",
        "sections": [
            {
                "title": "Crecimiento y desarrollo",
                "fields": [
                    _field("edad_gestacional", "Edad gestacional al nacer", "text", max_length=80),
                    _field("peso_nacer", "Peso al nacer (kg)", "number", min=0.2, max=8, step=0.01),
                    _field("alimentacion", "Alimentación actual"),
                    _field("desarrollo_psicomotor", "Hitos del desarrollo psicomotor"),
                    _field("esquema_vacunacion", "Esquema de vacunación", "select", options=["Completo", "Incompleto", "No documentado"]),
                    _field("percentil_crecimiento", "Percentiles y patrón de crecimiento", "text", max_length=200),
                    _field("entorno_escolar", "Desempeño y entorno escolar"),
                    _field("responsable", "Nombre y relación del acompañante", "text", max_length=150),
                ],
            },
        ],
    },
    "ginecologia": {
        "label": "Ginecología",
        "sections": [
            {
                "title": "Historia gineco-obstétrica",
                "fields": [
                    _field("menarquia", "Edad de menarquia", "number", min=7, max=20, step=1),
                    _field("fum", "Fecha de última menstruación", "date"),
                    _field("ciclo_menstrual", "Características del ciclo menstrual"),
                    _field("embarazo_actual", "Embarazo actual", "select", options=YES_NO),
                    _field(
                        "edad_gestacional_actual",
                        "Edad gestacional actual (semanas)",
                        "number",
                        min=1,
                        max=45,
                        step=1,
                        depends_on={"field": "embarazo_actual", "equals": "Sí"},
                    ),
                    _field("gestaciones", "Gestaciones", "number", min=0, max=30, step=1),
                    _field("partos", "Partos", "number", min=0, max=30, step=1),
                    _field("cesareas", "Cesáreas", "number", min=0, max=30, step=1),
                    _field("abortos", "Abortos", "number", min=0, max=30, step=1),
                    _field("anticoncepcion", "Método anticonceptivo"),
                    _field("citologia", "Última citología y resultado"),
                    _field("antecedentes_ginecologicos", "Antecedentes ginecológicos relevantes"),
                ],
            },
        ],
    },
    "cardiologia": {
        "label": "Cardiología",
        "sections": [
            {
                "title": "Evaluación cardiovascular",
                "fields": [
                    _field("dolor_toracico", "Características del dolor torácico"),
                    _field("disnea_clase", "Disnea / clase funcional", "select", options=["Sin disnea", "NYHA I", "NYHA II", "NYHA III", "NYHA IV"]),
                    _field("palpitaciones", "Palpitaciones o síncope"),
                    _field("edema", "Edema", "select", options=YES_NO),
                    _field("capacidad_funcional", "Capacidad funcional"),
                    _field("riesgo_cardiovascular", "Factores de riesgo cardiovascular"),
                    _field("ecg", "Hallazgos de ECG"),
                    _field("fraccion_eyeccion", "Fracción de eyección (%)", "number", min=1, max=100, step=0.1),
                ],
            },
        ],
    },
    "ortopedia": {
        "label": "Ortopedia",
        "sections": [
            {
                "title": "Evaluación musculoesquelética",
                "fields": [
                    _field("region_anatomica", "Región anatómica afectada", "text", required=True, max_length=150),
                    _field("lateralidad", "Lateralidad", "select", options=LATERALITY),
                    _field("mecanismo_lesion", "Mecanismo de lesión"),
                    _field("escala_dolor", "Dolor (0–10)", "number", min=0, max=10, step=1),
                    _field("rango_movimiento", "Rango de movimiento"),
                    _field("estabilidad", "Estabilidad articular"),
                    _field("estado_neurovascular", "Estado neurovascular distal"),
                    _field("marcha", "Marcha y apoyo"),
                    _field("imagenes_ortopedicas", "Imágenes revisadas y hallazgos"),
                ],
            },
        ],
    },
    "dermatologia": {
        "label": "Dermatología",
        "sections": [
            {
                "title": "Evaluación dermatológica",
                "fields": [
                    _field("tipo_lesion", "Tipo de lesión primaria", "text", required=True, max_length=150),
                    _field("localizacion", "Localización y distribución"),
                    _field("extension", "Extensión o superficie corporal afectada"),
                    _field("morfologia", "Morfología, color y bordes"),
                    _field("evolucion_lesion", "Evolución de la lesión"),
                    _field("sintomas_cutaneos", "Prurito, dolor u otros síntomas"),
                    _field("exposiciones", "Exposiciones, productos o contactos"),
                    _field("dermatoscopia", "Hallazgos de dermatoscopia"),
                ],
            },
        ],
    },
    "oftalmologia": {
        "label": "Oftalmología",
        "sections": [
            {
                "title": "Evaluación oftalmológica",
                "fields": [
                    _field("ojo_afectado", "Ojo evaluado", "select", options=["Derecho", "Izquierdo", "Ambos"]),
                    _field("agudeza_visual_od", "Agudeza visual OD", "text", max_length=50),
                    _field("agudeza_visual_oi", "Agudeza visual OI", "text", max_length=50),
                    _field("presion_intraocular_od", "Presión intraocular OD (mmHg)", "number", min=0, max=80, step=0.1),
                    _field("presion_intraocular_oi", "Presión intraocular OI (mmHg)", "number", min=0, max=80, step=0.1),
                    _field("segmento_anterior", "Segmento anterior"),
                    _field("fondo_ojo", "Fondo de ojo"),
                    _field("motilidad_pupilas", "Motilidad ocular y pupilas"),
                    _field("refraccion", "Refracción"),
                ],
            },
        ],
    },
    "otorrinolaringologia": {
        "label": "Otorrinolaringología",
        "sections": [
            {
                "title": "Evaluación ORL",
                "fields": [
                    _field("area_afectada", "Área principal", "select", options=["Oído", "Nariz y senos", "Garganta y laringe", "Cuello", "Múltiple"]),
                    _field("lateralidad", "Lateralidad", "select", options=LATERALITY),
                    _field("otoscopia", "Otoscopia"),
                    _field("audicion", "Audición, tinnitus o vértigo"),
                    _field("exploracion_nasal", "Exploración nasal y senos paranasales"),
                    _field("orofaringe", "Orofaringe y laringe"),
                    _field("cuello", "Cuello y adenopatías"),
                    _field("pruebas_orl", "Audiometría u otras pruebas"),
                ],
            },
        ],
    },
    "neurologia": {
        "label": "Neurología",
        "sections": [
            {
                "title": "Evaluación neurológica",
                "fields": [
                    _field("estado_mental", "Estado mental y orientación"),
                    _field("pares_craneales", "Pares craneales"),
                    _field("fuerza_muscular", "Fuerza muscular"),
                    _field("sensibilidad", "Sensibilidad"),
                    _field("reflejos", "Reflejos"),
                    _field("coordinacion", "Coordinación y marcha"),
                    _field("glasgow", "Escala de Glasgow", "number", min=3, max=15, step=1),
                    _field("crisis", "Crisis, pérdida de conciencia o aura"),
                    _field("cefalea", "Características de cefalea"),
                ],
            },
        ],
    },
    "psiquiatria": {
        "label": "Psiquiatría",
        "sections": [
            {
                "title": "Examen mental y riesgo",
                "fields": [
                    _field("apariencia_conducta", "Apariencia y conducta"),
                    _field("estado_animo", "Estado de ánimo y afecto"),
                    _field("lenguaje_pensamiento", "Lenguaje y curso del pensamiento"),
                    _field("percepcion", "Percepción"),
                    _field("cognicion", "Cognición, orientación y memoria"),
                    _field("juicio_insight", "Juicio e introspección"),
                    _field("riesgo_suicida", "Riesgo suicida", "select", required=True, options=["No identificado", "Bajo", "Moderado", "Alto"]),
                    _field("riesgo_violencia", "Riesgo de violencia", "select", options=["No identificado", "Bajo", "Moderado", "Alto"]),
                    _field("red_apoyo", "Red de apoyo y factores protectores"),
                    _field("consumo_sustancias", "Consumo de sustancias"),
                ],
            },
        ],
    },
    "general": {
        "label": "Evaluación especializada",
        "sections": [
            {
                "title": "Evaluación de la especialidad",
                "fields": [
                    _field("hallazgos_especificos", "Hallazgos específicos"),
                    _field("escalas_pruebas", "Escalas o pruebas aplicadas"),
                    _field("consideraciones", "Consideraciones de la especialidad"),
                ],
            },
        ],
    },
}


SPECIALTY_ALIASES = {
    "medicina general": "medicina-general",
    "medicina interna": "medicina-general",
    "medico general": "medicina-general",
    "medicina familiar": "medicina-general",
    "pediatria": "pediatria",
    "ginecologia": "ginecologia",
    "ginecologia y obstetricia": "ginecologia",
    "obstetricia": "ginecologia",
    "cardiologia": "cardiologia",
    "ortopedia": "ortopedia",
    "ortopedia y traumatologia": "ortopedia",
    "traumatologia": "ortopedia",
    "dermatologia": "dermatologia",
    "oftalmologia": "oftalmologia",
    "otorrinolaringologia": "otorrinolaringologia",
    "orl": "otorrinolaringologia",
    "neurologia": "neurologia",
    "psiquiatria": "psiquiatria",
}


def normalize_specialty(value):
    """Convertir una especialidad libre a una clave de esquema estable."""
    normalized = unicodedata.normalize("NFKD", str(value or ""))
    normalized = "".join(char for char in normalized if not unicodedata.combining(char))
    normalized = re.sub(r"\s+", " ", normalized.casefold()).strip()
    return SPECIALTY_ALIASES.get(normalized, "general")


def get_specialty_schema(specialty):
    """Obtener una copia segura del esquema público para una especialidad."""
    key = normalize_specialty(specialty)
    schema = deepcopy(SPECIALTY_SCHEMAS[key])
    schema["key"] = key
    schema["version"] = SCHEMA_VERSION
    schema["source_specialty"] = str(specialty or "").strip()
    return schema


def validate_specialty_data(form, schema):
    """Validar y normalizar respuestas dinámicas enviadas por un formulario."""
    values = {}
    errors = []
    for section in schema["sections"]:
        for field in section["fields"]:
            name = field["name"]
            raw_value = form.get(f"{FIELD_PREFIX}{name}", "")
            dependency = field.get("depends_on")
            if dependency:
                controller = form.get(
                    f"{FIELD_PREFIX}{dependency['field']}",
                    "",
                )
                if str(controller).strip() != str(dependency["equals"]):
                    values[name] = None
                    continue
            if field["type"] == "checkbox":
                value = str(raw_value).lower() in {"1", "true", "on", "yes"}
            else:
                value = str(raw_value or "").strip()

            if field.get("required") and (value == "" or value is False):
                errors.append(f"{field['label']} es obligatorio")
                continue
            if value == "":
                values[name] = None
                continue

            if field["type"] == "number":
                try:
                    number = float(value)
                except (TypeError, ValueError):
                    errors.append(f"{field['label']} debe ser un número válido")
                    continue
                if number < field.get("min", number) or number > field.get("max", number):
                    errors.append(f"{field['label']} está fuera del rango permitido")
                    continue
                value = int(number) if field.get("step") == 1 and number.is_integer() else number
            elif field["type"] == "date":
                try:
                    date.fromisoformat(value)
                except ValueError:
                    errors.append(f"{field['label']} debe ser una fecha válida")
                    continue
            elif field["type"] == "select" and value not in field.get("options", []):
                errors.append(f"{field['label']} contiene una opción no permitida")
                continue
            else:
                max_length = int(field.get("max_length", 5000))
                if len(value) > max_length:
                    errors.append(f"{field['label']} supera {max_length} caracteres")
                    continue

            values[name] = value
    return values, errors
