from datetime import datetime
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import app as app_module
import routes.clinical_history as clinical_history
from clinical_specialties import (
    SPECIALTY_SCHEMAS,
    get_specialty_schema,
    normalize_specialty,
    validate_specialty_data,
)


class ClinicalSpecialtySchemaTests(unittest.TestCase):
    def test_ten_requested_specialties_have_dedicated_schemas(self):
        expected = {
            "medicina-general",
            "pediatria",
            "ginecologia",
            "cardiologia",
            "ortopedia",
            "dermatologia",
            "oftalmologia",
            "otorrinolaringologia",
            "neurologia",
            "psiquiatria",
        }
        self.assertTrue(expected.issubset(SPECIALTY_SCHEMAS))
        self.assertEqual(len(expected), 10)
        for key in expected:
            schema = SPECIALTY_SCHEMAS[key]
            self.assertTrue(schema["sections"])
            self.assertTrue(schema["sections"][0]["fields"])

    def test_catalog_variants_are_normalized(self):
        cases = {
            "Medicina Interna": "medicina-general",
            "Ginecología y Obstetricia": "ginecologia",
            "Ortopedia y Traumatología": "ortopedia",
            "Otorrinolaringología": "otorrinolaringologia",
            "ORL": "otorrinolaringologia",
        }
        for source, expected in cases.items():
            with self.subTest(source=source):
                self.assertEqual(normalize_specialty(source), expected)

    def test_unknown_specialty_uses_generic_schema(self):
        schema = get_specialty_schema("Medicina del deporte")
        self.assertEqual(schema["key"], "general")
        self.assertEqual(schema["source_specialty"], "Medicina del deporte")

    def test_required_and_numeric_fields_are_validated(self):
        schema = get_specialty_schema("Ortopedia")
        _, errors = validate_specialty_data(
            {
                "especialidad_region_anatomica": "",
                "especialidad_escala_dolor": "20",
            },
            schema,
        )
        self.assertTrue(any("Región anatómica" in error for error in errors))
        self.assertTrue(any("Dolor" in error for error in errors))

    def test_dependent_field_is_ignored_when_condition_is_not_met(self):
        schema = get_specialty_schema("Ginecología")
        values, errors = validate_specialty_data(
            {
                "especialidad_embarazo_actual": "No",
                "especialidad_edad_gestacional_actual": "99",
            },
            schema,
        )
        self.assertEqual(errors, [])
        self.assertIsNone(values["edad_gestacional_actual"])

    def test_select_values_and_dates_are_rejected_server_side(self):
        schema = get_specialty_schema("Ginecología")
        _, errors = validate_specialty_data(
            {
                "especialidad_embarazo_actual": "Tal vez",
                "especialidad_fum": "2026-99-99",
            },
            schema,
        )
        self.assertEqual(len(errors), 2)


class ClinicalSpecialtyIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.flask_app = app_module.app
        self.flask_app.config.update(TESTING=True)

    @staticmethod
    def _unwrapped(handler):
        while hasattr(handler, "__wrapped__"):
            handler = handler.__wrapped__
        return handler

    def test_schema_endpoint_uses_doctor_from_current_tenant(self):
        handler = self._unwrapped(
            clinical_history.api_historia_clinica_plantilla_especialidad
        )
        with self.flask_app.test_request_context(
            "/api/facturacion/historia-clinica/plantilla-especialidad/8"
        ), patch.object(
            clinical_history,
            "get_current_tenant_id",
            return_value=14,
        ), patch.object(
            clinical_history,
            "execute_query",
            return_value={"id": 8, "especialidad": "Cardiología"},
        ) as execute_query:
            response = handler(8)

        self.assertEqual(response.get_json()["key"], "cardiologia")
        self.assertEqual(execute_query.call_args.args[1], (8, 14))

    def test_form_data_uses_server_side_doctor_specialty(self):
        with self.flask_app.test_request_context(
            "/facturacion/historia-clinica",
            method="POST",
            data={
                "especialidad_region_anatomica": "Rodilla",
                "especialidad_lateralidad": "Derecha",
                "especialidad_escala_dolor": "7",
            },
        ):
            data = {}
            error = clinical_history.completar_datos_especialidad(
                data,
                {"id": 5, "especialidad": "Ortopedia y Traumatología"},
            )

        self.assertIsNone(error)
        self.assertEqual(data["especialidad_consulta"], "Ortopedia y Traumatología")
        self.assertEqual(data["datos_especialidad"]["region_anatomica"], "Rodilla")
        self.assertEqual(data["datos_especialidad"]["escala_dolor"], 7)

    def test_new_consultation_persists_specialty_snapshot(self):
        handler = self._unwrapped(
            clinical_history.facturacion_historia_clinica_nueva
        )
        updates = []

        def execute_update(query, params=()):
            self.assertEqual(query.count("%s"), len(params))
            updates.append((query, params))
            return 81 if "INSERT INTO consultas_clinicas" in query else None

        form = {
            "fecha": datetime.now().strftime("%Y-%m-%d"),
            "hora": "09:30",
            "medico_id": "7",
            "motivo_consulta": "Control cardiovascular",
            "diagnostico_principal": "Hipertensión arterial",
            "especialidad_disnea_clase": "NYHA II",
            "especialidad_fraccion_eyeccion": "58.5",
        }
        patient = {
            "id": 3,
            "cedula": "00100000001",
            "fecha_nacimiento": "1980-01-01",
        }
        doctor = {"id": 7, "especialidad": "Cardiología"}
        with self.flask_app.test_request_context(
            "/facturacion/historia-clinica/paciente/3/nueva",
            method="POST",
            data=form,
        ), patch.object(
            clinical_history,
            "get_current_tenant_id",
            return_value=12,
        ), patch.object(
            clinical_history,
            "execute_query",
            side_effect=[patient, doctor],
        ), patch.object(
            clinical_history,
            "execute_update",
            side_effect=execute_update,
        ), patch.object(
            clinical_history,
            "sincronizar_cita_desde_historia",
            return_value=None,
        ), patch.object(
            clinical_history,
            "current_user",
            SimpleNamespace(id=22),
        ):
            response = handler(3)

        self.assertEqual(response.status_code, 302)
        insert_params = updates[0][1]
        self.assertEqual(insert_params[3], "Cardiología")
        self.assertEqual(insert_params[4], 1)
        specialty_data = json.loads(insert_params[5])
        self.assertEqual(specialty_data["disnea_clase"], "NYHA II")
        self.assertEqual(specialty_data["fraccion_eyeccion"], 58.5)

    def test_old_consultations_receive_safe_empty_specialty_data(self):
        consultation = {
            "id": 4,
            "medico_especialidad": "Neurología",
            "enfermedad_actual": "{}",
            "antecedentes_personales": "{}",
            "antecedentes_familiares": "{}",
            "signos_vitales": "{}",
            "examen_fisico": "{}",
            "plan_tratamiento": "{}",
        }
        with patch.object(
            clinical_history,
            "execute_query",
            return_value=consultation,
        ):
            result = clinical_history.obtener_consulta_clinica(4, 2)

        self.assertEqual(result["datos_especialidad"], {})
        self.assertEqual(result["esquema_especialidad"]["key"], "neurologia")

    def test_migration_declares_all_specialty_columns(self):
        migration = (
            Path(app_module.__file__).resolve().parent
            / "crear_modulo_historia_clinica.py"
        ).read_text(encoding="utf-8")
        for column in (
            "especialidad_consulta",
            "plantilla_version",
            "datos_especialidad",
        ):
            self.assertIn(column, migration)


if __name__ == "__main__":
    unittest.main()
