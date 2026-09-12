import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import app as app_module
import routes.messaging as messaging_routes
import routes.users_roles as users_roles_routes


class InternalMessagingTests(unittest.TestCase):
    def setUp(self):
        self.flask_app = app_module.app
        self.flask_app.config.update(TESTING=True)
        self.user = SimpleNamespace(
            id=10,
            tenant_id=5,
            is_authenticated=True,
        )

    @staticmethod
    def _unwrapped(handler):
        while hasattr(handler, "__wrapped__"):
            handler = handler.__wrapped__
        return handler

    def test_user_list_is_scoped_to_current_tenant(self):
        handler = self._unwrapped(messaging_routes.api_mensajeria_usuarios)
        with self.flask_app.test_request_context(
            "/api/mensajeria/usuarios"
        ), patch.object(
            messaging_routes,
            "current_user",
            self.user,
        ), patch.object(
            messaging_routes,
            "get_current_tenant_id",
            return_value=5,
        ), patch.object(
            messaging_routes,
            "execute_query",
            return_value=[],
        ) as execute_query:
            response = handler()

        self.assertEqual(response.status_code, 200)
        query, params = execute_query.call_args.args[:2]
        self.assertIn("tenant_id=%s", query)
        self.assertEqual(params, (5, 10))

    def test_message_rejects_recipient_from_another_tenant(self):
        handler = self._unwrapped(messaging_routes.api_mensajeria_enviar)
        with self.flask_app.test_request_context(
            "/api/mensajeria/mensajes",
            method="POST",
            json={"destinatario_id": 22, "cuerpo": "Hola"},
        ), patch.object(
            messaging_routes,
            "current_user",
            self.user,
        ), patch.object(
            messaging_routes,
            "get_current_tenant_id",
            return_value=5,
        ), patch.object(
            messaging_routes,
            "execute_query",
            return_value=None,
        ) as execute_query, patch.object(
            messaging_routes,
            "execute_update",
        ) as execute_update:
            response, status = handler()

        self.assertEqual(status, 404)
        self.assertEqual(execute_query.call_args.args[1], (22, 5))
        execute_update.assert_not_called()
        self.assertIn("no encontrado", response.get_json()["error"])

    def test_send_creates_canonical_pair_and_sanitizes_text(self):
        handler = self._unwrapped(messaging_routes.api_mensajeria_enviar)
        with self.flask_app.test_request_context(
            "/api/mensajeria/mensajes",
            method="POST",
            json={"destinatario_id": 7, "cuerpo": "<b>Hola</b>"},
        ), patch.object(
            messaging_routes,
            "current_user",
            self.user,
        ), patch.object(
            messaging_routes,
            "get_current_tenant_id",
            return_value=5,
        ), patch.object(
            messaging_routes,
            "execute_query",
            return_value={"id": 7, "nombre": "Ana", "perfil": "Nivel 2"},
        ), patch.object(
            messaging_routes,
            "execute_update",
            side_effect=[31, 91, None],
        ) as execute_update:
            response, status = handler()

        self.assertEqual(status, 201)
        conversation_params = execute_update.call_args_list[0].args[1]
        self.assertEqual(conversation_params, (5, 7, 10))
        message_params = execute_update.call_args_list[1].args[1]
        self.assertEqual(message_params, (5, 31, 10, 7, "Hola"))
        self.assertEqual(response.get_json()["mensaje"]["cuerpo"], "Hola")

    def test_message_body_over_limit_is_rejected_before_database_write(self):
        handler = self._unwrapped(messaging_routes.api_mensajeria_enviar)
        with self.flask_app.test_request_context(
            "/api/mensajeria/mensajes",
            method="POST",
            json={"destinatario_id": 7, "cuerpo": "a" * 4001},
        ), patch.object(
            messaging_routes,
            "current_user",
            self.user,
        ), patch.object(
            messaging_routes,
            "get_current_tenant_id",
            return_value=5,
        ), patch.object(
            messaging_routes,
            "execute_update",
        ) as execute_update:
            _, status = handler()

        self.assertEqual(status, 400)
        execute_update.assert_not_called()

    def test_loading_messages_checks_user_and_conversation_tenant(self):
        handler = self._unwrapped(messaging_routes.api_mensajeria_mensajes)
        message = {
            "id": 80,
            "remitente_id": 7,
            "destinatario_id": 10,
            "cuerpo": "Mensaje",
            "created_at": "2026-09-12 07:00:00",
            "leido_at": None,
        }
        with self.flask_app.test_request_context(
            "/api/mensajeria/mensajes/7?after_id=70"
        ), patch.object(
            messaging_routes,
            "current_user",
            self.user,
        ), patch.object(
            messaging_routes,
            "get_current_tenant_id",
            return_value=5,
        ), patch.object(
            messaging_routes,
            "execute_query",
            side_effect=[
                {"id": 7, "nombre": "Ana", "perfil": "Nivel 2"},
                {"id": 31},
                [message],
            ],
        ) as execute_query:
            response = handler(7)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["mensajes"][0]["id"], 80)
        self.assertEqual(execute_query.call_args_list[0].args[1], (7, 5))
        self.assertEqual(execute_query.call_args_list[1].args[1], (5, 7, 10))
        self.assertEqual(execute_query.call_args_list[2].args[1], (5, 31, 70))

    def test_mark_read_updates_only_messages_for_current_recipient(self):
        handler = self._unwrapped(messaging_routes.api_mensajeria_marcar_leidos)
        with self.flask_app.test_request_context(
            "/api/mensajeria/leer",
            method="POST",
            json={"usuario_id": 7, "hasta_id": 99},
        ), patch.object(
            messaging_routes,
            "current_user",
            self.user,
        ), patch.object(
            messaging_routes,
            "get_current_tenant_id",
            return_value=5,
        ), patch.object(
            messaging_routes,
            "execute_query",
            side_effect=[
                {"id": 7, "nombre": "Ana", "perfil": "Nivel 2"},
                {"id": 31},
            ],
        ), patch.object(
            messaging_routes,
            "execute_update",
        ) as execute_update:
            response = handler()

        self.assertEqual(response.status_code, 200)
        query, params = execute_update.call_args.args
        self.assertIn("destinatario_id=%s", query)
        self.assertEqual(params, (5, 31, 10, 7, 99))

    def test_no_unread_count_is_scoped_to_recipient_and_tenant(self):
        handler = self._unwrapped(messaging_routes.api_mensajeria_no_leidos)
        with self.flask_app.test_request_context(
            "/api/mensajeria/no-leidos"
        ), patch.object(
            messaging_routes,
            "current_user",
            self.user,
        ), patch.object(
            messaging_routes,
            "get_current_tenant_id",
            return_value=5,
        ), patch.object(
            messaging_routes,
            "execute_query",
            return_value={"total": 4},
        ) as execute_query:
            response = handler()

        self.assertEqual(response.get_json()["total"], 4)
        self.assertEqual(execute_query.call_args.args[1], (5, 10))

    def test_schema_and_authenticated_shell_include_messaging(self):
        root = Path(app_module.__file__).resolve().parent
        migration = (root / "crear_modulo_mensajeria_interna.py").read_text(
            encoding="utf-8"
        )
        template = (root / "templates" / "base.html").read_text(
            encoding="utf-8"
        )
        settings = (
            root / "templates" / "perfil" / "configuracion.html"
        ).read_text(encoding="utf-8")
        self.assertIn("UNIQUE KEY uq_conversacion_pareja", migration)
        self.assertIn("tenant_id INT NOT NULL", migration)
        self.assertIn("mostrar_chat TINYINT(1) NOT NULL DEFAULT 1", migration)
        self.assertIn("id=\"arsChatPanel\"", template)
        self.assertIn("class=\"ars-chat-fab\"", template)
        self.assertIn("{% if current_user.mostrar_chat %}", template)
        self.assertIn("js/chat.js", template)
        self.assertIn('name="mostrar_chat"', settings)

    def test_profile_can_hide_floating_chat_button(self):
        handler = self._unwrapped(users_roles_routes.perfil_configuracion)
        user = SimpleNamespace(
            id=10,
            tenant_id=5,
            is_authenticated=True,
            tema_color="cyan",
            fuente_ui="arsflow",
            mostrar_chat=True,
        )
        with self.flask_app.test_request_context(
            "/perfil/configuracion",
            method="POST",
            data={"tema_color": "cyan", "fuente_ui": "arsflow"},
        ), patch.object(
            users_roles_routes,
            "current_user",
            user,
        ), patch.object(
            users_roles_routes,
            "get_current_tenant_id",
            return_value=5,
        ), patch.object(
            users_roles_routes,
            "execute_update",
        ) as execute_update:
            response = handler()

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            execute_update.call_args.args[1],
            ("cyan", "arsflow", 0, 10, 5),
        )
        self.assertFalse(user.mostrar_chat)

    def test_chat_is_visible_by_default_for_new_user_objects(self):
        user = app_module.User(
            id=1,
            nombre="Usuario",
            email="u@example.test",
            perfil="Nivel 2",
        )
        self.assertTrue(user.mostrar_chat)


if __name__ == "__main__":
    unittest.main()
