import unittest
from unittest.mock import patch

from services.tenant_mail import (
    enviar_correo_consultorio,
    resumen_correo_empresa,
    smtp_consultorio_listo,
)


class TenantMailTests(unittest.TestCase):
    def test_summary_exposes_empty_smtp_when_company_has_none(self):
        resumen = resumen_correo_empresa(None)
        self.assertFalse(resumen['configurado'])
        self.assertFalse(resumen['listo_para_enviar'])
        self.assertEqual(resumen['smtp_port'], 587)
        self.assertEqual(resumen['smtp_host'], '')

    def test_summary_marks_configured_when_host_and_sender_exist(self):
        resumen = resumen_correo_empresa({
            'smtp_host': 'smtp.consultorio.do',
            'smtp_remitente': 'citas@consultorio.do',
            'smtp_password_cifrado': 'x',
        })
        self.assertTrue(resumen['configurado'])
        self.assertTrue(resumen['listo_para_enviar'])
        self.assertTrue(resumen['tiene_password'])

    def test_listo_requiere_password(self):
        self.assertFalse(smtp_consultorio_listo({
            'smtp_host': 'smtp.gmail.com',
            'smtp_remitente': 'a@b.com',
        }))

    def test_smtp_configurado_no_usa_plataforma_si_falla(self):
        empresa = {
            'smtp_host': 'smtp.gmail.com',
            'smtp_remitente': 'a@b.com',
            'smtp_password_cifrado': 'token',
        }
        with (
            patch('services.tenant_mail.execute_query', return_value=empresa),
            patch('services.tenant_mail.asegurar_esquema_correo'),
            patch(
                'services.tenant_mail._enviar_smtp',
                return_value=(False, 'Auth failed'),
            ),
            patch('services.platform_mail.enviar_correo_plataforma') as plataforma,
        ):
            ok, detalle = enviar_correo_consultorio(
                1, 'paciente@example.com', 'Asunto', '<p>Hola</p>',
            )
        self.assertFalse(ok)
        self.assertEqual(detalle, 'Auth failed')
        plataforma.assert_not_called()

    def test_sin_smtp_usa_plataforma(self):
        with (
            patch('services.tenant_mail.execute_query', return_value={}),
            patch('services.tenant_mail.asegurar_esquema_correo'),
            patch(
                'services.platform_mail.enviar_correo_plataforma',
                return_value=(True, 'ok'),
            ) as plataforma,
        ):
            ok, _detalle = enviar_correo_consultorio(
                1, 'paciente@example.com', 'Asunto', '<p>Hola</p>',
            )
        self.assertTrue(ok)
        plataforma.assert_called_once()
