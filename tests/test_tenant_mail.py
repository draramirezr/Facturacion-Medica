import unittest

from services.tenant_mail import resumen_correo_empresa


class TenantMailTests(unittest.TestCase):
    def test_summary_exposes_empty_smtp_when_company_has_none(self):
        resumen = resumen_correo_empresa(None)
        self.assertFalse(resumen['configurado'])
        self.assertEqual(resumen['smtp_port'], 587)
        self.assertEqual(resumen['smtp_host'], '')

    def test_summary_marks_configured_when_host_and_sender_exist(self):
        resumen = resumen_correo_empresa({
            'smtp_host': 'smtp.consultorio.do',
            'smtp_remitente': 'citas@consultorio.do',
            'smtp_password_cifrado': 'x',
        })
        self.assertTrue(resumen['configurado'])
        self.assertTrue(resumen['tiene_password'])
