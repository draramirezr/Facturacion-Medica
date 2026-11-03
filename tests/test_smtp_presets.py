import unittest

from services.smtp_presets import (
    estado_configuracion_smtp,
    sugerir_preset_por_remitente,
    validar_formulario_smtp,
)


class SmtpPresetsTests(unittest.TestCase):
    def test_sugiere_outlook_para_hotmail(self):
        self.assertEqual(
            sugerir_preset_por_remitente('francis_2416@hotmail.com'),
            'outlook',
        )

    def test_sugiere_gmail(self):
        self.assertEqual(
            sugerir_preset_por_remitente('clinica@gmail.com'),
            'gmail',
        )

    def test_estado_listo_con_password(self):
        estado = estado_configuracion_smtp({
            'smtp_host': 'smtp.gmail.com',
            'smtp_remitente': 'a@b.com',
            'tiene_password': True,
        })
        self.assertTrue(estado['listo_para_enviar'])
        self.assertEqual(estado['faltantes'], [])

    def test_validacion_exige_host_si_hay_remitente(self):
        self.assertIn(
            'servidor SMTP',
            validar_formulario_smtp('', 'a@b.com', None, False, False),
        )

    def test_prueba_exige_password(self):
        self.assertIn(
            'contraseña',
            validar_formulario_smtp(
                'smtp.gmail.com', 'a@gmail.com', None, False, True,
            ).lower(),
        )


if __name__ == '__main__':
    unittest.main()
