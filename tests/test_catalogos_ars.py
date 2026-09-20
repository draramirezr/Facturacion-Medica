import unittest
from unittest.mock import patch

from services.catalogos_ars import ARS_PREDETERMINADAS, sembrar_ars_tenant


class CatalogosArsTests(unittest.TestCase):
    def test_catalogo_incluye_ars_nacionales(self):
        codigos = {codigo for codigo, _nombre in ARS_PREDETERMINADAS}
        self.assertIn('SENASA', codigos)
        self.assertIn('HUMANO', codigos)
        self.assertIn('UNIVERSAL', codigos)
        self.assertGreaterEqual(len(ARS_PREDETERMINADAS), 10)

    def test_no_siembra_sin_empresa(self):
        self.assertEqual(sembrar_ars_tenant(None), 0)
        self.assertEqual(sembrar_ars_tenant(0), 0)

    def test_inserta_solo_ars_faltantes(self):
        existentes = [{'codigo': 'SENASA'}, {'codigo': 'HUMANO'}]
        with (
            patch(
                'services.catalogos_ars.execute_query',
                return_value=existentes,
            ),
            patch('services.catalogos_ars.execute_update') as update,
        ):
            creadas = sembrar_ars_tenant(22)
        self.assertEqual(
            creadas, len(ARS_PREDETERMINADAS) - len(existentes)
        )
        self.assertEqual(update.call_count, creadas)
        primer_insert = update.call_args_list[0].args
        self.assertIn('INSERT INTO ars', primer_insert[0])
        self.assertEqual(primer_insert[1][0], 22)
