import unittest

from services.lab_catalog import coincidencias_catalogo


class LabCatalogSearchTests(unittest.TestCase):
    def test_finds_tests_by_partial_word(self):
        nombres = coincidencias_catalogo('hemo')
        self.assertTrue(any('Hemograma' in item for item in nombres))
        self.assertTrue(any('glicosilada' in item.lower() or 'HbA1c' in item for item in coincidencias_catalogo('hba')))

    def test_finds_by_synonym(self):
        orina = coincidencias_catalogo('ego')
        self.assertTrue(any('orina' in item.lower() for item in orina))

    def test_empty_query_is_empty(self):
        self.assertEqual(coincidencias_catalogo(''), [])
        self.assertEqual(coincidencias_catalogo('   '), [])


if __name__ == '__main__':
    unittest.main()
