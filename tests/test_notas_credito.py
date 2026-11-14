import unittest
from unittest.mock import patch

from services.notas_credito import NotaCreditoError, saldo_creditable_factura


class NotasCreditoServiceTests(unittest.TestCase):
    @patch("services.notas_credito.execute_query")
    def test_saldo_resta_notas_confirmadas(self, mock_query):
        def side_effect(sql, params, fetch=None):
            if "FROM facturas" in sql and "total" in sql:
                return {"total": "1000.00", "estado": "Pagada"}
            if "SUM(total)" in sql:
                return {"acumulado": "300.00"}
            return None

        mock_query.side_effect = side_effect
        saldo = saldo_creditable_factura(1, 99)
        self.assertEqual(str(saldo), "700.00")

    @patch("services.notas_credito.execute_query")
    def test_factura_anulada_rechazada(self, mock_query):
        mock_query.return_value = {"total": "100", "estado": "Anulada"}
        with self.assertRaises(NotaCreditoError):
            saldo_creditable_factura(1, 1)


if __name__ == "__main__":
    unittest.main()