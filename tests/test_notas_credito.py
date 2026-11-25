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

    def test_crear_bloquea_factura_antes_de_calcular_saldo(self):
        from flask import Flask, g

        from services.notas_credito import crear_nota_credito

        consultas = []

        def fake_query(sql, params=None, fetch="one"):
            consultas.append(sql)
            if "FOR UPDATE" in sql:
                return {"id": 99}
            raise AssertionError("se detiene tras la primera lectura de saldo")

        app = Flask(__name__)
        with app.app_context():
            g.db_transaction_active = True
            with patch("services.notas_credito.execute_query", side_effect=fake_query):
                with self.assertRaises(AssertionError):
                    crear_nota_credito(
                        tenant_id=1, factura_id=99, tipo="total",
                        motivo="Error de monto", usuario_id=5,
                    )
        self.assertIn("FOR UPDATE", consultas[0])
        self.assertIn("tenant_id=%s", consultas[0])

    def test_crear_exige_transaccion(self):
        from flask import Flask

        from services.notas_credito import crear_nota_credito

        app = Flask(__name__)
        with app.app_context(), patch("services.notas_credito.execute_query") as query:
            with self.assertRaises(RuntimeError):
                crear_nota_credito(
                    tenant_id=1, factura_id=99, tipo="total",
                    motivo="Error", usuario_id=5,
                )
            query.assert_not_called()


if __name__ == "__main__":
    unittest.main()