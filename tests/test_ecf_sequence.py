import unittest
from datetime import date, timedelta

from ecf.sequence import (
    ECFSequenceError,
    ECFSequenceExhausted,
    build_encf,
    reserve_encf,
)


class FakeCursor:
    def __init__(self, sequence):
        self.sequence = sequence
        self.rowcount = 0
        self._mode = None

    def execute(self, query, params):
        normalized = " ".join(query.split()).upper()
        self.rowcount = 0
        if "FROM ECF_SECUENCIAS" in normalized:
            self._mode = "sequences"
        elif "FROM FACTURAS_ECF" in normalized:
            self._mode = "duplicate"
        elif normalized.startswith("UPDATE ECF_SECUENCIAS"):
            self.sequence["ultimo_numero"] = params[0]
            self.rowcount = 1
            self._mode = "updated"
        else:
            raise AssertionError(f"Consulta inesperada: {normalized}")

    def fetchall(self):
        return [self.sequence] if self._mode == "sequences" else []

    def fetchone(self):
        return None


class ENCFSequenceTests(unittest.TestCase):
    def make_sequence(self, **overrides):
        sequence = {
            "id": 7,
            "tenant_id": 1,
            "tipo_ecf": "31",
            "secuencia_inicial": 1,
            "secuencia_final": 3,
            "ultimo_numero": 0,
            "fecha_autorizacion": date.today() - timedelta(days=1),
            "fecha_vencimiento": date.today() + timedelta(days=30),
            "activo": 1,
        }
        sequence.update(overrides)
        return sequence

    def test_builds_official_thirteen_character_format(self):
        self.assertEqual(build_encf("31", 1), "E310000000001")
        self.assertEqual(len(build_encf("31", 1)), 13)

    def test_rejects_invalid_type_and_number(self):
        with self.assertRaises(ECFSequenceError):
            build_encf("3", 1)
        with self.assertRaises(ECFSequenceError):
            build_encf("31", 0)

    def test_reserves_consecutive_numbers_within_same_transaction(self):
        cursor = FakeCursor(self.make_sequence())
        first = reserve_encf(cursor, tenant_id=1)
        second = reserve_encf(cursor, tenant_id=1)
        self.assertEqual(first.value, "E310000000001")
        self.assertEqual(second.value, "E310000000002")

    def test_does_not_exceed_authorized_range(self):
        cursor = FakeCursor(self.make_sequence(ultimo_numero=3))
        with self.assertRaises(ECFSequenceExhausted):
            reserve_encf(cursor, tenant_id=1)


if __name__ == "__main__":
    unittest.main()
