from types import SimpleNamespace
import unittest

import requests

from ecf.dgii import (
    DGIIClient,
    DGIIClientError,
    DGIIResponseError,
    DGIITimeoutError,
    DGIIToken,
    classify_dgii_status,
)


class FakeResponse:
    def __init__(self, status_code=200, payload=None, content=None):
        self.status_code = status_code
        self._payload = payload
        if content is None and payload is not None:
            import json
            content = json.dumps(payload).encode("utf-8")
        self.content = content or b""
        self.text = self.content.decode("utf-8", errors="replace")

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []
        self.headers = {}

    def request(self, method, url, **kwargs):
        self.requests.append((method, url, kwargs))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class FakeSigner:
    def __init__(self):
        self.calls = []

    def sign_authentication_seed(self, xml, expected_signer_id):
        self.calls.append((xml, expected_signer_id))
        return SimpleNamespace(signed_xml="<Semilla><Signature/></Semilla>")


def make_config(environment="PRUEBAS"):
    segment = {
        "PRUEBAS": "testecf",
        "CERTIFICACION": "certecf",
        "PRODUCCION": "ecf",
    }[environment]
    base_url = f"https://ecf.dgii.gov.do/{segment}"
    return SimpleNamespace(
        environment=environment,
        enabled=environment != "PRODUCCION",
        allow_production=False,
        authentication_url=f"{base_url}/autenticacion",
        reception_url=f"{base_url}/recepcion",
        result_url=f"{base_url}/consultaresultado",
        track_url=f"{base_url}/consultatrackids",
        connect_timeout_seconds=10,
        read_timeout_seconds=30,
    )


class DGIIClientTests(unittest.TestCase):
    def test_authenticates_and_submits_to_official_resources(self):
        session = FakeSession([
            FakeResponse(content=b"<Semilla><valor>abc</valor></Semilla>"),
            FakeResponse(payload={
                "token": "token-secreto",
                "expira": "2026-09-11T23:00:00Z",
                "expedido": "2026-09-11T22:00:00Z",
            }),
            FakeResponse(payload={
                "trackId": "TRACK-123",
                "error": "",
                "mensaje": "",
            }),
        ])
        signer = FakeSigner()
        client = DGIIClient(make_config(), signer=signer, session=session)

        result = client.submit_e31(
            "<ECF><Signature/></ECF>",
            "101672919",
            "E310000000001",
        )

        self.assertEqual(result.track_id, "TRACK-123")
        self.assertEqual(
            session.requests[0][1],
            "https://ecf.dgii.gov.do/testecf/autenticacion/"
            "api/autenticacion/semilla",
        )
        self.assertEqual(
            session.requests[1][1],
            "https://ecf.dgii.gov.do/testecf/autenticacion/"
            "api/autenticacion/validarsemilla",
        )
        self.assertEqual(
            session.requests[2][1],
            "https://ecf.dgii.gov.do/testecf/recepcion/"
            "api/facturaselectronicas",
        )
        reception_kwargs = session.requests[2][2]
        self.assertEqual(
            reception_kwargs["headers"]["Authorization"],
            "Bearer token-secreto",
        )
        self.assertEqual(
            reception_kwargs["files"]["xml"][0],
            "101672919E310000000001.xml",
        )
        self.assertNotIn("token-secreto", repr(result))

    def test_reception_timeout_is_marked_as_uncertain(self):
        session = FakeSession([
            FakeResponse(content=b"<Semilla/>"),
            FakeResponse(payload={"token": "secret"}),
            requests.Timeout("timeout"),
        ])
        client = DGIIClient(
            make_config(), signer=FakeSigner(), session=session
        )
        with self.assertRaises(DGIITimeoutError) as captured:
            client.submit_e31(
                "<ECF/>", "101672919", "E310000000001"
            )
        self.assertTrue(captured.exception.delivery_uncertain)
        self.assertNotIn("secret", str(captured.exception))

    def test_http_success_without_trackid_is_not_success(self):
        session = FakeSession([
            FakeResponse(content=b"<Semilla/>"),
            FakeResponse(payload={"token": "secret"}),
            FakeResponse(payload={"mensaje": "Documento no recibido"}),
        ])
        client = DGIIClient(
            make_config(), signer=FakeSigner(), session=session
        )
        with self.assertRaisesRegex(
            DGIIResponseError, "Documento no recibido"
        ) as captured:
            client.submit_e31(
                "<ECF/>", "101672919", "E310000000001"
            )
        self.assertTrue(captured.exception.delivery_uncertain)

    def test_accepts_xml_contract_responses(self):
        session = FakeSession([
            FakeResponse(content=b"<Semilla/>"),
            FakeResponse(content=(
                b"<TokenModel><token>secret</token>"
                b"<expira>2026-09-11T23:00:00Z</expira></TokenModel>"
            )),
            FakeResponse(content=(
                b"<Recepcion><trackId>TRACK-XML</trackId></Recepcion>"
            )),
        ])
        result = DGIIClient(
            make_config(), signer=FakeSigner(), session=session
        ).submit_e31("<ECF/>", "101672919", "E310000000001")
        self.assertEqual(result.track_id, "TRACK-XML")

    def test_production_is_explicitly_blocked(self):
        with self.assertRaisesRegex(DGIIClientError, "no permite producción"):
            DGIIClient(
                make_config("PRODUCCION"),
                signer=FakeSigner(),
                session=FakeSession([]),
            )

    def test_production_client_requires_and_accepts_both_explicit_gates(self):
        config = make_config("PRODUCCION")
        config.enabled = True
        config.allow_production = True
        client = DGIIClient(
            config,
            signer=FakeSigner(),
            session=FakeSession([]),
        )
        self.assertEqual(client.config.environment, "PRODUCCION")

    def test_queries_result_by_trackid(self):
        session = FakeSession([
            FakeResponse(payload={
                "trackId": "TRACK-123",
                "codigo": 1,
                "estado": "Aceptado",
                "rnc": "101672919",
                "eNCF": "E310000000001",
                "secuenciaUtilizada": True,
                "fechaRecepcion": "2026-09-11T22:00:00",
                "mensajes": [{"codigo": 100, "valor": "Documento válido"}],
            }),
        ])
        client = DGIIClient(
            make_config(), signer=FakeSigner(), session=session
        )
        result = client.query_result(
            "TRACK-123",
            "101672919",
            token=DGIIToken("secret"),
        )
        self.assertEqual(result.code, "1")
        self.assertEqual(result.status, "Aceptado")
        self.assertTrue(result.sequence_used)
        self.assertEqual(result.messages, ("100: Documento válido",))
        self.assertEqual(
            session.requests[0][2]["params"],
            {"trackid": "TRACK-123"},
        )

    def test_finds_trackid_before_any_retry(self):
        session = FakeSession([
            FakeResponse(payload=[
                {
                    "trackId": "TRACK-FOUND",
                    "estado": "En Proceso",
                    "fechaRecepcion": "2026-09-11T22:00:00",
                }
            ]),
        ])
        client = DGIIClient(
            make_config(), signer=FakeSigner(), session=session
        )
        results = client.find_track_ids(
            "101672919",
            "E310000000001",
            token=DGIIToken("secret"),
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].track_id, "TRACK-FOUND")
        self.assertEqual(
            session.requests[0][2]["params"],
            {
                "rncemisor": "101672919",
                "encf": "E310000000001",
            },
        )

    def test_classifies_only_final_official_statuses_as_final(self):
        self.assertEqual(classify_dgii_status(1, "Aceptado"), "ACEPTADO")
        self.assertEqual(
            classify_dgii_status(4, "Aceptado Condicional"), "ACEPTADO"
        )
        self.assertEqual(classify_dgii_status(2, "Rechazado"), "RECHAZADO")
        self.assertEqual(classify_dgii_status(3, "En Proceso"), "ENVIADO")
        self.assertEqual(classify_dgii_status(0, "No encontrado"), "ENVIADO")


if __name__ == "__main__":
    unittest.main()
