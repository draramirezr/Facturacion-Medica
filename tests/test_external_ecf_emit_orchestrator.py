import unittest
from decimal import Decimal

from integrations.external_ecf_service.adapters.hka.mapper import HkaMappedDocument
from integrations.external_ecf_service.domain.canonical import CanonicalElectronicDocument
from integrations.external_ecf_service.services.external_emit_orchestrator import (
    ExternalEmitOrchestrator,
)


def _mapped_e32():
    canonical = CanonicalElectronicDocument(
        schema_version='1',
        document_type='E32',
        encf='E320000000099',
        issuer_rnc='01400204101',
        issuer={},
        buyer={},
        currency_code='DOP',
        exchange_rate=None,
        lines=[],
        subtotals=[],
        discounts_surcharges=[],
        totals={},
        payment_forms=[],
        reference=None,
        fiscal_dates={},
        branch=None,
        identification={},
        other_currency=None,
        transport=None,
        additional_info=None,
        pagination=[],
        observations=[],
        installments=[],
        serial_device=None,
        dgii_motor_ready=False,
        dgii_motor_notes=['E32 pendiente'],
    )
    return HkaMappedDocument(
        canonical=canonical,
        external_document_id='V-1',
        fecha_documento='2026-11-14',
        moneda='DOP',
        total=Decimal('160'),
        tipo_ecf='E32',
        encf='E320000000099',
        rnc_emisor='01400204101',
        rnc_comprador=None,
    )


class ExternalEmitOrchestratorTests(unittest.TestCase):
    def test_e32_en_cola_fase3(self):
        result = ExternalEmitOrchestrator().attempt(
            tenant_id=16,
            mapped=_mapped_e32(),
        )
        self.assertEqual(result.estado_documento, 'pendiente_emision')
        self.assertTrue(result.emit_attempted)
        self.assertIn('E32', result.mensaje_respuesta)


if __name__ == '__main__':
    unittest.main()