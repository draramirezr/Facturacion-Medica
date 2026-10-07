"""Batería de pruebas DGII tras cargar el certificado por tenant."""

from datetime import datetime, timezone

from .certificates import ECFCertificateResolutionError, TenantCertificateProvider
from .dgii import DGIIClient, DGIIClientError, DGIIToken


def _step(name, ok, detail=""):
    return {
        "name": name,
        "ok": bool(ok),
        "detail": detail or ("OK" if ok else "Falló"),
    }


def _finish(ok, ambiente, started, steps, cert_meta=None):
    return {
        "ok": bool(ok),
        "ambiente": ambiente,
        "started_at": started,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "steps": steps,
        "certificado": cert_meta or {},
    }


def run_dgii_pruebas(
    *,
    config,
    tenant_id,
    tenant_config,
    issuer_rnc,
    client=None,
):
    """Certificado, semilla, firma, token y ping de recepción."""
    ambiente = getattr(config, "environment", "") or ""
    steps = []
    started = datetime.now(timezone.utc).isoformat()
    cert_meta = {}

    try:
        resolved, metadata = TenantCertificateProvider(config).inspect(
            tenant_id, issuer_rnc, tenant_config
        )
        signer = resolved.signer()
        vence = getattr(metadata, "valid_until", None)
        vence_txt = vence.date().isoformat() if vence else "sin fecha"
        huella = getattr(metadata, "fingerprint", "") or ""
        cert_meta = {
            "fingerprint": huella,
            "not_after": vence.isoformat() if vence else "",
        }
        steps.append(
            _step(
                "Certificado legible",
                True,
                f"Huella {huella[:16]}… · vence {vence_txt}" if huella else "OK",
            )
        )
    except (ECFCertificateResolutionError, Exception) as error:
        steps.append(_step("Certificado legible", False, str(error)))
        steps.append(_step("Semilla DGII", False, "Omitida"))
        steps.append(_step("Firma de semilla", False, "Omitida"))
        steps.append(_step("Token obtenido", False, "Omitido"))
        steps.append(_step("Conexión recepción", False, "Omitida"))
        return _finish(False, ambiente, started, steps)

    dgii = client or DGIIClient(config, signer=signer)
    seed_xml = None
    try:
        seed_xml = dgii.fetch_authentication_seed()
        steps.append(
            _step("Semilla DGII", True, f"Recibida ({len(seed_xml)} bytes)")
        )
    except DGIIClientError as error:
        steps.append(_step("Semilla DGII", False, str(error)))
        steps.append(_step("Firma de semilla", False, "Omitida (sin semilla)"))
        steps.append(_step("Token obtenido", False, "Omitido"))
        steps.append(_step("Conexión recepción", False, "Omitida"))
        return _finish(False, ambiente, started, steps, cert_meta)

    signed_seed = None
    try:
        signed_seed = dgii.sign_authentication_seed(seed_xml, issuer_rnc)
        signed_xml = getattr(signed_seed, "signed_xml", signed_seed)
        size = len(signed_xml) if signed_xml is not None else 0
        steps.append(_step("Firma de semilla", True, f"XML firmado ({size} bytes)"))
    except DGIIClientError as error:
        steps.append(_step("Firma de semilla", False, str(error)))
        steps.append(_step("Token obtenido", False, "Omitido"))
        steps.append(_step("Conexión recepción", False, "Omitida"))
        return _finish(False, ambiente, started, steps, cert_meta)

    token = None
    try:
        token = dgii.validate_signed_seed(signed_seed)
        if not isinstance(token, DGIIToken) or not token.value:
            raise DGIIClientError("DGII no devolvió un token de autenticación")
        steps.append(_step("Token obtenido", True, "JWT recibido"))
    except DGIIClientError as error:
        steps.append(_step("Token obtenido", False, str(error)))
        steps.append(_step("Conexión recepción", False, "Omitida"))
        return _finish(False, ambiente, started, steps, cert_meta)

    try:
        status = dgii.ping_reception(token)
        steps.append(
            _step("Conexión recepción", True, f"Recepción alcanzable HTTP {status}")
        )
    except DGIIClientError as error:
        steps.append(_step("Conexión recepción", False, str(error)))
        return _finish(False, ambiente, started, steps, cert_meta)

    return _finish(True, ambiente, started, steps, cert_meta)
