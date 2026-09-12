"""Componentes de facturación electrónica DGII."""

from .builder import ECFBuildError, ECFBuildResult, ECFBuilder
from .certificates import (
    ECFCertificateResolutionError,
    ResolvedTenantCertificate,
    TenantCertificateProvider,
)
from .config import ECFConfig, ECFConfigurationError
from .dgii import (
    DGIIClient,
    DGIIClientError,
    DGIIReceptionResult,
    DGIIResponseError,
    DGIIStatusResult,
    DGIITrackResult,
    DGIITimeoutError,
    DGIIToken,
    classify_dgii_status,
)
from .sequence import (
    ECF_TYPE_CATALOG,
    REGISTERABLE_ECF_TYPES,
    SUPPORTED_ECF_TYPES,
    ECFSequenceError,
    ECFSequenceExhausted,
    ECFSequenceNotConfigured,
    ReservedENCF,
    build_encf,
    reserve_encf,
)
from .printable import ECFPrintableError, ECFPrintableResult, generate_e31_pdf
from .readiness import (
    ECFReadinessCheck,
    ECFReadinessReport,
    assess_readiness,
)
from .qr import (
    ECFQRCode,
    ECFStamp,
    ECFStampError,
    build_stamp,
    generate_qr,
)
from .signer import (
    ECFCertificateMetadata,
    ECFSignatureResult,
    ECFSigner,
    ECFSigningError,
)
from .validator import (
    ECFSchemaError,
    ECFValidationError,
    ECFValidationResult,
    ECFValidator,
)

__all__ = [
    "ECFBuildError",
    "ECFBuildResult",
    "ECFBuilder",
    "ECFCertificateResolutionError",
    "ResolvedTenantCertificate",
    "TenantCertificateProvider",
    "ECFConfig",
    "ECFConfigurationError",
    "DGIIClient",
    "DGIIClientError",
    "DGIIReceptionResult",
    "DGIIResponseError",
    "DGIIStatusResult",
    "DGIITrackResult",
    "DGIITimeoutError",
    "DGIIToken",
    "classify_dgii_status",
    "ECF_TYPE_CATALOG",
    "REGISTERABLE_ECF_TYPES",
    "SUPPORTED_ECF_TYPES",
    "ECFSequenceError",
    "ECFSequenceExhausted",
    "ECFSequenceNotConfigured",
    "ECFPrintableError",
    "ECFPrintableResult",
    "generate_e31_pdf",
    "ECFReadinessCheck",
    "ECFReadinessReport",
    "assess_readiness",
    "ECFQRCode",
    "ECFStamp",
    "ECFStampError",
    "build_stamp",
    "generate_qr",
    "ECFSignatureResult",
    "ECFCertificateMetadata",
    "ECFSigner",
    "ECFSigningError",
    "ECFSchemaError",
    "ECFValidationError",
    "ECFValidationResult",
    "ECFValidator",
    "ReservedENCF",
    "build_encf",
    "reserve_encf",
]
