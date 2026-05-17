import pytest
from src.biometric import (
    BiometricProvider,
    DocumentVerifier,
    SimulatedBiometricProvider,
    SimulatedDocumentVerifier,
    FingerprintReaderProvider,
    IrisScannerProvider,
    NfcDocumentVerifier,
    get_biometric_provider,
    get_document_verifier,
)


@pytest.mark.phc
class TestSimulatedProviderGuard:
    def test_biometric_disabled_by_default(self):
        with pytest.raises(RuntimeError, match="disabled in production"):
            SimulatedBiometricProvider(allow_simulated=False)

    def test_document_disabled_by_default(self):
        with pytest.raises(RuntimeError, match="disabled in production"):
            SimulatedDocumentVerifier(allow_simulated=False)

    def test_biometric_enabled_with_flag(self):
        provider = SimulatedBiometricProvider(allow_simulated=True)
        assert provider is not None

    def test_document_enabled_with_flag(self):
        verifier = SimulatedDocumentVerifier(allow_simulated=True)
        assert verifier is not None


@pytest.mark.phc
class TestProductionStubs:
    def test_fingerprint_raises_not_implemented(self):
        with pytest.raises(NotImplementedError):
            FingerprintReaderProvider()

    def test_iris_raises_not_implemented(self):
        with pytest.raises(NotImplementedError):
            IrisScannerProvider()

    def test_nfc_raises_not_implemented(self):
        with pytest.raises(NotImplementedError):
            NfcDocumentVerifier()


@pytest.mark.phc
class TestFactoryFunctions:
    def test_get_biometric_simulated(self):
        provider = get_biometric_provider(allow_simulated=True)
        assert isinstance(provider, SimulatedBiometricProvider)

    def test_get_biometric_production_fails(self):
        with pytest.raises(RuntimeError, match="No production"):
            get_biometric_provider(allow_simulated=False)

    def test_get_document_simulated(self):
        verifier = get_document_verifier(allow_simulated=True)
        assert isinstance(verifier, SimulatedDocumentVerifier)

    def test_get_document_production_fails(self):
        with pytest.raises(RuntimeError, match="No production"):
            get_document_verifier(allow_simulated=False)


@pytest.mark.phc
class TestBiometricCaptureData:
    def test_capture_has_required_fields(self):
        provider = SimulatedBiometricProvider(allow_simulated=True)
        capture = provider.capture()

        assert hasattr(capture, "template_hash")
        assert hasattr(capture, "score")
        assert hasattr(capture, "method")
        assert hasattr(capture, "captured_at")
        assert hasattr(capture, "liveness_passed")
        assert hasattr(capture, "device_id")
        assert hasattr(capture, "device_attestation")

    def test_document_has_required_fields(self):
        verifier = SimulatedDocumentVerifier(allow_simulated=True)
        result = verifier.verify("PASSPORT-123")

        assert hasattr(result, "document_hash")
        assert hasattr(result, "document_type")
        assert hasattr(result, "verified")
        assert hasattr(result, "verified_at")
        assert hasattr(result, "verification_method")
        assert hasattr(result, "issuing_country")
