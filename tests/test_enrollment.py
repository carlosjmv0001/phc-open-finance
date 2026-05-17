import pytest
import time
from src.enrollment import (
    perform_enrollment,
    verify_enrollment_token,
    EnrollmentCeremony,
)
from src.biometric import (
    SimulatedBiometricProvider,
    SimulatedDocumentVerifier,
    BiometricProvider,
    DocumentVerifier,
    BiometricCapture,
    DocumentVerification,
)
from src.config import BIOMETRIC_THRESHOLD


@pytest.mark.phc
@pytest.mark.enrollment
class TestBiometricProvider:
    def test_simulated_requires_flag(self):
        with pytest.raises(RuntimeError, match="disabled in production"):
            SimulatedBiometricProvider(allow_simulated=False)

    def test_simulated_capture_returns_valid_structure(self):
        provider = SimulatedBiometricProvider(allow_simulated=True)
        capture = provider.capture()
        assert len(capture.template_hash) == 64  
        assert capture.score == 95.0
        assert capture.liveness_passed is True
        assert capture.device_id == "SIMULATED-DEV-001"
        assert "simulated" in capture.method

    def test_unique_templates(self):
        provider = SimulatedBiometricProvider(allow_simulated=True)
        a = provider.capture()
        b = provider.capture()
        assert a.template_hash != b.template_hash

    def test_liveness_check(self):
        provider = SimulatedBiometricProvider(allow_simulated=True)
        capture = provider.capture()
        assert provider.verify_liveness(capture) is True


@pytest.mark.phc
@pytest.mark.enrollment
class TestDocumentVerifier:
    def test_simulated_requires_flag(self):
        with pytest.raises(RuntimeError, match="disabled in production"):
            SimulatedDocumentVerifier(allow_simulated=False)

    def test_returns_valid_structure(self):
        verifier = SimulatedDocumentVerifier(allow_simulated=True)
        result = verifier.verify("PASSPORT-123")
        assert result.verified is True
        assert result.document_type == "passport"
        assert len(result.document_hash) == 64
        assert result.verification_method == "simulated_nfc"

    def test_deterministic_hash(self):
        verifier = SimulatedDocumentVerifier(allow_simulated=True)
        a = verifier.verify("PASSPORT-123")
        b = verifier.verify("PASSPORT-123")
        assert a.document_hash == b.document_hash

    def test_different_docs_different_hash(self):
        verifier = SimulatedDocumentVerifier(allow_simulated=True)
        a = verifier.verify("PASSPORT-123")
        b = verifier.verify("PASSPORT-456")
        assert a.document_hash != b.document_hash


@pytest.mark.phc
@pytest.mark.enrollment
class TestEnrollmentCeremony:
    def test_successful_ceremony(self):
        bio = SimulatedBiometricProvider(allow_simulated=True)
        doc = SimulatedDocumentVerifier(allow_simulated=True)
        secret = b"test-enrollment-secret-key-for-phc-unit-tests-minimum-32-bytes"

        ceremony = EnrollmentCeremony(bio, doc, enrollment_secret=secret)
        result = ceremony.perform("PASSPORT-BR-123456789")

        assert len(result.person_hash) == 64
        assert result.biometric_score == 95
        assert result.enrollment_token
        assert result.enrollment_timestamp > 0
        assert result.liveness_passed is True
        assert result.device_id == "SIMULATED-DEV-001"

    def test_liveness_failure_rejects(self):

        class FailLivenessProvider(BiometricProvider):
            def capture(self):
                return BiometricCapture(
                    template_hash="a" * 64, score=95.0, method="test",
                    captured_at=int(time.time()), liveness_passed=False,
                    device_id="test"
                )
            def verify_liveness(self, capture):
                return False

        doc = SimulatedDocumentVerifier(allow_simulated=True)
        secret = b"test-enrollment-secret-key-for-phc-unit-tests-minimum-32-bytes"
        ceremony = EnrollmentCeremony(FailLivenessProvider(), doc, enrollment_secret=secret)

        with pytest.raises(ValueError, match="Liveness detection FAILED"):
            ceremony.perform("PASSPORT-123")

    def test_low_score_rejects(self):
        class LowScoreProvider(BiometricProvider):
            def capture(self):
                return BiometricCapture(
                    template_hash="a" * 64, score=50.0, method="test",
                    captured_at=int(time.time()), liveness_passed=True,
                    device_id="test"
                )
            def verify_liveness(self, capture):
                return True

        doc = SimulatedDocumentVerifier(allow_simulated=True)
        secret = b"test-enrollment-secret-key-for-phc-unit-tests-minimum-32-bytes"
        ceremony = EnrollmentCeremony(LowScoreProvider(), doc, enrollment_secret=secret)

        with pytest.raises(ValueError, match="below threshold"):
            ceremony.perform("PASSPORT-123")

    def test_unverified_document_rejects(self):
        class FailDocVerifier(DocumentVerifier):
            def verify(self, document_id):
                return DocumentVerification(
                    document_hash="b" * 64, document_type="passport",
                    verified=False, verified_at=int(time.time()),
                    verification_method="test"
                )

        bio = SimulatedBiometricProvider(allow_simulated=True)
        secret = b"test-enrollment-secret-key-for-phc-unit-tests-minimum-32-bytes"
        ceremony = EnrollmentCeremony(bio, FailDocVerifier(), enrollment_secret=secret)

        with pytest.raises(ValueError, match="Document verification failed"):
            ceremony.perform("PASSPORT-123")


@pytest.mark.phc
@pytest.mark.enrollment
class TestPerformEnrollment:

    def test_successful_enrollment(self):
        bio = {"template_hash": "a" * 64, "score": 95.0}
        doc = {"document_hash": "b" * 64, "verified": True}
        result = perform_enrollment(bio, doc, secret_key="a" * 32)

        assert len(result.person_hash) == 64
        assert result.biometric_score == 95
        assert result.enrollment_token
        assert result.enrollment_timestamp > 0

    def test_below_threshold_rejected(self):
        bio = {"template_hash": "a" * 64, "score": 50.0}
        doc = {"document_hash": "b" * 64, "verified": True}
        with pytest.raises(ValueError, match="below threshold"):
            perform_enrollment(bio, doc, secret_key="a" * 32)

    def test_unverified_document_rejected(self):
        bio = {"template_hash": "a" * 64, "score": 95.0}
        doc = {"document_hash": "b" * 64, "verified": False}
        with pytest.raises(ValueError, match="Document verification failed"):
            perform_enrollment(bio, doc, secret_key="a" * 32)

    def test_person_hash_deterministic(self):
        bio = {"template_hash": "a" * 64, "score": 95.0}
        doc = {"document_hash": "b" * 64, "verified": True}
        r1 = perform_enrollment(bio, doc, secret_key="a" * 32)
        r2 = perform_enrollment(bio, doc, secret_key="a" * 32)
        assert r1.person_hash == r2.person_hash

    def test_different_biometrics_different_hash(self):
        doc = {"document_hash": "b" * 64, "verified": True}
        r1 = perform_enrollment({"template_hash": "a" * 64, "score": 95.0}, doc, secret_key="a" * 32)
        r2 = perform_enrollment({"template_hash": "c" * 64, "score": 95.0}, doc, secret_key="a" * 32)
        assert r1.person_hash != r2.person_hash


@pytest.mark.phc
@pytest.mark.enrollment
class TestEnrollmentToken:
    def test_valid_token(self):
        bio = {"template_hash": "a" * 64, "score": 95.0}
        doc = {"document_hash": "b" * 64, "verified": True}
        key = "a" * 32
        result = perform_enrollment(bio, doc, secret_key=key)

        assert verify_enrollment_token(
            result.person_hash,
            str(result.enrollment_timestamp),
            result.enrollment_token,
            secret_key=key,
        )

    def test_tampered_hash_fails(self):
        bio = {"template_hash": "a" * 64, "score": 95.0}
        doc = {"document_hash": "b" * 64, "verified": True}
        key = "a" * 32
        result = perform_enrollment(bio, doc, secret_key=key)

        assert not verify_enrollment_token(
            "tampered_hash_value_1234567890",
            str(result.enrollment_timestamp),
            result.enrollment_token,
            secret_key=key,
        )

    def test_tampered_token_fails(self):
        bio = {"template_hash": "a" * 64, "score": 95.0}
        doc = {"document_hash": "b" * 64, "verified": True}
        key = "a" * 32
        result = perform_enrollment(bio, doc, secret_key=key)

        assert not verify_enrollment_token(
            result.person_hash,
            str(result.enrollment_timestamp),
            "fake_token",
            secret_key=key,
        )

    def test_wrong_secret_key_fails(self):
        bio = {"template_hash": "a" * 64, "score": 95.0}
        doc = {"document_hash": "b" * 64, "verified": True}
        result = perform_enrollment(bio, doc, secret_key="correct-key-minimum-32-bytes!!!")

        assert not verify_enrollment_token(
            result.person_hash,
            str(result.enrollment_timestamp),
            result.enrollment_token,
            secret_key="wrong-key-but-still-minimum-32-b",
        )
