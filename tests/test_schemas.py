import pytest
from pydantic import ValidationError
from src.schemas import (
    CredentialAttributes,
    ProofRequest,
    EnrollmentResult,
    BiometricCaptureResult,
    DocumentVerificationResult,
    ReauthResult,
)


@pytest.mark.unit
class TestCredentialAttributes:
    def test_valid_attributes(self):
        attrs = CredentialAttributes(
            person_hash="valid-hash-123",
            biometric_score="85",
            controller_did="did:sov:abc123def456"
        )
        assert attrs.person_hash == "valid-hash-123"
        assert attrs.biometric_score == "85"

    def test_invalid_biometric_score(self):
        with pytest.raises(ValidationError):
            CredentialAttributes(
                person_hash="valid-hash",
                biometric_score="150",  # Above 100
                controller_did="did:sov:abc123"
            )

    def test_invalid_did_format(self):
        with pytest.raises(ValidationError):
            CredentialAttributes(
                person_hash="valid-hash",
                biometric_score="75",
                controller_did="invalid-did"
            )

    def test_short_person_hash(self):
        with pytest.raises(ValidationError):
            CredentialAttributes(
                person_hash="short",
                biometric_score="75",
                controller_did="did:sov:abc123"
            )

    def test_float_score_rejected(self):
        """PHC requires integer scores for AnonCreds predicate compatibility."""
        with pytest.raises(ValidationError):
            CredentialAttributes(
                person_hash="valid-hash-123",
                biometric_score="85.5",
                controller_did="did:sov:abc123"
            )


@pytest.mark.unit
class TestProofRequest:
    def test_valid_proof_request(self):
        proof = ProofRequest(
            connection_id="valid-connection-id-123",
            presentation_request={"test": "data"}
        )
        assert proof.connection_id == "valid-connection-id-123"
        assert proof.service_id == "bank_open_finance"

    def test_custom_service_id(self):
        proof = ProofRequest(
            connection_id="valid-connection-id-123",
            presentation_request={"test": "data"},
            service_id="insurance_co"
        )
        assert proof.service_id == "insurance_co"

    def test_invalid_connection_id(self):
        with pytest.raises(ValidationError):
            ProofRequest(
                connection_id="short",
                presentation_request={"test": "data"}
            )


@pytest.mark.unit
class TestEnrollmentResult:
    def test_valid_result(self):
        result = EnrollmentResult(
            person_hash="a" * 64,
            biometric_score=95,
            enrollment_timestamp=1711900800,
            enrollment_token="token123"
        )
        assert result.biometric_score == 95
        assert result.liveness_passed is False

    def test_valid_result_with_liveness(self):
        result = EnrollmentResult(
            person_hash="a" * 64,
            biometric_score=95,
            enrollment_timestamp=1711900800,
            enrollment_token="token123",
            liveness_passed=True,
            device_id="FP-001",
            device_attestation="attestation_data",
        )
        assert result.liveness_passed is True
        assert result.device_id == "FP-001"

    def test_score_out_of_range(self):
        with pytest.raises(ValidationError):
            EnrollmentResult(
                person_hash="a" * 64,
                biometric_score=150,
                enrollment_timestamp=1711900800,
                enrollment_token="token123"
            )


@pytest.mark.unit
class TestBiometricCaptureResult:
    def test_valid_capture(self):
        result = BiometricCaptureResult(
            template_hash="a" * 64,
            score=95.0,
            method="fingerprint",
            captured_at=1711900800,
            liveness_passed=True,
        )
        assert result.score == 95.0

    def test_invalid_hex_hash(self):
        with pytest.raises(ValidationError):
            BiometricCaptureResult(
                template_hash="not-hex!" * 8,
                score=95.0,
                method="fingerprint",
                captured_at=1711900800,
                liveness_passed=True,
            )

    def test_score_range(self):
        with pytest.raises(ValidationError):
            BiometricCaptureResult(
                template_hash="a" * 64,
                score=150.0,
                method="fingerprint",
                captured_at=1711900800,
                liveness_passed=True,
            )


@pytest.mark.unit
class TestReauthResult:
    def test_valid_reauth(self):
        result = ReauthResult(
            person_hash="a" * 64,
            reauth_timestamp=1711900800,
            reauth_token="token",
            biometric_score=90,
            liveness_passed=True,
        )
        assert result.reauth_count == 1

    def test_score_out_of_range(self):
        with pytest.raises(ValidationError):
            ReauthResult(
                person_hash="a" * 64,
                reauth_timestamp=1711900800,
                reauth_token="token",
                biometric_score=150,
                liveness_passed=True,
            )
