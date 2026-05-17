import pytest
import time
from src.reauth import ReauthPolicy, perform_reauth, verify_reauth_token
from src.biometric import (
    BiometricProvider,
    BiometricCapture,
    SimulatedBiometricProvider,
)


@pytest.mark.phc
class TestReauthPolicy:
    def test_needs_reauth_when_never_authenticated(self):
        policy = ReauthPolicy(max_age_seconds=86400, max_uses=100)
        assert policy.needs_reauth(0, 0) is True

    def test_no_reauth_when_fresh(self):
        policy = ReauthPolicy(max_age_seconds=86400, max_uses=100)
        assert policy.needs_reauth(int(time.time()), 0) is False

    def test_needs_reauth_when_expired(self):
        policy = ReauthPolicy(max_age_seconds=10, max_uses=100)
        old_timestamp = int(time.time()) - 20
        assert policy.needs_reauth(old_timestamp, 0) is True

    def test_needs_reauth_when_usage_exceeded(self):
        policy = ReauthPolicy(max_age_seconds=86400, max_uses=5)
        assert policy.needs_reauth(int(time.time()), 10) is True

    def test_no_reauth_within_limits(self):
        policy = ReauthPolicy(max_age_seconds=86400, max_uses=100)
        assert policy.needs_reauth(int(time.time()), 50) is False


@pytest.mark.phc
class TestPerformReauth:
    def test_successful_reauth(self):
        provider = SimulatedBiometricProvider(allow_simulated=True)
        secret = b"test-enrollment-secret-key-for-phc-unit-tests-minimum-32-bytes"
        person_hash = "a" * 64

        result = perform_reauth(provider, person_hash, secret)

        assert result.person_hash == person_hash
        assert result.biometric_score == 95
        assert result.liveness_passed is True
        assert result.reauth_token
        assert result.reauth_timestamp > 0

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

        secret = b"test-enrollment-secret-key-for-phc-unit-tests-minimum-32-bytes"
        with pytest.raises(ValueError, match="Liveness detection did not pass"):
            perform_reauth(FailLivenessProvider(), "a" * 64, secret)

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

        secret = b"test-enrollment-secret-key-for-phc-unit-tests-minimum-32-bytes"
        with pytest.raises(ValueError, match="below threshold"):
            perform_reauth(LowScoreProvider(), "a" * 64, secret)

    def test_token_verification(self):
        provider = SimulatedBiometricProvider(allow_simulated=True)
        secret = b"test-enrollment-secret-key-for-phc-unit-tests-minimum-32-bytes"
        person_hash = "a" * 64

        result = perform_reauth(provider, person_hash, secret)

        assert verify_reauth_token(
            person_hash, result.reauth_timestamp, result.reauth_token, secret
        )

    def test_tampered_token_rejected(self):
        provider = SimulatedBiometricProvider(allow_simulated=True)
        secret = b"test-enrollment-secret-key-for-phc-unit-tests-minimum-32-bytes"
        person_hash = "a" * 64

        result = perform_reauth(provider, person_hash, secret)

        assert not verify_reauth_token(
            person_hash, result.reauth_timestamp, "fake_token", secret
        )
