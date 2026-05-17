import hashlib
import hmac
import time

from .biometric import BiometricProvider, DocumentVerifier
from .config import (
    BIOMETRIC_THRESHOLD,
    REAUTH_INTERVAL_SECONDS,
    REAUTH_MAX_USES,
)
from .schemas import ReauthResult


class ReauthPolicy:


    def __init__(
        self,
        max_age_seconds: int = None,
        max_uses: int = None,
    ):
        self.max_age_seconds = max_age_seconds if max_age_seconds is not None else REAUTH_INTERVAL_SECONDS
        self.max_uses = max_uses if max_uses is not None else REAUTH_MAX_USES

    def needs_reauth(self, last_auth_timestamp: int, usage_count: int) -> bool:

        if last_auth_timestamp == 0:
            return True

        age = int(time.time()) - last_auth_timestamp
        if age > self.max_age_seconds:
            return True

        if usage_count > self.max_uses:
            return True

        return False


def perform_reauth(
    biometric_provider: BiometricProvider,
    person_hash: str,
    enrollment_secret: bytes,
    threshold: int = BIOMETRIC_THRESHOLD,
) -> ReauthResult:

    capture = biometric_provider.capture()

    if not biometric_provider.verify_liveness(capture):
        raise ValueError(
            "Re-authentication FAILED: Liveness detection did not pass. "
            "The biometric sample does not appear to be from a live person."
        )

    if not capture.liveness_passed:
        raise ValueError(
            "Re-authentication FAILED: Biometric capture did not pass liveness. "
            "This prevents stolen/transferred credentials from being refreshed."
        )

    if capture.score < threshold:
        raise ValueError(
            f"Re-authentication FAILED: Biometric score {capture.score} "
            f"below threshold {threshold}."
        )

    timestamp = int(time.time())
    token = hmac.new(
        enrollment_secret,
        (person_hash + "reauth" + str(timestamp)).encode(),
        hashlib.sha256,
    ).hexdigest()

    return ReauthResult(
        person_hash=person_hash,
        reauth_timestamp=timestamp,
        reauth_token=token,
        biometric_score=int(capture.score),
        liveness_passed=capture.liveness_passed,
    )


def verify_reauth_token(
    person_hash: str,
    timestamp: int,
    token: str,
    enrollment_secret: bytes,
) -> bool:
    expected = hmac.new(
        enrollment_secret,
        (person_hash + "reauth" + str(timestamp)).encode(),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, token)


def apply_reauth(
    biometric_provider: BiometricProvider,
    person_hash: str,
    enrollment_secret: bytes,
) -> ReauthResult:

    result = perform_reauth(biometric_provider, person_hash, enrollment_secret)

    from .utils import save_holder_state
    save_holder_state("last_reauth_timestamp", result.reauth_timestamp)
    save_holder_state("usage_count_since_reauth", 0)  # Reset counter

    print(f"   [PHC] Re-authentication PASSED at {result.reauth_timestamp}")
    print(f"   [PHC] Score: {result.biometric_score} | Liveness: {result.liveness_passed}")

    return result
