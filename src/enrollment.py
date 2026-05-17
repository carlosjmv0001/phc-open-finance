import hashlib
import hmac
import time

from .biometric import (
    BiometricProvider,
    DocumentVerifier,
    BiometricCapture,
    DocumentVerification,
    get_biometric_provider,
    get_document_verifier,
)
from .config import BIOMETRIC_THRESHOLD, ALLOW_SIMULATED_BIOMETRICS, get_enrollment_secret
from .schemas import EnrollmentResult


class EnrollmentCeremony:


    def __init__(
        self,
        biometric_provider: BiometricProvider,
        document_verifier: DocumentVerifier,
        enrollment_secret: bytes = None,
        threshold: int = BIOMETRIC_THRESHOLD,
    ):
        self.biometric_provider = biometric_provider
        self.document_verifier = document_verifier
        self._enrollment_secret = enrollment_secret
        self.threshold = threshold

    @property
    def enrollment_secret(self) -> bytes:
        if self._enrollment_secret is None:
            self._enrollment_secret = get_enrollment_secret()
        return self._enrollment_secret

    def perform(self, document_id: str) -> EnrollmentResult:

        biometric = self.biometric_provider.capture()

        if not self.biometric_provider.verify_liveness(biometric):
            raise ValueError(
                "Liveness detection FAILED. The biometric sample does not "
                "appear to be from a live person. This prevents AI systems "
                "and replay attacks from obtaining credentials."
            )

        if not biometric.liveness_passed:
            raise ValueError(
                "Biometric capture did not pass liveness check. "
                "Ensure enrollment is conducted with a live person "
                "at a certified enrollment station."
            )

        if biometric.score < self.threshold:
            raise ValueError(
                f"Biometric score {biometric.score} below threshold "
                f"{self.threshold}. Re-capture required."
            )

        document = self.document_verifier.verify(document_id)
        if not document.verified:
            raise ValueError(
                "Document verification failed. Ensure a valid government-issued "
                "document is presented at the enrollment station."
            )

        raw = biometric.template_hash + document.document_hash
        person_hash = hashlib.sha256(raw.encode()).hexdigest()

        timestamp = int(time.time())
        token = hmac.new(
            self.enrollment_secret,
            (person_hash + str(timestamp)).encode(),
            hashlib.sha256,
        ).hexdigest()

        return EnrollmentResult(
            person_hash=person_hash,
            biometric_score=int(biometric.score),
            enrollment_timestamp=timestamp,
            enrollment_token=token,
            liveness_passed=biometric.liveness_passed,
            device_id=biometric.device_id,
            device_attestation=biometric.device_attestation,
        )


def perform_enrollment(
    biometric_data: dict,
    document_data: dict,
    secret_key: str = None,
) -> EnrollmentResult:

    score = biometric_data.get("score", 0)
    if score < BIOMETRIC_THRESHOLD:
        raise ValueError(
            f"Biometric score {score} below threshold {BIOMETRIC_THRESHOLD}"
        )

    if not document_data.get("verified", False):
        raise ValueError("Document verification failed")

    raw = biometric_data["template_hash"] + document_data["document_hash"]
    person_hash = hashlib.sha256(raw.encode()).hexdigest()

    timestamp = int(time.time())

    if secret_key is not None:
        key_bytes = secret_key.encode()
    else:
        key_bytes = get_enrollment_secret()

    token = hmac.new(
        key_bytes,
        (person_hash + str(timestamp)).encode(),
        hashlib.sha256,
    ).hexdigest()

    liveness = biometric_data.get("liveness_passed", False)

    return EnrollmentResult(
        person_hash=person_hash,
        biometric_score=int(score),
        enrollment_timestamp=timestamp,
        enrollment_token=token,
        liveness_passed=liveness,
        device_id=biometric_data.get("device_id", "unknown"),
        device_attestation=biometric_data.get("device_attestation", ""),
    )


def verify_enrollment_token(
    person_hash: str,
    timestamp: str,
    token: str,
    secret_key: str = None,
) -> bool:

    if secret_key is not None:
        key_bytes = secret_key.encode()
    else:
        key_bytes = get_enrollment_secret()

    expected = hmac.new(
        key_bytes,
        (person_hash + str(timestamp)).encode(),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, token)


def get_enrollment_ceremony(
    enrollment_secret: bytes = None,
) -> EnrollmentCeremony:
 
    bio_provider = get_biometric_provider(ALLOW_SIMULATED_BIOMETRICS)
    doc_verifier = get_document_verifier(ALLOW_SIMULATED_BIOMETRICS)

    return EnrollmentCeremony(
        biometric_provider=bio_provider,
        document_verifier=doc_verifier,
        enrollment_secret=enrollment_secret,
    )
