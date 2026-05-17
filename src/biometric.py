import hashlib
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class BiometricCapture:
    template_hash: str
    score: float
    method: str
    captured_at: int
    liveness_passed: bool
    device_id: str = "unknown"
    device_attestation: str = ""


@dataclass
class DocumentVerification:
    document_hash: str
    document_type: str
    verified: bool
    verified_at: int
    verification_method: str = "unknown"
    issuing_country: str = ""


class BiometricProvider(ABC):


    @abstractmethod
    def capture(self) -> BiometricCapture:
        ...

    @abstractmethod
    def verify_liveness(self, capture: BiometricCapture) -> bool:
        ...


class DocumentVerifier(ABC):


    @abstractmethod
    def verify(self, document_id: str) -> DocumentVerification:
        ...


class SimulatedBiometricProvider(BiometricProvider):


    def __init__(self, allow_simulated: bool = False):
        if not allow_simulated:
            raise RuntimeError(
                "SimulatedBiometricProvider is disabled in production. "
                "Set PHC_ALLOW_SIMULATED=true for testing only. "
                "Use FingerprintReaderProvider or IrisScannerProvider in production."
            )
        self._allow_simulated = allow_simulated

    def capture(self) -> BiometricCapture:
        return BiometricCapture(
            template_hash=hashlib.sha256(uuid.uuid4().bytes).hexdigest(),
            score=95.0,
            method="fingerprint_simulated",
            captured_at=int(time.time()),
            liveness_passed=True,
            device_id="SIMULATED-DEV-001",
            device_attestation="none-simulated",
        )

    def verify_liveness(self, capture: BiometricCapture) -> bool:
        return True


class SimulatedDocumentVerifier(DocumentVerifier):


    def __init__(self, allow_simulated: bool = False):
        if not allow_simulated:
            raise RuntimeError(
                "SimulatedDocumentVerifier is disabled in production. "
                "Set PHC_ALLOW_SIMULATED=true for testing only."
            )

    def verify(self, document_id: str) -> DocumentVerification:
        return DocumentVerification(
            document_hash=hashlib.sha256(document_id.encode()).hexdigest(),
            document_type="passport",
            verified=True,
            verified_at=int(time.time()),
            verification_method="simulated_nfc",
            issuing_country="BR",
        )


class FingerprintReaderProvider(BiometricProvider):


    def __init__(self, device_path: str = "/dev/fingerprint0"):
        self.device_path = device_path
        raise NotImplementedError(
            "FingerprintReaderProvider requires vendor SDK integration. "
            "Implement capture() and verify_liveness() with your hardware."
        )

    def capture(self) -> BiometricCapture:
        raise NotImplementedError("Connect fingerprint hardware SDK")

    def verify_liveness(self, capture: BiometricCapture) -> bool:
        raise NotImplementedError("Connect fingerprint liveness detection SDK")


class IrisScannerProvider(BiometricProvider):


    def __init__(self, device_path: str = "/dev/iris0"):
        self.device_path = device_path
        raise NotImplementedError(
            "IrisScannerProvider requires vendor SDK integration. "
            "Implement capture() and verify_liveness() with your hardware."
        )

    def capture(self) -> BiometricCapture:
        raise NotImplementedError("Connect iris scanner hardware SDK")

    def verify_liveness(self, capture: BiometricCapture) -> bool:
        raise NotImplementedError("Connect iris liveness detection SDK")


class NfcDocumentVerifier(DocumentVerifier):


    def __init__(self, reader_name: str = "default"):
        self.reader_name = reader_name
        raise NotImplementedError(
            "NfcDocumentVerifier requires NFC reader SDK and ICAO 9303 library. "
            "Implement verify() with your hardware."
        )

    def verify(self, document_id: str) -> DocumentVerification:
        raise NotImplementedError("Connect NFC document reader SDK")


def get_biometric_provider(allow_simulated: bool = False) -> BiometricProvider:

    if allow_simulated:
        return SimulatedBiometricProvider(allow_simulated=True)
    raise RuntimeError(
        "No production biometric provider configured. "
        "Set PHC_ALLOW_SIMULATED=true for testing, or implement "
        "FingerprintReaderProvider / IrisScannerProvider for production."
    )


def get_document_verifier(allow_simulated: bool = False) -> DocumentVerifier:

    if allow_simulated:
        return SimulatedDocumentVerifier(allow_simulated=True)
    raise RuntimeError(
        "No production document verifier configured. "
        "Set PHC_ALLOW_SIMULATED=true for testing, or implement "
        "NfcDocumentVerifier for production."
    )
