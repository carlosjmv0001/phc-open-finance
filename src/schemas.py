from pydantic import BaseModel, Field, field_validator
from typing import Optional
import time


class CredentialAttributes(BaseModel):
    person_hash: str = Field(..., min_length=8, max_length=128)
    biometric_score: str = Field(..., pattern=r'^\d{1,3}$')
    timestamp: str = Field(default_factory=lambda: str(int(time.time())))
    controller_did: str = Field(..., pattern=r'^did:sov:[a-zA-Z0-9]+$')

    @field_validator('biometric_score')
    @classmethod
    def validate_score(cls, v):
        score = int(v)
        if not 0 <= score <= 100:
            raise ValueError('Score must be between 0 and 100')
        return v


class EnrollmentResult(BaseModel):
    person_hash: str = Field(..., min_length=8, max_length=128)
    biometric_score: int = Field(..., ge=0, le=100)
    enrollment_timestamp: int
    enrollment_token: str
    liveness_passed: bool = Field(
        default=False,
        description="Whether biometric liveness detection passed during enrollment"
    )
    device_id: str = Field(
        default="unknown",
        description="Hardware device ID that performed the biometric capture"
    )
    device_attestation: str = Field(
        default="",
        description="Cryptographic attestation from the capture hardware"
    )


class BiometricCaptureResult(BaseModel):
    template_hash: str = Field(..., min_length=64, max_length=64)
    score: float = Field(..., ge=0.0, le=100.0)
    method: str = Field(..., min_length=1)
    captured_at: int
    liveness_passed: bool
    device_id: str = Field(default="unknown")
    device_attestation: str = Field(default="")

    @field_validator('template_hash')
    @classmethod
    def validate_hex_hash(cls, v):
        try:
            int(v, 16)
        except ValueError:
            raise ValueError('template_hash must be a valid hex string')
        return v


class DocumentVerificationResult(BaseModel):
    document_hash: str = Field(..., min_length=64, max_length=64)
    document_type: str = Field(..., min_length=1)
    verified: bool
    verified_at: int
    verification_method: str = Field(default="unknown")
    issuing_country: str = Field(default="")


class ReauthResult(BaseModel):
    person_hash: str = Field(..., min_length=8, max_length=128)
    reauth_timestamp: int
    reauth_token: str
    biometric_score: int = Field(..., ge=0, le=100)
    liveness_passed: bool
    reauth_count: int = Field(default=1, ge=1)


class ProofRequest(BaseModel):
    connection_id: str
    presentation_request: dict
    service_id: Optional[str] = Field(default="bank_open_finance")

    @field_validator('connection_id')
    @classmethod
    def validate_connection_id(cls, v):
        if not v or len(v) < 10:
            raise ValueError('Invalid connection ID')
        return v
