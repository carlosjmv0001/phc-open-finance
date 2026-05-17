import pytest
import requests
from unittest.mock import patch, Mock
from src.verifier_proof import send_proof_request, NonceRegistry


@pytest.mark.verification
def test_send_proof_request():
    with patch('requests.post') as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"pres_ex_id": "test-id"}

        result = send_proof_request("test-connection-id", "test-cred-def-id")
        assert result is not None

        call_args = mock_post.call_args
        payload = call_args[1]["json"]
        pres_req = payload["presentation_request"]["anoncreds"]

        assert pres_req["requested_attributes"] == {}

        predicates = pres_req["requested_predicates"]
        assert "0_biometric_pred" in predicates
        assert "0_expiry_pred" in predicates
        assert predicates["0_biometric_pred"]["p_type"] == ">="
        assert predicates["0_expiry_pred"]["p_type"] == ">="


@pytest.mark.verification
def test_nonce_is_cryptographically_random():
    import time
    with patch('requests.post') as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"pres_ex_id": "test-id"}

        send_proof_request("test-connection-id", "test-cred-def-id")

        payload = mock_post.call_args[1]["json"]
        nonce = payload["presentation_request"]["anoncreds"]["nonce"]

        now = int(time.time())
        nonce_val = int(nonce)
        assert nonce_val > now * 1000, (
            f"Nonce {nonce_val} looks like a timestamp. "
            "Must be cryptographically random (128-bit)."
        )


@pytest.mark.verification
def test_nonces_are_unique():
    nonces = []
    with patch('requests.post') as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"pres_ex_id": "test-id"}

        for _ in range(10):
            send_proof_request("conn-id", "cred-def-id")
            payload = mock_post.call_args[1]["json"]
            nonce = payload["presentation_request"]["anoncreds"]["nonce"]
            nonces.append(nonce)

    assert len(set(nonces)) == 10, "Nonces must be unique across requests"


@pytest.mark.verification
def test_send_proof_request_with_service_id():
    with patch('requests.post') as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"pres_ex_id": "test-id"}

        result = send_proof_request("conn-id", "cred-def-id", service_id="insurance_co")
        assert result is not None


@pytest.mark.error
def test_send_proof_request_api_error():
    with patch('requests.post') as mock_post:
        mock_post.return_value.status_code = 500
        mock_post.return_value.text = "Internal Server Error"

        result = send_proof_request("test-connection-id", "test-cred-def-id")
        assert result is None


@pytest.mark.error
def test_send_proof_request_connection_not_found():
    with patch('requests.post') as mock_post:
        mock_post.return_value.status_code = 500
        mock_post.return_value.text = "Connection not found"

        result = send_proof_request(None, "test-cred-def-id")
        assert result is None


@pytest.mark.phc
def test_no_attributes_revealed():
    with patch('requests.post') as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"pres_ex_id": "id"}

        send_proof_request("conn", "cred_def")

        payload = mock_post.call_args[1]["json"]
        req_attrs = payload["presentation_request"]["anoncreds"]["requested_attributes"]
        assert len(req_attrs) == 0, "PHC proof must not request revealed attributes"


@pytest.mark.phc
class TestNonceRegistry:
    def test_issue_returns_unique_nonces(self):
        registry = NonceRegistry(ttl_seconds=60)
        nonces = {registry.issue() for _ in range(100)}
        assert len(nonces) == 100

    def test_validate_and_consume_succeeds(self):
        registry = NonceRegistry(ttl_seconds=60)
        nonce = registry.issue()
        assert registry.validate_and_consume(nonce) is True

    def test_replay_rejected(self):
        registry = NonceRegistry(ttl_seconds=60)
        nonce = registry.issue()
        assert registry.validate_and_consume(nonce) is True
        assert registry.validate_and_consume(nonce) is False

    def test_unknown_nonce_rejected(self):
        registry = NonceRegistry(ttl_seconds=60)
        assert registry.validate_and_consume("never-issued") is False

    def test_expired_nonce_rejected(self):
        registry = NonceRegistry(ttl_seconds=0)
        nonce = registry.issue()
        import time
        time.sleep(0.01)
        assert registry.validate_and_consume(nonce) is False
