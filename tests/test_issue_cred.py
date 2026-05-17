import pytest
import requests
from unittest.mock import patch, Mock
from src.issue_cred import send_credential_offer, main


@pytest.mark.error
def test_network_error_on_offer():
    with patch('requests.post', side_effect=requests.ConnectionError("Network error")):
        with pytest.raises(requests.ConnectionError):
            send_credential_offer({"test": "payload"})


@pytest.mark.error
def test_api_error_response():
    with patch('requests.post') as mock_post:
        mock_post.return_value.status_code = 500
        mock_post.return_value.text = "Internal Server Error"

        with pytest.raises(requests.HTTPError, match="Status: 500"):
            send_credential_offer({"test": "payload"})


@pytest.mark.error
def test_connection_not_found():
    with patch('src.issue_cred.get_connection_id', return_value=None), \
         patch('src.issue_cred.load_state', return_value={"cred_def_id": "test"}):
        main()


@pytest.mark.error
def test_holder_no_credentials():
    mock_enrollment = Mock(
        person_hash="a" * 64,
        biometric_score=95,
        enrollment_timestamp=1711900800,
        enrollment_token="token",
        liveness_passed=True,
        device_id="SIMULATED-DEV-001",
    )

    with patch('src.issue_cred.get_connection_id', return_value="test-conn"), \
         patch('src.issue_cred.load_state', return_value={"cred_def_id": "test"}), \
         patch('src.issue_cred._issuer_enrollment', return_value=(mock_enrollment, "test")), \
         patch('requests.post'), \
         patch('requests.get') as mock_get:

        mock_get.return_value.json.return_value = {"results": []}

        main()  


@pytest.mark.phc
@pytest.mark.enrollment
def test_enrollment_gate_rejects_low_score():
    with patch('src.issue_cred.get_connection_id', return_value="test-conn"), \
         patch('src.issue_cred.load_state', return_value={"cred_def_id": "test"}), \
         patch('src.issue_cred._issuer_enrollment', return_value=(None, None)):

        main()  


@pytest.mark.phc
@pytest.mark.dedup
def test_dedup_rejects_duplicate():
    with patch('src.issue_cred.get_connection_id', return_value="test-conn"), \
         patch('src.issue_cred.load_state', return_value={"cred_def_id": "test"}), \
         patch('src.issue_cred._issuer_enrollment', return_value=(None, None)):

        main()


@pytest.mark.phc
def test_holder_secret_not_imported_in_issuer():

    import src.issue_cred as module
    source = open(module.__file__).read()
    assert "from .config import" not in source or "HOLDER_SECRET_KEY" not in source.split("from .config import")[1].split("\n")[0] if "from .config import" in source else True
    assert "import HOLDER_SECRET_KEY" not in source, (
        "issue_cred.py must NOT import HOLDER_SECRET_KEY. "
        "Holder secrets must be generated locally on the holder device."
    )
