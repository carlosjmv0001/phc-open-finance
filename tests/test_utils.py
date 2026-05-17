import pytest
import json
import os
import requests_mock
import requests
from src.utils import (
    load_state, save_state, get_connection_id,
    load_holder_state, save_holder_state,
)
from src.config import ISSUER_URL, HOLDER_A_URL, VERIFIER_A_URL


@pytest.mark.unit
def test_load_state_empty(mock_state_file):
    assert load_state() == {}


@pytest.mark.unit
def test_save_and_load_state(mock_state_file):
    save_state("test_key", "test_value")
    assert os.path.exists(mock_state_file)
    state = load_state()
    assert state["test_key"] == "test_value"


@pytest.mark.unit
def test_save_state_overwrite(mock_state_file):
    save_state("key1", "value1")
    save_state("key2", "value2")
    state = load_state()
    assert state["key1"] == "value1"
    assert state["key2"] == "value2"


@pytest.mark.unit
def test_holder_state_separate(mock_state_file, mock_holder_state_file):
    save_state("issuer_key", "issuer_value")
    save_holder_state("holder_key", "holder_value")

    issuer_state = load_state()
    assert "holder_key" not in issuer_state

    holder_state = load_holder_state()
    assert "issuer_key" not in holder_state

    assert issuer_state["issuer_key"] == "issuer_value"
    assert holder_state["holder_key"] == "holder_value"


@pytest.mark.unit
def test_holder_state_empty(mock_holder_state_file):
    assert load_holder_state() == {}


@pytest.mark.unit
def test_get_connection_id_success():
    with requests_mock.Mocker() as m:
        m.get(
            f"{ISSUER_URL}/connections",
            json={
                "results": [
                    {
                        "connection_id": "conn-123",
                        "alias": "test_alias",
                        "state": "active"
                    }
                ]
            }
        )
        conn_id = get_connection_id(ISSUER_URL, "test_alias")
        assert conn_id == "conn-123"


@pytest.mark.unit
def test_get_connection_id_not_found():
    with requests_mock.Mocker() as m:
        m.get(
            f"{ISSUER_URL}/connections",
            json={"results": []}
        )
        conn_id = get_connection_id(ISSUER_URL, "nonexistent")
        assert conn_id is None


@pytest.mark.error
def test_get_connection_id_api_error():
    with requests_mock.Mocker() as m:
        m.get(
            f"{ISSUER_URL}/connections",
            status_code=500
        )
        with pytest.raises(requests.exceptions.RequestException):
            get_connection_id(ISSUER_URL, "test_alias")
