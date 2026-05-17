import pytest
import json
import os
import time
from unittest.mock import patch
from src.dedup_registry import (
    is_person_registered,
    register_person,
    mark_revoked,
    JsonFileRegistry,
)


@pytest.fixture(autouse=True)
def temp_registry(tmp_path):
    registry_file = str(tmp_path / "test_person_registry.json")
    with patch("src.dedup_registry.DEDUP_REGISTRY_FILE", registry_file), \
         patch("src.dedup_registry.DEDUP_REGISTRY_BACKEND", "json"):
        yield registry_file


@pytest.mark.phc
@pytest.mark.dedup
class TestJsonFileRegistry:
    def test_empty_when_no_file(self):
        assert not is_person_registered("unknown_hash_1234")

    def test_register_and_check(self):
        register_person("hash_abc_12345678", "cred_def_1", int(time.time()))
        assert is_person_registered("hash_abc_12345678")

    def test_unregistered_person(self):
        assert not is_person_registered("unknown_hash_123")

    def test_duplicate_detected(self):
        register_person("hash_dup_12345678", "cred_def_1", int(time.time()))
        assert is_person_registered("hash_dup_12345678")

    def test_revoked_allows_reregistration(self):
        register_person("hash_rev_12345678", "cred_def_1", int(time.time()))
        assert is_person_registered("hash_rev_12345678")

        mark_revoked("hash_rev_12345678")
        assert not is_person_registered("hash_rev_12345678")

        register_person("hash_rev_12345678", "cred_def_2", int(time.time()))
        assert is_person_registered("hash_rev_12345678")

    def test_mark_revoked(self):
        register_person("hash_to_revoke_123", "cd1", int(time.time()))
        mark_revoked("hash_to_revoke_123")
        assert not is_person_registered("hash_to_revoke_123")

    def test_revoke_nonexistent_no_error(self):
        mark_revoked("nonexistent_hash_1")


@pytest.mark.phc
@pytest.mark.dedup
class TestHmacIntegrity:
    def test_tampered_registry_detected(self, tmp_path):
        registry_file = str(tmp_path / "tamper_test.json")
        key = b"test-integrity-key-at-least-32-bytes-long-enough"
        reg = JsonFileRegistry(file_path=registry_file, integrity_key=key)

        reg.register_person("hash_1234567890ab", "cd1", int(time.time()))
        assert reg.is_person_registered("hash_1234567890ab")

        with open(registry_file, "r") as f:
            data = json.load(f)
        data["registry"]["hash_1234567890ab"]["revoked"] = True
        with open(registry_file, "w") as f:
            json.dump(data, f)

        with pytest.raises(RuntimeError, match="integrity check FAILED"):
            reg.is_person_registered("hash_1234567890ab")

    def test_valid_registry_passes_integrity(self, tmp_path):
        registry_file = str(tmp_path / "valid_test.json")
        key = b"test-integrity-key-at-least-32-bytes-long-enough"
        reg = JsonFileRegistry(file_path=registry_file, integrity_key=key)

        reg.register_person("hash_valid_12345", "cd1", int(time.time()))
        assert reg.is_person_registered("hash_valid_12345")
