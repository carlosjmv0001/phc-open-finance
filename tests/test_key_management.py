import pytest
import os
from src.key_management import (
    EnvironmentKeyProvider,
    FileKeyProvider,
    HsmKeyProvider,
    generate_key,
    get_key_provider,
    MIN_KEY_LENGTH,
)


@pytest.mark.phc
class TestEnvironmentKeyProvider:
    def test_loads_enrollment_secret(self):
        provider = EnvironmentKeyProvider()
        key = provider.get_enrollment_secret()
        assert len(key) >= MIN_KEY_LENGTH

    def test_missing_enrollment_key_raises(self, monkeypatch):
        monkeypatch.delenv("PHC_ENROLLMENT_SECRET_KEY", raising=False)
        provider = EnvironmentKeyProvider()
        with pytest.raises(RuntimeError, match="not set"):
            provider.get_enrollment_secret()

    def test_short_key_raises(self, monkeypatch):
        monkeypatch.setenv("PHC_ENROLLMENT_SECRET_KEY", "short")
        provider = EnvironmentKeyProvider()
        with pytest.raises(RuntimeError, match="too short"):
            provider.get_enrollment_secret()


@pytest.mark.phc
class TestFileKeyProvider:
    def test_loads_from_file(self, tmp_path, monkeypatch):
        key_file = tmp_path / "enrollment.key"
        key_file.write_text("a" * 64)
        monkeypatch.setenv("PHC_ENROLLMENT_KEY_FILE", str(key_file))

        provider = FileKeyProvider()
        key = provider.get_enrollment_secret()
        assert len(key) == 64

    def test_missing_file_raises(self, monkeypatch):
        monkeypatch.setenv("PHC_ENROLLMENT_KEY_FILE", "/nonexistent/path")
        provider = FileKeyProvider()
        with pytest.raises(RuntimeError, match="not found"):
            provider.get_enrollment_secret()

    def test_missing_env_var_raises(self, monkeypatch):
        monkeypatch.delenv("PHC_ENROLLMENT_KEY_FILE", raising=False)
        provider = FileKeyProvider()
        with pytest.raises(RuntimeError, match="not set"):
            provider.get_enrollment_secret()


@pytest.mark.phc
class TestHsmKeyProvider:
    def test_raises_not_implemented(self):
        provider = HsmKeyProvider()
        with pytest.raises(NotImplementedError, match="PKCS#11"):
            provider.get_enrollment_secret()
        with pytest.raises(NotImplementedError, match="PKCS#11"):
            provider.get_holder_secret()


@pytest.mark.phc
class TestGenerateKey:
    def test_generates_correct_length(self):
        key = generate_key(32)
        assert len(key) == 64

    def test_generates_unique_keys(self):
        keys = {generate_key() for _ in range(100)}
        assert len(keys) == 100

    def test_is_valid_hex(self):
        key = generate_key()
        int(key, 16)


@pytest.mark.phc
class TestGetKeyProvider:
    def test_default_is_environment(self, monkeypatch):
        monkeypatch.delenv("PHC_KEY_PROVIDER", raising=False)
        provider = get_key_provider()
        assert isinstance(provider, EnvironmentKeyProvider)

    def test_file_provider(self, monkeypatch):
        monkeypatch.setenv("PHC_KEY_PROVIDER", "file")
        provider = get_key_provider()
        assert isinstance(provider, FileKeyProvider)

    def test_hsm_provider(self, monkeypatch):
        monkeypatch.setenv("PHC_KEY_PROVIDER", "hsm")
        provider = get_key_provider()
        assert isinstance(provider, HsmKeyProvider)
