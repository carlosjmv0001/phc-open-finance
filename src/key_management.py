import os
import secrets
from abc import ABC, abstractmethod


MIN_KEY_LENGTH = 32


class KeyProvider(ABC):


    @abstractmethod
    def get_enrollment_secret(self) -> bytes:
        ...

    @abstractmethod
    def get_holder_secret(self) -> bytes:
        ...


class EnvironmentKeyProvider(KeyProvider):


    ENROLLMENT_VAR = "PHC_ENROLLMENT_SECRET_KEY"
    HOLDER_VAR = "PHC_HOLDER_SECRET_KEY"

    def get_enrollment_secret(self) -> bytes:
        return self._load_key(self.ENROLLMENT_VAR)

    def get_holder_secret(self) -> bytes:
        return self._load_key(self.HOLDER_VAR)

    def _load_key(self, env_var: str) -> bytes:
        value = os.environ.get(env_var)
        if not value:
            raise RuntimeError(
                f"Environment variable {env_var} is not set. "
                f"Generate one with: python -c \"import secrets; print(secrets.token_hex({MIN_KEY_LENGTH}))\""
            )
        key_bytes = value.encode("utf-8")
        if len(key_bytes) < MIN_KEY_LENGTH:
            raise RuntimeError(
                f"{env_var} is too short ({len(key_bytes)} bytes). "
                f"Minimum is {MIN_KEY_LENGTH} bytes for 256-bit security."
            )
        return key_bytes


class FileKeyProvider(KeyProvider):


    ENROLLMENT_FILE_VAR = "PHC_ENROLLMENT_KEY_FILE"
    HOLDER_FILE_VAR = "PHC_HOLDER_KEY_FILE"

    def get_enrollment_secret(self) -> bytes:
        return self._load_key_file(self.ENROLLMENT_FILE_VAR)

    def get_holder_secret(self) -> bytes:
        return self._load_key_file(self.HOLDER_FILE_VAR)

    def _load_key_file(self, env_var: str) -> bytes:
        file_path = os.environ.get(env_var)
        if not file_path:
            raise RuntimeError(f"Environment variable {env_var} is not set.")

        if not os.path.exists(file_path):
            raise RuntimeError(f"Key file not found: {file_path}")

        if hasattr(os, "stat"):
            import stat
            file_stat = os.stat(file_path)
            mode = file_stat.st_mode
            if os.name != "nt" and (mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH)):
                raise RuntimeError(
                    f"Key file {file_path} has insecure permissions. "
                    f"Run: chmod 600 {file_path}"
                )

        with open(file_path, "r") as f:
            key_data = f.read().strip()

        key_bytes = key_data.encode("utf-8")
        if len(key_bytes) < MIN_KEY_LENGTH:
            raise RuntimeError(
                f"Key in {file_path} is too short ({len(key_bytes)} bytes). "
                f"Minimum is {MIN_KEY_LENGTH} bytes."
            )
        return key_bytes


class HsmKeyProvider(KeyProvider):


    def get_enrollment_secret(self) -> bytes:
        raise NotImplementedError(
            "HSM integration requires PyKCS11 and a configured PKCS#11 module. "
            "See docs/hsm-setup.md for production deployment instructions."
        )

    def get_holder_secret(self) -> bytes:
        raise NotImplementedError(
            "HSM integration requires PyKCS11 and a configured PKCS#11 module. "
            "See docs/hsm-setup.md for production deployment instructions."
        )


def generate_key(length: int = 32) -> str:

    return secrets.token_hex(length)


def get_key_provider() -> KeyProvider:

    provider_type = os.environ.get("PHC_KEY_PROVIDER", "env").lower()

    if provider_type == "hsm":
        return HsmKeyProvider()
    elif provider_type == "file":
        return FileKeyProvider()
    else:
        return EnvironmentKeyProvider()
