import hashlib
import hmac
import os
import secrets


class HolderSecretManager:


    def __init__(self, storage_path: str = None):
        from .config import HOLDER_STATE_FILE
        self.storage_path = storage_path or HOLDER_STATE_FILE

    def generate_secret(self) -> str:

        return secrets.token_hex(32)

    def load_or_create(self) -> str:

        import json

        if os.path.exists(self.storage_path):
            with open(self.storage_path, "r") as f:
                data = json.load(f)
            existing = data.get("holder_local_secret")
            if existing:
                return existing

        new_secret = self.generate_secret()
        self._save("holder_local_secret", new_secret)
        print("   [PHC] Generated new holder-local secret (256-bit entropy).")
        return new_secret

    def _save(self, key: str, value: str) -> None:
        import json
        data = {}
        if os.path.exists(self.storage_path):
            with open(self.storage_path, "r") as f:
                data = json.load(f)
        data[key] = value
        with open(self.storage_path, "w") as f:
            json.dump(data, f, indent=4)


def derive_pseudonym(person_secret: str, service_id: str) -> str:

    return hmac.new(
        person_secret.encode(),
        service_id.encode(),
        hashlib.sha256,
    ).hexdigest()


def create_person_secret(person_hash: str, holder_key: str) -> str:

    return hmac.new(
        holder_key.encode(),
        person_hash.encode(),
        hashlib.sha256,
    ).hexdigest()
