import hashlib
import hmac
import json
import os
import time
from abc import ABC, abstractmethod

from .config import DEDUP_REGISTRY_FILE, DEDUP_REGISTRY_BACKEND, ISSUER_URL


class DedupRegistry(ABC):

    @abstractmethod
    def is_person_registered(self, person_hash: str) -> bool:
        ...

    @abstractmethod
    def register_person(self, person_hash: str, cred_def_id: str, issued_at: int) -> None:
        ...

    @abstractmethod
    def mark_revoked(self, person_hash: str) -> None:
        ...


class JsonFileRegistry(DedupRegistry):


    def __init__(self, file_path: str = None, integrity_key: bytes = None):
        self.file_path = file_path or DEDUP_REGISTRY_FILE
        self._integrity_key = integrity_key

    @property
    def integrity_key(self) -> bytes:
        if self._integrity_key is None:
            from .config import get_enrollment_secret
            self._integrity_key = get_enrollment_secret()
        return self._integrity_key

    def _compute_hmac(self, data: str) -> str:
        return hmac.new(
            self.integrity_key,
            data.encode(),
            hashlib.sha256,
        ).hexdigest()

    def _load(self) -> dict:
        if not os.path.exists(self.file_path):
            return {}

        with open(self.file_path, "r") as f:
            wrapper = json.load(f)

        if isinstance(wrapper, dict) and "_hmac" in wrapper:
            stored_hmac = wrapper.pop("_hmac")
            data_str = json.dumps(wrapper.get("registry", {}), sort_keys=True)
            expected_hmac = self._compute_hmac(data_str)
            if not hmac.compare_digest(stored_hmac, expected_hmac):
                raise RuntimeError(
                    "Dedup registry integrity check FAILED. "
                    "The registry file has been tampered with. "
                    "This could indicate an attack to bypass the one-per-person limit."
                )
            return wrapper.get("registry", {})

        if isinstance(wrapper, dict):
            return wrapper
        return {}

    def _save(self, registry: dict) -> None:
        data_str = json.dumps(registry, sort_keys=True)
        hmac_tag = self._compute_hmac(data_str)
        wrapper = {
            "registry": registry,
            "_hmac": hmac_tag,
            "_updated_at": int(time.time()),
        }
        with open(self.file_path, "w") as f:
            json.dump(wrapper, f, indent=4)

    def is_person_registered(self, person_hash: str) -> bool:
        registry = self._load()
        entry = registry.get(person_hash)
        if entry is None:
            return False
        return not entry.get("revoked", False)

    def register_person(self, person_hash: str, cred_def_id: str, issued_at: int) -> None:
        registry = self._load()
        registry[person_hash] = {
            "cred_def_id": cred_def_id,
            "issued_at": issued_at,
            "revoked": False,
        }
        self._save(registry)
        print(f"   [Dedup] Registered person_hash: {person_hash[:16]}...")

    def mark_revoked(self, person_hash: str) -> None:
        registry = self._load()
        if person_hash in registry:
            registry[person_hash]["revoked"] = True
            self._save(registry)
            print(f"   [Dedup] Marked as revoked: {person_hash[:16]}...")


class LedgerBackedRegistry(DedupRegistry):


    def __init__(self, issuer_url: str = None, cache_file: str = None):
        import requests
        self._requests = requests
        self.issuer_url = issuer_url or ISSUER_URL
        self._cache = JsonFileRegistry(
            file_path=cache_file or DEDUP_REGISTRY_FILE
        )

    def _commitment(self, person_hash: str) -> str:
        """One-way commitment: SHA-256(person_hash). Never store raw hash on ledger."""
        return hashlib.sha256(person_hash.encode()).hexdigest()

    def _get_issuer_did(self) -> str:
        resp = self._requests.get(f"{self.issuer_url}/wallet/did/public")
        resp.raise_for_status()
        return resp.json()["result"]["did"]

    def is_person_registered(self, person_hash: str) -> bool:
        if self._cache.is_person_registered(person_hash):
            return True

        commitment = self._commitment(person_hash)
        try:
            issuer_did = self._get_issuer_did()
            resp = self._requests.get(
                f"{self.issuer_url}/ledger/get-attrib",
                params={"did": issuer_did, "attr_name": f"phc_dedup_{commitment[:16]}"},
            )
            if resp.status_code == 200:
                result = resp.json().get("result", {})
                if result and result.get("data"):
                    data = json.loads(result["data"]) if isinstance(result["data"], str) else result["data"]
                    if data.get("commitment") == commitment and not data.get("revoked", False):
                        return True
        except Exception as e:
            print(f"   [Dedup] Ledger check warning: {e}. Falling back to local cache.")

        return False

    def register_person(self, person_hash: str, cred_def_id: str, issued_at: int) -> None:
        commitment = self._commitment(person_hash)

        try:
            issuer_did = self._get_issuer_did()
            attrib_data = {
                "commitment": commitment,
                "cred_def_id": cred_def_id,
                "issued_at": issued_at,
                "revoked": False,
            }
            resp = self._requests.post(
                f"{self.issuer_url}/ledger/register-attrib",
                json={
                    "did": issuer_did,
                    "attrib_name": f"phc_dedup_{commitment[:16]}",
                    "attrib_value": json.dumps(attrib_data),
                },
            )
            if resp.status_code == 200:
                print(f"   [Dedup] Commitment written to ledger: {commitment[:16]}...")
            else:
                print(f"   [Dedup] Ledger write warning: {resp.text}. Using local cache.")
        except Exception as e:
            print(f"   [Dedup] Ledger write warning: {e}. Using local cache.")

        self._cache.register_person(person_hash, cred_def_id, issued_at)

    def mark_revoked(self, person_hash: str) -> None:

        self._cache.mark_revoked(person_hash)


def get_registry() -> DedupRegistry:
    if DEDUP_REGISTRY_BACKEND == "ledger":
        return LedgerBackedRegistry()
    return JsonFileRegistry()



def load_registry() -> dict:
    reg = JsonFileRegistry()
    return reg._load()


def save_registry(registry: dict) -> None:
    reg = JsonFileRegistry()
    reg._save(registry)


def is_person_registered(person_hash: str) -> bool:
    return get_registry().is_person_registered(person_hash)


def register_person(person_hash: str, cred_def_id: str, issued_at: int) -> None:
    get_registry().register_person(person_hash, cred_def_id, issued_at)


def mark_revoked(person_hash: str) -> None:
    get_registry().mark_revoked(person_hash)
