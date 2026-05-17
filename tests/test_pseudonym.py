import pytest
import os
import json
from src.pseudonym import derive_pseudonym, create_person_secret, HolderSecretManager


@pytest.mark.phc
@pytest.mark.pseudonym
class TestPseudonymDerivation:
    def test_deterministic(self):
        p1 = derive_pseudonym("secret123", "bank_open_finance")
        p2 = derive_pseudonym("secret123", "bank_open_finance")
        assert p1 == p2

    def test_different_services_unlinkable(self):
        p_bank = derive_pseudonym("secret123", "bank_open_finance")
        p_insurance = derive_pseudonym("secret123", "insurance_co")
        p_health = derive_pseudonym("secret123", "health_system")
        assert p_bank != p_insurance
        assert p_bank != p_health
        assert p_insurance != p_health

    def test_different_persons_different_pseudonyms(self):
        p1 = derive_pseudonym("secret_person_1", "bank_open_finance")
        p2 = derive_pseudonym("secret_person_2", "bank_open_finance")
        assert p1 != p2

    def test_pseudonym_is_hex_sha256(self):
        p = derive_pseudonym("secret", "service")
        assert len(p) == 64
        int(p, 16)


@pytest.mark.phc
@pytest.mark.pseudonym
class TestPersonSecret:
    def test_deterministic(self):
        s1 = create_person_secret("hash123", "key456")
        s2 = create_person_secret("hash123", "key456")
        assert s1 == s2

    def test_different_hash_different_secret(self):
        s1 = create_person_secret("hash_a", "key")
        s2 = create_person_secret("hash_b", "key")
        assert s1 != s2

    def test_different_key_different_secret(self):
        s1 = create_person_secret("hash", "key_a")
        s2 = create_person_secret("hash", "key_b")
        assert s1 != s2


@pytest.mark.phc
@pytest.mark.pseudonym
class TestHolderSecretManager:
    def test_generates_256bit_secret(self, tmp_path):
        mgr = HolderSecretManager(storage_path=str(tmp_path / "holder.json"))
        secret = mgr.generate_secret()
        assert len(secret) == 64
        int(secret, 16)

    def test_load_or_create_persists(self, tmp_path):
        path = str(tmp_path / "holder.json")
        mgr = HolderSecretManager(storage_path=path)

        secret1 = mgr.load_or_create()
        secret2 = mgr.load_or_create()
        assert secret1 == secret2

        with open(path, "r") as f:
            data = json.load(f)
        assert data["holder_local_secret"] == secret1

    def test_different_holders_different_secrets(self, tmp_path):
        mgr1 = HolderSecretManager(storage_path=str(tmp_path / "holder1.json"))
        mgr2 = HolderSecretManager(storage_path=str(tmp_path / "holder2.json"))

        s1 = mgr1.load_or_create()
        s2 = mgr2.load_or_create()
        assert s1 != s2

    def test_issuer_cannot_derive_pseudonym(self, tmp_path):

        mgr = HolderSecretManager(storage_path=str(tmp_path / "holder.json"))
        holder_secret = mgr.load_or_create()
        person_hash = "a" * 64

        real_person_secret = create_person_secret(person_hash, holder_secret)
        real_pseudonym = derive_pseudonym(real_person_secret, "bank")

        issuer_guess_secret = create_person_secret(person_hash, "issuer-does-not-know-this")
        issuer_guess_pseudonym = derive_pseudonym(issuer_guess_secret, "bank")

        assert real_pseudonym != issuer_guess_pseudonym
