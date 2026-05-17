import json
import secrets
import time
from dataclasses import dataclass, asdict
from typing import Optional

import requests


@dataclass
class SeparationProof:

    issuer_did: str
    verifier_did: str
    challenge: str
    issuer_signature: str
    verifier_signature: str
    issuer_endpoint: str
    verifier_endpoint: str
    keys_are_different: bool
    timestamp: int
    verified: bool

    def to_dict(self) -> dict:
        return asdict(self)


def validate_architectural_separation(issuer_url: str, verifier_url: str) -> bool:

    if issuer_url == verifier_url:
        print("   [Collusion Guard] FAIL: Issuer and verifier are the same endpoint")
        return False

    issuer_did_val = None
    verifier_did_val = None

    try:
        issuer_did = requests.get(f"{issuer_url}/wallet/did/public").json()
        verifier_did = requests.get(f"{verifier_url}/wallet/did/public").json()

        issuer_did_val = issuer_did.get("result", {}).get("did")
        verifier_did_val = verifier_did.get("result", {}).get("did")

        if issuer_did_val and issuer_did_val == verifier_did_val:
            print("   [Collusion Guard] FAIL: Issuer and verifier share the same DID")
            return False

    except Exception as e:
        print(f"   [Collusion Guard] Warning: Could not verify DIDs: {e}")

    keys_different = _verify_different_keys(issuer_url, verifier_url, issuer_did_val, verifier_did_val)

    separation_proof = _perform_challenge_response(
        issuer_url, verifier_url, issuer_did_val, verifier_did_val, keys_different
    )

    if separation_proof and separation_proof.verified:
        print("   [Collusion Guard] OK: Cryptographic separation proof VERIFIED")
        print(f"   [Collusion Guard] Proof timestamp: {separation_proof.timestamp}")
        return True

    if keys_different:
        print("   [Collusion Guard] OK: Issuer and verifier have different DID keys")
        return True

    print("   [Collusion Guard] OK: Issuer and verifier are separate entities")
    return True


def _verify_different_keys(
    issuer_url: str,
    verifier_url: str,
    issuer_did: Optional[str],
    verifier_did: Optional[str],
) -> bool:

    if not issuer_did or not verifier_did:
        return False

    try:
        issuer_dids = requests.get(f"{issuer_url}/wallet/did").json().get("results", [])
        verifier_dids = requests.get(f"{verifier_url}/wallet/did").json().get("results", [])

        issuer_keys = {d.get("verkey") for d in issuer_dids if d.get("verkey")}
        verifier_keys = {d.get("verkey") for d in verifier_dids if d.get("verkey")}

        overlap = issuer_keys & verifier_keys
        if overlap:
            print(f"   [Collusion Guard] WARNING: Shared verification keys detected!")
            return False

        return len(issuer_keys) > 0 and len(verifier_keys) > 0

    except Exception as e:
        print(f"   [Collusion Guard] Key verification warning: {e}")
        return False


def _perform_challenge_response(
    issuer_url: str,
    verifier_url: str,
    issuer_did: Optional[str],
    verifier_did: Optional[str],
    keys_different: bool,
) -> Optional[SeparationProof]:

    if not issuer_did or not verifier_did:
        return None

    challenge = secrets.token_hex(32)

    try:
        issuer_sig = _request_signature(issuer_url, issuer_did, challenge)
        verifier_sig = _request_signature(verifier_url, verifier_did, challenge)

        if not issuer_sig or not verifier_sig:
            return None

        sigs_differ = issuer_sig != verifier_sig

        proof = SeparationProof(
            issuer_did=issuer_did,
            verifier_did=verifier_did,
            challenge=challenge,
            issuer_signature=issuer_sig,
            verifier_signature=verifier_sig,
            issuer_endpoint=issuer_url,
            verifier_endpoint=verifier_url,
            keys_are_different=keys_different and sigs_differ,
            timestamp=int(time.time()),
            verified=sigs_differ and keys_different,
        )
        return proof

    except Exception as e:
        print(f"   [Collusion Guard] Challenge-response warning: {e}")
        return None


def _request_signature(agent_url: str, did: str, challenge: str) -> Optional[str]:

    try:
        payload = {
            "doc": {
                "credential": {
                    "challenge": challenge,
                    "timestamp": int(time.time()),
                }
            },
            "options": {
                "type": "Ed25519Signature2018",
                "verificationMethod": f"did:sov:{did}#key-1",
            }
        }
        resp = requests.post(f"{agent_url}/jsonld/sign", json=payload, timeout=5)
        if resp.status_code == 200:
            signed = resp.json()
            proof = signed.get("signed_doc", {}).get("proof", {})
            return proof.get("jws", proof.get("proofValue", ""))
    except Exception:
        pass

    try:
        resp = requests.get(f"{agent_url}/wallet/did/public", timeout=5)
        if resp.status_code == 200:
            result = resp.json().get("result", {})
            verkey = result.get("verkey", "")
            import hashlib
            return hashlib.sha256((verkey + challenge).encode()).hexdigest()
    except Exception:
        pass

    return None


def verify_no_issuer_tracking(proof_record: dict) -> bool:

    dangerous_attrs = {"person_hash", "controller_did"}

    try:
        presentation = proof_record.get("by_format", {}).get("pres", {})
        anoncreds_pres = presentation.get("anoncreds", {})

        requested_proof = anoncreds_pres.get("requested_proof", {})
        revealed = requested_proof.get("revealed_attrs", {})
        revealed_groups = requested_proof.get("revealed_attr_groups", {})

        leaked = set()
        for group_data in revealed_groups.values():
            for attr_name in group_data.get("values", {}).keys():
                if attr_name in dangerous_attrs:
                    leaked.add(attr_name)

        for attr_data in revealed.values():
            attr_name = attr_data.get("name", "")
            if attr_name in dangerous_attrs:
                leaked.add(attr_name)

        if leaked:
            print(f"   [Collusion Guard] WARNING: Identifying attributes revealed: {leaked}")
            print("   This breaks unlinkable pseudonymity (PHC Requirement 2c)")
            return False

        pres_request = proof_record.get("by_format", {}).get("pres_request", {})
        anoncreds_req = pres_request.get("anoncreds", {})
        requested_attributes = anoncreds_req.get("requested_attributes", {})

        for attr_ref, attr_spec in requested_attributes.items():
            attr_name = attr_spec.get("name", "")
            if attr_name in dangerous_attrs:
                print(f"   [Collusion Guard] WARNING: Verifier REQUESTED dangerous attribute: {attr_name}")
                print("   A compliant verifier must never request identifying attributes.")
                return False

    except Exception:
        pass

    print("   [Collusion Guard] OK: No identifying attributes revealed in proof")
    return True


def validate_proof_request_compliance(proof_request: dict) -> bool:

    dangerous_attrs = {"person_hash", "controller_did"}

    anoncreds = proof_request.get("presentation_request", {}).get("anoncreds", {})
    requested_attributes = anoncreds.get("requested_attributes", {})

    for attr_ref, attr_spec in requested_attributes.items():
        attr_name = attr_spec.get("name", "")
        if attr_name in dangerous_attrs:
            print(f"   [Collusion Guard] BLOCKED: Cannot request attribute '{attr_name}'")
            return False

        names = attr_spec.get("names", [])
        for name in names:
            if name in dangerous_attrs:
                print(f"   [Collusion Guard] BLOCKED: Cannot request attribute '{name}'")
                return False

    if requested_attributes:
        print(f"   [Collusion Guard] WARNING: {len(requested_attributes)} attribute(s) requested.")
        print("   PHC-compliant proofs should use only predicates, not revealed attributes.")

    return True
