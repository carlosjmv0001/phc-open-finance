import requests
import json
import secrets
import time
import sys
from .config import (
    VERIFIER_A_URL, VERIFIER_B_URL, ISSUER_URL,
    CREDENTIAL_TTL_SECONDS, BIOMETRIC_THRESHOLD,
    HOLDER_A_STATE_FILE, HOLDER_B_STATE_FILE, get_holder_config,
)
from .utils import load_state, load_holder_state, save_holder_state, get_connection_id
from .pseudonym import derive_pseudonym
from .collusion_guard import validate_architectural_separation, verify_no_issuer_tracking


def _print_safe(text: str):
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode("ascii", errors="replace").decode("ascii"))


class NonceRegistry:

    def __init__(self, ttl_seconds: int = 300):
        self._nonces: dict = {}
        self._ttl = ttl_seconds

    def issue(self) -> str:
        nonce = str(secrets.randbelow(2**128))
        self._nonces[nonce] = time.time()
        self._cleanup()
        return nonce

    def validate_and_consume(self, nonce: str) -> bool:
        self._cleanup()
        if nonce in self._nonces:
            del self._nonces[nonce]
            return True
        return False

    def _cleanup(self):
        now = time.time()
        self._nonces = {n: t for n, t in self._nonces.items() if now - t < self._ttl}


_nonce_registry = NonceRegistry(ttl_seconds=300)


def send_proof_request(conn_id, cred_def_id, service_id="bank_open_finance", verifier_url=None):
    to_timestamp = int(time.time())
    min_timestamp = to_timestamp - CREDENTIAL_TTL_SECONDS

    nonce = _nonce_registry.issue()

    proof_request = {
        "connection_id": conn_id,
        "presentation_request": {
            "anoncreds": {
                "name": "PHC Proof of Personhood",
                "version": "2.0",
                "nonce": nonce,
                "requested_attributes": {},
                "requested_predicates": {
                    "0_biometric_pred": {
                        "name": "biometric_score",
                        "p_type": ">=",
                        "p_value": BIOMETRIC_THRESHOLD,
                        "restrictions": [{"cred_def_id": cred_def_id}],
                        "non_revoked": {"from": 0, "to": to_timestamp},
                    },
                    "0_expiry_pred": {
                        "name": "timestamp",
                        "p_type": ">=",
                        "p_value": min_timestamp,
                        "restrictions": [{"cred_def_id": cred_def_id}],
                        "non_revoked": {"from": 0, "to": to_timestamp},
                    },
                },
                "non_revoked": {"from": 0, "to": to_timestamp},
            }
        },
    }

    url = verifier_url or VERIFIER_A_URL
    try:
        resp = requests.post(f"{url}/present-proof-2.0/send-request", json=proof_request)
        if resp.status_code != 200:
            print(f"Request Error: {resp.text}")
            return None

        pres_ex_id = resp.json().get("pres_ex_id")
        print(f"   [OK] Transaction ID: {pres_ex_id}")
        print(f"   [PHC] Nonce: {nonce[:16]}... (cryptographically random, single-use)")
        return pres_ex_id

    except Exception as e:
        print(f"Send error: {e}")
        return None


def verify_with_bank(verifier_url, bank_name, conn_alias, service_id, cred_def_id,
                     holder_state, holder_state_file=None):

    print(f"\n   --- {bank_name}: Proof Verification ---")

    conn_id = get_connection_id(verifier_url, conn_alias)
    if not conn_id:
        print(f"   Error: Connection not found for {bank_name} (alias: {conn_alias}).")
        return False

    validate_architectural_separation(ISSUER_URL, verifier_url)

    person_secret = holder_state.get("person_secret")
    if person_secret:
        pseudonym = derive_pseudonym(person_secret, service_id)
        print(f"   [PHC] Service pseudonym for '{service_id}': {pseudonym[:16]}...")
        print(f"   [PHC] This pseudonym is unlinkable to other services.")

    print("   Sending PHC challenge (ZKP predicates, no attribute disclosure)...")
    print(f"   [PHC] Predicate: biometric_score >= {BIOMETRIC_THRESHOLD}")
    print(f"   [PHC] Predicate: credential age <= {CREDENTIAL_TTL_SECONDS}s (TTL)")

    pres_ex_id = send_proof_request(conn_id, cred_def_id, service_id, verifier_url=verifier_url)
    if not pres_ex_id:
        return False

    print("   Awaiting proof from Bot...")

    for i in range(20):
        time.sleep(2)
        try:
            status_resp = requests.get(f"{verifier_url}/present-proof-2.0/records/{pres_ex_id}")
            if status_resp.status_code == 404:
                break

            status_data = status_resp.json()
            state_proof = status_data.get("state", "unknown")

            sys.stdout.write(f"\r   [{bank_name}] Status: '{state_proof}'   ")
            sys.stdout.flush()

            if state_proof == "presentation-received":
                sys.stdout.write(" [Verifying...] ")
                verify_resp = requests.post(f"{verifier_url}/present-proof-2.0/records/{pres_ex_id}/verify-presentation")

                verify_data = verify_resp.json()
                verified = verify_data.get("verified")
                error_msg = verify_data.get("verified_msgs", [])

                verify_no_issuer_tracking(verify_data)

                usage = holder_state.get("usage_count_since_reauth", 0) + 1
                save_holder_state("usage_count_since_reauth", usage, state_file=holder_state_file)

                is_valid = str(verified).lower() == "true"

                _print_safe(f"\n\n   [{bank_name}] CYCLE COMPLETE!")
                _print_safe(f"   TECHNICAL RESULT: {verified}")

                if is_valid:
                    _print_safe(f"   \U0001f7e2 STATUS: VALID")
                    _print_safe(f"   [{bank_name}] Access to banking data: GRANTED.")
                    _print_safe(f"   [PHC] Proof verified via ZKP predicates only.")
                    _print_safe(f"   [PHC] No personal attributes were revealed.")
                else:
                    _print_safe(f"   \U0001f534 STATUS: INVALID / REVOKED")
                    _print_safe(f"   [OPEN FINANCE] Access DENIED.")
                    if error_msg:
                        _print_safe(f"   Reason: {error_msg}")

                return is_valid

        except Exception as e:
            print(f"\nPolling error: {e}")
            break

    print(f"\n   [{bank_name}] Timeout exceeded.")
    return False


def verify_holder_with_bank(holder_id: str = "a"):

    hcfg = get_holder_config(holder_id)
    state = load_state()
    holder_state = load_holder_state(hcfg["state_file"])
    cred_def_id = state.get("cred_def_id")

    if not cred_def_id:
        print("   Error: 'cred_def_id' not found.")
        return False

    return verify_with_bank(
        verifier_url=hcfg["bank_url"],
        bank_name=hcfg["bank_name"],
        conn_alias=hcfg["bank_conn_alias"],
        service_id=hcfg["bank_service_id"],
        cred_def_id=cred_def_id,
        holder_state=holder_state,
        holder_state_file=hcfg["state_file"],
    )


def main():
    print("### 4. PHC PROOF VERIFICATION (BANK A + BANK B) ###")

    state = load_state()
    cred_def_id = state.get("cred_def_id")

    if not cred_def_id:
        print("   Error: 'cred_def_id' not found.")
        return

    holder_a_state = load_holder_state(HOLDER_A_STATE_FILE)
    holder_b_state = load_holder_state(HOLDER_B_STATE_FILE)

    person_secret_a = holder_a_state.get("person_secret")
    person_secret_b = holder_b_state.get("person_secret")

    if person_secret_a:
        pseudo_a = derive_pseudonym(person_secret_a, "bank_a_open_finance")
        print(f"\n   [PHC] Holder A pseudonym at Bank A: {pseudo_a[:16]}...")

    if person_secret_b:
        pseudo_b = derive_pseudonym(person_secret_b, "bank_b_open_finance")
        print(f"   [PHC] Holder B pseudonym at Bank B: {pseudo_b[:16]}...")

    verify_holder_with_bank("a")

    verify_holder_with_bank("b")

if __name__ == "__main__":
    main()
