import requests
import time
import secrets
from .config import (
    HOLDER_A_URL, HOLDER_B_URL, ISSUER_URL,
    HOLDER_A_STATE_FILE, HOLDER_B_STATE_FILE,
    CREDENTIAL_TTL_SECONDS, BIOMETRIC_THRESHOLD,
    get_holder_config,
)
from .utils import load_state, load_holder_state, get_connection_id
from .pseudonym import derive_pseudonym


def _send_holder_proof_request(requester_url, conn_id, cred_def_id):

    to_timestamp = int(time.time())
    min_timestamp = to_timestamp - CREDENTIAL_TTL_SECONDS
    nonce = str(secrets.randbelow(2**128))

    proof_request = {
        "connection_id": conn_id,
        "presentation_request": {
            "anoncreds": {
                "name": "PHC Mutual Authentication",
                "version": "1.0",
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

    resp = requests.post(
        f"{requester_url}/present-proof-2.0/send-request",
        json=proof_request,
    )
    if resp.status_code != 200:
        return None, f"Proof request failed: {resp.text}"

    pres_ex_id = resp.json().get("pres_ex_id")
    return pres_ex_id, None


def _wait_and_verify(requester_url, pres_ex_id, label, timeout=40):

    for _ in range(timeout // 2):
        time.sleep(2)
        try:
            resp = requests.get(f"{requester_url}/present-proof-2.0/records/{pres_ex_id}")
            if resp.status_code == 404:
                return False, f"{label}: Record not found"

            data = resp.json()
            state = data.get("state", "unknown")

            if state == "presentation-received":
                verify_resp = requests.post(
                    f"{requester_url}/present-proof-2.0/records/{pres_ex_id}/verify-presentation"
                )
                verify_data = verify_resp.json()
                verified = str(verify_data.get("verified", "false")).lower() == "true"

                if verified:
                    return True, f"{label}: Humanity VERIFIED via ZKP"
                else:
                    msgs = verify_data.get("verified_msgs", [])
                    return False, f"{label}: Verification FAILED — {msgs}"

            if state == "done":
                verified = str(data.get("verified", "false")).lower() == "true"
                if verified:
                    return True, f"{label}: Humanity VERIFIED via ZKP"
                return False, f"{label}: Verification FAILED"

        except Exception as e:
            return False, f"{label}: Error — {e}"

    return False, f"{label}: Timeout"


def perform_mutual_authentication() -> dict:

    messages = []
    state = load_state()
    cred_def_id = state.get("cred_def_id")

    if not cred_def_id:
        return {"success": False, "messages": ["Error: cred_def_id not found. Run issuer setup first."]}

    holder_a_state = load_holder_state(HOLDER_A_STATE_FILE)
    holder_b_state = load_holder_state(HOLDER_B_STATE_FILE)

    service_id_mutual = "mutual_auth_p2p"
    pseudo_a = pseudo_b = None

    person_secret_a = holder_a_state.get("person_secret")
    if person_secret_a:
        pseudo_a = derive_pseudonym(person_secret_a, service_id_mutual)
        messages.append(f"[Holder A] Pseudonym for mutual auth: {pseudo_a[:16]}...")

    person_secret_b = holder_b_state.get("person_secret")
    if person_secret_b:
        pseudo_b = derive_pseudonym(person_secret_b, service_id_mutual)
        messages.append(f"[Holder B] Pseudonym for mutual auth: {pseudo_b[:16]}...")

    if pseudo_a and pseudo_b:
        messages.append(f"[PHC] Pseudonyms are {'DIFFERENT' if pseudo_a != pseudo_b else 'SAME'} — unlinkable identities confirmed.")

    messages.append("\n--- Phase 1: Holder A verifies Holder B ---")

    conn_a_to_b = get_connection_id(HOLDER_A_URL, "Connection_HolderA_HolderB")
    if not conn_a_to_b:
        return {"success": False, "messages": messages + ["Error: Connection Holder A -> Holder B not found."]}

    pres_ex_id_1, err = _send_holder_proof_request(HOLDER_A_URL, conn_a_to_b, cred_def_id)
    if err:
        return {"success": False, "messages": messages + [err]}

    messages.append("[Holder A] Proof request sent to Holder B...")
    ok_1, msg_1 = _wait_and_verify(HOLDER_A_URL, pres_ex_id_1, "Holder A → Holder B")
    messages.append(msg_1)

    messages.append("\n--- Phase 2: Holder B verifies Holder A ---")

    conn_b_to_a = get_connection_id(HOLDER_B_URL, "Connection_HolderB_HolderA")
    if not conn_b_to_a:
        return {"success": False, "a_verified_b": ok_1, "b_verified_a": False,
                "messages": messages + ["Error: Connection Holder B -> Holder A not found."]}

    pres_ex_id_2, err = _send_holder_proof_request(HOLDER_B_URL, conn_b_to_a, cred_def_id)
    if err:
        return {"success": False, "a_verified_b": ok_1, "b_verified_a": False,
                "messages": messages + [err]}

    messages.append("[Holder B] Proof request sent to Holder A...")
    ok_2, msg_2 = _wait_and_verify(HOLDER_B_URL, pres_ex_id_2, "Holder B → Holder A")
    messages.append(msg_2)

    success = ok_1 and ok_2
    if success:
        messages.append("\n[PHC] MUTUAL AUTHENTICATION COMPLETE — Both users verified as human.")
    else:
        messages.append("\n[PHC] MUTUAL AUTHENTICATION FAILED.")

    return {
        "success": success,
        "a_verified_b": ok_1,
        "b_verified_a": ok_2,
        "pseudonym_a": pseudo_a,
        "pseudonym_b": pseudo_b,
        "messages": messages,
    }
