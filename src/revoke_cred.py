import requests
import json
import sys
import time
from .config import ISSUER_URL, HOLDER_URL
from .utils import load_state, save_state
from .dedup_registry import mark_revoked


def main():
    print("### 5. REVOKING CREDENTIAL (PHC COMPLIANT) ###")

    print("   Fetching credential from Holder...")
    try:
        creds_resp = requests.get(f"{HOLDER_URL}/credentials")
        if creds_resp.status_code != 200:
            print("   Error fetching credentials from Holder")
            return

        credentials = creds_resp.json()['results']
        if not credentials:
            print("   No credentials found in Holder")
            return

        credential = credentials[0]
        rev_reg_id = credential.get('rev_reg_id')
        cred_rev_id = credential.get('cred_rev_id')

        print(f"   Registry ID: {rev_reg_id}")
        print(f"   Credential Revocation ID: {cred_rev_id}")

    except Exception as e:
        print(f"   Error: {e}")
        return

    print("   Sending revocation order...")

    from .utils import get_connection_id
    conn_id = get_connection_id(ISSUER_URL, "Connection_Gov_Bot")

    revoke_payload = {
        "rev_reg_id": rev_reg_id,
        "cred_rev_id": cred_rev_id,
        "publish": True,
        "notify": bool(conn_id),
    }
    if conn_id:
        revoke_payload["connection_id"] = conn_id

    try:
        revoke_resp = requests.post(f"{ISSUER_URL}/anoncreds/revocation/revoke", json=revoke_payload)

        if revoke_resp.status_code == 200:
            print("\n   SUCCESS: Credential REVOKED and published to Ledger!")

            state = load_state()
            person_hash = state.get("person_hash")
            if person_hash:
                mark_revoked(person_hash)
                print("   [PHC] Person can now re-enroll (one-per-person limit reset).")

            from .utils import load_holder_state, save_holder_state
            save_holder_state("person_secret", "")
            save_holder_state("usage_count_since_reauth", 0)
            save_holder_state("last_reauth_timestamp", 0)
            print("   [PHC] Holder state cleared (pseudonym secret invalidated).")

            print("   -----------------------------------------------------")
            print("   FINAL TEST: Run 'script 4' now.")
            print("   The Bank MUST deny access (Invalid Signature).")
            print("   -----------------------------------------------------")
        else:
            print(f"\n   Revocation failed: {revoke_resp.status_code}")
            print(f"Details: {revoke_resp.text}")

    except Exception as e:
        print(f"   Exception: {e}")

if __name__ == "__main__":
    main()
