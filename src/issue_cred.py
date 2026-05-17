import requests
import json
import time
import sys
import uuid
from .config import (
    ISSUER_URL, HOLDER_A_URL, HOLDER_B_URL,
    HOLDER_A_STATE_FILE, HOLDER_B_STATE_FILE,
    ALLOW_SIMULATED_BIOMETRICS, get_holder_config,
)
from .utils import load_state, save_state, save_holder_state, get_connection_id
from .retry import retry_with_backoff
from .schemas import CredentialAttributes
from .enrollment import (
    perform_enrollment,
    verify_enrollment_token,
    get_enrollment_ceremony,
)
from .dedup_registry import is_person_registered, register_person
from .pseudonym import create_person_secret, HolderSecretManager


@retry_with_backoff(max_attempts=3, initial_delay=1.0)
def send_credential_offer(payload):
    resp = requests.post(f"{ISSUER_URL}/issue-credential-2.0/send-offer", json=payload)
    if resp.status_code != 200:
        raise requests.HTTPError(f"Status: {resp.status_code}, Response: {resp.text}")
    return resp


def _issuer_enrollment(conn_id_issuer: str) -> tuple:

    state = load_state()
    cred_def_id = state.get("cred_def_id")
    if not cred_def_id:
        print("   Error: 'cred_def_id' not found.")
        return None, None

    print("   [PHC] Starting offline enrollment ceremony...")

    if ALLOW_SIMULATED_BIOMETRICS:
        from .biometric import SimulatedBiometricProvider, SimulatedDocumentVerifier
        bio = SimulatedBiometricProvider(allow_simulated=True)
        doc = SimulatedDocumentVerifier(allow_simulated=True)

        biometric_capture = bio.capture()
        document_check = doc.verify("PASSPORT-BR-123456789")

        biometric_data = {
            "template_hash": biometric_capture.template_hash,
            "score": biometric_capture.score,
            "method": biometric_capture.method,
            "captured_at": biometric_capture.captured_at,
            "liveness_passed": biometric_capture.liveness_passed,
            "device_id": biometric_capture.device_id,
            "device_attestation": biometric_capture.device_attestation,
        }
        document_data = {
            "document_hash": document_check.document_hash,
            "document_type": document_check.document_type,
            "verified": document_check.verified,
            "verified_at": document_check.verified_at,
            "verification_method": document_check.verification_method,
        }

        try:
            enrollment = perform_enrollment(biometric_data, document_data)
        except ValueError as e:
            print(f"   [PHC] Enrollment REJECTED: {e}")
            return None, None
    else:
        try:
            ceremony = get_enrollment_ceremony()
            enrollment = ceremony.perform("PASSPORT-BR-123456789")
        except (ValueError, RuntimeError) as e:
            print(f"   [PHC] Enrollment REJECTED: {e}")
            return None, None

    if not verify_enrollment_token(
        enrollment.person_hash,
        str(enrollment.enrollment_timestamp),
        enrollment.enrollment_token,
    ):
        print("   [PHC] Enrollment token verification FAILED")
        return None, None

    if not enrollment.liveness_passed:
        print("   [PHC] REJECTED: Liveness detection did not pass.")
        return None, None

    print(f"   [PHC] Enrollment OK | person_hash: {enrollment.person_hash[:16]}...")
    print(f"   [PHC] Liveness: PASSED | Device: {enrollment.device_id}")

    if is_person_registered(enrollment.person_hash):
        print("   [PHC] REJECTED: This person already holds an active credential.")
        return None, None

    print("   [PHC] Dedup check passed: no active credential for this person.")
    return enrollment, cred_def_id


def _holder_store_secret(person_hash: str, state_file: str = None):

    secret_mgr = HolderSecretManager(storage_path=state_file)
    holder_local_secret = secret_mgr.load_or_create()

    person_secret = create_person_secret(person_hash, holder_local_secret)
    save_holder_state("person_secret", person_secret, state_file=state_file)
    save_holder_state("person_hash", person_hash, state_file=state_file)
    print("   [PHC] Holder-side secret generated and stored locally.")
    print("   [PHC] Issuer has NO access to this secret (PHC Requirement 2c).")


def issue_to_holder(holder_id: str = "a"):

    hcfg = get_holder_config(holder_id)
    holder_url = hcfg["url"]
    state_file = hcfg["state_file"]
    gov_alias = f"Connection_Gov_Bot{holder_id.upper()}"

    print(f"### 3. ISSUING CREDENTIAL TO HOLDER {holder_id.upper()} (PHC COMPLIANT) ###")

    state = load_state()
    cred_def_id = state.get("cred_def_id")

    if not cred_def_id:
        print("   Error: 'cred_def_id' not found.")
        return False

    conn_id_issuer = get_connection_id(ISSUER_URL, gov_alias)
    if not conn_id_issuer:
        print(f"   Error: Connection not found for {gov_alias}.")
        return False

    enrollment, cred_def_id = _issuer_enrollment(conn_id_issuer)
    if enrollment is None:
        return False

    print(f"   [Issuer] Sending offer (AnonCreds format)...")

    attributes = CredentialAttributes(
        person_hash=enrollment.person_hash,
        biometric_score=str(enrollment.biometric_score),
        controller_did=f"did:sov:{uuid.uuid4().hex[:32]}",
    )

    payload = {
        "connection_id": conn_id_issuer,
        "credential_preview": {
            "@type": "issue-credential/2.0/credential-preview",
            "attributes": [
                {"name": "person_hash", "value": attributes.person_hash},
                {"name": "biometric_score", "value": attributes.biometric_score},
                {"name": "timestamp", "value": attributes.timestamp},
                {"name": "controller_did", "value": attributes.controller_did},
            ],
        },
        "filter": {"anoncreds": {"cred_def_id": cred_def_id}},
        "auto_remove": False,
    }

    try:
        resp = send_credential_offer(payload)
        print("   [Issuer] Offer sent successfully!")
    except Exception as e:
        print(f"\n   ISSUER ERROR after 3 attempts: {e}")
        return False

    print("   [Bot] Processing...")
    time.sleep(3)

    try:
        all_records = requests.get(f"{holder_url}/issue-credential-2.0/records").json()['results']
        if not all_records:
            print("   ERROR: Bot received nothing.")
            return False

        target_record = all_records[-1].get('cred_ex_record', all_records[-1])
        cred_ex_id = target_record['cred_ex_id']
        state_cred = target_record['state']

        print(f"   -> Record: {cred_ex_id} | State: {state_cred}")

        if state_cred == "offer-received":
            requests.post(f"{holder_url}/issue-credential-2.0/records/{cred_ex_id}/send-request")
            time.sleep(2)
            rec = requests.get(f"{holder_url}/issue-credential-2.0/records/{cred_ex_id}").json()
            state_cred = rec.get('cred_ex_record', rec)['state']

        if state_cred == "credential-received":
            requests.post(f"{holder_url}/issue-credential-2.0/records/{cred_ex_id}/store",
                          json={"credential_id": cred_ex_id})
            print("   Credential stored!")

        elif state_cred == "request-sent":
            print("   State 'request-sent'. Forcing Issuer...")
            iss_recs = requests.get(f"{ISSUER_URL}/issue-credential-2.0/records", params={"state": "request-received"}).json()['results']
            if iss_recs:
                 t = iss_recs[-1].get('cred_ex_record', iss_recs[-1])
                 requests.post(f"{ISSUER_URL}/issue-credential-2.0/records/{t['cred_ex_id']}/issue", json={"comment":"force"})
                 print("   [Issuer] Issued.")
                 time.sleep(2)
                 requests.post(f"{holder_url}/issue-credential-2.0/records/{cred_ex_id}/store", json={"credential_id": cred_ex_id})
                 print("   Credential stored!")

        elif state_cred == "done":
             print("   Already completed.")

        register_person(enrollment.person_hash, cred_def_id, int(time.time()))
        save_state("person_hash", enrollment.person_hash)

        _holder_store_secret(enrollment.person_hash, state_file=state_file)

        final = requests.get(f"{holder_url}/credentials").json()['results']
        print(f"\n   SUMMARY: Holder {holder_id.upper()} has {len(final)} credential(s).")
        return True

    except Exception as e:
        print(f"Bot error: {e}")
        return False


def main():
    issue_to_holder("a")
    issue_to_holder("b")

if __name__ == "__main__":
    main()
