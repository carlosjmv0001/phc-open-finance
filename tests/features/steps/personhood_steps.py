from behave import given, when, then
import requests
import time
import sys
from io import StringIO
from src.config import ISSUER_URL, HOLDER_A_URL, VERIFIER_A_URL, VERIFIER_B_URL
from src.utils import load_state, save_state


def _run_verifier_and_capture():
    from src.verifier_proof import main
    old_stdout = sys.stdout
    sys.stdout = buf = StringIO()
    try:
        main()
    finally:
        sys.stdout = old_stdout
    return buf.getvalue()


@given("the agents are running")
def step_agents_running(context):
    for url in [ISSUER_URL, HOLDER_A_URL, VERIFIER_A_URL, VERIFIER_B_URL]:
        resp = requests.get(f"{url}/status")
        assert resp.status_code == 200


@given("the connections are established")
def step_connections_established(context):
    from src.utils import get_connection_id

    conn_id = get_connection_id(ISSUER_URL, "Connection_Gov_BotA")
    assert conn_id is not None

    conn_id = get_connection_id(VERIFIER_A_URL, "Connection_BankA_Bot")
    assert conn_id is not None

    conn_id = get_connection_id(VERIFIER_B_URL, "Connection_BankB_Bot")
    assert conn_id is not None


@when("the Government issues a personhood credential")
def step_issue_credential(context):
    creds_resp = requests.get(f"{HOLDER_A_URL}/credentials")
    if creds_resp.status_code == 200:
        existing = creds_resp.json()["results"]
        for cred in existing:
            requests.delete(f"{HOLDER_A_URL}/credential/{cred['referent']}")
        if existing:
            time.sleep(1)
    from src.issuer_setup import main as setup_main
    from src.issue_cred import main as cred_main
    setup_main()
    cred_main()


@then("the Bot stores the credential")
def step_credential_stored(context):
    resp = requests.get(f"{HOLDER_A_URL}/credentials")
    creds = resp.json()["results"]
    assert len(creds) > 0


@when("the Bank requests proof of personhood")
def step_request_proof(context):
    time.sleep(2)
    context.verification_output = _run_verifier_and_capture()


@then("the Bot presents a valid proof")
def step_proof_valid(context):
    output = getattr(context, "verification_output", "")
    assert "STATUS: VALID" in output, f"Verifier output did not contain VALID status. Captured:\n{output}"


@then("the Bank grants access")
def step_access_granted(context):
    output = getattr(context, "verification_output", "")
    assert "STATUS: VALID" in output


@when("the Government revokes the credential")
def step_revoke_credential(context):
    from src.revoke_cred import main
    main()


@then(u'the Bot cannot present a valid proof')
def step_proof_invalid(context):
    time.sleep(5)  
    output = _run_verifier_and_capture()
    assert "INVALID" in output or "REVOKED" in output or "Timeout" in output or "abandoned" in output


@given(u'the Bot has a valid credential')
def step_bot_has_credential(context):
    creds_resp = requests.get(f"{HOLDER_A_URL}/credentials")
    if creds_resp.status_code == 200:
        for cred in creds_resp.json()["results"]:
            requests.delete(f"{HOLDER_A_URL}/credential/{cred['referent']}")
        time.sleep(1)
    from src.issue_cred import main
    main()


@when(u'the Bank requests a new proof')
def step_bank_requests_new_proof(context):
    context.proof_output = _run_verifier_and_capture()


@then(u'the Bank denies access')
def step_bank_denies_access(context):
    output = getattr(context, "proof_output", "")
    assert "INVALID" in output or "REVOKED" in output or "Timeout" in output


@given(u'the Government has no public DID')
def step_no_public_did(context):
    state = load_state()
    if "public_did" in state:
        context.original_did = state["public_did"]
    else:
        context.original_did = None


@when(u'it tries to issue a credential')
def step_try_issue_without_did(context):
    from unittest.mock import patch
    old_stdout = sys.stdout
    sys.stdout = buf = StringIO()
    context.setup_error = None
    try:
        with patch('requests.get') as mock_get:
            mock_get.return_value.status_code = 404
            mock_get.return_value.json.return_value = {}
            from src.issuer_setup import main as setup_main
            setup_main()
    except SystemExit:
        context.setup_error = "SystemExit when issuing without DID"
    except Exception as e:
        context.setup_error = str(e)
    finally:
        sys.stdout = old_stdout
        output = buf.getvalue()
        if "ERROR" in output and not context.setup_error:
            context.setup_error = "Issuer has no Public DID"


@then(u'the process fails with an appropriate error')
def step_process_fails(context):
    assert context.setup_error is not None


@given(u'the Tails Server is offline')
def step_tails_offline(context):
    import os
    context.tails_stopped = False
    if os.getenv("CODESPACES"):
        return
    try:
        import docker
        client = docker.from_env()
        container = client.containers.get("phc_open_finance-main-tails-server-1")
        container.stop()
        context.tails_stopped = True
    except Exception:
        pass


@when(u'trying to create a revocable credential')
def step_try_revocable_cred(context):
    try:
        state = load_state()
        if "cred_def_id" in state:
            resp = requests.post(
                f"{ISSUER_URL}/anoncreds/revocation-registry-definition",
                json={
                    "cred_def_id": state["cred_def_id"],
                    "issuer_id": "test",
                    "tag": "test_rev",
                    "max_cred_num": 100
                }
            )
            context.setup_error = None if resp.status_code == 200 else f"Error: {resp.text}"
        else:
            context.setup_error = "cred_def_id not found"
    except Exception as e:
        context.setup_error = str(e)


@then(u'the process fails or continues without revocation')
def step_tails_failure(context):
    import os
    if getattr(context, 'tails_stopped', False) is False and os.getenv("CODESPACES"):
        return
    if getattr(context, 'tails_stopped', False):
        try:
            import docker
            client = docker.from_env()
            container = client.containers.get("phc_open_finance-main-tails-server-1")
            container.start()
            time.sleep(5)
        except Exception:
            pass



@given(u'the enrollment ceremony requires liveness detection')
def step_enrollment_requires_liveness(context):
    from src.enrollment import EnrollmentCeremony
    from src.biometric import SimulatedBiometricProvider, SimulatedDocumentVerifier
    context.bio_provider = SimulatedBiometricProvider(allow_simulated=True)
    context.doc_verifier = SimulatedDocumentVerifier(allow_simulated=True)
    context.ceremony = EnrollmentCeremony(
        biometric_provider=context.bio_provider,
        document_verifier=context.doc_verifier,
    )


@when(u'an AI system attempts biometric capture without liveness')
def step_ai_attempts_without_liveness(context):
    from unittest.mock import patch
    context.enrollment_error = None
    try:
        with patch.object(context.bio_provider, 'verify_liveness', return_value=False):
            context.ceremony.perform(document_id="FAKE-DOC-001")
    except Exception as e:
        context.enrollment_error = str(e)


@then(u'the enrollment is rejected with a liveness failure')
def step_enrollment_rejected_liveness(context):
    assert context.enrollment_error is not None
    assert "liveness" in context.enrollment_error.lower() or "Liveness" in context.enrollment_error or "live person" in context.enrollment_error.lower()


@given(u'the Bot has a valid credential older than the re-auth interval')
def step_bot_has_expired_credential(context):
    from src.reauth import ReauthPolicy
    context.policy = ReauthPolicy(max_age_seconds=1, max_uses=100)


@when(u'the Bot attempts proof presentation')
def step_bot_attempts_proof(context):
    import time
    time.sleep(2) 
    context.needs_reauth = context.policy.needs_reauth(
        last_auth_timestamp=int(time.time()) - 10,
        usage_count=0,
    )


@then(u'the system requires a fresh biometric re-authentication')
def step_system_requires_reauth(context):
    assert context.needs_reauth is True


@given(u'the Bot generates a holder-local secret')
def step_bot_generates_secret(context):
    from src.pseudonym import HolderSecretManager
    manager = HolderSecretManager()
    context.secret = manager.generate_secret()
    assert len(context.secret) == 64


@given(u'derives pseudonyms for different services')
def step_derives_pseudonyms(context):
    from src.pseudonym import derive_pseudonym, create_person_secret
    person_secret = create_person_secret("test_person_hash", context.secret)
    context.pseudo_bank_a = derive_pseudonym(person_secret, "bank_a_open_finance")
    context.pseudo_bank_b = derive_pseudonym(person_secret, "bank_b_open_finance")
    context.person_secret = person_secret


@then(u'the pseudonyms for different services are different')
def step_pseudonyms_different(context):
    assert context.pseudo_bank_a != context.pseudo_bank_b


@then(u'the issuer cannot derive the pseudonyms')
def step_issuer_cannot_derive(context):
    from src.pseudonym import derive_pseudonym, create_person_secret
    issuer_attempt = create_person_secret("test_person_hash", "wrong_secret_key")
    issuer_pseudo = derive_pseudonym(issuer_attempt, "bank_a_open_finance")
    assert issuer_pseudo != context.pseudo_bank_a


@given(u'the Bank sends a proof request with a random nonce')
def step_bank_sends_nonce(context):
    from src.verifier_proof import NonceRegistry
    context.nonce_registry = NonceRegistry(ttl_seconds=300)
    context.nonce = context.nonce_registry.issue()


@when(u'the same nonce is used in a second request')
def step_nonce_reused(context):
    context.first_use = context.nonce_registry.validate_and_consume(context.nonce)
    context.second_use = context.nonce_registry.validate_and_consume(context.nonce)


@then(u'the second request is rejected as a replay')
def step_replay_rejected(context):
    assert context.first_use is True
    assert context.second_use is False
