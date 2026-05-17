import pytest  
import requests  
import time  
import os  
import requests_mock  
import subprocess  
import sys  
from unittest.mock import patch  
from src.config import ISSUER_URL, HOLDER_A_URL, VERIFIER_A_URL, VERIFIER_B_URL
from src.utils import load_state, save_state, get_connection_id  
from src.retry import retry_with_backoff  
  
@pytest.mark.integration  
class TestCredentialFlow:  
  
    @pytest.fixture(autouse=True)  
    def setup(self, docker_compose):  
        if os.path.exists("system_state.json"):  
            os.remove("system_state.json")  
  
        from src.setup_connections import main  
        main()  
  
    def test_issuer_setup(self):  
        from src.issuer_setup import main  
  
        did_resp = requests.get(f"{ISSUER_URL}/wallet/did/public")  
        if did_resp.status_code == 200:  
            issuer_did = did_resp.json()['result']['did']  
        else:  
            pytest.skip("Issuer has no public DID")  
  
        state = load_state()  
        if "schema_id" in state:  
            schema_id = state["schema_id"]  
            resp = requests.get(f"{ISSUER_URL}/anoncreds/schema/{schema_id}")  
            assert resp.status_code == 200  
        else:  
            try:  
                main()  
            except SystemExit:  
                pass  
  
            state = load_state()  
  
            if "schema_id" not in state:  
                resp = requests.get(f"{ISSUER_URL}/anoncreds/schemas",  
                                params={"schema_issuer_id": issuer_did,  
                                        "schema_name": "personhood_credential_revocable",  
                                        "schema_version": "2.0"})  
                if resp.status_code == 200 and resp.json()["schema_ids"]:  
                    schema_id = resp.json()["schema_ids"][0]  
                    save_state("schema_id", schema_id)  
                    state = load_state()  
  
            if "schema_id" in state:  
                schema_id = state["schema_id"]  
                resp = requests.get(f"{ISSUER_URL}/anoncreds/schema/{schema_id}")  
                assert resp.status_code == 200  
  
        if "cred_def_id" not in state and "schema_id" in state:  
            resp = requests.get(f"{ISSUER_URL}/anoncreds/credential-definitions",  
                            params={"schema_id": state["schema_id"]})  
            if resp.status_code == 200 and resp.json()["credential_definition_ids"]:  
                cred_def_id = resp.json()["credential_definition_ids"][0]  
                save_state("cred_def_id", cred_def_id)  
                state = load_state()  
  
        if "cred_def_id" in state:  
            cred_def_id = state["cred_def_id"]  
            resp = requests.get(f"{ISSUER_URL}/anoncreds/credential-definition/{cred_def_id}")  
            assert resp.status_code == 200  
  
        assert "schema_id" in state  
        assert "cred_def_id" in state  
  
    def test_credential_issuance(self):  
        did_resp = requests.get(f"{ISSUER_URL}/wallet/did/public")  
        if did_resp.status_code == 200:  
            issuer_did = did_resp.json()['result']['did']  
        else:  
            pytest.skip("Issuer has no public DID")  
  
        state = load_state()  
        if "schema_id" not in state or "cred_def_id" not in state:  
            try:  
                from src.issuer_setup import main  
                main()  
            except SystemExit:  
                state = load_state()  
                if "schema_id" not in state:  
                    resp = requests.get(f"{ISSUER_URL}/anoncreds/schemas",  
                                    params={"schema_issuer_id": issuer_did,  
                                            "schema_name": "personhood_credential_revocable",  
                                            "schema_version": "2.0"})  
                    if resp.status_code == 200 and resp.json()["schema_ids"]:  
                        schema_id = resp.json()["schema_ids"][0]  
                        save_state("schema_id", schema_id)  
  
                if "cred_def_id" not in state:  
                    state = load_state()  
                    if "schema_id" in state:  
                        resp = requests.get(f"{ISSUER_URL}/anoncreds/credential-definitions",  
                                        params={"schema_id": state["schema_id"]})  
                        if resp.status_code == 200 and resp.json()["credential_definition_ids"]:  
                            cred_def_id = resp.json()["credential_definition_ids"][0]  
                            save_state("cred_def_id", cred_def_id)  
  
        from src.issue_cred import main  
        main()  
  
        resp = requests.get(f"{HOLDER_A_URL}/credentials")  
        assert resp.status_code == 200  
        creds = resp.json()["results"]  
        assert len(creds) > 0  
  
        cred = creds[0]  
        assert "person_hash" in cred["attrs"]  
        assert "biometric_score" in cred["attrs"]  
  
    def test_proof_verification(self):  
        from src.issuer_setup import main  
        from src.issue_cred import main  
        main()  
        main()  
  
        from src.verifier_proof import main  
        main()  
  
  
    def test_proof_verification_flow(self, docker_compose):  
        from src.issuer_setup import main as setup_main  
        from src.issue_cred import main as cred_main  
        from src.verifier_proof import main as verify_main  
  
        try:  
            setup_main()  
        except SystemExit:  
            pass  
  
        print("   Clearing existing credentials...")  
        creds_resp = requests.get(f"{HOLDER_A_URL}/credentials")  
        if creds_resp.status_code == 200:  
            existing_creds = creds_resp.json()['results']  
            for cred in existing_creds:  
                cred_id = cred['referent']  
                delete_resp = requests.delete(f"{HOLDER_A_URL}/credential/{cred_id}")  
                if delete_resp.status_code != 200:  
                    print(f"   ⚠️ Failed to delete credential {cred_id}: {delete_resp.status_code}")  
            print(f"   Removed {len(existing_creds)} old credentials.")  
  
        cred_main()  
  
        from io import StringIO  
        import sys  
  
        old_stdout = sys.stdout  
        sys.stdout = captured_output = StringIO()  
  
        try:  
            verify_main()  
            output = captured_output.getvalue()  
        finally:  
            sys.stdout = old_stdout  
  
        assert "🟢 STATUS: VALID" in output

    def test_dual_bank_verification(self, docker_compose):

        from src.issuer_setup import main as setup_main
        from src.issue_cred import main as cred_main
        from src.verifier_proof import verify_with_bank
        from src.utils import load_state, load_holder_state

        try:
            setup_main()
        except SystemExit:
            pass

        creds_resp = requests.get(f"{HOLDER_A_URL}/credentials")
        if creds_resp.status_code == 200:
            for cred in creds_resp.json()['results']:
                requests.delete(f"{HOLDER_A_URL}/credential/{cred['referent']}")

        cred_main()

        state = load_state()
        holder_state = load_holder_state()
        cred_def_id = state.get("cred_def_id")

        result_a = verify_with_bank(
            verifier_url=VERIFIER_A_URL,
            bank_name="Bank A",
            conn_alias="Connection_BankA_Bot",
            service_id="bank_a_open_finance",
            cred_def_id=cred_def_id,
            holder_state=holder_state,
        )
        assert result_a is True, "Bank A verification should succeed"

        result_b = verify_with_bank(
            verifier_url=VERIFIER_B_URL,
            bank_name="Bank B",
            conn_alias="Connection_BankB_Bot",
            service_id="bank_b_open_finance",
            cred_def_id=cred_def_id,
            holder_state=holder_state,
        )
        assert result_b is True, "Bank B verification should succeed"

        from src.pseudonym import derive_pseudonym
        person_secret = holder_state.get("person_secret")
        if person_secret:
            pseudo_a = derive_pseudonym(person_secret, "bank_a_open_finance")
            pseudo_b = derive_pseudonym(person_secret, "bank_b_open_finance")
            assert pseudo_a != pseudo_b, "Pseudonyms must differ across banks"

    def test_revoked_proof_verification(self, docker_compose):  
        from src.issuer_setup import main as setup_main  
        from src.issue_cred import main as cred_main  
        from src.revoke_cred import main as revoke_main  
        from src.verifier_proof import main as verify_main  
  
        try:  
            setup_main()  
        except SystemExit:  
            pass  
  
        print("   Clearing existing credentials...")  
        creds_resp = requests.get(f"{HOLDER_A_URL}/credentials")  
        if creds_resp.status_code == 200:  
            existing_creds = creds_resp.json()['results']  
            for cred in existing_creds:  
                cred_id = cred['referent']  
                delete_resp = requests.delete(f"{HOLDER_A_URL}/credential/{cred_id}")  
                if delete_resp.status_code != 200:  
                    print(f"   ⚠️ Failed to delete credential {cred_id}: {delete_resp.status_code}")  
            print(f"   Removed {len(existing_creds)} old credentials.")  
  
            time.sleep(1)  
            final_check = requests.get(f"{HOLDER_A_URL}/credentials")  
            if final_check.status_code == 200:  
                remaining = len(final_check.json()['results'])  
                print(f"   ✅ Check: Bot now has {remaining} credential(s).")  
  
        cred_main()  
  
        revoke_main()  
  
        print("   Waiting for revocation sync on ledger...")  
        time.sleep(10)  
  
        from io import StringIO  
        import sys  
  
        old_stdout = sys.stdout  
        sys.stdout = captured_output = StringIO()  
  
        try:  
            verify_main()  
            output = captured_output.getvalue()  
        finally:  
            sys.stdout = old_stdout  
  
        assert "🔴 STATUS: INVALID / REVOKED" in output 
  
@pytest.mark.integration  
class TestErrorScenarios:  
  
    def test_missing_did(self):  
        with requests_mock.Mocker() as m:  
            m.get(f"{ISSUER_URL}/wallet/did/public", status_code=404)  
  
            from src.issuer_setup import main  
  
            main()  
  
    def test_missing_cred_def(self):  
        if os.path.exists("system_state.json"):  
            os.remove("system_state.json")  
  
        from src.issue_cred import main  
  
        main()  
  
    def test_existing_schema_handling(self):  
        with patch('requests.post') as mock_post:  
            mock_post.return_value.status_code = 409  
            mock_post.return_value.text = "Schema already exists"  
  
            with patch('requests.get') as mock_get:  
                mock_get.return_value.status_code = 200  
                mock_get.return_value.json.return_value = {  
                    "schema_ids": ["test-schema-id"]  
                }  
  
                from src.issuer_setup import main  
                main()    
  
@pytest.mark.integration  
class TestRetryMechanism:  
  
    def test_retry_decorator_success(self):  
        @retry_with_backoff(max_attempts=3, initial_delay=0.01)  
        def success_func():  
            return "success"  
  
        assert success_func() == "success"  
  
    def test_retry_then_success(self):  
        from unittest.mock import Mock  
  
        mock_func = Mock(side_effect=[Exception("fail"), "success"])  
  
        @retry_with_backoff(max_attempts=3, initial_delay=0.01)  
        def test_func():  
            return mock_func()  
  
        with patch('time.sleep'):  
            assert test_func() == "success"  
            assert mock_func.call_count == 2  
  
    def test_retry_max_attempts_reached(self):  
        @retry_with_backoff(max_attempts=2, initial_delay=0.01)  
        def always_fail():  
            raise Exception("always fails")  
  
        with patch('time.sleep'):  
            with pytest.raises(Exception, match="always fails"):  
                always_fail()