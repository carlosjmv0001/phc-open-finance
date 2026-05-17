import pytest  
import requests  
import time  
from unittest.mock import patch  
from src.config import ISSUER_URL, HOLDER_A_URL, VERIFIER_A_URL  
from src.utils import load_state, save_state  
  
class TestRevocationFlow:  
  
    @pytest.fixture(autouse=True)  
    def setup(self, docker_compose):  
        state = load_state()  
  
        if "schema_id" not in state:  
            resp = requests.get(f"{ISSUER_URL}/anoncreds/schemas",  
                              params={"schema_issuer_id": "JHwVxCXyxk49hhXS3DQxxy",  
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
  
    @pytest.mark.revocation  
    def test_successful_revocation(self):  
        from src.revoke_cred import main  
  
        main()  
  
        time.sleep(2)  
  
    @pytest.mark.revocation  
    def test_verification_after_revocation_fails(self):  
        from src.revoke_cred import main  
        main()  
  
        from src.verifier_proof import main  
  
        result = main()  
        assert result is None   
  
    @pytest.mark.revocation  
    def test_revocation_without_credentials(self):  
        resp = requests.get(f"{ISSUER_URL}/issue-credential-2.0/records")  
        records = resp.json()["results"]  
  
        for record in records:  
            cred_ex_id = record.get("cred_ex_id", record.get("cred_ex_record", {}).get("cred_ex_id"))  
            if cred_ex_id:  
                requests.delete(f"{ISSUER_URL}/issue-credential-2.0/records/{cred_ex_id}")  
  
        from src.revoke_cred import main  
  
        main()  
  
    @pytest.mark.revocation
    def test_dynamic_cred_rev_id(self):
        from unittest.mock import Mock

        def mock_get_side_effect(url, **kwargs):
            resp = Mock()
            resp.status_code = 200
            if "credentials" in url:
                resp.json.return_value = {
                    "results": [{
                        "rev_reg_id": "test-reg-id",
                        "cred_rev_id": "42"
                    }]
                }
            elif "connections" in url:
                resp.json.return_value = {
                    "results": [{"connection_id": "test-conn-id", "alias": "Connection_Gov_BotA"}]
                }
            else:
                resp.json.return_value = {"results": []}
            return resp

        with patch('requests.get', side_effect=mock_get_side_effect), \
             patch('requests.post') as mock_post:
            mock_post.return_value.status_code = 200
            from src.revoke_cred import main
            main()
  
    @pytest.mark.error  
    def test_no_credentials_to_revoke(self):  
        with patch('requests.get') as mock_get:  
            mock_get.return_value.json.return_value = {"results": []}  
  
            from src.revoke_cred import main 
            main()
  
    @pytest.mark.error  
    def test_missing_rev_reg_id(self):  
        with patch('requests.get') as mock_get:  
            mock_get.return_value.json.return_value = {  
                "results": [{  
                    "cred_ex_record": {  
                        "by_format": {"cred_issue": {"anoncreds": {}}}  
                    }  
                }]  
            }  
  
            from src.revoke_cred import main
            main()
  
    @pytest.mark.error  
    def test_revocation_api_error(self):  
        with patch('requests.get') as mock_get, \
            patch('requests.post') as mock_post:  
  
            mock_get.return_value.json.return_value = {  
                "results": [{  
                    "cred_ex_record": {  
                        "by_format": {  
                            "cred_issue": {  
                                "anoncreds": {  
                                    "rev_reg_id": "test-reg-id"  
                                }  
                            }  
                        }  
                    }  
                }]  
            }  
  
            mock_post.return_value.status_code = 400  
            mock_post.return_value.text = "Bad Request"  
  
            from src.revoke_cred import main 
            main()  
  
    @pytest.mark.error  
    def test_network_error_during_revocation(self):  
        with patch('requests.get') as mock_get, \
            patch('requests.post', side_effect=requests.Timeout("Request timeout")):  
  
            mock_get.return_value.json.return_value = {  
                "results": [{  
                    "cred_ex_record": {  
                        "by_format": {  
                            "cred_issue": {  
                                "anoncreds": {  
                                    "rev_reg_id": "test-reg-id"  
                                }  
                            }  
                        }  
                    }  
                }]  
            }  
  
            from src.revoke_cred import main
            main()
  
@pytest.mark.revocation  
def test_tails_server_integration():  
    tails_url = "http://localhost:6543"  
    resp = requests.get(tails_url)  
    assert resp.status_code in [200, 404]  
  
    state = load_state()  
    if "cred_def_id" in state:  
        cred_def_id = state["cred_def_id"]  
        resp = requests.get(f"{ISSUER_URL}/anoncreds/revocation/registries",  
                          params={"cred_def_id": cred_def_id})  
        assert resp.status_code == 200