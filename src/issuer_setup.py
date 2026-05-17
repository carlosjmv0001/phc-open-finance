import requests  
import json  
import sys  
import time  
from .config import ISSUER_URL  
from .utils import save_state, load_state  
  
def main():  
    print("### 2. CONFIGURING ISSUER (ASKAR-ANONCREDS + REVOCATION) ###")  
  
    try:  
        did_resp = requests.get(f"{ISSUER_URL}/wallet/did/public")  
        if did_resp.status_code != 200 or not did_resp.json().get('result'):  
            print(f"ERROR: Issuer has no Public DID.")  
            return  
        issuer_did = did_resp.json()['result']['did']  
        print(f"   DID Detected: {issuer_did}")  
    except:  
        print("Connection error with agent.")  
        return  
  
    print("   Creating Schema (AnonCreds Standard)...")  
  
    schema_payload = {  
        "schema": {  
            "name": "personhood_credential_revocable",  
            "version": "2.0",  
            "attrNames": ["person_hash", "biometric_score", "timestamp", "controller_did"],  
            "issuerId": issuer_did  
        },  
        "options": {  
            "type": "finished"  
        }  
    }  
  
    resp_schema = requests.post(f"{ISSUER_URL}/anoncreds/schema", json=schema_payload)  
  
    if resp_schema.status_code != 200:  
        if "already exists" in resp_schema.text:  
            print("   Schema already exists on ledger. Fetching ID...")  
            resp = requests.get(f"{ISSUER_URL}/anoncreds/schemas",  
                              params={"schema_issuer_id": issuer_did,  
                                      "schema_name": "personhood_credential_revocable",  
                                      "schema_version": "2.0"})  
            if resp.status_code == 200 and resp.json()["schema_ids"]:  
                schema_id = resp.json()["schema_ids"][0]  
            else:  
                print(f"Error fetching existing schema: {resp.text}")  
                sys.exit(1)  
        else:  
            print(f"Error creating Schema: {resp_schema.text}")  
            sys.exit(1)  
    else:  
        schema_state = resp_schema.json()["schema_state"]  
        schema_id = schema_state["schema_id"]  
  
    save_state("schema_id", schema_id)  
    print(f"   [OK] Schema ID: {schema_id}")  
  
    print("   Creating Credential Definition (Supports Revocation)...")  
    print("   (This may take a while because it generates and uploads the Tails File)")  
  
    cred_def_payload = {  
        "credential_definition": {  
            "schemaId": schema_id,  
            "tag": "gov_revocable_v1",  
            "issuerId": issuer_did  
        },  
        "options": {  
            "support_revocation": True,  
            "revocation_registry_size": 1000  
        }  
    }  
  
    resp_cd = requests.post(f"{ISSUER_URL}/anoncreds/credential-definition", json=cred_def_payload)  
  
    if resp_cd.status_code != 200:  
        if "already exists" in resp_cd.text:  
            print("   Credential Definition already exists on ledger. Fetching ID...")  
            resp = requests.get(f"{ISSUER_URL}/anoncreds/credential-definitions",  
                              params={"schema_id": schema_id})  
            if resp.status_code == 200 and resp.json()["credential_definition_ids"]:  
                cred_def_id = resp.json()["credential_definition_ids"][0]  
                print(f"   [OK] Existing Cred Def ID: {cred_def_id}")  
            else:  
                print(f"Error fetching existing cred_def: {resp.text}")  
                sys.exit(1)  
        else:  
            print(f"Error creating CredDef: {resp_cd.text}")  
            sys.exit(1)  
    else:  
        cd_state = resp_cd.json()["credential_definition_state"]  
        cred_def_id = cd_state["credential_definition_id"]  
  
    save_state("cred_def_id", cred_def_id)  
    print(f"   [OK] Cred Def ID: {cred_def_id}")  
  
if __name__ == "__main__":  
    main()