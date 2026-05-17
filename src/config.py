import os

ISSUER_URL = "http://localhost:8001"
HOLDER_A_URL = "http://localhost:8011"    
HOLDER_B_URL = "http://localhost:8041"    
VERIFIER_A_URL = "http://localhost:8021"  
VERIFIER_B_URL = "http://localhost:8031"  

HOLDER_URL = HOLDER_A_URL

STATE_FILE = "system_state.json"
HOLDER_A_STATE_FILE = "holder_a_state.json"
HOLDER_B_STATE_FILE = "holder_b_state.json"
HOLDER_STATE_FILE = HOLDER_A_STATE_FILE  

BIOMETRIC_THRESHOLD = 80

CREDENTIAL_TTL_SECONDS = 86400

DEDUP_REGISTRY_FILE = "person_registry.json"

REAUTH_INTERVAL_SECONDS = int(os.environ.get("PHC_REAUTH_INTERVAL", "86400"))
REAUTH_MAX_USES = int(os.environ.get("PHC_REAUTH_MAX_USES", "100"))

ALLOW_SIMULATED_BIOMETRICS = os.environ.get("PHC_ALLOW_SIMULATED", "false").lower() == "true"


DEDUP_REGISTRY_BACKEND = os.environ.get("PHC_DEDUP_BACKEND", "json").lower()

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_MAX_CALLS = int(os.environ.get("GROQ_MAX_CALLS", "100"))

HOLDERS = {
    "a": {
        "url": HOLDER_A_URL,
        "state_file": HOLDER_A_STATE_FILE,
        "bank_url": VERIFIER_A_URL,
        "bank_name": "Bank A",
        "bank_service_id": "bank_a_open_finance",
        "bank_conn_alias": "Connection_BankA_Bot",
        "gov_conn_alias": "Connection_Bot_Gov_A",
        "peer_conn_alias": "Connection_HolderA_HolderB",
    },
    "b": {
        "url": HOLDER_B_URL,
        "state_file": HOLDER_B_STATE_FILE,
        "bank_url": VERIFIER_B_URL,
        "bank_name": "Bank B",
        "bank_service_id": "bank_b_open_finance",
        "bank_conn_alias": "Connection_BankB_Bot",
        "gov_conn_alias": "Connection_Bot_Gov_B",
        "peer_conn_alias": "Connection_HolderB_HolderA",
    },
}


def get_holder_config(holder_id: str) -> dict:
    holder_id = holder_id.lower()
    if holder_id not in HOLDERS:
        raise ValueError(f"Unknown holder_id: {holder_id}. Must be 'a' or 'b'.")
    return HOLDERS[holder_id]


def validate_config() -> None:
    from .key_management import get_key_provider

    provider = get_key_provider()

    try:
        provider.get_enrollment_secret()
    except (RuntimeError, NotImplementedError) as e:
        raise RuntimeError(f"Enrollment key validation failed: {e}")

    if not ALLOW_SIMULATED_BIOMETRICS:
        pass


def get_enrollment_secret() -> bytes:
    from .key_management import get_key_provider
    return get_key_provider().get_enrollment_secret()
