import requests
import time
from .config import ISSUER_URL, HOLDER_A_URL, HOLDER_B_URL, VERIFIER_A_URL, VERIFIER_B_URL
from .utils import save_state

def connect_agents(inviter_url, invitee_url, alias_inviter, alias_invitee):
    print(f"--- Connecting {alias_inviter} -> {alias_invitee} ---")

    invite = requests.post(f"{inviter_url}/out-of-band/create-invitation",
                           json={"alias": alias_inviter, "handshake_protocols": ["https://didcomm.org/didexchange/1.0"]}).json()

    requests.post(f"{invitee_url}/out-of-band/receive-invitation",
                  json=invite["invitation"],
                  params={"alias": alias_invitee})

    print("   Invitation accepted. Awaiting synchronization...")
    time.sleep(3)  # Time for handshake

def main():
    print("### 1. ESTABLISHING CONNECTIONS ###")

    connect_agents(ISSUER_URL, HOLDER_A_URL, "Connection_Gov_BotA", "Connection_Bot_Gov_A")

    connect_agents(ISSUER_URL, HOLDER_B_URL, "Connection_Gov_BotB", "Connection_Bot_Gov_B")

    connect_agents(VERIFIER_A_URL, HOLDER_A_URL, "Connection_BankA_Bot", "Connection_Bot_BankA")

    connect_agents(VERIFIER_B_URL, HOLDER_B_URL, "Connection_BankB_Bot", "Connection_Bot_BankB")

    connect_agents(HOLDER_A_URL, HOLDER_B_URL, "Connection_HolderA_HolderB", "Connection_HolderB_HolderA")

    print("All connections established.")

if __name__ == "__main__":
    main()
