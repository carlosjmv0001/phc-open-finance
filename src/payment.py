import time
import uuid
from .mutual_auth import perform_mutual_authentication
from .verifier_proof import verify_holder_with_bank
from .config import get_holder_config
from .utils import load_holder_state
from .pseudonym import derive_pseudonym


def execute_cross_bank_payment(
    from_holder: str,
    to_holder: str,
    amount: float,
    description: str = "",
) -> dict:

    messages = []
    tx_id = uuid.uuid4().hex[:12].upper()

    from_cfg = get_holder_config(from_holder)
    to_cfg = get_holder_config(to_holder)

    messages.append(f"=== CROSS-BANK PAYMENT — TX {tx_id} ===")
    messages.append(f"From: User {from_holder.upper()} ({from_cfg['bank_name']})")
    messages.append(f"To: User {to_holder.upper()} ({to_cfg['bank_name']})")
    messages.append(f"Amount: R$ {amount:,.2f}")
    if description:
        messages.append(f"Description: {description}")
    messages.append("")

    messages.append("--- Phase 1: Mutual Authentication (PHC) ---")
    messages.append("Both users must prove they are real humans...")
    auth_result = perform_mutual_authentication()
    messages.extend(auth_result["messages"])

    if not auth_result["success"]:
        messages.append(f"\n[PAYMENT ABORTED] Mutual authentication failed.")
        messages.append("Both parties must be verified as human to proceed.")
        return {
            "success": False,
            "tx_id": tx_id,
            "phase_failed": "mutual_auth",
            "messages": messages,
        }

    messages.append("")

    messages.append(f"--- Phase 2: {from_cfg['bank_name']} Authorization (Debit) ---")
    messages.append(f"User {from_holder.upper()} proving humanity to {from_cfg['bank_name']}...")

    payer_ok = verify_holder_with_bank(from_holder)
    if not payer_ok:
        messages.append(f"\n[PAYMENT ABORTED] {from_cfg['bank_name']} denied access to User {from_holder.upper()}.")
        return {
            "success": False,
            "tx_id": tx_id,
            "phase_failed": "payer_bank_auth",
            "messages": messages,
        }
    messages.append(f"[{from_cfg['bank_name']}] Debit AUTHORIZED for User {from_holder.upper()}.")
    messages.append("")

    messages.append(f"--- Phase 3: {to_cfg['bank_name']} Authorization (Credit) ---")
    messages.append(f"User {to_holder.upper()} proving humanity to {to_cfg['bank_name']}...")

    payee_ok = verify_holder_with_bank(to_holder)
    if not payee_ok:
        messages.append(f"\n[PAYMENT ABORTED] {to_cfg['bank_name']} denied access to User {to_holder.upper()}.")
        return {
            "success": False,
            "tx_id": tx_id,
            "phase_failed": "payee_bank_auth",
            "messages": messages,
        }
    messages.append(f"[{to_cfg['bank_name']}] Credit AUTHORIZED for User {to_holder.upper()}.")
    messages.append("")

    messages.append("--- Phase 4: Fund Transfer (Open Finance Phase 3) ---")
    messages.append(f"[{from_cfg['bank_name']}] Debiting R$ {amount:,.2f} from User {from_holder.upper()}'s account...")
    messages.append(f"[{to_cfg['bank_name']}] Crediting R$ {amount:,.2f} to User {to_holder.upper()}'s account...")
    messages.append(f"[Open Finance] Transfer {from_cfg['bank_name']} → {to_cfg['bank_name']}: COMPLETED")
    messages.append("")

    messages.append("=== PAYMENT COMPLETE ===")
    messages.append(f"Transaction ID: {tx_id}")
    messages.append(f"Amount: R$ {amount:,.2f}")
    messages.append(f"From: User {from_holder.upper()} ({from_cfg['bank_name']})")
    messages.append(f"To: User {to_holder.upper()} ({to_cfg['bank_name']})")
    messages.append("")
    messages.append("[PHC] All verifications used ZKP — zero personal data revealed.")
    messages.append("[PHC] Pseudonyms are unlinkable across all parties.")

    from_state = load_holder_state(from_cfg["state_file"])
    to_state = load_holder_state(to_cfg["state_file"])

    ps_from = from_state.get("person_secret")
    ps_to = to_state.get("person_secret")

    if ps_from and ps_to:
        p1 = derive_pseudonym(ps_from, from_cfg["bank_service_id"])
        p2 = derive_pseudonym(ps_from, "mutual_auth_p2p")
        p3 = derive_pseudonym(ps_to, to_cfg["bank_service_id"])
        p4 = derive_pseudonym(ps_to, "mutual_auth_p2p")

        messages.append("")
        messages.append("Pseudonym audit (all different, unlinkable):")
        messages.append(f"  User {from_holder.upper()} @ {from_cfg['bank_name']}: {p1[:16]}...")
        messages.append(f"  User {from_holder.upper()} @ mutual auth:  {p2[:16]}...")
        messages.append(f"  User {to_holder.upper()} @ {to_cfg['bank_name']}: {p3[:16]}...")
        messages.append(f"  User {to_holder.upper()} @ mutual auth:  {p4[:16]}...")

    return {
        "success": True,
        "tx_id": tx_id,
        "amount": amount,
        "from_holder": from_holder,
        "to_holder": to_holder,
        "messages": messages,
    }
