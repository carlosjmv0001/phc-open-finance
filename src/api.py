import os
import traceback
from contextlib import asynccontextmanager

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .config import (
    ISSUER_URL, HOLDER_A_URL, HOLDER_B_URL,
    VERIFIER_A_URL, VERIFIER_B_URL,
    HOLDER_A_STATE_FILE, HOLDER_B_STATE_FILE,
    get_holder_config, HOLDERS,
)
from .chatbot import HolderChatbot


_chatbots: dict[str, HolderChatbot] = {}


def _get_chatbot(holder_id: str) -> HolderChatbot:
    holder_id = holder_id.lower()
    if holder_id not in _chatbots:
        _chatbots[holder_id] = HolderChatbot(holder_id)
    return _chatbots[holder_id]


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        _chatbots["a"] = HolderChatbot("a")
        _chatbots["b"] = HolderChatbot("b")
    except Exception as e:
        print(f"[WARNING] Could not initialize chatbots: {e}")
    yield
    _chatbots.clear()


app = FastAPI(
    title="PHC Open Finance API",
    description="REST API for Personhood Credentials in Open Finance",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)



class ChatRequest(BaseModel):
    message: str

class ChatResponse(BaseModel):
    response: str
    action: str | None = None
    params: dict = Field(default_factory=dict)

class PaymentRequest(BaseModel):
    from_holder: str = "a"
    to_holder: str = "b"
    amount: float = 2000.0
    description: str = ""

class ActionResult(BaseModel):
    success: bool
    messages: list[str] = Field(default_factory=list)
    data: dict = Field(default_factory=dict)



@app.get("/api/health")
def health():
    import requests
    agents = {
        "issuer": ISSUER_URL,
        "holder_a": HOLDER_A_URL,
        "holder_b": HOLDER_B_URL,
        "bank_a": VERIFIER_A_URL,
        "bank_b": VERIFIER_B_URL,
    }
    status = {}
    for name, url in agents.items():
        try:
            r = requests.get(f"{url}/status", timeout=3)
            status[name] = "online" if r.status_code == 200 else "error"
        except Exception:
            status[name] = "offline"

    return {"status": "ok", "agents": status}



@app.post("/api/setup/connections", response_model=ActionResult)
def setup_connections():
    try:
        from .setup_connections import main as connect_main
        connect_main()
        return ActionResult(success=True, messages=["All connections established."])
    except Exception as e:
        return ActionResult(success=False, messages=[f"Connection setup failed: {e}"])


@app.post("/api/setup/issuer", response_model=ActionResult)
def setup_issuer():
    try:
        from .issuer_setup import main as issuer_main
        issuer_main()
        return ActionResult(success=True, messages=["Issuer setup complete."])
    except Exception as e:
        return ActionResult(success=False, messages=[f"Issuer setup failed: {e}"])


@app.post("/api/setup/full", response_model=ActionResult)
def setup_full():
    messages = []
    try:
        from .setup_connections import main as connect_main
        connect_main()
        messages.append("Connections established.")
    except Exception as e:
        return ActionResult(success=False, messages=[f"Connection setup failed: {e}"])

    try:
        from .issuer_setup import main as issuer_main
        issuer_main()
        messages.append("Issuer configured.")
    except Exception as e:
        return ActionResult(success=False, messages=messages + [f"Issuer setup failed: {e}"])

    try:
        from .issue_cred import issue_to_holder
        issue_to_holder("a")
        messages.append("Credential issued to Holder A.")
        issue_to_holder("b")
        messages.append("Credential issued to Holder B.")
    except Exception as e:
        return ActionResult(success=False, messages=messages + [f"Credential issuance failed: {e}"])

    return ActionResult(success=True, messages=messages)



@app.post("/api/issue/{holder_id}", response_model=ActionResult)
def issue_credential(holder_id: str):
    try:
        from .issue_cred import issue_to_holder
        ok = issue_to_holder(holder_id)
        if ok:
            return ActionResult(success=True, messages=[f"Credential issued to Holder {holder_id.upper()}."])
        return ActionResult(success=False, messages=[f"Credential issuance failed for Holder {holder_id.upper()}."])
    except Exception as e:
        return ActionResult(success=False, messages=[str(e)])



@app.post("/api/verify/{holder_id}", response_model=ActionResult)
def verify_holder(holder_id: str):
    try:
        from .verifier_proof import verify_holder_with_bank
        hcfg = get_holder_config(holder_id)
        ok = verify_holder_with_bank(holder_id)
        if ok:
            return ActionResult(
                success=True,
                messages=[f"Holder {holder_id.upper()} verified by {hcfg['bank_name']}. Access GRANTED."],
            )
        return ActionResult(
            success=False,
            messages=[f"Holder {holder_id.upper()} verification FAILED at {hcfg['bank_name']}."],
        )
    except Exception as e:
        return ActionResult(success=False, messages=[str(e)])



@app.post("/api/mutual-auth", response_model=ActionResult)
def mutual_authentication():
    try:
        from .mutual_auth import perform_mutual_authentication
        result = perform_mutual_authentication()
        return ActionResult(
            success=result["success"],
            messages=result["messages"],
            data={
                "a_verified_b": result.get("a_verified_b"),
                "b_verified_a": result.get("b_verified_a"),
                "pseudonym_a": result.get("pseudonym_a"),
                "pseudonym_b": result.get("pseudonym_b"),
            },
        )
    except Exception as e:
        return ActionResult(success=False, messages=[str(e)])



@app.post("/api/payment", response_model=ActionResult)
def cross_bank_payment(req: PaymentRequest):
    try:
        from .payment import execute_cross_bank_payment
        result = execute_cross_bank_payment(
            from_holder=req.from_holder,
            to_holder=req.to_holder,
            amount=req.amount,
            description=req.description,
        )
        return ActionResult(
            success=result["success"],
            messages=result["messages"],
            data={
                "tx_id": result.get("tx_id"),
                "amount": result.get("amount"),
            },
        )
    except Exception as e:
        return ActionResult(success=False, messages=[str(e)])



@app.get("/api/status/{holder_id}")
def holder_status(holder_id: str):
    import requests as req_lib
    try:
        hcfg = get_holder_config(holder_id)
        holder_url = hcfg["url"]

        try:
            agent_resp = req_lib.get(f"{holder_url}/status", timeout=3)
            agent_online = agent_resp.status_code == 200
        except Exception:
            agent_online = False

        creds = []
        if agent_online:
            try:
                creds_resp = req_lib.get(f"{holder_url}/credentials", timeout=5)
                creds = creds_resp.json().get("results", [])
            except Exception:
                pass

        from .utils import load_holder_state
        state = load_holder_state(hcfg["state_file"])

        return {
            "holder_id": holder_id.upper(),
            "agent_online": agent_online,
            "credential_count": len(creds),
            "has_person_secret": "person_secret" in state,
            "bank": hcfg["bank_name"],
            "usage_count": state.get("usage_count_since_reauth", 0),
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))



@app.post("/api/chat/{holder_id}", response_model=ChatResponse)
def chat(holder_id: str, req: ChatRequest):
    try:
        bot = _get_chatbot(holder_id)
        result = bot.process_message(req.message)

        action = result.get("action")
        params = result.get("params", {})
        response_text = result.get("response", "")

        if action:
            action_result = _execute_chatbot_action(holder_id, action, params)
            if action_result:
                summary = bot.inject_result(action_result)
                response_text = summary.get("response", action_result)
                action = None

        return ChatResponse(response=response_text, action=action, params=params)

    except Exception as e:
        return ChatResponse(response=f"Error: {e}", action=None, params={})


@app.post("/api/chat/{holder_id}/reset")
def reset_chat(holder_id: str):
    holder_id = holder_id.lower()
    if holder_id in _chatbots:
        _chatbots[holder_id].reset()
    return {"status": "ok"}


def _execute_chatbot_action(holder_id: str, action: str, params: dict) -> str | None:
    try:
        if action == "verify":
            from .verifier_proof import verify_holder_with_bank
            hcfg = get_holder_config(holder_id)
            ok = verify_holder_with_bank(holder_id)
            if ok:
                return f"SUCCESS: Holder {holder_id.upper()} verified by {hcfg['bank_name']}. Access GRANTED."
            return f"FAILED: Holder {holder_id.upper()} verification failed at {hcfg['bank_name']}."

        elif action == "mutual_auth":
            from .mutual_auth import perform_mutual_authentication
            result = perform_mutual_authentication()
            return "\n".join(result["messages"])

        elif action == "pay":
            from .payment import execute_cross_bank_payment
            peer = "b" if holder_id.lower() == "a" else "a"
            amount = params.get("amount", 2000)
            desc = params.get("description", "")
            result = execute_cross_bank_payment(holder_id, peer, amount, desc)
            return "\n".join(result["messages"])

        elif action == "status":
            import requests as req_lib
            hcfg = get_holder_config(holder_id)
            try:
                creds = req_lib.get(f"{hcfg['url']}/credentials", timeout=5).json().get("results", [])
            except Exception:
                creds = []
            from .utils import load_holder_state
            state = load_holder_state(hcfg["state_file"])
            return (
                f"Holder {holder_id.upper()} Status:\n"
                f"  Bank: {hcfg['bank_name']}\n"
                f"  Credentials: {len(creds)}\n"
                f"  Has secret: {'yes' if state.get('person_secret') else 'no'}\n"
                f"  Usage count: {state.get('usage_count_since_reauth', 0)}"
            )

        elif action == "setup":
            from .setup_connections import main as connect_main
            from .issuer_setup import main as issuer_main
            from .issue_cred import issue_to_holder
            connect_main()
            issuer_main()
            issue_to_holder(holder_id)
            return f"Setup complete for Holder {holder_id.upper()}. Connections established and credential issued."

    except Exception as e:
        return f"Action '{action}' failed: {e}\n{traceback.format_exc()}"

    return None
