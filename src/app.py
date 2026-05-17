import os
import requests
from dotenv import load_dotenv
load_dotenv()

import gradio as gr
from .api import app as fastapi_app
from .chatbot import HolderChatbot
from .config import (
    ISSUER_URL, HOLDER_A_URL, HOLDER_B_URL,
    VERIFIER_A_URL, VERIFIER_B_URL,
    HOLDER_A_STATE_FILE, HOLDER_B_STATE_FILE,
    get_holder_config,
)

_chatbots: dict[str, HolderChatbot] = {}


def _get_chatbot(holder_id: str) -> HolderChatbot:
    if holder_id not in _chatbots:
        _chatbots[holder_id] = HolderChatbot(holder_id)
    return _chatbots[holder_id]



def chat_handler(message: str, history: list, holder_id: str):
    if not message.strip():
        return history, ""

    bot = _get_chatbot(holder_id)
    result = bot.process_message(message)

    action = result.get("action")
    params = result.get("params", {})
    response = result.get("response", "")

    if action:
        action_output = _execute_action(holder_id, action, params)
        summary = bot.inject_result(action_output)
        response = summary.get("response", action_output)

    history = history or []
    history.append({"role": "user", "content": message})
    history.append({"role": "assistant", "content": response})

    return history, ""


def _execute_action(holder_id: str, action: str, params: dict) -> str:
    try:
        if action == "verify":
            from .verifier_proof import verify_holder_with_bank
            hcfg = get_holder_config(holder_id)
            ok = verify_holder_with_bank(holder_id)
            return f"{'SUCCESS' if ok else 'FAILED'}: Verification at {hcfg['bank_name']}"

        elif action == "mutual_auth":
            from .mutual_auth import perform_mutual_authentication
            result = perform_mutual_authentication()
            return "\n".join(result["messages"])

        elif action == "pay":
            from .payment import execute_cross_bank_payment
            peer = "b" if holder_id == "a" else "a"
            amount = params.get("amount", 2000)
            desc = params.get("description", "")
            result = execute_cross_bank_payment(holder_id, peer, amount, desc)
            return "\n".join(result["messages"])

        elif action == "status":
            return _get_status_text(holder_id)

        elif action == "setup":
            return _run_full_setup()

    except Exception as e:
        return f"Action error: {e}"

    return "Unknown action."



def run_setup_connections():
    try:
        from .setup_connections import main as connect_main
        connect_main()
        return "All connections established successfully."
    except Exception as e:
        return f"Error: {e}"


def run_setup_issuer():
    try:
        from .issuer_setup import main as issuer_main
        issuer_main()
        return "Issuer configured: Schema + Credential Definition registered."
    except Exception as e:
        return f"Error: {e}"


def run_issue_credential(holder_id):
    try:
        from .issue_cred import issue_to_holder
        ok = issue_to_holder(holder_id)
        return f"{'Success' if ok else 'Failed'}: Credential issuance to Holder {holder_id.upper()}"
    except Exception as e:
        return f"Error: {e}"


def _run_full_setup():
    msgs = []
    msgs.append(run_setup_connections())
    msgs.append(run_setup_issuer())
    msgs.append(run_issue_credential("a"))
    msgs.append(run_issue_credential("b"))
    return "\n".join(msgs)


def run_full_setup():
    return _run_full_setup()



def _get_status_text(holder_id: str) -> str:
    hcfg = get_holder_config(holder_id)
    lines = [f"=== Holder {holder_id.upper()} Status ==="]

    try:
        r = requests.get(f"{hcfg['url']}/status", timeout=3)
        lines.append(f"Agent: {'ONLINE' if r.status_code == 200 else 'ERROR'}")
    except Exception:
        lines.append("Agent: OFFLINE")

    try:
        creds = requests.get(f"{hcfg['url']}/credentials", timeout=5).json().get("results", [])
        lines.append(f"Credentials: {len(creds)}")
    except Exception:
        lines.append("Credentials: unavailable")

    from .utils import load_holder_state
    state = load_holder_state(hcfg["state_file"])
    lines.append(f"Has secret: {'Yes' if state.get('person_secret') else 'No'}")
    lines.append(f"Usage count: {state.get('usage_count_since_reauth', 0)}")
    lines.append(f"Bank: {hcfg['bank_name']}")

    return "\n".join(lines)


def get_system_status():
    agents = {
        "Issuer (Gov)": ISSUER_URL,
        "Holder A": HOLDER_A_URL,
        "Holder B": HOLDER_B_URL,
        "Bank A": VERIFIER_A_URL,
        "Bank B": VERIFIER_B_URL,
    }
    lines = ["=== System Status ===", ""]
    for name, url in agents.items():
        try:
            r = requests.get(f"{url}/status", timeout=3)
            status = "ONLINE" if r.status_code == 200 else "ERROR"
        except Exception:
            status = "OFFLINE"
        lines.append(f"{name}: {status}")

    return "\n".join(lines)



def run_mutual_auth():
    try:
        from .mutual_auth import perform_mutual_authentication
        result = perform_mutual_authentication()
        return "\n".join(result["messages"])
    except Exception as e:
        return f"Error: {e}"



def run_payment(from_h, to_h, amount, description):
    try:
        from .payment import execute_cross_bank_payment
        result = execute_cross_bank_payment(from_h, to_h, float(amount), description)
        return "\n".join(result["messages"])
    except Exception as e:
        return f"Error: {e}"



def create_gradio_app():
    with gr.Blocks(
        title="Personhood Credentials in Open Finance",
    ) as demo:

        gr.Markdown(
            "# Personhood Credentials in Open Finance\n"
            "Dual-holder system with Groq-powered chatbots, mutual authentication, "
            "and cross-bank payments."
        )

        with gr.Tabs():
            with gr.Tab("User A (Bank A)"):
                gr.Markdown("### Chat with Holder A's AI Agent")
                chatbot_a = gr.Chatbot(
                    label="Holder A Chatbot",
                    height=400,
                )
                msg_a = gr.Textbox(
                    placeholder="Ask your AI agent... (e.g., 'Verify my identity', 'Pay R$2000 to User B')",
                    label="Message",
                    lines=1,
                )
                with gr.Row():
                    send_a = gr.Button("Send", variant="primary")
                    clear_a = gr.Button("Clear Chat")

                send_a.click(
                    fn=lambda m, h: chat_handler(m, h, "a"),
                    inputs=[msg_a, chatbot_a],
                    outputs=[chatbot_a, msg_a],
                )
                msg_a.submit(
                    fn=lambda m, h: chat_handler(m, h, "a"),
                    inputs=[msg_a, chatbot_a],
                    outputs=[chatbot_a, msg_a],
                )
                clear_a.click(lambda: ([], ""), outputs=[chatbot_a, msg_a])

            with gr.Tab("User B (Bank B)"):
                gr.Markdown("### Chat with Holder B's AI Agent")
                chatbot_b = gr.Chatbot(
                    label="Holder B Chatbot",
                    height=400,
                )
                msg_b = gr.Textbox(
                    placeholder="Ask your AI agent... (e.g., 'Check my status', 'Verify my identity')",
                    label="Message",
                    lines=1,
                )
                with gr.Row():
                    send_b = gr.Button("Send", variant="primary")
                    clear_b = gr.Button("Clear Chat")

                send_b.click(
                    fn=lambda m, h: chat_handler(m, h, "b"),
                    inputs=[msg_b, chatbot_b],
                    outputs=[chatbot_b, msg_b],
                )
                msg_b.submit(
                    fn=lambda m, h: chat_handler(m, h, "b"),
                    inputs=[msg_b, chatbot_b],
                    outputs=[chatbot_b, msg_b],
                )
                clear_b.click(lambda: ([], ""), outputs=[chatbot_b, msg_b])

            with gr.Tab("System Setup"):
                gr.Markdown("### Infrastructure Setup")
                setup_output = gr.Textbox(label="Output", lines=15, interactive=False)

                with gr.Row():
                    btn_full_setup = gr.Button("Full Setup (All Steps)", variant="primary")
                    btn_connections = gr.Button("1. Connections")
                    btn_issuer = gr.Button("2. Issuer Setup")

                with gr.Row():
                    btn_issue_a = gr.Button("3a. Issue to Holder A")
                    btn_issue_b = gr.Button("3b. Issue to Holder B")

                btn_full_setup.click(fn=run_full_setup, outputs=setup_output)
                btn_connections.click(fn=run_setup_connections, outputs=setup_output)
                btn_issuer.click(fn=run_setup_issuer, outputs=setup_output)
                btn_issue_a.click(fn=lambda: run_issue_credential("a"), outputs=setup_output)
                btn_issue_b.click(fn=lambda: run_issue_credential("b"), outputs=setup_output)

                gr.Markdown("### System Status")
                status_output = gr.Textbox(label="Agent Status", lines=8, interactive=False)
                btn_status = gr.Button("Refresh Status")
                btn_status.click(fn=get_system_status, outputs=status_output)

            with gr.Tab("Mutual Authentication"):
                gr.Markdown(
                    "### Holder-to-Holder Mutual Authentication\n"
                    "Both holders prove to each other they act on behalf of real humans."
                )
                mutual_output = gr.Textbox(label="Result", lines=20, interactive=False)
                btn_mutual = gr.Button("Run Mutual Authentication", variant="primary")
                btn_mutual.click(fn=run_mutual_auth, outputs=mutual_output)

            with gr.Tab("Cross-Bank Payment"):
                gr.Markdown(
                    "### Open Finance Phase 3 — Cross-Bank Payment\n"
                    "Executes: mutual auth → bank verification (both) → fund transfer."
                )
                with gr.Row():
                    pay_from = gr.Dropdown(choices=["a", "b"], value="a", label="From (Payer)")
                    pay_to = gr.Dropdown(choices=["a", "b"], value="b", label="To (Payee)")
                    pay_amount = gr.Number(value=2000, label="Amount (R$)")

                pay_desc = gr.Textbox(label="Description", placeholder="Payment for...")
                payment_output = gr.Textbox(label="Payment Result", lines=25, interactive=False)
                btn_pay = gr.Button("Execute Payment", variant="primary")
                btn_pay.click(
                    fn=run_payment,
                    inputs=[pay_from, pay_to, pay_amount, pay_desc],
                    outputs=payment_output,
                )

    return demo



def main():
    demo = create_gradio_app()
    app = gr.mount_gradio_app(fastapi_app, demo, path="/")

    import uvicorn
    print("\n=== PHC Open Finance ===")
    print("Gradio UI: http://localhost:7860")
    print("FastAPI docs: http://localhost:7860/docs")
    print("========================\n")
    uvicorn.run(app, host="0.0.0.0", port=7860)


if __name__ == "__main__":
    main()
