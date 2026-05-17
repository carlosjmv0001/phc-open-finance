import os
import json
from groq import Groq
from .config import GROQ_API_KEY, GROQ_MODEL, GROQ_MAX_CALLS


SYSTEM_PROMPT_TEMPLATE = """You are the AI assistant for User {user_id} in the PHC Open Finance system.
You manage their digital identity wallet (Holder {user_id}) and help them interact with the banking system.

AVAILABLE ACTIONS (use exactly these action names):
- "verify" — Use when the user wants to verify identity, prove humanity, authenticate with the bank, or confirm who they are. This triggers a ZKP proof to {bank_name}.
- "mutual_auth" — Use when the user wants to verify another user, check if the other person is real, or do mutual authentication between holders.
- "pay" — Use when the user wants to send money, make a payment, or transfer funds to the other user.
- "status" — Use ONLY when the user explicitly asks to check status, see credentials, or view system info.
- "setup" — Use when the user wants to initialize connections or issue credentials.

CRITICAL RULES FOR ACTION SELECTION:
- "Verify my identity" or "Prove I am human" or "Authenticate me" → action MUST be "verify", NOT "status"
- "Check my status" or "Show my credentials" → action is "status"
- "Pay R$2000 to User B" → action is "pay"
- Never use "status" when the user is asking for verification or authentication

RESPONSE FORMAT:
Always respond with a JSON action block on the FIRST line when an action is needed:
{{"action": "<action_name>", "params": {{}}}}

Then follow with your conversational response explaining what you're doing.

For payments, extract the amount:
{{"action": "pay", "params": {{"amount": 2000, "description": "Payment to User B"}}}}

If the user is just chatting or asking questions, respond normally without an action block.

CONTEXT:
- User {user_id} is a client of {bank_name}
- The other user ({peer_id}) is a client of {peer_bank}
- All verifications use ZKP (Zero-Knowledge Proofs) — no personal data is ever revealed
- Pseudonyms are unlinkable across services
- You should always explain what's happening in simple terms
"""


class HolderChatbot:

    def __init__(self, holder_id: str):
        self.holder_id = holder_id.upper()
        self.peer_id = "B" if self.holder_id == "A" else "A"
        self.bank_name = "Bank A" if self.holder_id == "A" else "Bank B"
        self.peer_bank = "Bank B" if self.holder_id == "A" else "Bank A"

        api_key = GROQ_API_KEY
        if not api_key:
            raise RuntimeError("GROQ_API_KEY not set. Configure it in .env")

        self.client = Groq(api_key=api_key)
        self.model = GROQ_MODEL
        self.system_prompt = SYSTEM_PROMPT_TEMPLATE.format(
            user_id=self.holder_id,
            bank_name=self.bank_name,
            peer_id=self.peer_id,
            peer_bank=self.peer_bank,
        )
        self.messages = [{"role": "system", "content": self.system_prompt}]
        self._call_count = 0

    def process_message(self, user_message: str) -> dict:

        self._call_count += 1
        if self._call_count > GROQ_MAX_CALLS:
            return {
                "response": f"API call limit ({GROQ_MAX_CALLS}) reached for this session.",
                "action": None,
                "params": {},
            }

        try:
            self.messages.append({"role": "user", "content": user_message})
            result = self.client.chat.completions.create(
                model=self.model,
                messages=self.messages,
            )
            text = result.choices[0].message.content.strip()
            self.messages.append({"role": "assistant", "content": text})

            action = None
            params = {}
            response_text = text

            lines = text.split("\n", 1)
            first_line = lines[0].strip()
            if first_line.startswith("{") and first_line.endswith("}"):
                try:
                    action_data = json.loads(first_line)
                    action = action_data.get("action")
                    params = action_data.get("params", {})
                    response_text = lines[1].strip() if len(lines) > 1 else ""
                except json.JSONDecodeError:
                    pass

            return {
                "response": response_text,
                "action": action,
                "params": params,
            }

        except Exception as e:
            return {
                "response": f"Error communicating with Groq: {e}",
                "action": None,
                "params": {},
            }

    def inject_result(self, action_result: str) -> dict:
        self._call_count += 1
        if self._call_count > GROQ_MAX_CALLS:
            return {"response": action_result, "action": None, "params": {}}

        try:
            inject_msg = (
                f"[SYSTEM RESULT] The action completed with this result:\n{action_result}\n\n"
                f"Please summarize this result for the user in simple, friendly terms."
            )
            self.messages.append({"role": "user", "content": inject_msg})
            result = self.client.chat.completions.create(
                model=self.model,
                messages=self.messages,
            )
            text = result.choices[0].message.content.strip()
            self.messages.append({"role": "assistant", "content": text})
            return {
                "response": text,
                "action": None,
                "params": {},
            }
        except Exception as e:
            return {"response": action_result, "action": None, "params": {}}

    def reset(self):
        self.messages = [{"role": "system", "content": self.system_prompt}]
        self._call_count = 0
