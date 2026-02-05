import time
from fastapi import FastAPI
from fastapi import Header, HTTPException
from fastapi import Request
from pydantic import BaseModel
from typing import Dict, List, Optional
import re
import uuid

app = FastAPI(title="Agentic Scam Honeypot API")
API_KEY = "35Cryptic821"



# =========================
# HOME
# =========================
@app.get("/")
def home():
    return {"message": "Honeypot API running. Go to /docs"}


# =========================
# MEMORY (conversation)
# =========================
MEMORY: Dict[str, List[Dict[str, str]]] = {}

# Stores extracted data cumulatively per session
SESSION_DATA: Dict[str, Dict[str, List[str]]] = {}


# =========================
# REGEX FOR EXTRACTION
# =========================
UPI_REGEX = re.compile(r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b")
URL_REGEX = re.compile(r"https?://[^\s]+")
IFSC_REGEX = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
PHONE_REGEX = re.compile(r"\b[6-9]\d{9}\b")
BANK_REGEX = re.compile(r"\b\d{9,18}\b")


def extract_data(text: str):
    upi = list(set(UPI_REGEX.findall(text)))
    links = list(set(URL_REGEX.findall(text)))
    ifsc = list(set(IFSC_REGEX.findall(text)))
    phones = list(set(PHONE_REGEX.findall(text)))
    banks = list(set(BANK_REGEX.findall(text)))

    return {
        "upi_ids": upi,
        "bank_accounts": banks,
        "ifsc_codes": ifsc,
        "phone_numbers": phones,
        "phishing_links": links
    }


# =========================
# SCAM DETECTION
# =========================
SCAM_KEYWORDS = [
    # phishing
    "verify", "click", "link", "blocked", "urgent", "otp", "kyc",

    # smishing
    "sms", "text message", "sent you",

    # vishing
    "call", "customer care", "helpline", "bank officer",

    # quishing
    "qr", "scan", "qr code",

    # payments
    "upi", "pay", "refund", "account"
]


def detect_scam(message: str):
    msg = message.lower()
    score = 0

    for word in SCAM_KEYWORDS:
        if word in msg:
            score += 1

    is_scam = score >= 1
    confidence = min(0.95, 0.3 + score * 0.1)

    scam_type = "Unknown Scam"

    if "qr" in msg or "scan" in msg:
        scam_type = "Quishing"
    elif "call" in msg or "customer care" in msg or "helpline" in msg:
        scam_type = "Vishing"
    elif "sms" in msg or "text message" in msg:
        scam_type = "Smishing"
    elif "link" in msg or "click" in msg:
        scam_type = "Phishing"

    return is_scam, round(confidence, 2), scam_type


# =========================
# HONEYPOT AGENT REPLY
# =========================
def honeypot_reply(scam_type: str, message: str):
    msg = message.lower()

    # ---- QUISHING ----
    if scam_type == "Quishing":
        return (
            "I tried scanning the QR but it is not working. "
            "Please send your UPI ID or payment link directly."
        )

    # ---- VISHING ----
    if scam_type == "Vishing":
        return (
            "I cannot talk on call right now. "
            "Kindly send your bank account number + IFSC or UPI ID here."
        )

    # ---- SMISHING ----
    if scam_type == "Smishing":
        return (
            "The SMS link is not opening on my phone. "
            "Please resend the full link and also share your UPI ID."
        )

    # ---- PHISHING CASES ----
    if "link" in msg or "click" in msg:
        return (
            "The link is not opening properly on my side. "
            "Can you resend the correct link and your UPI ID?"
        )

    if "otp" in msg:
        return (
            "OTP not received correctly. "
            "Meanwhile please share your UPI ID or bank account + IFSC."
        )

   # ---- DEFAULT FORMAL + CONTEXT AWARE ----

    # Greeting responses
    if any(greet in msg for greet in ["good morning", "good evening", "good afternoon", "hello", "hi", "hey"]):
        return "Good day! How can I help you?"

    # If message is just small talk
    if len(msg.split()) <= 3:
        return "Hello, could you please explain your request in detail?"

    # If it sounds like service/payment related
    return (
        "Thank you for the information. For security reasons I need to verify this request. "
        "Kindly share your official contact details and the payment reference. "
        "You can also send the UPI ID or bank account number with IFSC for verification."
    )


# =========================
# REQUEST MODEL
# =========================
class AnalyzeRequest(BaseModel):
    message: Optional[str] = None
    text: Optional[str] = None
    input: Optional[str] = None
    content: Optional[str] = None
    conversation_id: Optional[str] = None

    def get_message(self):
        return self.message or self.text or self.input or self.content or ""


@app.post("/debug")
async def debug(request: Request):
    body = await request.json()
    return {
        "received_body": body,
        "keys": list(body.keys())
    }


# =========================
# API ENDPOINT
# =========================
@app.post("/analyze")
def analyze(req: AnalyzeRequest, x_api_key: str = Header(None)):
    start = time.time()


    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    conv_id = req.conversation_id or str(uuid.uuid4())

    # Initialize conversation memory
    if conv_id not in MEMORY:
        MEMORY[conv_id] = []

    # Initialize cumulative extraction store
    if conv_id not in SESSION_DATA:
        SESSION_DATA[conv_id] = {
            "upi_ids": [],
            "bank_accounts": [],
            "ifsc_codes": [],
            "phone_numbers": [],
            "phishing_links": []
        }

    # Store scammer message
    user_msg = req.get_message()
    MEMORY[conv_id].append({"role": "scammer", "message": user_msg})


    # Detect scam + extract
    is_scam, confidence, scam_type = detect_scam(user_msg)
    extracted = extract_data(user_msg)


    # Update session cumulative data
    for k in extracted:
        SESSION_DATA[conv_id][k].extend(extracted[k])

    # Remove duplicates
    for k in SESSION_DATA[conv_id]:
        SESSION_DATA[conv_id][k] = list(set(SESSION_DATA[conv_id][k]))

    # Agent reply
    if is_scam:
        reply = honeypot_reply(scam_type, req.message)
    else:
        reply = "Hello. Can you explain your issue clearly?"

    # Store agent reply
    MEMORY[conv_id].append({"role": "agent", "message": reply})

    # keep memory small for speed
    if len(MEMORY[conv_id]) > 20:
        MEMORY[conv_id] = MEMORY[conv_id][-10:]

        # ----- METRICS CALCULATION -----
    total_turns = len(MEMORY[conv_id])

    scammer_messages = len([
        m for m in MEMORY[conv_id] if m["role"] == "scammer"
    ])

    agent_messages = len([
        m for m in MEMORY[conv_id] if m["role"] == "agent"
    ])

    extracted_items = (
        len(SESSION_DATA[conv_id]["upi_ids"]) +
        len(SESSION_DATA[conv_id]["bank_accounts"]) +
        len(SESSION_DATA[conv_id]["ifsc_codes"]) +
        len(SESSION_DATA[conv_id]["phishing_links"]) +
        len(SESSION_DATA[conv_id]["phone_numbers"])
    )

    # prevent long processing
    if time.time() - start > 5:
        return {
            "error": "processing timeout",
            "conversation_id": conv_id
        }


    return {
        "conversation_id": conv_id,
        "is_scam": is_scam,
        "scam_type": scam_type,
        "confidence": confidence,
        "agent_reply": reply,
        "extracted_data_current_message": extracted,
        "session_extracted_data": SESSION_DATA[conv_id],
        "conversation": MEMORY[conv_id],

        "metrics": {
        "total_turns": total_turns,
        "scammer_messages": scammer_messages,
        "agent_messages": agent_messages,
        "extracted_items": extracted_items
    }

}


# =========================
# SESSION ENDPOINT
# =========================
@app.get("/session/{conversation_id}")
def get_session(conversation_id: str):
    if conversation_id not in MEMORY:
        return {"error": "Conversation not found"}

    return {
        "conversation_id": conversation_id,
        "conversation": MEMORY[conversation_id],
        "session_extracted_data": SESSION_DATA.get(conversation_id, {})
    }


# =========================
# HEALTH CHECK
# =========================
@app.get("/health")
def health():
    return {"status": "running"}
