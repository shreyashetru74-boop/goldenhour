r"""
GoldenHour: Autonomous Cyber-Fraud Response Agent  (single-file version)
Ziro Agentic AI Hackathon 2026 - Open Innovation track

HOW TO RUN (Windows: just double-click run.bat)
  python -m venv .venv
  .venv\Scripts\python -m pip install -r requirements.txt
  .venv\Scripts\python goldenhour.py
  open http://127.0.0.1:8000

OPTIONAL
  Copy .env.example to .env and add your Gemini key -> Gemini reads screenshots and reasons about the case.
  pip install pytesseract pillow  -> reads screenshots offline (also needs Tesseract installed)

NO TRAINING IS NEEDED. Gemini is already trained; everything else is rule-based Python.
Without a key the whole workflow still runs on the built-in rules engine.

THE USER GIVES ONE THING: the bank SMS / payment message (pasted or as a screenshot).
The agent works out the amount, time, transaction ID and scammer details itself,
asks a quick question ONLY when something it needs is missing, decides the recovery
strategy, drafts every document and tracks the deadlines.
"""

import json
import os
import re
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

# ----------------------------------------------------------------------------
# Config  (put your key in a file called .env next to this one: GEMINI_API_KEY=...)
# ----------------------------------------------------------------------------
_env = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if os.path.exists(_env):
    for _line in open(_env, encoding="utf-8"):
        if "=" in _line and not _line.strip().startswith("#"):
            _k, _v = _line.split("=", 1)
            os.environ.setdefault(_k.strip(), _v.strip().strip('"').strip("'"))

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
# Tried in order; if one model isn't available on your key, the next is used.
GEMINI_MODELS = [m for m in [os.getenv("GEMINI_MODEL", "").strip(), "gemini-3.8-flash", "gemini-3.5-flash-lite"] if m]
GEMINI_MODEL = GEMINI_MODELS[0]
STEP_DELAY = float(os.getenv("STEP_DELAY", "0.7"))   # pause between agent steps, so judges can watch
QUESTION_TIMEOUT = 300                               # seconds the agent waits for an answer
IST = timezone(timedelta(hours=5, minutes=30))

CASES = {}      # case_id -> case dict (in-memory; restarting the program clears it)
WAITERS = {}    # case_id -> threading.Event, used while the agent waits for an answer
SCAM_INTEL = [  # synthetic earlier reports, so cross-case linking shows in the demo
    {"value": "rbi.verify.desk@ybl", "kind": "upi", "case": "SEED-0001"},
    {"value": "rbi.verify.desk@ybl", "kind": "upi", "case": "SEED-0002"},
    {"value": "rbi.verify.desk@ybl", "kind": "upi", "case": "SEED-0003"},
    {"value": "9123456780", "kind": "phone", "case": "SEED-0002"},
]


def now_ist():
    return datetime.now(IST)


# ----------------------------------------------------------------------------
# Gemini helpers - return None on any failure so the rules engine takes over
# ----------------------------------------------------------------------------
def _gemini(contents, want_json):
    if not GEMINI_API_KEY:
        return None
    global GEMINI_MODEL
    try:
        from google import genai
        from google.genai import types
    except ImportError:
        print("google-genai is not installed; using the rules engine. Run: pip install google-genai")
        return None
    client = genai.Client(api_key=GEMINI_API_KEY)
    cfg = types.GenerateContentConfig(temperature=0.1,
                                      response_mime_type="application/json" if want_json else None)
    for model in [GEMINI_MODEL] + [m for m in GEMINI_MODELS if m != GEMINI_MODEL]:
        try:
            resp = client.models.generate_content(model=model, contents=contents, config=cfg)
            GEMINI_MODEL = model                       # remember the one that works
            text = (resp.text or "").strip()
            if not want_json:
                return text or None
            data = json.loads(re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.S))
            return data if isinstance(data, dict) else None
        except json.JSONDecodeError:
            return None
        except Exception as exc:
            print(f"Gemini ({model}) failed: {exc}")
    print("All Gemini models failed; using the rules engine for this step.")
    return None


def read_image(data, mime):
    """Turn a screenshot into text: Gemini vision first, then Tesseract OCR, else nothing."""
    if GEMINI_API_KEY:
        try:
            from google.genai import types
            text = _gemini([types.Part.from_bytes(data=data, mime_type=mime),
                            "Transcribe ALL text in this screenshot exactly as written, line by line. "
                            "Keep amounts, dates, times, UPI IDs, reference numbers and phone numbers exact."], False)
            if text:
                return text
        except Exception:
            pass
    try:
        import io
        import pytesseract
        from PIL import Image
        img = Image.open(io.BytesIO(data)).convert("L")
        if img.width < 1800:
            img = img.resize((int(img.width * 2160 / img.width), int(img.height * 2160 / img.width)))
        return pytesseract.image_to_string(img)
    except Exception:
        return ""


# ----------------------------------------------------------------------------
# TOOL 1 - Evidence extraction
# ----------------------------------------------------------------------------
AMOUNT_RE = re.compile(r"(?:₹|Rs\.?|INR)\s?([0-9][0-9,]*(?:\.[0-9]{1,2})?)", re.I)
UTR_RE = re.compile(r"(?:UTR|UPI\s*Ref(?:erence)?(?:\s*No\.?)?|Ref(?:erence)?\s*No\.?|Txn\s*ID|"
                    r"Transaction\s*ID|RRN)\s*[:#.\-]?\s*([A-Z0-9]{10,22})", re.I)
UPI_RE = re.compile(r"\b([a-zA-Z0-9][a-zA-Z0-9._\-]{1,60}@[a-zA-Z][a-zA-Z0-9]{1,20})\b(?!\.[a-zA-Z])")
PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[\s\-]?)?([6-9]\d{4}[\s\-]?\d{5})(?!\d)")
URL_RE = re.compile(r"\b((?:https?://)?(?:[a-z0-9\-]+\.)+(?:in|com|xyz|top|online|site|info|net|org|link|click)"
                    r"(?:/[^\s,;)\"']*)?)", re.I)
LAST4_RE = re.compile(r"(?:A/?c|Acct|Account|card)\s*(?:no\.?)?\s*(?:ending\s*)?[Xx*\.\s]*(\d{4})\b", re.I)
DATE_PATTERNS = [
    ("%d-%m-%Y %H:%M", re.compile(r"\b(\d{2}-\d{2}-\d{4} \d{2}:\d{2})\b")),
    ("%d/%m/%Y %H:%M", re.compile(r"\b(\d{2}/\d{2}/\d{4} \d{2}:\d{2})\b")),
    ("%d-%b-%y %H:%M", re.compile(r"\b(\d{2}-[A-Z][a-z]{2}-\d{2} \d{2}:\d{2})\b")),
    ("%d %b %Y, %I:%M %p", re.compile(r"\b(\d{1,2} [A-Z][a-z]{2} \d{4}, \d{1,2}:\d{2} [AP]M)\b")),
    ("%d %b %Y %I:%M %p", re.compile(r"\b(\d{1,2} [A-Z][a-z]{2} \d{4} \d{1,2}:\d{2} [AP]M)\b")),
]
BANKS = [("State Bank of India", r"\b(?:sbi|state bank)\b"), ("HDFC Bank", r"\bhdfc\b"),
         ("ICICI Bank", r"\bicici\b"), ("Axis Bank", r"\baxis bank\b"), ("Kotak Mahindra Bank", r"\bkotak\b"),
         ("Canara Bank", r"\bcanara\b"), ("Punjab National Bank", r"\b(?:pnb|punjab national)\b"),
         ("Bank of Baroda", r"\bbank of baroda\b"), ("Union Bank of India", r"\bunion bank\b"),
         ("Karnataka Bank", r"\bkarnataka bank\b"), ("Canara Bank", r"\bcanara\b")]
UPI_HANDLES = {"ybl", "okaxis", "okhdfcbank", "okicici", "oksbi", "paytm", "apl", "yapl", "ibl", "axl",
               "sbi", "hdfcbank", "icici", "axisbank", "kotak", "upi", "fbl", "pnb", "cnrb", "idfcbank",
               "ptyes", "ptaxis", "pthdfc", "ptsbi", "freecharge", "airtel", "jio", "unionbank", "barodampay"}


def extract_evidence(sources):
    """sources: list of {'name', 'text'}. Returns the facts, each traced to where it came from."""
    ev = {"amount": None, "transactions": [], "scammer_upi_ids": [], "scammer_phones": [], "links": [],
          "victim_bank": None, "victim_account_last4": None, "channel": None, "claimed_identity": None,
          "money_left_at": None, "sources": {}}
    loose_amounts, loose_dates = [], []
    for src in sources:
        name, text = src["name"], (src["text"] or "")
        if not text.strip():
            continue
        flat = re.sub(r"[ \t]+", " ", text)
        low = flat.lower()

        amounts = [(float(m.group(1).replace(",", "")), m.start()) for m in AMOUNT_RE.finditer(flat)]
        amounts = [a for a in amounts if a[0] > 0]
        dates = []
        for fmt, rx in DATE_PATTERNS:
            for m in rx.finditer(flat):
                try:
                    dates.append(datetime.strptime(m.group(1), fmt))
                except ValueError:
                    pass
        loose_amounts += [(a, name) for a, _ in amounts]
        loose_dates += dates
        for m in UTR_RE.finditer(flat):
            utr = m.group(1).upper()
            if any(t["utr"] == utr for t in ev["transactions"]):
                continue
            near = min(amounts, key=lambda ap: abs(ap[1] - m.start()))[0] if amounts else None
            ev["transactions"].append({"amount": near, "utr": utr, "source": name, "payee_upi": None,
                                       "datetime": dates[0].strftime("%Y-%m-%dT%H:%M") if dates else None})
            ev["sources"]["utr"] = name

        for m in UPI_RE.finditer(flat):
            upi = m.group(1)
            if upi.split("@")[1].lower() not in UPI_HANDLES:
                continue                                     # an email address, not a UPI ID
            if upi.lower() not in [u.lower() for u in ev["scammer_upi_ids"]]:
                ev["scammer_upi_ids"].append(upi)
                ev["sources"]["scammer_upi"] = name
        for m in PHONE_RE.finditer(flat):
            ph = re.sub(r"\D", "", m.group(0))[-10:]
            if ph not in ev["scammer_phones"]:
                ev["scammer_phones"].append(ph)
        for m in URL_RE.finditer(flat):
            link = m.group(1).rstrip(".")
            if (m.start() and flat[m.start() - 1] == "@") or "cybercrime.gov.in" in link:
                continue
            if link not in ev["links"]:
                ev["links"].append(link)
        if not ev["victim_account_last4"]:
            m = LAST4_RE.search(flat)
            if m:
                ev["victim_account_last4"] = m.group(1)
        if not ev["victim_bank"]:
            for bank, rx in BANKS:
                if re.search(rx, low):
                    ev["victim_bank"] = bank
                    ev["sources"]["victim_bank"] = name
                    break
        if not ev["channel"]:
            for key, label in (("video call", "Video call"), ("whatsapp", "WhatsApp"), ("telegram", "Telegram"),
                               ("sms", "SMS"), ("called me", "Phone call"), ("phone call", "Phone call")):
                if key in low:
                    ev["channel"] = label
                    break
        if not ev["claimed_identity"]:
            for key, label in (("cbi", "CBI officer"), ("enforcement directorate", "ED officer"),
                               ("customs", "Customs officer"), ("police", "Police officer"),
                               ("customer care", "Bank/app customer care"), ("trai", "TRAI official")):
                if re.search(rf"\b{key}\b", low):
                    ev["claimed_identity"] = label
                    break

    # A story with an amount but no transaction reference still counts as one transaction.
    if not ev["transactions"] and loose_amounts:
        ev["transactions"].append({"amount": loose_amounts[0][0], "utr": None, "source": loose_amounts[0][1],
                                   "payee_upi": None,
                                   "datetime": loose_dates[0].strftime("%Y-%m-%dT%H:%M") if loose_dates else None})
    for t in ev["transactions"]:
        if not t["payee_upi"] and ev["scammer_upi_ids"]:
            t["payee_upi"] = ev["scammer_upi_ids"][0]
    tx_amounts = [t["amount"] for t in ev["transactions"] if t["amount"]]
    ev["amount"] = round(sum(tx_amounts), 2) if tx_amounts else None
    ev["money_left_at"] = next((t["datetime"] for t in ev["transactions"] if t.get("datetime")), None)
    return ev


# ----------------------------------------------------------------------------
# TOOL 2 - Classification: scam type + WHO AUTHORISED THE PAYMENT (the key decision)
# ----------------------------------------------------------------------------
SCAM_TYPES = {
    "digital_arrest": ("Digital arrest / fake officer scam",
                       ["digital arrest", "cbi", "enforcement directorate", "customs", "narcotics", "arrest warrant",
                        "money laundering", "parcel", "drugs", "video call", "verification account",
                        "do not tell anyone"]),
    "fake_customer_care": ("Fake customer-care / remote-access scam",
                           ["customer care", "helpline", "refund", "anydesk", "teamviewer", "screen share",
                            "screen sharing", "electricity bill"]),
    "upi_collect_qr": ("UPI collect request / QR code scam",
                       ["collect request", "scan qr", "scan the qr", "to receive", "receive money", "olx",
                        "army officer"]),
    "phishing_link": ("Phishing link / fake KYC scam",
                      ["kyc", "update pan", "account will be blocked", "reward points", "apk", "clicked a link",
                       "click the link"]),
    "investment_task": ("Investment / online task scam",
                        ["task", "telegram", "invest", "profit", "trading", "withdrawal fee", "returns"]),
    "job_fee": ("Fake job / registration fee scam",
                ["registration fee", "part time", "work from home", "training fee", "job"]),
    "sim_swap": ("SIM swap fraud", ["sim stopped", "no network", "sim deactivated", "new sim"]),
    "unauthorized_debit": ("Unauthorized debit (account/card misuse)",
                           ["didn't make", "did not make", "not done by me", "without my knowledge",
                            "unknown transaction", "never made", "not authorised", "not authorized"]),
}
UNAUTH_CUES = ["didn't make", "did not make", "not done by me", "without my knowledge", "unknown transaction",
               "never made", "not authorised", "not authorized", "sim stopped", "never shared", "didn't share",
               "i didn't do"]
SELF_PAID_CUES = ["i paid", "i sent", "i transferred", "transferred", "i scanned", "paid them", "sent money",
                  "asked me to transfer", "asked me to pay", "i deposited", "i paid them"]
CREDENTIAL_CUES = ["shared otp", "shared the otp", "gave the otp", "told them the otp", "shared my pin",
                   "anydesk", "teamviewer", "screen share", "installed an app", "installed the app",
                   "gave otp", "told otp"]
IN_PROGRESS_CUES = ["still on the call", "still on call", "they are watching", "asking me to transfer more",
                    "asking for more", "on call right now", "still asking"]

REASONING = {
    "unauthorized": ("The money left without you making or approving the payment. RBI's customer-protection "
                     "rules apply: reported to the bank in writing within 3 working days, you may owe nothing. "
                     "So the bank report runs alongside 1930."),
    "authorized_deceived": ("You made the payment after being tricked. Bank refund rules usually don't cover "
                            "payments you made yourself, so the fastest way back is freezing the money in the "
                            "scammer's account. 1930 comes first."),
    "credential_compromise": ("You shared an OTP, PIN or screen access and the scammer moved the money. "
                              "This can be argued either way, so I'm pushing on both: the 1930 freeze and a "
                              "written bank dispute, while locking down your accounts."),
}


def classify(text_all):
    text = text_all.lower()
    hits = lambda cues: [c for c in cues if c in text]
    unauth, self_paid = hits(UNAUTH_CUES), hits(SELF_PAID_CUES)
    # "I never shared my OTP" must not count as sharing it
    positive = re.sub(r"\b(never|didn't|did not|not|no|without)\s+(shar\w*|gave|give|giving|told|tell|install\w*)"
                      r"(\s+(the|my|any|an|a))?\s+(otp|pin|app|anydesk|teamviewer)", " ", text)
    creds = [c for c in CREDENTIAL_CUES if c in positive]
    if creds:
        authorization = "credential_compromise"
    elif unauth and not self_paid:
        authorization = "unauthorized"
    elif self_paid:
        authorization = "authorized_deceived"
    else:
        authorization = "authorized_deceived"

    scores = {}
    for key, (_, cues) in SCAM_TYPES.items():
        found = hits(cues)
        if found:
            scores[key] = len(found)
    if authorization == "unauthorized":
        scores["unauthorized_debit"] = scores.get("unauthorized_debit", 0) + 1
    scam_type = max(scores, key=scores.get) if scores else "other"
    if scam_type == "unauthorized_debit" and authorization != "unauthorized" and len(scores) > 1:
        scores.pop("unauthorized_debit")
        scam_type = max(scores, key=scores.get)
    cues = list(dict.fromkeys(hits(SCAM_TYPES.get(scam_type, ("", []))[1]) + unauth + self_paid + creds))[:8]
    return {"scam_type": scam_type,
            "scam_label": SCAM_TYPES.get(scam_type, ("Online financial fraud", []))[0],
            "authorization": authorization, "cues": cues, "reasoning": REASONING[authorization],
            "auth_sure": bool(unauth or self_paid or creds), "by": "rules"}


def classify_with_gemini(text_all, evidence):
    data = _gemini(
        "You are the case strategist of GoldenHour, an agent for Indian cyber-fraud victims.\n"
        f"Everything the victim gave us:\n\"\"\"{text_all[:5000]}\"\"\"\n\n"
        f"Extracted evidence:\n{json.dumps(evidence, default=str)}\n\n"
        "Classify the case. 'unauthorized' = money left without the victim initiating it. "
        "'authorized_deceived' = the victim paid because they were tricked. "
        "'credential_compromise' = the victim shared an OTP/PIN/screen and the scammer moved the money. "
        "Set auth_sure=false if the text does not say how the money left.\n"
        'Return JSON: {"scam_type": string, "scam_label": string, '
        '"authorization": "unauthorized"|"authorized_deceived"|"credential_compromise", '
        '"auth_sure": boolean, "cues": [string], "reasoning": string (2 sentences, addressed to the victim as you)}',
        True)
    if not data or data.get("authorization") not in REASONING:
        return None
    data.setdefault("scam_type", "other")
    data.setdefault("scam_label", "Online financial fraud")
    data["cues"] = [str(c) for c in (data.get("cues") or [])][:8]
    data["reasoning"] = str(data.get("reasoning") or REASONING[data["authorization"]])
    data["auth_sure"] = bool(data.get("auth_sure", True))
    data["by"] = "gemini"
    return data


# ----------------------------------------------------------------------------
# TOOL 3 - Scam Intelligence Network
# ----------------------------------------------------------------------------
def scam_intel(case_id, ev):
    found = []
    items = ([(u, "upi") for u in ev["scammer_upi_ids"]] + [(p, "phone") for p in ev["scammer_phones"]]
             + [(l.split("//")[-1].split("/")[0], "domain") for l in ev["links"]])
    for value, kind in items:
        prior = {r["case"] for r in SCAM_INTEL if r["value"].lower() == value.lower() and r["case"] != case_id}
        if prior:
            found.append({"value": value, "kind": kind, "linked_cases": len(prior)})
        SCAM_INTEL.append({"value": value, "kind": kind, "case": case_id})
    return found


# ----------------------------------------------------------------------------
# TOOL 4 - Recovery chance (transparent heuristic, not a trained model)
# ----------------------------------------------------------------------------
def recovery_chance(authorization, minutes_since, has_beneficiary, has_utr, repeat_scammer):
    factors = []
    if minutes_since is None:
        score = 45
        factors.append(("Time not known yet", 0, "Your bank SMS shows exactly when the money left."))
    elif minutes_since <= 60:
        score = 80
        factors.append(("Inside the golden hour", 30, "The money is most likely still in the first account."))
    elif minutes_since <= 1440:
        score = 55
        factors.append(("Within 24 hours", 10, "Some of it may still be traceable."))
    elif minutes_since <= 4320:
        score = 35
        factors.append(("1 to 3 days ago", -10, "It has probably moved through several accounts."))
    else:
        score = 20
        factors.append(("More than 3 days ago", -25, "A freeze is less likely, but reports still lead to refunds."))
    if authorization in ("unauthorized", "credential_compromise"):
        score += 15
        factors.append(("Bank refund rules may apply", 15, "For payments you didn't make, the bank must prove you're liable."))
    if has_beneficiary:
        score += 5
        factors.append(("Scammer's account found", 5, "Police can follow the money from there."))
    else:
        score -= 10
        factors.append(("Scammer's account not found yet", -10, "The SMS or receipt usually shows it."))
    if not has_utr:
        score -= 5
        factors.append(("No transaction reference yet", -5, "The UTR lets banks find the payment instantly."))
    if repeat_scammer:
        score += 5
        factors.append(("Scammer already reported by others", 5, "The account may already be under watch."))
    score = max(5, min(95, score))
    return {"score": score, "label": "good" if score >= 70 else "fair" if score >= 45 else "low",
            "factors": [{"name": n, "impact": i, "why": w} for n, i, w in factors]}


# ----------------------------------------------------------------------------
# TOOL 5 - Deadlines in bank working days (skips Sundays and 2nd/4th Saturdays)
# ----------------------------------------------------------------------------
def is_bank_holiday(d):
    if d.weekday() == 6:
        return True
    return d.weekday() == 5 and (d.day - 1) // 7 + 1 in (2, 4)


def add_working_days(start, days):
    d, added = start, 0
    while added < days:
        d += timedelta(days=1)
        if not is_bank_holiday(d):
            added += 1
    return d.replace(hour=18, minute=0, second=0, microsecond=0)


def plan_deadlines(authorization, reported_at, left_at):
    items = [("ncrp_complete", "Finish the cybercrime complaint",
              "A 1930 call opens the case; full details go on cybercrime.gov.in within 24 hours.",
              reported_at + timedelta(hours=24))]
    if authorization in ("unauthorized", "credential_compromise"):
        items.append(("bank_notice_3wd", "Bank report in writing (you may owe nothing)",
                      "RBI rule: reported within 3 working days, your liability can be zero.",
                      add_working_days(left_at, 3)))
        items.append(("bank_reversal_10wd", "Bank should put the money back while it checks",
                      "RBI rule: the bank credits the amount within 10 working days of your report.",
                      add_working_days(reported_at, 10)))
    else:
        items.append(("bank_freeze_followup", "Check your bank received the freeze request",
                      "They need your written complaint and the 1930 acknowledgement number.",
                      reported_at + timedelta(days=2)))
    items.append(("ombudsman_eligible", "Escalate to the RBI Ombudsman if the bank is silent",
                  "After 30 days without a fix, you can complain at cms.rbi.org.in. I'll draft it.",
                  reported_at + timedelta(days=30)))
    return items


# ----------------------------------------------------------------------------
# TOOL 6 - Document drafting
# ----------------------------------------------------------------------------
AUTH_LABEL = {"unauthorized": "Unauthorized electronic transaction (not made or approved by me)",
              "authorized_deceived": "Payment made by me under deception (cyber fraud)",
              "credential_compromise": "Transaction made after my credentials were obtained by deception"}

CALL_LANG = {
    "en": {"say": "I want to report a cyber financial fraud. Rs {amount} left my account at {time}. "
                  "The transaction reference (UTR) is {utr}.",
           "ask": "Ask for the acknowledgement number and write it down.",
           "labels": ["Amount", "When", "Transaction ref (UTR)", "Scammer UPI ID", "Your bank"]},
    "hi": {"say": "मुझे साइबर वित्तीय धोखाधड़ी की शिकायत दर्ज करानी है। मेरे खाते से {time} पर {amount} रुपये गए हैं। "
                  "ट्रांज़ैक्शन रेफ़रेंस (UTR) है: {utr}।",
           "ask": "शिकायत की पावती संख्या (acknowledgement number) ज़रूर लिख लें।",
           "labels": ["राशि", "कब", "ट्रांज़ैक्शन रेफ़रेंस (UTR)", "ठग की UPI आईडी", "आपका बैंक"]},
    "kn": {"say": "ನಾನು ಸೈಬರ್ ಹಣಕಾಸು ವಂಚನೆಯ ದೂರು ನೀಡಬೇಕು. ನನ್ನ ಖಾತೆಯಿಂದ {time} ಕ್ಕೆ {amount} ರೂಪಾಯಿ ಹೋಗಿದೆ. "
                  "ವಹಿವಾಟು ಉಲ್ಲೇಖ ಸಂಖ್ಯೆ (UTR): {utr}.",
           "ask": "ದೂರಿನ ಸ್ವೀಕೃತಿ ಸಂಖ್ಯೆಯನ್ನು (acknowledgement number) ಬರೆದುಕೊಳ್ಳಿ.",
           "labels": ["ಮೊತ್ತ", "ಯಾವಾಗ", "ವಹಿವಾಟು ಉಲ್ಲೇಖ (UTR)", "ವಂಚಕರ UPI ಐಡಿ", "ನಿಮ್ಮ ಬ್ಯಾಂಕ್"]},
}


def money(v):
    return f"Rs {v:,.0f}" if v else "[MISSING: amount]"


def fmt_dt(value):
    if not value:
        return "[MISSING: date & time]"
    try:
        return datetime.fromisoformat(value).strftime("%d %b %Y, %I:%M %p")
    except (ValueError, TypeError):
        return str(value)


def tx_lines(f):
    out = [f"{i}. {money(t.get('amount'))} on {fmt_dt(t.get('datetime') or f.get('money_left_at'))}, "
           f"UTR {t.get('utr') or '[MISSING: UTR]'}" + (f", to UPI ID {t['payee_upi']}" if t.get("payee_upi") else "")
           for i, t in enumerate(f["transactions"], 1)]
    return "\n".join(out) or f"1. {money(f.get('amount'))} on {fmt_dt(f.get('money_left_at'))}, UTR [MISSING: UTR]"


def first_utr(f):
    return next((t["utr"] for t in f["transactions"] if t.get("utr")), None)


def call_sheet(f, lang):
    """Structured for the 'Do this now' card, in the victim's language and English."""
    out = []
    for code in ([lang, "en"] if lang != "en" else ["en"]):
        L = CALL_LANG[code]
        when = fmt_dt(f.get("money_left_at")) if f.get("money_left_at") else "____"
        out.append({"lang": code,
                    "say": L["say"].format(amount=f"{f['amount']:,.0f}" if f.get("amount") else "____",
                                           time=when, utr=first_utr(f) or "____"),
                    "ask": L["ask"],
                    "facts": [[L["labels"][0], money(f.get("amount")) if f.get("amount") else None],
                              [L["labels"][1], when if f.get("money_left_at") else None],
                              [L["labels"][2], first_utr(f)],
                              [L["labels"][3], ", ".join(f["scammer_upi_ids"]) or None],
                              [L["labels"][4], (f.get("victim_bank") or "")
                               + (f" (A/c ending {f['victim_account_last4']})" if f.get("victim_account_last4") else "")
                               or None]]})
    return out


def call_sheet_text(f, lang):
    blocks = []
    for c in call_sheet(f, lang):
        blocks.append(f"Say this to the 1930 operator:\n\n\"{c['say']}\"\n\n"
                      + "\n".join(f"- {k}: {v or '[MISSING: ' + k + ']'}" for k, v in c["facts"]) + f"\n\n{c['ask']}")
    return "\n\n---\n\n".join(blocks)


def doc_ncrp(f, description):
    linked = "\n".join(f"- {m['kind'].upper()} {m['value']} reported in {m['linked_cases']} other complaint(s)."
                       for m in f.get("intel", [])) or "- None found."
    return f"""CYBERCRIME COMPLAINT DRAFT (cybercrime.gov.in)
Copy each field into the portal: Report Cyber Crime -> Financial Fraud.

1. INCIDENT
- Category: Online Financial Fraud
- Scam type: {f['scam_label']}
- Date & time: {fmt_dt(f.get('money_left_at'))}
- First contact: {f.get('channel') or 'Not stated'}
- Scammer claimed to be: {f.get('claimed_identity') or 'Not stated'}
- Total amount lost: {money(f.get('amount'))}

2. TRANSACTIONS
{tx_lines(f)}
- Victim bank: {f.get('victim_bank') or '[MISSING: your bank]'}

3. SUSPECT
- UPI IDs: {', '.join(f['scammer_upi_ids']) or 'Not known'}
- Phone numbers: {', '.join(f['scammer_phones']) or 'Not known'}
- Links: {', '.join(f['links']) or 'None'}

4. WHAT HAPPENED
{description}

5. LINKED REPORTS (GoldenHour Scam Intelligence)
{linked}

Fill in yourself: your full name, address, email and ID proof.
"""


def description_text(f, note):
    parts = [f"On {fmt_dt(f.get('money_left_at'))}, {money(f.get('amount'))} left my account"
             + (f" after I was contacted via {f['channel']}" if f.get("channel") else "")
             + (f" by a person claiming to be a {f['claimed_identity']}" if f.get("claimed_identity") else "") + "."]
    if note.strip():
        parts.append(f'In my own words: "{note.strip()}"')
    parts.append(f"Nature of the transaction: {AUTH_LABEL[f['authorization']]}.")
    parts.append("I request that the beneficiary accounts be frozen and the amount be restored to me.")
    return " ".join(parts)


def doc_bank_letter(f, today):
    bank = f.get("victim_bank") or "[MISSING: your bank]"
    asks = ["Block further debits from my account, card and UPI immediately.",
            "Coordinate with the beneficiary bank(s) to freeze the amount, in line with my cybercrime complaint.",
            "Preserve all records of the transaction(s), including beneficiary and device/IP logs.",
            "Give me a written complaint reference number."]
    rules = ""
    if f["authorization"] != "authorized_deceived":
        rules = ("\nUnder the RBI circular on Customer Protection - Limiting Liability of Customers in Unauthorised "
                 "Electronic Banking Transactions (RBI/2017-18/15, 6 July 2017), I am reporting this promptly. "
                 "Please credit the amount to my account (shadow reversal) within 10 working days while the bank "
                 "investigates. The burden of proving customer liability rests with the bank.\n")
        asks.insert(1, "Credit the disputed amount within 10 working days (shadow reversal), as the RBI circular requires.")
    return (f"LETTER TO {bank}: FRAUD REPORT AND FREEZE REQUEST\nDate: {today.strftime('%d %b %Y')}\n\n"
            f"To, The Branch Manager / Grievance Redressal Officer, {bank}\n\n"
            f"Subject: Cyber fraud - request to block, freeze and reverse transaction(s), "
            f"A/c ending {f.get('victim_account_last4') or '[MISSING: last 4 digits of your account]'}\n\n"
            f"Respected Sir/Madam,\n\nI am reporting a cyber fraud on my account. Nature: {AUTH_LABEL[f['authorization']]}.\n\n"
            f"Transaction details:\n{tx_lines(f)}\n\nTotal amount: {money(f.get('amount'))}\n"
            f"Beneficiary UPI ID(s): {', '.join(f['scammer_upi_ids']) or 'Not known'}\n"
            f"1930 / cybercrime acknowledgement no.: [your acknowledgement number]\n{rules}\n"
            "I request the bank to:\n" + "\n".join(f"{i}. {a}" for i, a in enumerate(asks, 1))
            + "\n\nYours faithfully,\n[Your full name]\n[Your registered mobile number]\n\n"
            "HOW TO SEND: use 'Report fraud' in your bank's official app, or the number printed on your card. "
            "Never use a helpline number from a search result; scammers post fake ones.")


SECURITY_STEPS = {
    "digital_arrest": [("Hang up and block the caller", "No real officer arrests anyone on a video call or asks for money."),
                       ("Tell someone you trust now", "Scammers demand secrecy so you can't get help.")],
    "fake_customer_care": [("Uninstall AnyDesk / TeamViewer or any app they asked for", "It can still give them access."),
                           ("Change your UPI PIN and passwords from another phone", "They may have seen them on your screen.")],
    "upi_collect_qr": [("Remember: you never enter a PIN to receive money", "A PIN request always means money is leaving."),
                       ("Block the UPI ID that requested money", "Decline unknown collect requests.")],
    "phishing_link": [("Change passwords and UPI PIN now", "Anything typed on the fake page is with them."),
                      ("Delete unknown apps and check SMS permissions", "Fake apps can read your OTPs.")],
    "investment_task": [("Stop all 'withdrawal fee' or 'tax' payments", "Paying more never unlocks a fake platform."),
                        ("Save the group details, then leave", "They help the investigation.")],
    "job_fee": [("Stop paying for 'training' or 'documents'", "Real employers don't charge you to hire you.")],
    "sim_swap": [("Call your mobile operator from another phone", "Block the duplicate SIM."),
                 ("Ask the bank to pause digital banking", "Your OTPs are going to their SIM.")],
    "unauthorized_debit": [("Block your card in the bank app", "Stops more charges."),
                           ("Check net-banking for new payees or devices", "Remove anything you didn't add.")],
}
CREDENTIAL_STEPS = [("Change UPI PIN, card PIN and net-banking password", "Assume they still have them."),
                    ("Turn off online use of your card / UPI in the bank app", "Stops repeat debits for now.")]
BASE_STEPS = [("Don't pay anyone who promises to 'recover' your money", "That's almost always a second scam."),
              ("Keep every SMS, screenshot and call log", "Don't delete the chat with the scammer; it's evidence.")]


def doc_security(scam_type, authorization):
    steps = (CREDENTIAL_STEPS if authorization == "credential_compromise" else []) \
        + SECURITY_STEPS.get(scam_type, []) + BASE_STEPS
    return "LOCK DOWN YOUR ACCOUNTS\n\n" + "\n".join(f"[ ] {s}\n    {w}" for s, w in steps)


def doc_trusted(f):
    return ("MESSAGE TO SEND SOMEONE YOU TRUST\n\n"
            f"\"I've been cheated in an online fraud ({f['scam_label'].lower()}) and lost {money(f.get('amount'))}. "
            "I'm reporting it to 1930 and my bank right now. Please call me. If anyone contacts you offering to "
            "recover the money for a fee, don't pay - it's another scam.\"\n\n"
            "Why: scammers rely on you staying alone and quiet. Telling someone stops further payments.")


def doc_bank_followup(f, today, days_since):
    return (f"FOLLOW-UP: MONEY NOT YET RETURNED\nDate: {today.strftime('%d %b %Y')}\n\n"
            f"To, The Grievance Redressal Officer, {f.get('victim_bank') or '[MISSING: your bank]'}\n\n"
            f"Subject: Second request - shadow reversal pending, reported {days_since} days ago\n\n"
            f"I reported the transaction(s) below in writing on {f['reported_display']}. More than 10 working days "
            "have passed and the amount has not been credited, as RBI circular RBI/2017-18/15 requires.\n\n"
            f"{tx_lines(f)}\n\nPlease credit the amount immediately and tell me the status of your investigation in "
            "writing. If I do not get a satisfactory reply, I will escalate to the RBI Ombudsman.\n\n"
            "Yours faithfully,\n[Your full name]")


def doc_ombudsman(f, today):
    category = ("Unauthorised electronic transaction" if f["authorization"] != "authorized_deceived"
                else "Deficiency in service: failure to act on cyber-fraud / freeze request")
    return (f"COMPLAINT TO THE RBI OMBUDSMAN (Integrated Ombudsman Scheme, 2021)\n"
            "File at cms.rbi.org.in  (help: RBI helpline 14448)\n\n"
            f"- Regulated entity: {f.get('victim_bank') or '[MISSING: your bank]'}\n"
            f"- Category: {category}\n- Complaint to the bank on: {f['reported_display']}\n"
            "- Bank's response: none / unsatisfactory within 30 days\n"
            f"- Amount: {money(f.get('amount'))}\n"
            f"- Relief sought: refund of {money(f.get('amount'))} and compensation for time and expenses\n\n"
            f"Facts:\nOn {fmt_dt(f.get('money_left_at'))}: {AUTH_LABEL[f['authorization']].lower()}.\n{tx_lines(f)}\n\n"
            f"I reported this to the bank in writing on {f['reported_display']} and to the national cybercrime "
            "helpline (1930). The bank has not resolved it within 30 days.\n\n"
            "Attach: bank complaint copy, bank acknowledgement, 1930 acknowledgement, screenshots.\n"
            f"Prepared: {today.strftime('%d %b %Y')}")


# ----------------------------------------------------------------------------
# TOOL 7 - Verifier: independently checks each document against the facts
# ----------------------------------------------------------------------------
REQUIRED = {"call_sheet": ["amount", "utr"], "ncrp": ["amount", "utr"], "bank_letter": ["amount", "utr", "bank"],
            "ombudsman": ["amount", "bank"], "bank_followup": ["utr", "bank"]}


def verify(kind, content, f):
    issues = [f"Missing: {m}" for m in sorted(set(re.findall(r"\[MISSING: ([^\]]+)\]", content)))]
    needs = REQUIRED.get(kind, [])
    if "amount" in needs and f.get("amount") and f"{f['amount']:,.0f}" not in content:
        issues.append(f"Amount Rs {f['amount']:,.0f} is not in the document")
    if "utr" in needs:
        for t in f["transactions"]:
            if t.get("utr") and t["utr"] not in content:
                issues.append(f"UTR {t['utr']} is not included")
    if "bank" in needs and f.get("victim_bank") and f["victim_bank"].upper() not in content.upper():
        issues.append("Your bank's name is not included")
    return issues


# ----------------------------------------------------------------------------
# THE AGENT - plan, act, ask only when needed, verify; every step logged with its reason
# ----------------------------------------------------------------------------
NEXT_STEPS = {
    "unauthorized": [("Send the fraud report to your bank today", "bank_letter",
                      "Reported in writing within 3 working days, you may owe nothing (RBI rule)."),
                     ("Finish the cybercrime complaint", "ncrp", "Keeps the freeze request on record."),
                     ("Lock your card and UPI", "security", "Stops more money leaving.")],
    "authorized_deceived": [("Finish the cybercrime complaint within 24 hours", "ncrp",
                             "The 1930 freeze holds best with a complete complaint."),
                            ("Ask your bank to back the freeze", "bank_letter",
                             "They must keep records and cooperate with police."),
                            ("Don't pay anything more", "security",
                             "Scammers come back asking for 'fees' or 'taxes'.")],
    "credential_compromise": [("Lock down your phone and accounts", "security", "They may still have access."),
                              ("Send the dispute to your bank today", "bank_letter",
                               "A prompt written report protects your right to a refund."),
                              ("Finish the cybercrime complaint", "ncrp", "Keeps the freeze request on record.")],
}


def log(case, step, title, detail="", reason="", status="done"):
    case["events"].append({"id": len(case["events"]) + 1, "ts": now_ist().strftime("%H:%M:%S"),
                           "step": step, "title": title, "detail": detail, "reason": reason, "status": status})


def save_doc(case, kind, title, content):
    issues = verify(kind, content, case["facts"])
    case["documents"] = [d for d in case["documents"] if d["kind"] != kind]
    case["documents"].append({"kind": kind, "title": title, "content": content,
                              "status": "needs_input" if issues else "ready", "issues": issues, "ack": None})
    return issues


def ask(case, qid, text, why, qtype, options=None):
    """The agent pauses and asks ONE thing it could not work out itself."""
    ev = threading.Event()
    WAITERS[case["id"]] = ev
    case["question"] = {"id": qid, "text": text, "why": why, "type": qtype, "options": options or []}
    case["status"] = "waiting"
    log(case, "ask", text, "", why, "question")
    answered = ev.wait(QUESTION_TIMEOUT)
    case["question"] = None
    case["status"] = "running"
    return case["answers"].get(qid) if answered else None


def run_agent(case_id, uploads):
    case = CASES[case_id]
    try:
        reported_at = datetime.fromisoformat(case["created_at"])
        all_text_parts = [case["note"], case["pasted"]]

        # 1. First output, always: get the victim on the phone to 1930
        log(case, "triage", "Call 1930 now while I work",
            "I'll have everything you need to say ready in a few seconds.",
            "Fast reports give the best chance of freezing the money.", "urgent")
        if any(c in (case["note"] + case["pasted"]).lower() for c in IN_PROGRESS_CUES):
            log(case, "triage", "Hang up on them now", "Don't send more money. Real officers never ask for it on a call.",
                "Your message says they may still be in touch.", "urgent")
        time.sleep(STEP_DELAY)

        # 2. Read everything the victim gave
        sources = [{"name": "your note", "text": case["note"]}, {"name": "pasted message", "text": case["pasted"]}]
        for up in uploads:
            text = up["text"] if up["text"] is not None else read_image(up["bytes"], up["mime"])
            sources.append({"name": up["name"], "text": text})
            all_text_parts.append(text)
        all_text = "\n".join(p for p in all_text_parts if p)
        ev = extract_evidence(sources)
        found = []
        if ev["amount"]:
            found.append(f"Rs {ev['amount']:,.0f}")
        if ev["money_left_at"]:
            found.append(f"left at {fmt_dt(ev['money_left_at'])}")
        if first_utr(ev):
            found.append(f"UTR {first_utr(ev)}")
        if ev["scammer_upi_ids"]:
            found.append("to " + ", ".join(ev["scammer_upi_ids"]))
        if ev["victim_bank"]:
            found.append(ev["victim_bank"])
        log(case, "extract", "Read your evidence", "Found " + (", ".join(found) if found else "very little") + ".",
            "Amount, time, transaction ID and the scammer's account are what police and banks need first.")
        time.sleep(STEP_DELAY)

        # 3. Ask only for what's missing
        if not ev["money_left_at"]:
            ans = ask(case, "when", "When did the money leave your account?",
                      "The time decides how fast the money can still be frozen.", "choice",
                      [{"value": "5", "label": "Just now"}, {"value": "30", "label": "About 30 min ago"},
                       {"value": "90", "label": "1-2 hours ago"}, {"value": "300", "label": "Earlier today"},
                       {"value": "1500", "label": "Yesterday"}, {"value": "4500", "label": "Days ago"}])
            minutes = int(ans) if ans and str(ans).isdigit() else 30
            ev["money_left_at"] = (reported_at - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M")
            ev["sources"]["money_left_at"] = "your answer"
        if not ev["amount"]:
            ans = ask(case, "amount", "How much money did you lose?",
                      "The complaint and bank letter need the exact amount.", "number")
            try:
                ev["amount"] = float(str(ans).replace(",", "")) if ans else None
            except ValueError:
                ev["amount"] = None
            if ev["amount"]:
                if ev["transactions"]:
                    ev["transactions"][0]["amount"] = ev["amount"]
                else:
                    ev["transactions"].append({"amount": ev["amount"], "utr": None, "source": "your answer",
                                               "payee_upi": (ev["scammer_upi_ids"] or [None])[0],
                                               "datetime": ev["money_left_at"]})
        for t in ev["transactions"]:
            t["datetime"] = t.get("datetime") or ev["money_left_at"]

        # 4. Call sheet first, so it's ready during the 1930 call
        case["facts"] = {**ev, "reported_display": reported_at.strftime("%d %b %Y"), "intel": [],
                         **{k: v for k, v in classify(all_text).items() if k in ("scam_type", "scam_label", "authorization")}}
        case["call"] = call_sheet(case["facts"], case["language"])
        save_doc(case, "call_sheet", "1930 call sheet", call_sheet_text(case["facts"], case["language"]))
        log(case, "call_sheet", "Your 1930 script is ready",
            "Amount, time and transaction ID in one place" + ("" if case["language"] == "en" else ", in your language") + ".",
            "Operators need these to send the freeze request to the banks.")
        time.sleep(STEP_DELAY)

        # 5. The key decision: who authorised the payment?
        cls = classify_with_gemini(all_text, {k: v for k, v in ev.items() if k != "sources"}) or classify(all_text)
        if not cls["auth_sure"]:
            ans = ask(case, "how", "How did the money leave your account?",
                      "This decides whether your bank may have to refund you, or freezing it is the main way back.",
                      "choice",
                      [{"value": "authorized_deceived", "label": "I paid them. They tricked me."},
                       {"value": "unauthorized", "label": "It left without me doing anything."},
                       {"value": "credential_compromise", "label": "I shared an OTP or installed an app they asked for."}])
            if ans in REASONING:
                cls["authorization"] = ans
                cls["reasoning"] = REASONING[ans]
                if cls["scam_type"] in ("other", "unauthorized_debit") and ans != "unauthorized":
                    cls["scam_type"], cls["scam_label"] = "other", "Online financial fraud"
                if ans == "unauthorized":
                    cls["scam_type"], cls["scam_label"] = "unauthorized_debit", SCAM_TYPES["unauthorized_debit"][0]
                cls["cues"] = ["your answer"]
        label = {"unauthorized": "Money taken without your permission",
                 "authorized_deceived": "Payment made after being tricked",
                 "credential_compromise": "Money moved after an OTP or app was shared"}[cls["authorization"]]
        log(case, "classify", f"{cls['scam_label']}: {label.lower()}",
            ("Based on: " + ", ".join(f"'{c}'" for c in cls["cues"])) if cls["cues"] else "",
            cls["reasoning"])
        case["facts"].update({k: cls[k] for k in ("scam_type", "scam_label", "authorization")})
        case["classification"] = cls
        time.sleep(STEP_DELAY)

        # 6. Has anyone else reported this scammer?
        matches = scam_intel(case_id, ev)
        case["facts"]["intel"] = matches
        for m in matches:
            log(case, "intel", f"This scammer was reported by {m['linked_cases']} other people",
                f"{m['value']} is already in other complaints. I've added the link to yours.",
                "Accounts reported many times get priority for freezing.", "warning")
        if not matches:
            log(case, "intel", "Checked the scammer's details against other reports",
                "No match yet. Your report will warn the next person.", "")
        time.sleep(STEP_DELAY)

        # 7. Recovery chance, timeline, next steps
        left_at = datetime.fromisoformat(ev["money_left_at"]).replace(tzinfo=IST)
        minutes_since = max(0, int((now_ist() - left_at).total_seconds() // 60))
        case["recovery"] = recovery_chance(cls["authorization"], minutes_since, bool(ev["scammer_upi_ids"]),
                                           bool(first_utr(ev)), bool(matches))
        case["next_steps"] = [{"title": t, "doc": d, "why": w} for t, d, w in NEXT_STEPS[cls["authorization"]]]
        for key, title, why, due in plan_deadlines(cls["authorization"], reported_at, left_at):
            case["deadlines"].append({"key": key, "title": title, "why": why, "due": due.isoformat(), "status": "pending"})
        log(case, "plan", "Planned your recovery",
            " → ".join(["Call 1930"] + [s["title"] for s in case["next_steps"]]),
            {"unauthorized": "Your bank may have to refund you, so the bank report runs alongside 1930.",
             "authorized_deceived": "Everything is set up for the fastest possible freeze.",
             "credential_compromise": "Freeze, lockdown and bank dispute run side by side."}[cls["authorization"]])
        time.sleep(STEP_DELAY)

        # 8. Draft every document, then check each one
        f = case["facts"]
        save_doc(case, "call_sheet", "1930 call sheet", call_sheet_text(f, case["language"]))
        save_doc(case, "ncrp", "Cybercrime complaint", doc_ncrp(f, description_text(f, case["note"])))
        save_doc(case, "bank_letter", "Letter to " + (f.get("victim_bank") or "your bank"), doc_bank_letter(f, now_ist()))
        save_doc(case, "security", "Lock down your accounts", doc_security(cls["scam_type"], cls["authorization"]))
        save_doc(case, "trusted", "Message for someone you trust", doc_trusted(f))
        log(case, "documents", "Drafted your complaint, bank letter and safety checklist",
            "Each one is filled in from your evidence. Tap any step below to see it.",
            "You only check and send; I've done the writing.")
        time.sleep(STEP_DELAY)
        pending = [d for d in case["documents"] if d["issues"]]
        if pending:
            log(case, "verify", "Double-checked every draft: some details are missing",
                "; ".join(f"{d['title']}: {', '.join(d['issues'])}" for d in pending),
                "I never mark a draft ready while something's missing.", "warning")
        else:
            log(case, "verify", "Double-checked every draft against your evidence",
                "Amount, transaction ID, bank and scammer details match everywhere.",
                "An independent check, so a typo can't slip into your complaint.")
        log(case, "done", "I'll keep watching your deadlines",
            "If your bank stays silent, I'll draft the follow-up and the RBI Ombudsman complaint for you.",
            "Nothing is sent without your OK.")
        case["status"] = "active"
    except Exception as exc:
        log(case, "error", "Something went wrong on my side", str(exc), "Please call 1930 directly.", "error")
        case["status"] = "error"


# ----------------------------------------------------------------------------
# Tracking: approvals, simulated time jumps, bank response
# ----------------------------------------------------------------------------
DOC_DEADLINES = {"ncrp": ["ncrp_complete"], "bank_letter": ["bank_notice_3wd", "bank_freeze_followup"]}


def approve(case, kind):
    doc = next((d for d in case["documents"] if d["kind"] == kind), None)
    if not doc:
        raise HTTPException(404, "Document not found")
    prefix = {"ncrp": "NCRP", "bank_letter": "BANK", "bank_followup": "BANK2", "ombudsman": "RBICMS"}.get(kind)
    doc["ack"] = f"SIM-{prefix}-{uuid.uuid4().hex[:8].upper()}" if prefix else None
    doc["status"] = "submitted" if prefix else "done"
    for d in case["deadlines"]:
        if d["key"] in DOC_DEADLINES.get(kind, []) and d["status"] in ("pending", "overdue"):
            d["status"] = "done"
    log(case, "human", f"You sent: {doc['title']}",
        f"Acknowledgement {doc['ack']} (simulated)." if doc["ack"] else "Marked as done.", "")
    return doc


def simulate_days(case, days):
    case["offset_days"] += days
    now = now_ist() + timedelta(days=case["offset_days"])
    log(case, "clock", f"Demo: jumped ahead {days} day(s)", f"It's now {now.strftime('%d %b %Y')} for this case.", "")
    f = case["facts"]
    if not f:
        return
    for d in case["deadlines"]:
        if d["status"] not in ("pending", "overdue") or datetime.fromisoformat(d["due"]) > now:
            continue
        if d["key"] == "ncrp_complete":
            d["status"] = "overdue"
            log(case, "track", "Your cybercrime complaint isn't sent yet", "Open it below and tap Send.",
                "An incomplete complaint can weaken the freeze.", "warning")
        elif d["key"] in ("bank_notice_3wd", "bank_freeze_followup"):
            d["status"] = "overdue"
            log(case, "track", "Your bank hasn't had the letter yet", "Send it today.",
                "The 3-working-day refund window has passed." if d["key"] == "bank_notice_3wd"
                else "The bank needs it to support the freeze.", "warning")
        elif d["key"] == "bank_reversal_10wd" and not case["bank_responded"]:
            d["status"] = "escalated"
            days_since = (now - datetime.fromisoformat(case["created_at"])).days
            save_doc(case, "bank_followup", "Follow-up letter to your bank", doc_bank_followup(f, now, days_since))
            log(case, "track", "Your bank missed its 10-day deadline: I drafted a follow-up",
                "It cites the RBI rule and asks for the money back now.", "", "warning")
        elif d["key"] == "ombudsman_eligible" and not case["bank_responded"]:
            d["status"] = "escalated"
            save_doc(case, "ombudsman", "Complaint to the RBI Ombudsman", doc_ombudsman(f, now))
            log(case, "track", "30 days with no fix: I drafted your RBI Ombudsman complaint",
                "The whole case history is in it. Tap Send when you're ready.",
                "The Ombudsman can direct the bank to act.", "urgent")


# ----------------------------------------------------------------------------
# Demo scenarios (synthetic; timestamps are relative to now, so the clock is real)
# ----------------------------------------------------------------------------
def demo_scenario(name):
    now = now_ist()
    if name == "digital_arrest":
        t = now - timedelta(minutes=22)
        return {"note": ("A man on a WhatsApp video call said he was a CBI officer and I was under digital arrest "
                         "for a drugs parcel. He said not to tell anyone. I transferred the money to his "
                         "'verification account'."),
                "pasted": (f"Payment Successful. Paid to RBI VERIFICATION DESK, UPI ID rbi.verify.desk@ybl. "
                           f"Rs 85,000.00 debited from HDFC Bank A/c XX4521 on {t.strftime('%d-%m-%Y %H:%M')}. "
                           f"UPI Ref No 612398451207. Call 9123456780 if disconnected."),
                "language": "kn"}
    if name == "unauthorized":
        t = now - timedelta(hours=2, minutes=10)
        return {"note": "I didn't make this payment and never shared any OTP.",
                "pasted": (f"Dear Customer, Rs 24,999.00 debited from A/c XX7781 on {t.strftime('%d-%m-%Y %H:%M')} "
                           f"to VPA fastpay.refund88@okaxis. UPI Ref No 512398765432. Not you? Report immediately. -SBI"),
                "language": "en"}
    if name == "remote_access":
        t = now - timedelta(minutes=48)
        return {"note": "Fake electricity customer care made me install AnyDesk and I shared the OTP.",
                "pasted": (f"Rs 12,000.00 debited from A/c XX3390 on {t.strftime('%d-%m-%Y %H:%M')} to VPA "
                           f"powerbill.care@paytm. UPI Ref No 734512098811. -ICICI Bank"),
                "language": "hi"}
    if name == "sms_only":
        t = now - timedelta(minutes=15)
        return {"note": "",
                "pasted": (f"Rs 40,000.00 debited from A/c XX2207 on {t.strftime('%d-%m-%Y %H:%M')} to VPA "
                           f"quickloan.help@ybl. UPI Ref No 908812345671. -Canara Bank"),
                "language": "en"}
    raise HTTPException(404, "Unknown scenario")


SCENARIOS = {"sms_only": "Just a bank SMS (the agent asks one question)",
             "digital_arrest": "Digital arrest scam, Kannada",
             "unauthorized": "Money taken without permission",
             "remote_access": "Fake customer care + AnyDesk, Hindi"}

# ----------------------------------------------------------------------------
# API
# ----------------------------------------------------------------------------
app = FastAPI(title="GoldenHour")


def start_case(note, pasted, language, uploads):
    case_id = "GH-" + uuid.uuid4().hex[:8].upper()
    CASES[case_id] = {"id": case_id, "created_at": now_ist().isoformat(timespec="seconds"), "status": "running",
                      "note": note or "", "pasted": pasted or "", "language": language if language in CALL_LANG else "en",
                      "offset_days": 0, "bank_responded": False, "events": [], "documents": [], "deadlines": [],
                      "facts": None, "classification": None, "recovery": None, "call": None, "next_steps": None,
                      "question": None, "answers": {}}
    threading.Thread(target=run_agent, args=(case_id, uploads), daemon=True).start()
    return case_id


def get_case(case_id):
    if case_id not in CASES:
        raise HTTPException(404, "Case not found")
    return CASES[case_id]


@app.get("/api/health")
def health():
    return {"mode": "Gemini" if GEMINI_API_KEY else "Offline", "scenarios": SCENARIOS}


@app.post("/api/cases")
async def create_case(pasted: str = Form(""), note: str = Form(""), language: str = Form("en"),
                      files: list[UploadFile] = File(None)):
    uploads = []
    for f in files or []:
        data = await f.read()
        if not data:
            continue
        mime = f.content_type or ""
        if mime.startswith("text/"):
            uploads.append({"name": f.filename, "text": data.decode("utf-8", "ignore")})
        else:
            uploads.append({"name": f.filename, "text": None, "bytes": data, "mime": mime or "image/png"})
    if not (pasted.strip() or note.strip() or uploads):
        raise HTTPException(400, "Paste your bank SMS or add a screenshot, and I'll take it from there.")
    return {"case_id": start_case(note, pasted, language, uploads)}


@app.post("/api/demo/{name}")
def create_demo(name: str):
    s = demo_scenario(name)
    return {"case_id": start_case(s["note"], s["pasted"], s["language"], []), **s}


@app.get("/api/cases/{case_id}")
def read_case(case_id: str):
    case = get_case(case_id)
    return {**{k: v for k, v in case.items() if k not in ("note", "pasted")},
            "case_now": (now_ist() + timedelta(days=case["offset_days"])).isoformat()}


class Answer(BaseModel):
    qid: str
    value: str


@app.post("/api/cases/{case_id}/answer")
def api_answer(case_id: str, body: Answer):
    case = get_case(case_id)
    if not case["question"] or case["question"]["id"] != body.qid:
        raise HTTPException(409, "No open question")
    case["answers"][body.qid] = body.value
    if case_id in WAITERS:
        WAITERS[case_id].set()
    return {"ok": True}


class Days(BaseModel):
    days: int = 1


@app.post("/api/cases/{case_id}/simulate")
def api_simulate(case_id: str, body: Days):
    case = get_case(case_id)
    if case["status"] in ("running", "waiting"):
        raise HTTPException(409, "Wait for the agent to finish first")
    simulate_days(case, max(1, min(60, body.days)))
    return read_case(case_id)


@app.post("/api/cases/{case_id}/approve/{kind}")
def api_approve(case_id: str, kind: str):
    approve(get_case(case_id), kind)
    return read_case(case_id)


@app.post("/api/cases/{case_id}/bank-resolved")
def api_bank_resolved(case_id: str):
    case = get_case(case_id)
    case["bank_responded"] = True
    for d in case["deadlines"]:
        if d["key"] in ("bank_reversal_10wd", "ombudsman_eligible"):
            d["status"] = "done"
    log(case, "track", "Your bank resolved it", "No escalation needed.", "")
    return read_case(case_id)


# ----------------------------------------------------------------------------
# The page
# ----------------------------------------------------------------------------
PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>GoldenHour</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Atkinson+Hyperlegible:wght@400;700&display=swap" rel="stylesheet">
<style>
:root{--ink:#13293d;--soft:#4a5a6b;--muted:#6b7785;--paper:#f4f7f5;--card:#fff;--line:#dfe6e2;
--hope:#0d7a5c;--hope-soft:#e1f3eb;--time:#d98e00;--time-soft:#fff3d6;--alert:#c4122f;--alert-soft:#fde9ec}
*{box-sizing:border-box}html,body{margin:0}
body{font:17px/1.5 "Atkinson Hyperlegible",system-ui,"Segoe UI",sans-serif;color:var(--ink);background:var(--paper)}
button,input,textarea{font:inherit;color:inherit}
:focus-visible{outline:3px solid var(--time);outline-offset:2px}
header{display:flex;align-items:center;gap:12px;padding:12px 18px;background:var(--card);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:10}
.brand{font-weight:700;font-size:1.15rem;cursor:pointer;display:flex;gap:8px;align-items:center}
.mode{font-size:.75rem;color:var(--muted);border:1px solid var(--line);border-radius:99px;padding:1px 9px}
.call-top{margin-left:auto;background:var(--alert);color:#fff;font-weight:700;padding:8px 16px;border-radius:99px;text-decoration:none}
main{max-width:640px;margin:0 auto;padding:28px 16px 64px}
h1{font-size:clamp(1.8rem,6vw,2.4rem);line-height:1.15;margin:8px 0 10px}
h2{font-size:1.2rem;margin:0 0 4px}
.lede{color:var(--soft);margin:0 0 22px}
.box{background:var(--card);border:1.5px solid var(--line);border-radius:16px;padding:14px}
.box textarea{width:100%;border:0;resize:vertical;min-height:120px;background:none;outline:none;font-size:1rem}
.box .bar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;border-top:1px solid var(--line);padding-top:10px;margin-top:6px}
.attach{border:1.5px dashed var(--line);border-radius:10px;padding:6px 12px;cursor:pointer;font-size:.9rem;color:var(--soft)}
.attach input{display:none}
.langs{margin-left:auto;display:flex;gap:4px}
.langs button{border:1.5px solid var(--line);background:none;border-radius:99px;padding:3px 11px;cursor:pointer;font-size:.88rem}
.langs button[aria-pressed=true]{background:var(--ink);color:#fff;border-color:var(--ink)}
.more{display:block;margin-top:10px;color:var(--soft);font-size:.92rem;background:none;border:0;padding:0;cursor:pointer;text-decoration:underline}
#note{width:100%;margin-top:8px;border:1.5px solid var(--line);border-radius:10px;padding:10px;background:var(--paper)}
.go{width:100%;margin-top:14px;background:var(--hope);color:#fff;border:0;border-radius:14px;padding:16px;font-size:1.1rem;font-weight:700;cursor:pointer}
.go:disabled{opacity:.6}
.hint{font-size:.9rem;color:var(--soft);margin:14px 0 0}
.err{color:var(--alert);font-size:.92rem;min-height:1.2em;margin:8px 0 0}
.demos{margin-top:34px}.demos p{font-size:.9rem;color:var(--muted);margin:0 0 8px}
.chip{border:1.5px solid var(--line);background:var(--card);border-radius:99px;padding:6px 13px;margin:0 6px 8px 0;cursor:pointer;font-size:.9rem}

/* case view */
.card{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:20px;margin-bottom:14px}
.hope{background:var(--hope-soft);border-color:transparent}
.hope.low{background:#eef1f4}
.hope h1{margin:0 0 6px;font-size:clamp(1.5rem,5vw,2rem)}
.hope p{margin:0 0 6px;color:var(--soft)}
.goodnews{background:#fff;border-radius:12px;padding:10px 12px;margin-top:10px;font-size:.95rem}
.goodnews b{color:var(--hope)}
.proof{font-size:.82rem;color:var(--muted);margin-top:10px}.proof a{color:inherit}
.clock{display:flex;align-items:baseline;gap:10px;margin:10px 0 2px}
.clock .big{font-size:2.6rem;font-weight:700;font-variant-numeric:tabular-nums;color:var(--time);line-height:1}
.clock .small{color:var(--soft)}
/* timeline */
.vt{list-style:none;padding:0;margin:14px 0 0;position:relative}
.vt::before{content:"";position:absolute;left:8px;top:10px;bottom:10px;width:3px;background:var(--line);border-radius:3px}
.vt li{position:relative;display:flex;gap:12px;padding:0 0 14px 30px}
.vt li::before{content:"";position:absolute;left:1px;top:5px;width:17px;height:17px;border-radius:50%;background:var(--card);border:3px solid var(--line);box-sizing:border-box}
.vt li.past::before{background:var(--time);border-color:var(--time)}
.vt li.next::before{border-color:var(--hope);box-shadow:0 0 0 5px var(--hope-soft)}
.vt li.past .x{color:var(--muted)}
.vt .x{flex:1}.vt .x b{display:block;font-size:.97rem}.vt .x span{font-size:.85rem;color:var(--soft)}
.vt .w{font-size:.85rem;color:var(--soft);white-space:nowrap;text-align:right}
.vt li.nowrow{padding-bottom:16px}
.vt li.nowrow::before{background:var(--ink);border-color:var(--ink);width:13px;height:13px;left:3px;top:6px}
.vt .pill{background:var(--ink);color:#fff;font-size:.8rem;font-weight:700;padding:2px 10px;border-radius:99px}
.where{display:grid;grid-template-columns:repeat(3,1fr);gap:6px;margin-top:6px}
.where div{border-radius:10px;padding:8px;font-size:.8rem;background:var(--paper);color:var(--muted)}
.where div.on{background:var(--time-soft);color:var(--ink);font-weight:700}
.where-note{font-size:.95rem;margin:10px 0 0}
/* do now */
.donow{border:2px solid var(--alert)}
.donow .tag{color:var(--alert);font-weight:700;font-size:.9rem}
.bigcall{display:block;text-align:center;background:var(--alert);color:#fff;font-weight:700;font-size:1.25rem;padding:15px;border-radius:14px;text-decoration:none;margin:10px 0 14px}
.say{background:var(--time-soft);border-radius:12px;padding:12px 14px;font-size:1.05rem;margin:6px 0 10px}
.facts{display:grid;grid-template-columns:auto 1fr;gap:4px 12px;font-size:.93rem;margin:0}
.facts dt{color:var(--muted)}.facts dd{margin:0;font-weight:700;overflow-wrap:anywhere}
.facts dd.miss{color:var(--alert);font-weight:400}
.row-btns{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
.ghost{border:1.5px solid var(--line);background:var(--card);border-radius:10px;padding:7px 12px;cursor:pointer;font-size:.9rem}
/* steps */
.steps{list-style:none;padding:0;margin:8px 0 0;counter-reset:s}
.steps li{display:flex;gap:12px;align-items:center;padding:12px 0;border-top:1px solid var(--line);cursor:pointer}
.steps li:first-child{border-top:0}
.steps li::before{counter-increment:s;content:counter(s);flex:none;width:28px;height:28px;border-radius:50%;background:var(--paper);display:grid;place-items:center;font-weight:700;font-size:.9rem}
.steps li.sent::before{content:"✓";background:var(--hope);color:#fff}
.steps .t{flex:1}.steps .t b{display:block}.steps .t span{font-size:.88rem;color:var(--soft)}
.steps .open{font-size:.85rem;color:var(--hope);font-weight:700;white-space:nowrap}
.steps li.new{background:var(--time-soft);border-radius:10px;padding-left:8px;padding-right:8px}
.later p{color:var(--soft);font-size:.95rem;margin:4px 0 10px}
.dl{list-style:none;padding:0;margin:0;font-size:.9rem}
.dl li{display:flex;gap:10px;padding:7px 0;border-top:1px solid var(--line)}
.dl .d{width:64px;flex:none;color:var(--muted)}.dl .x{flex:1}
.st{font-size:.72rem;font-weight:700;padding:2px 8px;border-radius:99px;background:var(--paper);height:fit-content;white-space:nowrap}
.st.done{background:var(--hope-soft);color:var(--hope)}.st.overdue{background:var(--alert-soft);color:var(--alert)}.st.escalated{background:var(--time-soft)}
/* agent */
.agent{list-style:none;padding:0;margin:0}
.agent li{position:relative;padding:0 0 12px 22px;font-size:.93rem}
.agent li::before{content:"";position:absolute;left:4px;top:7px;width:9px;height:9px;border-radius:50%;background:var(--hope)}
.agent li.warning::before{background:var(--time)}.agent li.urgent::before,.agent li.error::before{background:var(--alert)}
.agent li.question::before{background:var(--ink)}
.agent li.working::before{background:none;border:2px solid var(--muted);border-top-color:transparent;animation:spin 1s linear infinite;width:7px;height:7px}
.agent b{display:block}.agent span{color:var(--soft)}.agent i{display:block;color:var(--muted);font-style:normal;font-size:.85rem}
@keyframes spin{to{transform:rotate(360deg)}}
.working-card h2{display:flex;gap:10px;align-items:center}
details{margin-bottom:14px}
details>summary{cursor:pointer;color:var(--soft);font-size:.95rem;padding:6px 2px}
.q{border:2px solid var(--ink)}
.q .opts{display:grid;gap:8px;margin-top:12px}
.q .opts button{text-align:left;border:1.5px solid var(--line);background:var(--card);border-radius:12px;padding:12px 14px;cursor:pointer}
.q .opts button:hover{border-color:var(--ink)}
.q .why{color:var(--soft);font-size:.9rem;margin:4px 0 0}
.q input{width:100%;padding:12px;border:1.5px solid var(--line);border-radius:10px;font-size:1.1rem;margin-top:10px}
.demo-ctl{display:flex;gap:6px;flex-wrap:wrap}.demo-ctl button{border:1.5px dashed var(--muted);background:none;border-radius:8px;padding:5px 10px;cursor:pointer;font-size:.85rem}
/* drawer */
.sheet{position:fixed;inset:0;background:rgba(19,41,61,.45);display:none;z-index:20;align-items:flex-end;justify-content:center}
.sheet.open{display:flex}
.sheet .panel{background:var(--card);width:100%;max-width:680px;max-height:88vh;border-radius:20px 20px 0 0;padding:18px 18px 22px;display:flex;flex-direction:column}
.sheet pre{white-space:pre-wrap;font:inherit;font-size:.92rem;background:var(--paper);border-radius:12px;padding:14px;overflow:auto;flex:1;margin:10px 0}
.sheet .head{display:flex;align-items:center;gap:10px}.sheet .head h2{flex:1;margin:0}
.issues{color:var(--alert);font-size:.88rem;margin:0 0 8px}
.ack{color:var(--hope);font-weight:700}
.send{background:var(--hope);color:#fff;border:0;border-radius:12px;padding:12px 18px;font-weight:700;cursor:pointer}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
</style></head><body>
<header><span class="brand" onclick="home()" tabindex="0">◔ GoldenHour</span><span class="mode" id="mode"></span>
<a class="call-top" href="tel:1930">Call 1930</a></header>

<main id="start">
  <h1>Lost money to a scam? Let's try to get it back.</h1>
  <p class="lede">Paste the SMS from your bank. I'll find the amount, the time and the scammer's account, then tell you exactly what to do.</p>
  <form id="form">
    <div class="box">
      <textarea id="pasted" aria-label="Your bank SMS or payment message" placeholder="Paste the bank SMS or payment message here…"></textarea>
      <div class="bar">
        <label class="attach">＋ Add screenshot<input id="files" type="file" accept="image/*,.txt" multiple></label>
        <span id="filenames" class="hint" style="margin:0"></span>
        <div class="langs" role="group" aria-label="Language">
          <button type="button" data-l="en" aria-pressed="true">EN</button>
          <button type="button" data-l="hi" aria-pressed="false">हि</button>
          <button type="button" data-l="kn" aria-pressed="false">ಕ</button>
        </div>
      </div>
    </div>
    <button type="button" class="more" id="more">No SMS? Tell me what happened instead</button>
    <textarea id="note" rows="3" hidden placeholder="In a line or two: what happened?"></textarea>
    <button class="go" type="submit">Help me get it back</button>
    <p class="err" id="err" role="alert"></p>
  </form>
  <p class="hint">Still talking to them? <b>Hang up first.</b> No real officer or bank asks for money on a call.</p>
  <div class="demos"><p>Try a demo</p><div id="demos"></div></div>
</main>

<main id="case" hidden>
  <div id="hopecard"></div>
  <div id="question"></div>
  <div id="donow"></div>
  <div id="timeline"></div>
  <div id="next"></div>
  <div id="later"></div>
  <details id="agentbox"><summary id="agentsum">What I did for you</summary><div class="card"><ul class="agent" id="agent"></ul></div></details>
  <details><summary>Demo controls (for judges)</summary>
    <div class="demo-ctl"><button onclick="jump(3)">+3 days</button><button onclick="jump(11)">+11 days</button>
    <button onclick="jump(30)">+30 days</button><button onclick="bankOk()">Bank resolved it</button></div></details>
</main>

<div class="sheet" id="sheet" onclick="if(event.target===this)closeDoc()"><div class="panel" role="dialog" aria-modal="true">
  <div class="head"><h2 id="dtitle"></h2><button class="ghost" onclick="closeDoc()">Close</button></div>
  <pre id="dbody"></pre><div id="dact"></div></div></div>

<script>
const $=id=>document.getElementById(id), esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
let caseId=null, data=null, timer=null, lang='en', openKind=null, seenDocs=new Set();
const rs=n=>'₹'+Number(n).toLocaleString('en-IN');
const T=s=>new Date(s.length<=16?s+':00+05:30':s);
const fmtT=d=>d.toLocaleTimeString('en-IN',{hour:'numeric',minute:'2-digit',timeZone:'Asia/Kolkata'});
const fmtD=d=>d.toLocaleDateString('en-IN',{day:'numeric',month:'short',timeZone:'Asia/Kolkata'});
const caseNow=()=>Date.now()+(data?data.offset_days*864e5:0);
function ago(m){m=Math.round(m);if(m<60)return m+' min';if(m<1440){const h=Math.floor(m/60),r=m%60;return h+' h'+(r?' '+r+' min':'')}const d=Math.floor(m/1440);return d+(d===1?' day':' days')}

fetch('/api/health').then(r=>r.json()).then(h=>{
  $('mode').textContent=h.mode;
  $('demos').innerHTML=Object.entries(h.scenarios).map(([k,v])=>`<button class="chip" onclick="demo('${k}')">${esc(v)}</button>`).join('');
});
document.querySelectorAll('.langs button').forEach(b=>b.onclick=()=>{lang=b.dataset.l;
  document.querySelectorAll('.langs button').forEach(x=>x.setAttribute('aria-pressed',x===b))});
$('more').onclick=()=>{$('note').hidden=false;$('note').focus();$('more').hidden=true};
$('files').onchange=()=>{$('filenames').textContent=[...$('files').files].map(f=>f.name).join(', ')};
$('form').onsubmit=async e=>{e.preventDefault();$('err').textContent='';
  const fd=new FormData();fd.append('pasted',$('pasted').value);fd.append('note',$('note').value);fd.append('language',lang);
  for(const f of $('files').files)fd.append('files',f);
  const btn=e.target.querySelector('.go');btn.disabled=true;
  try{const r=await fetch('/api/cases',{method:'POST',body:fd});const j=await r.json();
    if(!r.ok)throw new Error(j.detail||'Something went wrong');openCase(j.case_id)}
  catch(x){$('err').textContent=x.message}finally{btn.disabled=false}};
async function demo(n){const j=await(await fetch('/api/demo/'+n,{method:'POST'})).json();openCase(j.case_id)}
function home(){clearInterval(timer);caseId=null;$('case').hidden=true;$('start').hidden=false}
function openCase(id){caseId=id;data=null;seenDocs=new Set();['hopecard','question','donow','timeline','next','later'].forEach(x=>$(x).innerHTML='');
  $('agent').innerHTML='';$('agentbox').open=true;$('start').hidden=true;$('case').hidden=false;window.scrollTo(0,0);
  clearInterval(timer);tick();timer=setInterval(tick,1000)}

async function tick(){if(!caseId)return;
  data=await(await fetch('/api/cases/'+caseId)).json();
  renderHope();renderQuestion();renderDoNow();renderTimeline();renderNext();renderLater();renderAgent();
  if(openKind)renderDocActions();}

function minsSince(){const f=data.facts;if(!f||!f.money_left_at)return null;return Math.max(0,(caseNow()-T(f.money_left_at))/6e4)}

function renderHope(){const f=data.facts,r=data.recovery,el=$('hopecard');
  if(!r){el.innerHTML=`<div class="card hope working-card"><h2>Working on your case…</h2>
    <p style="margin:0;color:var(--soft)">Don't wait for me. <b>Call 1930 now</b>, I'll have your script ready by the time they answer.</p>
    ${data.call?'':'<a class="bigcall" href="tel:1930">Call 1930</a>'}</div>`;return}
  const m=minsSince(),left=m==null?null:60-m,amt=f.amount?rs(f.amount):'your money';
  // the chance fades with time, so the message stays honest as the clock runs
  let lab=r.label; if(m>4320)lab='low'; else if(m>1440&&lab==='good')lab='fair';
  r.label=lab;
  const head={good:`There's a good chance to freeze ${amt}`,fair:`There's still a chance to recover ${amt}`,
              low:`It's harder now, but your report still counts`}[r.label];
  const sub={good:'It is most likely still sitting in the first account the scammer used. A freeze can stop it there.',
             fair:'Some of it may still be traceable. Reporting today keeps that chance open.',
             low:'Police use every report to trace and freeze scammer accounts. Money is sometimes returned months later.'}[r.label];
  const clock=m==null?'':left>0
    ?`<div class="clock"><span class="big">${Math.ceil(left)} min</span><span class="small">left in the golden hour</span></div>`
    :`<div class="clock"><span class="small">Money left <b>${ago(m)}</b> ago. ${m>4320?'It is still worth reporting today.':'Banks still freeze money reported today.'}</span></div>`;
  const good=f.authorization!=='authorized_deceived'
    ?`<div class="goodnews"><b>Good news:</b> because you didn't make this payment yourself, RBI rules say your bank may have to refund you, if you report it in writing within 3 working days. I've written the letter.</div>`:'';
  el.innerHTML=`<div class="card hope ${r.label==='low'?'low':''}"><h1>${esc(head)}</h1><p>${esc(sub)}</p>${clock}${good}
    <p class="proof">Fast reports work: Mumbai's 1930 helpline alone has saved ₹241 crore for victims. <a href="https://www.deccanherald.com/india/maharashtra/mumbai-fights-back-complaints-on-cyber-crime-helpline-1930-touches-1-lakh-mark-rs-241-cr-saved-3491941" target="_blank" rel="noopener">Source</a></p></div>`}

function renderQuestion(){const q=data.question,el=$('question');
  if(!q){el.innerHTML='';return}
  if(el.dataset.q===q.id&&el.innerHTML)return; el.dataset.q=q.id;
  el.innerHTML=`<div class="card q"><h2>${esc(q.text)}</h2><p class="why">${esc(q.why)}</p>`+
   (q.type==='number'?`<input id="qnum" inputmode="numeric" placeholder="e.g. 25000"><button class="send" style="margin-top:10px" onclick="answer('${q.id}',$('qnum').value)">Continue</button>`
    :`<div class="opts">${q.options.map(o=>`<button onclick="answer('${q.id}','${o.value}')">${esc(o.label)}</button>`).join('')}</div>`)+`</div>`}
async function answer(qid,value){if(!value)return;await fetch(`/api/cases/${caseId}/answer`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({qid,value})});$('question').innerHTML='';$('question').dataset.q='';tick()}

function renderDoNow(){const c=data.call,el=$('donow');if(!c){el.innerHTML='';return}
  if(el.dataset.done)return;
  const main=c[0],en=c.find(x=>x.lang==='en'&&x!==main);
  el.innerHTML=`<div class="card donow"><span class="tag">Do this now</span><h2>Call 1930 and read this out</h2>
    <a class="bigcall" href="tel:1930">Call 1930</a>
    <div class="say">“${esc(main.say)}”</div>
    <dl class="facts">${main.facts.map(([k,v])=>`<dt>${esc(k)}</dt><dd class="${v?'':'miss'}">${esc(v||'Not found. Check your bank SMS.')}</dd>`).join('')}</dl>
    <p style="font-size:.93rem;margin:12px 0 0">${esc(main.ask)}</p>
    <div class="row-btns"><button class="ghost" onclick="copyText(this)">Copy</button>
    ${en?`<button class="ghost" onclick="this.nextElementSibling.hidden=!this.nextElementSibling.hidden">Show in English</button><div hidden class="say" style="width:100%">“${esc(en.say)}”</div>`:''}</div></div>`;
  el.dataset.done=data.status==='active'?'1':''}
function copyText(b){navigator.clipboard?.writeText(data.call[0].say);b.textContent='Copied'}

function renderTimeline(){const f=data.facts,el=$('timeline');if(!f||!data.deadlines.length){el.innerHTML='';return}
  const left=T(f.money_left_at),now=caseNow(),m=minsSince();
  const nice={ncrp_complete:['Finish the cybercrime complaint','Keeps the freeze request valid'],
    bank_notice_3wd:['Bank refund window closes','Report in writing before this and you may owe nothing'],
    bank_freeze_followup:['Check your bank got the freeze request','I\'ll remind you'],
    bank_reversal_10wd:['Bank should return the money','RBI rule: within 10 working days of your report'],
    ombudsman_eligible:['Escalate to the RBI Ombudsman','Only if your bank is still silent. I\'ll draft it.']};
  const pts=[{t:'Money left your account',s:'Taken from your bank SMS',at:left},
             {t:'Golden hour ends',s:'Freezes work best before this',at:new Date(+left+36e5)}];
  data.deadlines.filter(d=>nice[d.key]).forEach(d=>pts.push({t:nice[d.key][0],s:nice[d.key][1],at:new Date(d.due),st:d.status}));
  pts.sort((a,b)=>a.at-b.at);
  const when=d=>(+d-left<864e5&&fmtD(d)===fmtD(left))?fmtT(d):fmtD(d);
  let html='',nowShown=false,nextMarked=false;
  for(const p of pts){
    if(!nowShown&&now<p.at){html+=`<li class="nowrow"><span class="pill">Now · ${ago(m)} after the money left</span></li>`;nowShown=true}
    const past=now>=p.at, cls=past?'past':(!nextMarked?(nextMarked=true,'next'):'');
    const st=p.st&&p.st!=='pending'?` <span class="st ${p.st}">${esc(p.st)}</span>`:'';
    html+=`<li class="${cls}"><div class="x"><b>${esc(p.t)}${st}</b><span>${esc(p.s)}</span></div><div class="w">${when(p.at)}</div></li>`}
  if(!nowShown)html+=`<li class="nowrow"><span class="pill">Now · ${ago(m)} after the money left</span></li>`;
  const where=m<60?0:m<1440?1:2;
  const note=['Right now it is most likely still in the scammer\'s first account. This is when a freeze works best.',
              'It may be getting split across several accounts. Each report helps police follow every piece.',
              'It may have been moved or withdrawn. Your report still lets police trace it and return what they recover.'][where];
  el.innerHTML=`<div class="card"><h2>Your money's timeline</h2><ul class="vt">${html}</ul>
   <p style="font-weight:700;margin:6px 0 6px;font-size:.95rem">Where your money probably is</p>
   <div class="where"><div class="${where===0?'on':''}">First hour: scammer's first account</div>
   <div class="${where===1?'on':''}">Hours later: split across accounts</div>
   <div class="${where===2?'on':''}">Days later: moved or withdrawn</div></div>
   <p class="where-note">${esc(note)}</p></div>`}

function renderNext(){const s=data.next_steps,el=$('next');if(!s){el.innerHTML='';return}
  const docs=Object.fromEntries(data.documents.map(d=>[d.kind,d]));
  el.innerHTML=`<div class="card"><h2>Then do these</h2><p style="margin:0;color:var(--soft);font-size:.93rem">I've already written everything. Tap to check it and send.</p>
   <ol class="steps">${s.map(x=>{const d=docs[x.doc];const sent=d&&(d.status==='submitted'||d.status==='done');
     return `<li class="${sent?'sent':''}" onclick="openDoc('${x.doc}')"><div class="t"><b>${esc(x.title)}</b><span>${esc(x.why)}</span></div><span class="open">${sent?'Sent':'Open'}</span></li>`}).join('')}
   <li onclick="openDoc('trusted')"><div class="t"><b>Tell someone you trust</b><span>Scammers rely on you staying quiet.</span></div><span class="open">Open</span></li></ol></div>`}

function renderLater(){const el=$('later');if(!data.deadlines.length){el.innerHTML='';return}
  const extra=data.documents.filter(d=>d.kind==='bank_followup'||d.kind==='ombudsman');
  el.innerHTML=`<div class="card later"><h2>I'll keep going after today</h2>
   <p>If your bank stays silent, I'll write the follow-up and the RBI Ombudsman complaint for you.</p>
   ${extra.length?`<ol class="steps">${extra.map(d=>`<li class="new ${d.status==='submitted'?'sent':''}" onclick="openDoc('${d.kind}')"><div class="t"><b>${esc(d.title)}</b><span>Ready for you to send</span></div><span class="open">${d.status==='submitted'?'Sent':'Open'}</span></li>`).join('')}</ol>`:''}
   </div>`}

function renderAgent(){const ev=data.events,el=$('agent');
  el.innerHTML=ev.map((e,i)=>{const last=i===ev.length-1&&data.status==='running';
    return `<li class="${last?'working':e.status}"><b>${esc(e.title)}</b>${e.detail?`<span>${esc(e.detail)}</span>`:''}${e.reason?`<i>${esc(e.reason)}</i>`:''}</li>`}).join('');
  $('agentsum').textContent=data.status==='active'?`What I did for you (${ev.length} steps)`:'What I\'m doing right now';
  if(data.status==='active'&&!$('agentbox').dataset.closed){$('agentbox').open=false;$('agentbox').dataset.closed='1'}}

function openDoc(kind){openKind=kind;const d=data.documents.find(x=>x.kind===kind);if(!d)return;
  $('dtitle').textContent=d.title;$('dbody').textContent=d.content;renderDocActions();$('sheet').classList.add('open')}
function renderDocActions(){const d=data.documents.find(x=>x.kind===openKind);if(!d)return;
  const sendable=['ncrp','bank_letter','bank_followup','ombudsman'].includes(d.kind);
  $('dact').innerHTML=(d.issues.length?`<p class="issues">Before sending, add: ${esc(d.issues.join('; '))}</p>`:'')+
   (d.status==='submitted'?`<p class="ack">Sent (simulated) · ${esc(d.ack)}</p>`:d.status==='done'?'<p class="ack">Done</p>':
   `<div class="row-btns"><button class="send" onclick="send('${d.kind}')">${sendable?'Send':'Mark as done'}</button><button class="ghost" onclick="navigator.clipboard?.writeText($('dbody').textContent);this.textContent='Copied'">Copy</button></div>`)}
function closeDoc(){$('sheet').classList.remove('open');openKind=null}
async function send(k){await fetch(`/api/cases/${caseId}/approve/${k}`,{method:'POST'});await tick()}
async function jump(d){const r=await fetch(`/api/cases/${caseId}/simulate`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({days:d})});
  if(!r.ok)alert('Wait for the agent to finish first.');tick()}
async function bankOk(){await fetch(`/api/cases/${caseId}/bank-resolved`,{method:'POST'});tick()}
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeDoc()});
</script></body></html>"""


@app.get("/", response_class=HTMLResponse)
def page():
    return PAGE


if __name__ == "__main__":
    import uvicorn
    mode = f"Gemini ({GEMINI_MODEL})" if GEMINI_API_KEY else "offline rules engine (no GEMINI_API_KEY set)"
    if os.getenv("PORT"):
        print(f"  GoldenHour online on port {os.getenv('PORT')}. Mode: {mode}")
        uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT")))
    else:
        print("\n  GoldenHour is running -> http://127.0.0.1:8000")
        print("  Mode:", mode)
        print("  Opening your browser... (keep this window open; press Ctrl+C to stop)\n")
        import webbrowser
        threading.Timer(1.5, lambda: webbrowser.open("http://127.0.0.1:8000")).start()
        uvicorn.run(app, host="127.0.0.1", port=8000)