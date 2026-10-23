"""Test cases for GoldenHour. Run:  .venv\\Scripts\\python -m pytest -v test_goldenhour.py
Uses the offline rules engine, so no API key or internet is needed."""
import os
import time

os.environ["GEMINI_API_KEY"] = ""       # test the offline engine
os.environ["STEP_DELAY"] = "0"

from fastapi.testclient import TestClient  # noqa: E402

import goldenhour as gh  # noqa: E402

gh.GEMINI_API_KEY = ""
client = TestClient(gh.app)


def wait(case_id, states=("active", "waiting", "error")):
    for _ in range(300):
        r = client.get(f"/api/cases/{case_id}").json()
        if r["status"] in states:
            return r
        time.sleep(0.05)
    raise AssertionError("agent did not finish")


def answer(case_id, qid, value):
    client.post(f"/api/cases/{case_id}/answer", json={"qid": qid, "value": value})


# 1. Reading the bank SMS
def test_reads_amount_time_utr_scammer_and_bank():
    sms = ("Rs 24,999.00 debited from A/c XX7781 on 19-10-2026 07:15 to VPA fastpay.refund88@okaxis. "
           "UPI Ref No 512398765432. -SBI")
    ev = gh.extract_evidence([{"name": "sms", "text": sms}])
    assert ev["amount"] == 24999
    assert ev["money_left_at"] == "2026-10-19T07:15"
    assert ev["transactions"][0]["utr"] == "512398765432"
    assert ev["scammer_upi_ids"] == ["fastpay.refund88@okaxis"]
    assert ev["victim_bank"] == "State Bank of India"
    assert ev["victim_account_last4"] == "7781"


def test_email_address_is_not_mistaken_for_upi_id():
    ev = gh.extract_evidence([{"name": "t", "text": "Write to ravi@gmail.com"}])
    assert ev["scammer_upi_ids"] == []


# 2. The key decision: who authorised the payment
def test_decides_unauthorized():
    assert gh.classify("I didn't make this payment, never shared OTP")["authorization"] == "unauthorized"


def test_decides_paid_under_deception():
    assert gh.classify("CBI officer said digital arrest, I transferred money")["authorization"] == "authorized_deceived"


def test_decides_credential_compromise():
    assert gh.classify("customer care made me install AnyDesk and I shared the OTP")["authorization"] == "credential_compromise"


def test_is_unsure_when_text_does_not_say():
    assert gh.classify("Rs 40,000 debited. UPI Ref No 908812345671")["auth_sure"] is False


# 3. Deadlines in bank working days
def test_working_days_skip_sunday_and_second_saturday():
    from datetime import datetime
    assert gh.add_working_days(datetime(2026, 10, 9, 10), 1).day == 12   # 10 Oct = 2nd Saturday, 11 = Sunday
    assert gh.add_working_days(datetime(2026, 10, 2, 10), 1).day == 3    # 3 Oct = 1st Saturday, a working day


# 4. Verifier catches mistakes in drafts
def test_verifier_flags_missing_and_wrong_details():
    facts = {"amount": 5000, "transactions": [{"utr": "123456789012"}], "victim_bank": "HDFC Bank"}
    issues = gh.verify("bank_letter", "Amount Rs 4,000 [MISSING: your bank]", facts)
    assert any("Missing" in i for i in issues)
    assert any("5,000" in i for i in issues)
    assert any("UTR" in i for i in issues)


# 5. End-to-end agent runs
def test_digital_arrest_case_end_to_end():
    r = wait(client.post("/api/demo/digital_arrest").json()["case_id"])
    assert r["status"] == "active"
    assert r["facts"]["authorization"] == "authorized_deceived"
    assert r["facts"]["amount"] == 85000
    assert r["facts"]["intel"][0]["linked_cases"] == 3            # known scammer flagged
    assert r["call"][0]["lang"] == "kn"                           # Kannada script
    assert {d["kind"] for d in r["documents"]} >= {"call_sheet", "ncrp", "bank_letter", "security", "trusted"}
    assert all(not d["issues"] for d in r["documents"])           # every draft passed the verifier


def test_unauthorized_case_gets_bank_refund_strategy():
    r = wait(client.post("/api/demo/unauthorized").json()["case_id"])
    assert r["facts"]["authorization"] == "unauthorized"
    assert any(d["key"] == "bank_notice_3wd" for d in r["deadlines"])
    letter = next(d for d in r["documents"] if d["kind"] == "bank_letter")
    assert "RBI/2017-18/15" in letter["content"]


def test_agent_asks_only_what_it_cannot_work_out():
    case_id = client.post("/api/demo/sms_only").json()["case_id"]
    r = wait(case_id)
    assert r["status"] == "waiting" and r["question"]["id"] == "how"   # SMS had amount + time, so only 1 question
    answer(case_id, "how", "authorized_deceived")
    r = wait(case_id, ("active", "error"))
    assert r["status"] == "active" and r["facts"]["authorization"] == "authorized_deceived"


def test_agent_asks_for_time_and_amount_when_missing():
    case_id = client.post("/api/cases", data={"note": "someone called me and took my money"}).json()["case_id"]
    asked = []
    for value in ["30", "15000", "credential_compromise"]:
        r = wait(case_id)
        if r["question"]:
            asked.append(r["question"]["id"])
            answer(case_id, r["question"]["id"], value)
    r = wait(case_id, ("active", "error"))
    assert asked == ["when", "amount", "how"]
    assert r["facts"]["amount"] == 15000


def test_escalates_automatically_when_bank_is_silent():
    case_id = wait(client.post("/api/demo/unauthorized").json()["case_id"])["id"]
    r = client.post(f"/api/cases/{case_id}/simulate", json={"days": 31}).json()
    kinds = {d["kind"] for d in r["documents"]}
    assert {"bank_followup", "ombudsman"} <= kinds


def test_nothing_is_sent_without_approval():
    r = wait(client.post("/api/demo/unauthorized").json()["case_id"])
    assert all(d["status"] != "submitted" for d in r["documents"])
    r = client.post(f"/api/cases/{r['id']}/approve/ncrp").json()
    sent = next(d for d in r["documents"] if d["kind"] == "ncrp")
    assert sent["status"] == "submitted" and sent["ack"].startswith("SIM-NCRP-")


def test_empty_submission_is_rejected():
    assert client.post("/api/cases", data={}).status_code == 400
