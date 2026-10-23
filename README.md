# GoldenHour

An AI agent for people who just lost money to a scam in India. The victim pastes one bank SMS; the agent works out the amount, the time and the scammer's account, asks only what it can't figure out, tells them exactly what to say on the 1930 helpline, writes their complaint and bank letter, and tracks every deadline after.

Ziro Agentic AI Hackathon 2026, Open Innovation track.

## Run it

**Windows:** double-click `run.bat`, then open http://127.0.0.1:8000.

**In VS Code** (terminal: Ctrl + `), one line at a time:
```
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python goldenhour.py
```
macOS/Linux: `./run.sh`

Stop it with Ctrl + C.

## Gemini (optional)

Copy `.env.example` to a new file named `.env` and paste your key from https://aistudio.google.com/apikey. The top bar then shows **Gemini** instead of **Offline**. With Gemini, the agent can also read uploaded screenshots.

Without a key, everything still works on the built-in rules engine. **No training is needed:** Gemini is already trained and the rest is plain Python.

## Demo for judges

1. Click **"Just a bank SMS"**. The agent reads everything from one message, then stops to ask the one thing it can't know: *how did the money leave your account?* That moment shows it's an agent.
2. Point out the hope card, the minutes left in the golden hour, and the 1930 script.
3. Go back and click **"Money taken without permission"**: a different answer leads to a different plan (the bank may have to refund you).
4. Tap a step to open the drafted complaint, then **Send**.
5. Open **Demo controls**, click **+30 days**: the agent drafts the RBI Ombudsman complaint on its own.

`sample_messages/` has SMS texts you can paste to try it by hand.

## What's simulated

Sending to cybercrime.gov.in and the RBI portal is simulated (no public API). Rules used: RBI circular RBI/2017-18/15 (limited liability, 3 working days, 10-day reversal) and the RBI Integrated Ombudsman Scheme 2021 (30 days). Not legal advice. All demo data is made up.
