#!/usr/bin/env bash
# GoldenHour: start on macOS / Linux
cd "$(dirname "$0")"
[ -d .venv ] || python3 -m venv .venv
.venv/bin/python -m pip install -q -r requirements.txt
.venv/bin/python goldenhour.py
