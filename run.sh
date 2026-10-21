#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
python3 -m venv .venv 2>/dev/null || true
source .venv/bin/activate
pip install -q -r requirements.txt
cp -n .env.example .env 2>/dev/null || true
echo "→ Starting on http://127.0.0.1:8000  (optional API keys go in .env)"
uvicorn app.main:app --reload --port 8000
