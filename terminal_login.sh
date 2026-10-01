#!/usr/bin/env bash
# ==============================================================================
# Direct Interactive Terminal Login & Manager for IVA / Sadad (Termux / Linux)
# ==============================================================================
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$BASE_DIR"

mkdir -p "$BASE_DIR/logs"
mkdir -p "$BASE_DIR/sessions"

python3 "$BASE_DIR/iva_telegram_bot.py" --cli
