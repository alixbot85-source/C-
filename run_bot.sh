#!/usr/bin/env bash
# ==============================================================================
# Runner & Auto-Restart Watchdog for IVA Telegram Bot (Termux / Linux)
# ==============================================================================

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$BASE_DIR"

mkdir -p "$BASE_DIR/logs"
mkdir -p "$BASE_DIR/sessions"

if [ -z "$TELEGRAM_BOT_TOKEN" ]; then
    echo "=================================================="
    echo "❌ ERROR: TELEGRAM_BOT_TOKEN is not configured!"
    echo "=================================================="
    echo "Please export your Telegram Bot Token before running:"
    echo "  export TELEGRAM_BOT_TOKEN='123456789:ABCdefGHIjklMNOpqrsTUVwxyz'"
    echo ""
    echo "Optionally set Admin ID for Admin Panel access:"
    echo "  export TELEGRAM_ADMIN_ID='123456789'"
    echo "=================================================="
    exit 1
fi

echo "=================================================="
echo "🤖 Starting IVA Telegram Bot..."
echo "📂 Working directory: $BASE_DIR"
echo "📝 Log file: $BASE_DIR/logs/iva_bot.log"
echo "Press Ctrl+C to stop the bot."
echo "=================================================="

# Trap SIGINT and SIGTERM to stop watchdog cleanly
trap 'echo -e "\n🛑 Stopping IVA Telegram Bot..."; exit 0' SIGINT SIGTERM

while true; do
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting process..."
    python3 "$BASE_DIR/iva_telegram_bot.py" 2>&1 | tee -a "$BASE_DIR/logs/iva_bot.log"
    EXIT_CODE=$?
    
    if [ $EXIT_CODE -eq 0 ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Bot stopped normally."
        break
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Bot exited with code $EXIT_CODE. Restarting in 5 seconds..."
        sleep 5
    fi
done
