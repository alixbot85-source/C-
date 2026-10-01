#!/usr/bin/env bash
# ==============================================================================
# Runner & Auto-Restart Watchdog for IVA Telegram Bot (Termux / Linux)
# ==============================================================================
set -u

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$BASE_DIR"

mkdir -p "$BASE_DIR/logs"
mkdir -p "$BASE_DIR/sessions"

# Optional: keep CPU awake in Termux
if command -v termux-wake-lock &>/dev/null; then
    termux-wake-lock 2>/dev/null || true
fi

if [ -z "${TELEGRAM_BOT_TOKEN:-}" ]; then
    echo "=================================================="
    echo "❌ ERROR: TELEGRAM_BOT_TOKEN is not configured!"
    echo "=================================================="
    echo "Please export your Telegram Bot Token before running:"
    echo "  export TELEGRAM_BOT_TOKEN='your_bot_token_here'"
    echo ""
    echo "Optionally set Admin ID for Admin Panel access:"
    echo "  export TELEGRAM_ADMIN_ID='your_telegram_numeric_id'"
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
trap 'echo -e "\n🛑 Stopping IVA Telegram Bot..."; [ -n "$(command -v termux-wake-unlock 2>/dev/null)" ] && termux-wake-unlock 2>/dev/null; exit 0' SIGINT SIGTERM

while true; do
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting bot process..."
    
    python3 "$BASE_DIR/iva_telegram_bot.py" 2>&1 | tee -a "$BASE_DIR/logs/iva_bot.log"
    PYTHON_EXIT="${PIPESTATUS[0]}"
    
    if [ "$PYTHON_EXIT" -eq 0 ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Bot process finished cleanly."
        sleep 2
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Bot process exited with code $PYTHON_EXIT. Auto-restarting in 5 seconds..."
        sleep 5
    fi
done
