#!/usr/bin/env bash
# ==============================================================================
# Setup & Bootstrap Script for IVA Telegram Bot on Android Termux / Linux
# ==============================================================================
set -e

echo "=================================================="
echo "🚀 IVA Telegram Bot Setup & Bootstrap (Termux/Linux)"
echo "=================================================="

# 1. Determine base path
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$BASE_DIR"

# 2. Check for Python 3
if ! command -v python3 &>/dev/null; then
    echo "❌ Python 3 is not installed."
    echo "   In Termux, please run: pkg update -y && pkg install -y python openssl git"
    exit 1
fi

PYTHON_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "✅ Python version detected: $PYTHON_VER"

# 3. Create required directories
echo "📁 Creating required directories..."
mkdir -p "$BASE_DIR/logs"
mkdir -p "$BASE_DIR/sessions"

# 4. Check OpenSSL / libcrypto
echo "🔐 Checking OpenSSL cryptographic engine..."
if python3 -c "import ctypes.util; assert ctypes.util.find_library('crypto') is not None" &>/dev/null; then
    echo "✅ OpenSSL libcrypto found and verified."
else
    echo "⚠️ Warning: OpenSSL libcrypto not found. In Termux, run: pkg install -y openssl"
fi

# 5. Verify Python script syntax
echo "🔍 Validating iva_telegram_bot.py syntax..."
python3 -m py_compile "$BASE_DIR/iva_telegram_bot.py"
echo "✅ Syntax validation PASSED."

# 6. Make run_bot.sh executable
if [ -f "$BASE_DIR/run_bot.sh" ]; then
    chmod +x "$BASE_DIR/run_bot.sh"
    echo "✅ run_bot.sh permissions updated."
fi

# 7. Check Configuration Environment Variables
echo ""
echo "=================================================="
echo "📋 Configuration Checklist:"
echo "=================================================="
if [ -z "$TELEGRAM_BOT_TOKEN" ]; then
    echo "⚠️  TELEGRAM_BOT_TOKEN is not set."
    echo "   Please set your bot token before running:"
    echo "   export TELEGRAM_BOT_TOKEN='your_bot_token_from_botfather'"
else
    echo "✅ TELEGRAM_BOT_TOKEN is set."
fi

if [ -z "$TELEGRAM_ADMIN_ID" ]; then
    echo "ℹ️  TELEGRAM_ADMIN_ID is optional (unset)."
    echo "   To enable the Admin Panel, set: export TELEGRAM_ADMIN_ID='your_telegram_numeric_id'"
else
    echo "✅ TELEGRAM_ADMIN_ID is set ($TELEGRAM_ADMIN_ID)."
fi

echo ""
echo "🎉 Setup completed successfully!"
echo "To start the bot, run:"
echo "  ./run_bot.sh"
echo "=================================================="
