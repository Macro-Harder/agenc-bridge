#!/usr/bin/env bash
# AgenC Bridge web relay watchdog — restart relay-web.py if it is
# not listening. Run it every few minutes from a cron so the web
# relay comes back after a machine restart or VM replacement.
# Prints nothing when all is well.
# Mirrors relay-watchdog.sh (the TCP relay); the web relay needs
# the venv python because it imports the websockets library.
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${AGENC_BRIDGE_WEB_RELAY_PORT:-8766}"
if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
  exit 0
fi
cd "$DIR"
nohup .venv/bin/python relay-web.py >> relay-web.log 2>&1 &
echo "web relay was down on port $PORT, restarted it"
