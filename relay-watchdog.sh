#!/usr/bin/env bash
# AgenC Bridge relay watchdog — restart relay.py if it is not listening.
# Run it every few minutes from a cron so the relay comes back after a
# machine restart or VM replacement. Prints nothing when all is well.
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${AGENC_BRIDGE_RELAY_PORT:-8765}"
if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
  exit 0
fi
cd "$DIR"
nohup python3 relay.py >> relay.log 2>&1 &
echo "relay was down on port $PORT, restarted it"
