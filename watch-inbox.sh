#!/bin/sh
# AgenC Bridge — check the assistant's inbox and unanswered prompts on a bus.
# Usage: watch-inbox.sh [bus-dir]
# Prints "(inbox empty)" / "(no unanswered prompts)" when there is nothing new.
# Messages are marked read when shown; prompts are NOT answered here —
# an assistant run answers them with `bridge.py reply`.
BUS="${1:-$HOME/workspace/agenc-bridge/bus}"
DIR="$(cd "$(dirname "$0")" && pwd)"
echo "== messages =="
python3 "$DIR/bridge.py" inbox --bus "$BUS" --node agenc-cloud --mark-read
echo "== prompts to the assistant =="
python3 "$DIR/bridge.py" prompts --bus "$BUS" --node agenc-cloud
