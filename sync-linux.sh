#!/bin/sh
# AgenC Bridge — GitHub bus sync loop (Linux).
# Usage: sync-linux.sh <bus-dir> <node> <project-root> [interval-seconds]
# Requires: git, python3, bridge.py beside this script, AGENC_BRIDGE_SECRET set,
# OPENROUTER_API_KEY set.
set -eu
BUS="${1:?bus dir}"; NODE="${2:?node}"; PROJECT="${3:?project root}"; INTERVAL="${4:-60}"
DIR="$(cd "$(dirname "$0")" && pwd)"
while true; do
  (cd "$BUS" && git pull --ff-only --quiet || true)
  python3 "$DIR/bridge.py" poll --bus "$BUS" --node "$NODE" --project-root "$PROJECT" || true
  (cd "$BUS" && git add -A && git commit -qm "bridge: $NODE $(date -u +%FT%TZ)" && git push --quiet || true)
  sleep "$INTERVAL"
done
