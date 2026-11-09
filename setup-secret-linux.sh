#!/bin/sh
# AgenC Bridge — set up the encrypted secret on a Linux desktop.
# Usage: ./setup-secret-linux.sh
# Asks for the bridge secret and the passphrase (both in BRIDGE-PASSPHRASE.txt),
# writes ~/.config/agenc-bridge/secret.enc, and deletes any plaintext secret.
# Needs: openssl. If you want the worker to run unattended (no typing the
# passphrase each time), answer yes to storing the passphrase in a mode-600
# file; otherwise you will be asked for it whenever the worker starts.
set -eu
CFG="$HOME/.config/agenc-bridge"
mkdir -p "$CFG"
printf "Bridge secret: "
stty -echo; read SECRET; stty echo; echo
printf "Passphrase: "
stty -echo; read PASS; stty echo; echo
printf "%s" "$SECRET" | openssl enc -aes-256-cbc -pbkdf2 -salt -pass "pass:$PASS" -out "$CFG/secret.enc"
chmod 600 "$CFG/secret.enc"
rm -f "$CFG/secret"
printf "Store the passphrase in %s/passphrase so the worker can run unattended? [y/N] " "$CFG"
read STORE
if [ "$STORE" = "y" ] || [ "$STORE" = "Y" ]; then
  printf "%s" "$PASS" > "$CFG/passphrase"
  chmod 600 "$CFG/passphrase"
  echo "Passphrase stored (mode 600)."
fi
echo "Done. Secret is encrypted at $CFG/secret.enc."
