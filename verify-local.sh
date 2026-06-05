#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8770}"
KEY="${KEY:-/etc/tortoise-ai/keys/tortoised_ed25519}"
PRINCIPAL="${PRINCIPAL:-local-test}"
NAMESPACE="${NAMESPACE:-tortoised}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CHALLENGE_JSON="$TMP_DIR/challenge.json"
NONCE_FILE="$TMP_DIR/nonce.txt"
SIG_FILE="$TMP_DIR/nonce.txt.sig"
VERIFY_JSON="$TMP_DIR/verify.json"

echo "==> Requesting challenge from $BASE_URL"
curl -fsS -X POST "$BASE_URL/challenge" > "$CHALLENGE_JSON"
cat "$CHALLENGE_JSON" | python3 -m json.tool

CHALLENGE_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["challenge_id"])' "$CHALLENGE_JSON")"
NONCE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["nonce"])' "$CHALLENGE_JSON")"

printf "%s" "$NONCE" > "$NONCE_FILE"

echo
echo "==> Signing nonce with $KEY"

ssh-keygen -Y sign \
  -f "$KEY" \
  -n "$NAMESPACE" \
  -q \
  "$NONCE_FILE" >/dev/null

if [ ! -f "$SIG_FILE" ]; then
    echo "ERROR: Expected signature file not found: $SIG_FILE"
    exit 1
fi

python3 - "$CHALLENGE_ID" "$PRINCIPAL" "$SIG_FILE" > "$VERIFY_JSON" <<'PY'
import json
import sys

challenge_id = sys.argv[1]
principal = sys.argv[2]
sig_path = sys.argv[3]

with open(sig_path, "r", encoding="utf-8") as f:
    signature = f.read()

print(json.dumps({
    "challenge_id": challenge_id,
    "principal": principal,
    "signature": signature,
}))
PY

echo
echo "==> Posting verification"
curl -fsS \
  -X POST "$BASE_URL/verify" \
  -H "Content-Type: application/json" \
  -d @"$VERIFY_JSON" | python3 -m json.tool
