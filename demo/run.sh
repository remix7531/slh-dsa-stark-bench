#!/usr/bin/env bash
#
# End-to-end demo of SLH-DSA STARK batch verification.
# Generates N keypairs, signs N messages, verifies signatures directly,
# generates a STARK proof, then verifies the proof.
#
# Usage: bash demo/run.sh [N]
#   N defaults to 1. Binaries must be built first: cargo build --release
#
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
BIN="$ROOT/target/release"
N="${1:-1}"

# Generate a JSON array of N deterministic messages.
# Uses three word lists with different strides to create varied content.
generate_messages() {
  local n="$1" out="$2"
  local words=("quantum" "hash" "merkle" "stark" "bitcoin" "block" "chain" "proof"
               "verify" "sign" "entropy" "nonce" "cipher" "lattice" "prime" "field"
               "curve" "digest" "oracle" "commit" "reveal" "forge" "trust" "node"
               "miner" "epoch" "shard" "state" "valid" "secure" "post" "future")
  printf '[\n' > "$out"
  for i in $(seq 1 "$n"); do
    local w1="${words[$(( (i * 7) % ${#words[@]} ))]}"
    local w2="${words[$(( (i * 13 + 3) % ${#words[@]} ))]}"
    local w3="${words[$(( (i * 19 + 7) % ${#words[@]} ))]}"
    [ "$i" -gt 1 ] && printf ',\n' >> "$out"
    printf '  "tx %d: %s %s %s"' "$i" "$w1" "$w2" "$w3" >> "$out"
  done
  printf '\n]\n' >> "$out"
}

# Print a step label and the command, then execute it.
run() {
  local label="$1"; shift
  local display
  display=$(echo "$@" | sed "s|$ROOT/target/release/||g; s|$DIR/||g")
  echo ""
  echo "[$label] \$ $display"
  "$@"
}

echo "=== SLH-DSA STARK Batch Verification Demo ==="
echo "Signatures: $N"

if [ ! -f "$BIN/prove" ]; then
  echo "Error: binaries not found. Run 'cargo build --release' first."
  exit 1
fi

# Generate messages and clean previous artifacts
MESSAGES="$DIR/generated.json"
generate_messages "$N" "$MESSAGES"
rm -f "$DIR"/secrets.json "$DIR"/pubkeys.json "$DIR"/signatures.json "$DIR"/proof.bin

# Step 1: Generate N keypairs
run "1/5" "$BIN/keygen" -n "$N" -o "$DIR/secrets.json" -p "$DIR/pubkeys.json" -v

# Step 2: Sign each message with its corresponding key
run "2/5" "$BIN/sign" -k "$DIR/secrets.json" -m "$MESSAGES" -o "$DIR/signatures.json" -v

# Step 3: Verify signatures directly (no proof)
run "3/5" "$BIN/verify" -s "$DIR/signatures.json" -k "$DIR/pubkeys.json" -m "$MESSAGES" -v

# Step 4: Generate a STARK proof that all signatures are valid
run "4/5" "$BIN/prove" -k "$DIR/pubkeys.json" -m "$MESSAGES" -s "$DIR/signatures.json" -o "$DIR/proof.bin" -v

# Step 5: Verify the STARK proof against the expected public inputs
run "5/5" "$BIN/verify" -p "$DIR/proof.bin" -k "$DIR/pubkeys.json" -m "$MESSAGES" -v

echo ""
