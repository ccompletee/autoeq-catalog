#!/usr/bin/env bash
set -euo pipefail

# AutoEQ ECDSA P-256 Keypair Generator
# Generates a NIST P-256 (secp256r1 / prime256v1) key pair for catalog manifest signing.
# Outputs:
#   - private_key.pem: ECDSA private key (keep secret, never commit!)
#   - public_key.pem:  X.509 SubjectPublicKeyInfo in PEM format
#   - public_key.der:  X.509 SubjectPublicKeyInfo in binary DER format (for Android app SPKI)

KEY_DIR="${1:-.}"
mkdir -p "$KEY_DIR"

PRIVATE_KEY="$KEY_DIR/private_key.pem"
PUBLIC_PEM="$KEY_DIR/public_key.pem"
PUBLIC_DER="$KEY_DIR/public_key.der"

if [ -f "$PRIVATE_KEY" ]; then
    echo "Warning: $PRIVATE_KEY already exists. Will not overwrite." >&2
    exit 1
fi

echo "Generating NIST P-256 private key at $PRIVATE_KEY..."
openssl ecparam -name prime256v1 -genkey -noout -out "$PRIVATE_KEY"
chmod 600 "$PRIVATE_KEY"

echo "Extracting public key in PEM format at $PUBLIC_PEM..."
openssl ec -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_PEM"

echo "Extracting public key in SPKI DER format at $PUBLIC_DER..."
openssl ec -in "$PRIVATE_KEY" -pubout -outform DER -out "$PUBLIC_DER"

echo "Done!"
echo "Private key: $PRIVATE_KEY (permissions set to 600)"
echo "Public key PEM: $PUBLIC_PEM"
echo "Public key SPKI DER: $PUBLIC_DER"
