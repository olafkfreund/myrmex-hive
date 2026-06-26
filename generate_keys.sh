#!/usr/bin/env bash
set -euo pipefail

echo "Generating Agent SSH keypair (Ed25519)..."
ssh-keygen -t ed25519 -f id_ed25519 -N "" -q

echo "Adding Agent public key to authorized_keys..."
cat id_ed25519.pub > authorized_keys

echo "Keys generated successfully."
echo "Private key: id_ed25519"
echo "Public key added to: authorized_keys"
chmod 600 id_ed25519
