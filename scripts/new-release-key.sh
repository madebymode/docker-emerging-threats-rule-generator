#!/usr/bin/env bash
# Creates an Ed25519 release signing key, uploads the private half to the
# `release-signing` GitHub environment, and adds the public half to
# release-signing.pub (newest first). The private key never touches the repo.
#
# Existing installations need a bridge release before key rotation; see
# releasing.md. This script changes the signer immediately.
#
# Usage: scripts/new-release-key.sh BACKUP_PATH
#   BACKUP_PATH  where to write an offline copy of the private key (e.g. an
#                encrypted volume). Store it in your password manager, then
#                delete the file. Losing it only means rotating to a new key.
set -euo pipefail

repo=madebymode/docker-emerging-threats-rule-generator
backup=${1:?usage: $0 BACKUP_PATH}
[[ ! -e $backup ]] || { echo "refusing to overwrite $backup" >&2; exit 1; }
cd "$(git rev-parse --show-toplevel)"

umask 077
openssl genpkey -algorithm ed25519 -out "$backup"
pub=$(openssl pkey -in "$backup" -pubout)

gh secret set RELEASE_SIGNING_KEY --repo "$repo" --env release-signing < "$backup"

{ printf '%s\n' "$pub"; cat release-signing.pub; } > release-signing.pub.new
mv release-signing.pub.new release-signing.pub
chmod 0644 release-signing.pub

echo "Private key backup: $backup (move it offline, then delete it)"
echo "Commit release-signing.pub. Binaries released after that commit trust the new key."
