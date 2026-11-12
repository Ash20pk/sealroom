#!/bin/sh
# Unpack the demo keys from the SEALROOM_KEYS secret (base64 tar.gz), then start the server.
# The tarball holds near-credentials/testnet/*.json (signing keys the server uses: a
# record_check-only key for the operator and the agent's seal_session-only key) and
# identity/*.json (the demo firms and lawyers, served to the browser by /api/demo/identity).
set -eu
mkdir -p "$SEALROOM_STATE" /root/.near-credentials
if [ -n "${SEALROOM_KEYS:-}" ]; then
  tmp="$(mktemp -d)"
  echo "$SEALROOM_KEYS" | base64 -d | tar -xz -C "$tmp"
  cp -R "$tmp/near-credentials/." /root/.near-credentials/
  mkdir -p "$SEALROOM_STATE/identity" && cp "$tmp"/identity/*.json "$SEALROOM_STATE/identity/"
  rm -rf "$tmp"
  chmod -R go-rwx /root/.near-credentials "$SEALROOM_STATE/identity"
fi
cd /srv/app
exec uv run --frozen --no-dev sealroom-web
