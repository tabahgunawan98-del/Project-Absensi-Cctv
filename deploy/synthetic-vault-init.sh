#!/usr/bin/env bash
# Synthetic Vault bootstrap for local verification only. On the office server the
# owner performs these steps interactively (see the runbook); unseal material is
# never written to a repo or a shared path. Here it stays in the throwaway root.
set -euo pipefail

ROOT="${1:-/tmp/absensi-stack}"
COMPOSE="docker compose -f deploy/compose.yaml"
V="$COMPOSE exec -T -e VAULT_ADDR=https://127.0.0.1:8200 -e VAULT_CACERT=/run/tls/ca.crt vault vault"

for _ in $(seq 1 30); do
  if $V status >/dev/null 2>&1 || $V status 2>&1 | grep -q Sealed; then break; fi
  sleep 2
done

if ! $V status -format=json 2>/dev/null | grep -q '"initialized": true'; then
  $V operator init -key-shares=1 -key-threshold=1 -format=json > "$ROOT/vault-init.json"
  chmod 600 "$ROOT/vault-init.json"
fi

UNSEAL_KEY="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["unseal_keys_b64"][0])' "$ROOT/vault-init.json")"
ROOT_TOKEN="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["root_token"])' "$ROOT/vault-init.json")"

$V operator unseal "$UNSEAL_KEY" >/dev/null

VT="$COMPOSE exec -T -e VAULT_ADDR=https://127.0.0.1:8200 -e VAULT_CACERT=/run/tls/ca.crt -e VAULT_TOKEN=$ROOT_TOKEN vault vault"
$VT secrets list 2>/dev/null | grep -q '^secret/' || $VT secrets enable -path=secret kv-v2 >/dev/null

# Synthetic values: a non-routable camera URL and a random manifest key.
$VT kv put secret/absensi/rtsp url="rtsp://camera.invalid/stream" >/dev/null
$VT kv put secret/absensi/backup key_b64="$(openssl rand -base64 32)" >/dev/null

$COMPOSE exec -T vault sh -c 'cat > /tmp/absensi-app.hcl' < deploy/vault-app-policy.hcl
$VT policy write absensi-app /tmp/absensi-app.hcl >/dev/null

APP_TOKEN="$($VT token create -policy=absensi-app -no-default-policy -ttl=24h -renewable=false -field=token)"
umask 077
printf '%s' "$APP_TOKEN" > "$ROOT/secrets/vault-app-token"
chown 65532:65532 "$ROOT/secrets/vault-app-token"
chmod 600 "$ROOT/secrets/vault-app-token"

echo "vault_bootstrap=ok"
