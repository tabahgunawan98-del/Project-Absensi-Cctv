#!/usr/bin/env bash
# Local synthetic stack harness. Creates a throwaway CA, TLS certificates,
# secret files, and an at-rest attestation under a temporary root, then runs the
# real Compose stack. No production data, no camera, no real credentials.
set -euo pipefail

ROOT="${1:-/tmp/absensi-stack}"
HOSTNAME_INTERNAL="absensi.office.local"
PORT="${ABSENSI_HTTPS_PORT:-8443}"

rm -rf "$ROOT"
mkdir -p "$ROOT"/{tls,secrets,data,backups}
chmod 700 "$ROOT/secrets"

openssl req -x509 -newkey rsa:2048 -nodes -days 3 \
  -subj "/CN=absensi-internal-ca" \
  -keyout "$ROOT/tls/ca.key" -out "$ROOT/tls/ca.crt" >/dev/null 2>&1

issue_cert() {
  local name="$1" cn="$2" san="$3"
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$cn" \
    -keyout "$ROOT/tls/$name.key" -out "$ROOT/tls/$name.csr" >/dev/null 2>&1
  openssl x509 -req -in "$ROOT/tls/$name.csr" -days 3 \
    -CA "$ROOT/tls/ca.crt" -CAkey "$ROOT/tls/ca.key" -CAcreateserial \
    -extfile <(printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\n' "$san") \
    -out "$ROOT/tls/$name.crt" >/dev/null 2>&1
  rm -f "$ROOT/tls/$name.csr"
}

issue_cert proxy "$HOSTNAME_INTERNAL" "DNS:$HOSTNAME_INTERNAL,DNS:localhost,IP:127.0.0.1"
issue_cert vault vault "DNS:vault,DNS:localhost,IP:127.0.0.1"

# Synthetic secrets generated locally; never reused outside this harness.
umask 077
printf 'kcuser' > "$ROOT/secrets/keycloak-db-user"
openssl rand -hex 24 > "$ROOT/secrets/keycloak-db-password"
printf 'bootstrap-admin' > "$ROOT/secrets/keycloak-admin-user"
openssl rand -hex 24 > "$ROOT/secrets/keycloak-admin-password"
openssl rand -hex 24 > "$ROOT/secrets/vault-app-token"
openssl rand -hex 24 > "$ROOT/secrets/oidc-client-secret"
openssl rand -base64 32 | tr -d '\n' | head -c 32 > "$ROOT/secrets/oauth-cookie-secret"

python3 - "$ROOT" <<'PY'
import json, sys, datetime
root = sys.argv[1]
expiry = (datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=30)).isoformat()
attestation = {
    "encrypted_at_rest": True,
    "mechanism": "synthetic-harness-luks2",
    "attested_by": "synthetic-operator",
    "expires_at": expiry,
}
with open(f"{root}/at-rest.json", "w", encoding="utf-8") as handle:
    json.dump(attestation, handle)
PY
chmod 600 "$ROOT/at-rest.json"

# Ownership per service, mirroring the runbook table.
chown 65532:65532 "$ROOT/secrets/vault-app-token" "$ROOT/at-rest.json" \
  "$ROOT/secrets/oauth-cookie-secret"
chown 65532:65532 "$ROOT/data" "$ROOT/backups"
chmod 700 "$ROOT/data" "$ROOT/backups"
chown 1000:4000 "$ROOT/secrets/keycloak-db-user" "$ROOT/secrets/keycloak-db-password"
chmod 644 "$ROOT/secrets/keycloak-db-user" "$ROOT/secrets/keycloak-db-password"
# Read by keycloak-bootstrap (1000) and oauth2-proxy (65532) via shared gid 4000.
chown 1000:4000 "$ROOT/secrets/oidc-client-secret"
chmod 640 "$ROOT/secrets/oidc-client-secret"
chown 1000:1000 "$ROOT/secrets/keycloak-admin-user" "$ROOT/secrets/keycloak-admin-password"
chown 100:1000 "$ROOT/tls/vault.key"
chown 1000:1000 "$ROOT/tls/proxy.key"
chmod 644 "$ROOT/tls/ca.crt" "$ROOT/tls/proxy.crt" "$ROOT/tls/vault.crt"
chmod 600 "$ROOT/tls/vault.key" "$ROOT/tls/proxy.key"

cat > "$ROOT/stack.env" <<ENV
ABSENSI_HOSTNAME=$HOSTNAME_INTERNAL
ABSENSI_BIND_ADDRESS=127.0.0.1
ABSENSI_HTTPS_PORT=$PORT
ABSENSI_TLS_CERT=$ROOT/tls/proxy.crt
ABSENSI_TLS_KEY=$ROOT/tls/proxy.key
VAULT_TLS_CERT=$ROOT/tls/vault.crt
VAULT_TLS_KEY=$ROOT/tls/vault.key
ABSENSI_INTERNAL_CA=$ROOT/tls/ca.crt
ABSENSI_ATTESTATION_FILE=$ROOT/at-rest.json
ABSENSI_DATA_DIR=$ROOT/data
ABSENSI_BACKUP_DIR=$ROOT/backups
ABSENSI_OIDC_ISSUER=https://$HOSTNAME_INTERNAL/realms/absensi
ABSENSI_OIDC_AUDIENCE=absensi-api
ABSENSI_JWKS_URI=https://$HOSTNAME_INTERNAL/realms/absensi/protocol/openid-connect/certs
ABSENSI_RTSP_SECRET_PATH=secret/data/absensi/rtsp
ABSENSI_MANIFEST_KEY_PATH=secret/data/absensi/backup
KEYCLOAK_DB_USER_FILE=$ROOT/secrets/keycloak-db-user
KEYCLOAK_DB_PASSWORD_FILE=$ROOT/secrets/keycloak-db-password
KEYCLOAK_ADMIN_USER_FILE=$ROOT/secrets/keycloak-admin-user
KEYCLOAK_ADMIN_PASSWORD_FILE=$ROOT/secrets/keycloak-admin-password
VAULT_APP_TOKEN_FILE=$ROOT/secrets/vault-app-token
OIDC_CLIENT_SECRET_FILE=$ROOT/secrets/oidc-client-secret
OAUTH_COOKIE_SECRET_FILE=$ROOT/secrets/oauth-cookie-secret
ENV

echo "harness_ready root=$ROOT"
