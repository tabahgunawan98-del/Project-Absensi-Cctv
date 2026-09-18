#!/bin/bash
# One-shot realm provisioning. Idempotent: safe to re-run on an existing realm.
# Reads every credential from mounted secret files; nothing is passed on the
# command line, printed, or written outside Keycloak.
set -euo pipefail

read_secret() {
  local path="$1"
  [[ -f "$path" ]] || { printf 'required secret file missing\n' >&2; exit 1; }
  IFS= read -r REPLY < "$path" || true
  [[ -n "$REPLY" ]] || { printf 'required secret file empty\n' >&2; exit 1; }
}

KCADM=/opt/keycloak/bin/kcadm.sh
CFG=(--config /tmp/kcadm.config)
REALM="${ABSENSI_REALM:-absensi}"
AUDIENCE="${ABSENSI_OIDC_AUDIENCE:-absensi-api}"
HOSTNAME_EXTERNAL="${ABSENSI_HOSTNAME:?hostname required}"

read_secret /run/secrets/keycloak_admin_user
ADMIN_USER="$REPLY"
read_secret /run/secrets/keycloak_admin_password
ADMIN_PASSWORD="$REPLY"
read_secret /run/secrets/oidc_client_secret
CLIENT_SECRET="$REPLY"
unset REPLY


for _ in $(seq 1 30); do
  if "$KCADM" config credentials "${CFG[@]}" --server http://keycloak:8080 --realm master \
      --user "$ADMIN_USER" --password "$ADMIN_PASSWORD" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
"$KCADM" config credentials "${CFG[@]}" --server http://keycloak:8080 --realm master \
  --user "$ADMIN_USER" --password "$ADMIN_PASSWORD" >/dev/null

"$KCADM" get "${CFG[@]}" "realms/$REALM" >/dev/null 2>&1 || \
  "$KCADM" create "${CFG[@]}" realms -s "realm=$REALM" -s enabled=true >/dev/null

for role in operator reviewer admin; do
  "$KCADM" get "${CFG[@]}" "roles/$role" -r "$REALM" >/dev/null 2>&1 || \
    "$KCADM" create "${CFG[@]}" roles -r "$REALM" -s "name=$role" >/dev/null
done

client_id() {
  "$KCADM" get "${CFG[@]}" clients -r "$REALM" -q "clientId=$1" --fields id --format csv --noquotes 2>/dev/null | head -1
}

if [[ -z "$(client_id absensi-dashboard)" ]]; then
  "$KCADM" create "${CFG[@]}" clients -r "$REALM" \
    -s clientId=absensi-dashboard \
    -s enabled=true \
    -s publicClient=false \
    -s standardFlowEnabled=true \
    -s directAccessGrantsEnabled=false \
    -s serviceAccountsEnabled=false \
    -s "secret=$CLIENT_SECRET" \
    -s "redirectUris=[\"https://$HOSTNAME_EXTERNAL/oauth2/callback\"]" \
    -s 'attributes."pkce.code.challenge.method"=S256' >/dev/null
else
  "$KCADM" update "${CFG[@]}" "clients/$(client_id absensi-dashboard)" -r "$REALM" \
    -s "secret=$CLIENT_SECRET" \
    -s "redirectUris=[\"https://$HOSTNAME_EXTERNAL/oauth2/callback\"]" >/dev/null
fi

DASHBOARD_ID="$(client_id absensi-dashboard)"

mapper_absent() {
  ! "$KCADM" get "${CFG[@]}" "clients/$DASHBOARD_ID/protocol-mappers/models" -r "$REALM" \
    --fields name --format csv --noquotes 2>/dev/null | grep -qx "$1"
}

if mapper_absent absensi-audience; then
  "$KCADM" create "${CFG[@]}" "clients/$DASHBOARD_ID/protocol-mappers/models" -r "$REALM" \
    -s name=absensi-audience -s protocol=openid-connect \
    -s protocolMapper=oidc-audience-mapper \
    -s "config.\"included.client.audience\"=$AUDIENCE" \
    -s 'config."access.token.claim"=true' >/dev/null
fi

if mapper_absent absensi-principal-type; then
  "$KCADM" create "${CFG[@]}" "clients/$DASHBOARD_ID/protocol-mappers/models" -r "$REALM" \
    -s name=absensi-principal-type -s protocol=openid-connect \
    -s protocolMapper=oidc-hardcoded-claim-mapper \
    -s 'config."claim.name"=absensi.principal_type' \
    -s 'config."claim.value"=user' \
    -s 'config."jsonType.label"=String' \
    -s 'config."access.token.claim"=true' >/dev/null
fi

unset ADMIN_PASSWORD CLIENT_SECRET
printf 'realm_bootstrap=ok\n'
