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

for role in operator reviewer admin events:write dashboard:read; do
  "$KCADM" get "${CFG[@]}" "roles/$role" -r "$REALM" >/dev/null 2>&1 || \
    "$KCADM" create "${CFG[@]}" roles -r "$REALM" -s "name=$role" >/dev/null
done

client_id() {
  "$KCADM" get "${CFG[@]}" clients -r "$REALM" -q "clientId=$1" --fields id --format csv --noquotes 2>/dev/null | head -1
}

# 1. Dashboard Client
if [[ -z "$(client_id absensi-dashboard)" ]]; then
  "$KCADM" create "${CFG[@]}" clients -r "$REALM" \
    -s clientId=absensi-dashboard \
    -s enabled=true \
    -s publicClient=false \
    -s standardFlowEnabled=true \
    -s directAccessGrantsEnabled=true \
    -s serviceAccountsEnabled=false \
    -s "secret=$CLIENT_SECRET" \
    -s "redirectUris=[\"https://$HOSTNAME_EXTERNAL/oauth2/callback\"]" \
    -s 'attributes."pkce.code.challenge.method"=S256' >/dev/null
fi
DASHBOARD_ID="$(client_id absensi-dashboard)"

# 2. Ingest Client
if [[ -z "$(client_id absensi-ingest)" ]]; then
  "$KCADM" create "${CFG[@]}" clients -r "$REALM" \
    -s clientId=absensi-ingest \
    -s enabled=true \
    -s publicClient=false \
    -s standardFlowEnabled=false \
    -s directAccessGrantsEnabled=false \
    -s serviceAccountsEnabled=true \
    -s "secret=$CLIENT_SECRET" >/dev/null
fi
INGEST_ID="$(client_id absensi-ingest)"

mapper_absent() {
  local cid="$1"
  local name="$2"
  ! "$KCADM" get "${CFG[@]}" "clients/$cid/protocol-mappers/models" -r "$REALM" \
    --fields name --format csv --noquotes 2>/dev/null | grep -qx "$name"
}

# Mappers for Dashboard
if mapper_absent "$DASHBOARD_ID" absensi-audience; then
  "$KCADM" create "${CFG[@]}" "clients/$DASHBOARD_ID/protocol-mappers/models" -r "$REALM" \
    -s name=absensi-audience -s protocol=openid-connect \
    -s protocolMapper=oidc-audience-mapper \
    -s "config.\"included.client.audience\"=$AUDIENCE" \
    -s 'config."access.token.claim"=true' >/dev/null
fi

if mapper_absent "$DASHBOARD_ID" absensi-principal-type; then
  "$KCADM" create "${CFG[@]}" "clients/$DASHBOARD_ID/protocol-mappers/models" -r "$REALM" \
    -s name=absensi-principal-type -s protocol=openid-connect \
    -s protocolMapper=oidc-hardcoded-claim-mapper \
    -s 'config."claim.name"=absensi.principal_type' \
    -s 'config."claim.value"=user' \
    -s 'config."jsonType.label"=String' \
    -s 'config."access.token.claim"=true' >/dev/null
fi

# Nested namespace claims consumed by the backend contract: absensi.event_types
# and absensi.sites. jsonType.label=JSON keeps them real JSON arrays, so the
# backend never has to do loose string coercion.
#
# These go through a JSON payload on stdin, not `-s`: kcadm tries to parse any
# `-s` value starting with `[` as JSON and then fails to assign the array into
# the string-typed config map ("Cannot parse the JSON").
create_list_claim_mapper() {
  local cid="$1" name="$2" claim="$3" value="$4"
  mapper_absent "$cid" "$name" || return 0
  printf '{"name":"%s","protocol":"openid-connect","protocolMapper":"oidc-hardcoded-claim-mapper","config":{"claim.name":"%s","claim.value":%s,"jsonType.label":"JSON","access.token.claim":"true","id.token.claim":"false"}}\n' \
    "$name" "$claim" "$(printf '%s' "$value" | sed 's/"/\\"/g; s/^/"/; s/$/"/')" \
    | "$KCADM" create "${CFG[@]}" "clients/$cid/protocol-mappers/models" -r "$REALM" -f - >/dev/null
}

create_list_claim_mapper "$DASHBOARD_ID" absensi-event-types absensi.event_types '["attendance.manual.v2"]'
create_list_claim_mapper "$DASHBOARD_ID" absensi-sites absensi.sites '["40000000-0000-4000-8000-000000000001"]'

if mapper_absent "$INGEST_ID" absensi-audience; then
  "$KCADM" create "${CFG[@]}" "clients/$INGEST_ID/protocol-mappers/models" -r "$REALM" \
    -s name=absensi-audience -s protocol=openid-connect \
    -s protocolMapper=oidc-audience-mapper \
    -s "config.\"included.client.audience\"=$AUDIENCE" \
    -s 'config."access.token.claim"=true' >/dev/null
fi

if mapper_absent "$INGEST_ID" absensi-principal-type; then
  "$KCADM" create "${CFG[@]}" "clients/$INGEST_ID/protocol-mappers/models" -r "$REALM" \
    -s name=absensi-principal-type -s protocol=openid-connect \
    -s protocolMapper=oidc-hardcoded-claim-mapper \
    -s 'config."claim.name"=absensi.principal_type' \
    -s 'config."claim.value"=machine' \
    -s 'config."jsonType.label"=String' \
    -s 'config."access.token.claim"=true' >/dev/null
fi

create_list_claim_mapper "$INGEST_ID" absensi-event-types absensi.event_types '["observation.detected.v2","identity.resolved.v2"]'
create_list_claim_mapper "$INGEST_ID" absensi-sites absensi.sites '["40000000-0000-4000-8000-000000000001"]'

# Roles and users
if ! "$KCADM" get "${CFG[@]}" users -r "$REALM" -q "username=smoke-operator" --fields id --format csv --noquotes 2>/dev/null | grep -q .; then
  # firstName/lastName/email are required: the realm's default VERIFY_PROFILE
  # action otherwise marks the account "not fully set up" and the password grant
  # fails with invalid_grant.
  "$KCADM" create "${CFG[@]}" users -r "$REALM" -s username=smoke-operator -s enabled=true \
    -s emailVerified=true -s email=smoke-operator@absensi.invalid \
    -s firstName=Smoke -s lastName=Operator -s 'requiredActions=[]' >/dev/null
  "$KCADM" set-password "${CFG[@]}" -r "$REALM" --username smoke-operator --new-password "smoke-password" >/dev/null
  "$KCADM" add-roles "${CFG[@]}" -r "$REALM" --uusername smoke-operator --rolename operator >/dev/null
  "$KCADM" add-roles "${CFG[@]}" -r "$REALM" --uusername smoke-operator --rolename dashboard:read >/dev/null
fi

# Service account roles for Ingest
SERVICE_ACCOUNT_USER=$("$KCADM" get "${CFG[@]}" users -r "$REALM" -q "username=service-account-absensi-ingest" --fields id --format csv --noquotes 2>/dev/null)
if [[ -n "$SERVICE_ACCOUNT_USER" ]]; then
  "$KCADM" add-roles "${CFG[@]}" -r "$REALM" --uid "$SERVICE_ACCOUNT_USER" --rolename "events:write" >/dev/null
fi


unset ADMIN_PASSWORD CLIENT_SECRET
printf 'realm_bootstrap=ok\n'
