#!/bin/bash
set -euo pipefail

read_secret() {
  local path="$1"
  [[ -f "$path" ]] || { printf 'required secret file missing\n' >&2; exit 1; }
  IFS= read -r REPLY < "$path"
  [[ -n "$REPLY" ]] || { printf 'required secret file empty\n' >&2; exit 1; }
}

read_secret /run/secrets/keycloak_db_user
export KC_DB_USERNAME="$REPLY"
read_secret /run/secrets/keycloak_db_password
export KC_DB_PASSWORD="$REPLY"
read_secret /run/secrets/keycloak_admin_user
export KC_BOOTSTRAP_ADMIN_USERNAME="$REPLY"
read_secret /run/secrets/keycloak_admin_password
export KC_BOOTSTRAP_ADMIN_PASSWORD="$REPLY"
unset REPLY

exec /opt/keycloak/bin/kc.sh start \
  --http-enabled=true \
  --hostname-strict=true \
  --proxy-headers=xforwarded \
  --health-enabled=true
