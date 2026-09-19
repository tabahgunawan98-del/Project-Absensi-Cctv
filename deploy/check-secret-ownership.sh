#!/bin/bash
# Verifies that secret file ownership on the host matches the contract in
# compose.yaml. Run before `docker compose up`; a mismatch is the cause of
# "Permission denied" crash loops on keycloak / keycloak-db / oauth2-proxy.
# Usage: bash deploy/check-secret-ownership.sh [/etc/absensi]
#
# Contract: the DB secrets are owned by postgres (uid 70) and read by keycloak
# (uid 1000) through the shared group 4000, which compose grants via `group_add`.
# Host-side `usermod -a -G` does NOT affect in-container identity, so the group
# must be declared in compose -- this script asserts both halves.
set -uo pipefail

ROOT="${1:-/etc/absensi}"
COMPOSE="$(cd "$(dirname "$0")" && pwd)/compose.yaml"
fail=0

expect_file() {
  local path="$ROOT/$1" want="$2" got
  got="$(stat -c '%u %g %a' "$path" 2>/dev/null)" || {
    printf 'MISSING %s\n' "$path"; fail=1; return; }
  if [[ "$got" == "$want" ]]; then
    printf 'ok      %-30s %s\n' "$1" "$got"
  else
    printf 'BAD     %-30s got=%s want=%s\n' "$1" "$got" "$want"; fail=1
  fi
}

# Prints the value of `key` inside the block of compose service `svc`.
svc_field() {
  awk -v s="  $1:" -v k="    $2:" '
    $0==s {f=1; next}
    f && /^  [a-z]/ {exit}
    f && index($0, k)==1 {sub(/^[^:]*: */, ""); print; exit}
  ' "$COMPOSE"
}

expect_compose() {
  local svc="$1" key="$2" want="$3" got
  got="$(svc_field "$svc" "$key")"
  if [[ "$got" == "$want" ]]; then
    printf 'ok      compose %-16s %s=%s\n' "$svc" "$key" "$got"
  else
    printf 'BAD     compose %-16s %s=%s want=%s\n' "$svc" "$key" "${got:-<none>}" "$want"; fail=1
  fi
}

# DB secrets: owner postgres(70), group 4000 shared with keycloak, 0640.
expect_file secrets/keycloak-db-user        "70 4000 640"
expect_file secrets/keycloak-db-password    "70 4000 640"
# oidc-client-secret: owner keycloak-bootstrap(1000), group 4000 for oauth2-proxy.
expect_file secrets/oidc-client-secret      "1000 4000 640"
expect_file secrets/keycloak-admin-user     "1000 1000 600"
expect_file secrets/keycloak-admin-password "1000 1000 600"
expect_file secrets/oauth-cookie-secret     "65532 65532 600"
expect_file secrets/vault-app-token         "65532 65532 600"

expect_compose keycloak     user      '"1000:0"'
expect_compose keycloak     group_add '["4000"]'
expect_compose keycloak-db  user      '"70:70"'
expect_compose oauth2-proxy user      '"65532:4000"'
expect_compose app          user      '"65532:65532"'

# oauth2-proxy rejects a cookie secret that is not raw 16/24/32 bytes or unpadded
# base64url of that length; `openssl rand -base64 32` (44 chars + newline) fails.
cookie_len=$(wc -c < "$ROOT/secrets/oauth-cookie-secret" 2>/dev/null || echo 0)
case "$cookie_len" in
  16|24|32|43) printf 'ok      oauth-cookie-secret length     %s bytes\n' "$cookie_len" ;;
  *) printf 'BAD     oauth-cookie-secret length     %s bytes (want 16/24/32 raw or 43 base64url)\n' "$cookie_len"; fail=1 ;;
esac

if (( fail )); then
  printf 'ownership_check=fail\n'; exit 1
fi
printf 'ownership_check=ok\n'
