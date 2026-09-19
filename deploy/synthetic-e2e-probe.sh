#!/usr/bin/env bash
# End-to-end smoke test against the running synthetic stack.
# Proves positive flows: OIDC discovery, actual token acquisition,
# ingest persistence, RBAC success/denial, and backup/restore integrity.
set -uo pipefail

ROOT="${1:-/tmp/absensi-stack}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Path absolut ke compose: probe ikut dipanggil dari cwd mana pun (lihat
# pemakaian di office runbook). Relatif dulu memicu
# `compose file "deploy/compose.yaml" is invalid` bila dijalankan dari luar repo.
C="docker compose -f $REPO/deploy/compose.yaml"
PASS=0
FAIL=0

check() {
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then
    printf 'PASS %s\n' "$name"; PASS=$((PASS + 1))
  else
    printf 'FAIL %s\n' "$name"; FAIL=$((FAIL + 1))
  fi
}

# --- Preparation ---
CLIENT_SECRET="$(cat "$ROOT/secrets/oidc-client-secret")"
MARKER="$(python3 -c 'import uuid; print(uuid.uuid4())')"
HOSTNAME="${ABSENSI_HOSTNAME:-absensi.office.local}"

# --- 1. Internal Integration Tests (actual tokens) ---
# Tests are mounted at run time; they are deliberately NOT baked into the
# application image, which ships only the runtime code.
printf 'Running Keycloak integration tests... '
# The probe runs as the app image's uid (65532); copy the secret into a
# world-readable throwaway file inside the harness root instead of loosening
# the real secret's 0640 group-only permissions.
PROBE_SECRET="$ROOT/probe/oidc-client-secret"
mkdir -p "$ROOT/probe"
printf '%s' "$CLIENT_SECRET" > "$PROBE_SECRET"
chmod 0444 "$PROBE_SECRET"
if $C run --rm --no-deps \
  -v "$REPO/tests:/app/tests:ro" \
  -v "$PROBE_SECRET:/run/probe/oidc-client-secret:ro" \
  -v "$ROOT/tls/ca.crt:/run/tls/ca.crt:ro" \
  -e ABSENSI_INTEGRATION_KEYCLOAK=1 \
  -e ABSENSI_OIDC_ISSUER="https://$HOSTNAME/realms/absensi" \
  -e ABSENSI_OIDC_AUDIENCE="absensi-api" \
  -e ABSENSI_JWKS_URI="https://$HOSTNAME/realms/absensi/protocol/openid-connect/certs" \
  -e VAULT_CACERT=/run/tls/ca.crt \
  -e OIDC_CLIENT_SECRET_FILE=/run/probe/oidc-client-secret \
  -e PYTHONPATH=/app/src:/app/tests \
  --entrypoint python \
  app -m unittest test_integration_keycloak -v > "$ROOT/integration-test.log" 2>&1; then
  printf 'ok\n'; PASS=$((PASS + 1))
else
  printf 'FAILED\n'; FAIL=$((FAIL + 1))
  cat "$ROOT/integration-test.log"
fi
rm -f "$PROBE_SECRET"

# --- 2. Positive Ingest ---
printf 'Getting machine token... '
MACHINE_TOKEN=$($C exec -T app python -c "
import urllib.request, urllib.parse, json
data = urllib.parse.urlencode({
    'grant_type': 'client_credentials',
    'client_id': 'absensi-ingest',
    'client_secret': '$CLIENT_SECRET'
}).encode()
req = urllib.request.Request('http://keycloak:8080/realms/absensi/protocol/openid-connect/token', data=data)
with urllib.request.urlopen(req) as f:
    print(json.loads(f.read().decode())['access_token'])
" 2>/dev/null)

if [[ -n "$MACHINE_TOKEN" ]]; then
  printf 'ok\n'
  check "Ingest a valid machine event (202)" \
    bash -c "$C exec -T app python - '$MARKER' '$MACHINE_TOKEN' < '$REPO/deploy/probe_ingest.py'"

  check "Marker exists in the SQLite database" \
    $C exec -T app python -c "import sqlite3; con=sqlite3.connect('/var/lib/absensi/attendance.sqlite3'); r=con.execute(\"SELECT 1 FROM events WHERE event_id='$MARKER'\").fetchone(); raise SystemExit(0 if r else 1)"
else
  printf 'FAILED to get machine token\n'; FAIL=$((FAIL + 2))
fi

# --- 3. Positive RBAC ---
printf 'Getting user token... '
USER_TOKEN=$($C exec -T app python -c "
import urllib.request, urllib.parse, json
data = urllib.parse.urlencode({
    'grant_type': 'password',
    'client_id': 'absensi-dashboard',
    'client_secret': '$CLIENT_SECRET',
    'username': 'smoke-operator',
    'password': 'smoke-password'
}).encode()
req = urllib.request.Request('http://keycloak:8080/realms/absensi/protocol/openid-connect/token', data=data)
with urllib.request.urlopen(req) as f:
    print(json.loads(f.read().decode())['access_token'])
" 2>/dev/null)

if [[ -n "$USER_TOKEN" ]]; then
  printf 'ok\n'
  check "Operator user can access the dashboard (200)" \
    bash -c "$C exec -T app python -c \"
import urllib.request
req = urllib.request.Request('http://127.0.0.1:8080/dashboard', headers={
    'Authorization': 'Bearer $USER_TOKEN'
})
with urllib.request.urlopen(req) as f:
    raise SystemExit(0 if f.status == 200 else 1)
\""

  # The dashboard renders attendance_records, not raw ingest rows: asserting the
  # event_id here would test the wrong contract. The marker's persistence is
  # proven directly against SQLite above.
  check "Dashboard renders operator content without leaking secrets" \
    bash -c "$C exec -T app python -c \"
import urllib.request
req = urllib.request.Request('http://127.0.0.1:8080/dashboard', headers={
    'Authorization': 'Bearer $USER_TOKEN'
})
with urllib.request.urlopen(req) as f:
    body = f.read().decode()
raise SystemExit(0 if 'dashboard' in body.lower() and 'secret' not in body.lower() else 1)
\""

  check "Machine token is denied on the dashboard route (wrong role)" \
    bash -c "! $C exec -T app python -c \"
import urllib.request
req = urllib.request.Request('http://127.0.0.1:8080/dashboard', headers={
    'Authorization': 'Bearer $MACHINE_TOKEN'
})
urllib.request.urlopen(req)
\""
else
  printf 'FAILED to get user token\n'; FAIL=$((FAIL + 3))
fi

# --- 4. Persistence across restart ---
printf 'Restarting app... '
$C restart app >/dev/null 2>&1
sleep 5
check "Event marker survives an application restart" \
  $C exec -T app python -c "import sqlite3; con=sqlite3.connect('/var/lib/absensi/attendance.sqlite3'); r=con.execute(\"SELECT 1 FROM events WHERE event_id='$MARKER'\").fetchone(); raise SystemExit(0 if r else 1)"

# --- 5. Backup / Restore (value-level, not table-level) ---
printf 'Testing backup/restore... '
$C exec -T app python -c "
import sqlite3
source = sqlite3.connect('/var/lib/absensi/attendance.sqlite3')
target = sqlite3.connect('/var/backups/absensi/smoke-backup.sqlite3')
source.backup(target)
target.close(); source.close()
"

# Destroy the marker row in the live database: proving the restore brings back
# this exact value is the point, a table that merely exists proves nothing.
$C exec -T app rm -f /var/lib/absensi/attendance.sqlite3 /var/lib/absensi/attendance.sqlite3-wal /var/lib/absensi/attendance.sqlite3-shm

check "Marker is gone after the database is destroyed" \
  bash -c "$C exec -T app python -c \"import os; raise SystemExit(0 if not os.path.exists('/var/lib/absensi/attendance.sqlite3') else 1)\""

check "Restore brings back the same marker row value" \
  $C exec -T app python -c "
import sqlite3, shutil
shutil.copy2('/var/backups/absensi/smoke-backup.sqlite3', '/var/lib/absensi/attendance.sqlite3')
con = sqlite3.connect('/var/lib/absensi/attendance.sqlite3')
row = con.execute(\"SELECT event_id, event_type FROM events WHERE event_id='$MARKER'\").fetchone()
con.close()
raise SystemExit(0 if row and row[0] == '$MARKER' and row[1] == 'observation.detected.v2' else 1)
"

printf 'probe_pass=%d probe_fail=%d\n' "$PASS" "$FAIL"
test "$FAIL" -eq 0
