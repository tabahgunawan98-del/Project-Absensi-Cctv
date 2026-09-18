#!/usr/bin/env bash
# End-to-end probe against the running synthetic stack: OIDC discovery, RBAC on
# the dashboard, ingest persistence, and backup/restore. Synthetic data only.
set -uo pipefail

ROOT="${1:-/tmp/absensi-stack}"
C="docker compose -f deploy/compose.yaml"
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

# --- OIDC ---
check "oidc discovery reachable through proxy" \
  $C exec -T proxy wget -qO- "https://${ABSENSI_HOSTNAME}/realms/absensi/.well-known/openid-configuration"

$C exec -T proxy wget -qO- "https://${ABSENSI_HOSTNAME}/realms/absensi/.well-known/openid-configuration" > "$ROOT/discovery.json" 2>/dev/null
check "discovery advertises the jwks endpoint" grep -q jwks_uri "$ROOT/discovery.json"
check "jwks endpoint serves keys" \
  $C exec -T proxy wget -qO- "https://${ABSENSI_HOSTNAME}/realms/absensi/protocol/openid-connect/certs"

# --- TLS chain (P3-1: no --no-check-certificate anywhere) ---
check "proxy tls chain validates against the internal CA" \
  $C exec -T proxy wget -qO- "https://${ABSENSI_HOSTNAME}/health/live"
check "compose has no certificate-verification bypass" \
  bash -c '! grep -rqE "no-check-certificate|--insecure|tls_skip_verify|-k " deploy/compose.yaml deploy/Caddyfile'

# --- RBAC ---
status_of() {
  $C exec -T proxy wget -S -qO- "$@" 2>&1 | awk '/HTTP\//{print $2; exit}'
}
UNAUTH="$($C exec -T app python -c "
import urllib.request, urllib.error
try:
    urllib.request.urlopen('http://127.0.0.1:8080/dashboard', timeout=5)
    print(200)
except urllib.error.HTTPError as e:
    print(e.code)
" 2>/dev/null | tr -d '\r')"
check "dashboard rejects an unauthenticated request (401)" test "$UNAUTH" = "401"

FORGED="$($C exec -T app python -c "
import urllib.request, urllib.error
req = urllib.request.Request('http://127.0.0.1:8080/dashboard')
req.add_header('Authorization', 'Bearer not-a-real-token')
try:
    urllib.request.urlopen(req, timeout=5)
    print(200)
except urllib.error.HTTPError as e:
    print(e.code)
" 2>/dev/null | tr -d '\r')"
check "dashboard rejects a forged bearer token (401)" test "$FORGED" = "401"

check "oauth2-proxy denies an anonymous dashboard hit (403/redirect, never 200)" \
  bash -c "$C exec -T proxy wget -S -qO- 'https://${ABSENSI_HOSTNAME}/dashboard' 2>&1 | grep -qE '403 Forbidden|30[237]|Location:'"

# --- ingest + persistence ---
check "ingest rejects an unauthenticated event (401)" \
  bash -c "$C exec -T app python -c \"
import urllib.request, urllib.error, json
data = json.dumps({'event_id':'probe'}).encode()
req = urllib.request.Request('http://127.0.0.1:8080/v2/events', data=data, headers={'Content-Type':'application/json'})
try:
    urllib.request.urlopen(req, timeout=5); raise SystemExit(1)
except urllib.error.HTTPError as e:
    raise SystemExit(0 if e.code == 401 else 1)
\""

check "attendance database file exists on the mounted volume" \
  $C exec -T app python -c "import pathlib,sys; sys.exit(0 if pathlib.Path('/var/lib/absensi/attendance.sqlite3').exists() else 1)"

check "database survives an application restart" bash -c "
  $C restart app >/dev/null 2>&1
  for _ in \$(seq 1 30); do
    $C exec -T app python -c \"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health/ready', timeout=3)\" >/dev/null 2>&1 && break
    sleep 2
  done
  $C exec -T app python -c \"import pathlib,sys; sys.exit(0 if pathlib.Path('/var/lib/absensi/attendance.sqlite3').stat().st_size > 0 else 1)\"
"

# --- backup / restore ---
check "backup writes a file into the backup volume" bash -c "
  $C exec -T app python -c \"
import sqlite3
source = sqlite3.connect('/var/lib/absensi/attendance.sqlite3')
target = sqlite3.connect('/var/backups/absensi/probe-backup.sqlite3')
source.backup(target)
target.close(); source.close()
\"
  test -s '$ROOT/backups/probe-backup.sqlite3'
"

check "restore from backup yields a readable database" \
  $C exec -T app python -c "
import sqlite3, shutil
shutil.copy2('/var/backups/absensi/probe-backup.sqlite3', '/tmp/restored.sqlite3')
con = sqlite3.connect('/tmp/restored.sqlite3')
names = [r[0] for r in con.execute(\"select name from sqlite_master where type='table'\")]
con.close()
raise SystemExit(0 if names else 1)
"

printf 'probe_pass=%d probe_fail=%d\n' "$PASS" "$FAIL"
test "$FAIL" -eq 0
