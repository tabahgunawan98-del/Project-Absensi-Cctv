ui = false

# SECURITY LIMIT — READ BEFORE CHANGING.
# mlock is disabled so Vault can run with `cap_drop: [ALL]` and a read-only
# root filesystem; enabling it would require CAP_IPC_LOCK (and setcap on the
# binary, i.e. a writable rootfs). Consequence: Vault memory containing
# unsealed key material can be swapped to disk. Accepted only because the host
# is required to have swap disabled or an encrypted swap device — the runbook
# makes that a precondition and the operator must verify it.
disable_mlock = true

storage "file" {
  path = "/vault/file"
}

listener "tcp" {
  address         = "0.0.0.0:8200"
  tls_cert_file   = "/run/tls/tls.crt"
  tls_key_file    = "/run/tls/tls.key"
  tls_client_ca_file = "/run/tls/ca.crt"
}

api_addr = "https://vault:8200"
cluster_addr = "https://vault:8201"
log_level = "warn"
