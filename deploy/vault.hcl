ui = false
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
