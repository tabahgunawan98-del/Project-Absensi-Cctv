# Runbook deployment kantor

## Scope dan batas

Paket ini menjalankan aplikasi, Keycloak, Vault, OAuth2 Proxy, Caddy, dan PostgreSQL pada satu server kantor. Hanya Caddy menerbitkan port. Binding default `127.0.0.1:443`; ubah ke alamat antarmuka VPN/LAN yang disetujui. Jangan bind `0.0.0.0`, meneruskan port router, atau membuka Keycloak/Vault/PostgreSQL ke internet.

Belum ada deployment ke `192.168.1.250`. RTSP nyata, enrollment biometrik, dan produksi tetap memerlukan persetujuan. Gambar/video wajah tidak disimpan oleh paket ini. Confidence rendah tetap `unknown`; jalur badge/QR tetap tersedia.

## Kapasitas awal pilot satu kamera

Minimum awal, bukan hasil benchmark server kantor:

- 4 CPU core x86-64;
- 8 GiB RAM; Compose membatasi sekitar 4.4 GiB total agar host memiliki headroom;
- 40 GiB storage terenkripsi untuk image, database, Vault, Keycloak, log, dan backup;
- tambahan disk raw berdasarkan pengukuran: `events_per_day × average_event_bytes × 30 × 1.5`;
- processed: `attendance_rows_per_day × average_row_bytes × 90 × 1.5`.

Image lokal yang diukur berjumlah sekitar 608 MiB compressed/layer size sebelum overhead runtime. Ukur CPU, RSS, queue depth, DB growth, dan backup duration selama synthetic soak; naikkan kapasitas sebelum kamera kedua bila p95 CPU >70%, RSS >80%, queue terus bertambah, atau ruang bebas <30%.

## Prasyarat owner

1. Server `192.168.1.250` dapat dijangkau hanya melalui VPN/LAN yang disetujui.
2. Docker Engine + Compose v2 terpasang. Firewall hanya mengizinkan TCP 443 dari subnet VPN/LAN operator dan ingest yang disetujui.
3. DNS internal menetapkan nama final, default `absensi.office.local`, ke alamat VPN/LAN server.
4. Sertifikat TLS reverse proxy memiliki SAN hostname dashboard. Sertifikat Vault terpisah memiliki SAN DNS `vault` untuk jaringan Compose. Keduanya ditandatangani CA internal yang dipasang pada client/operator dan container aplikasi.
5. `/var/lib/absensi`, `/var/backups/absensi`, dan Docker data-root berada pada LUKS2/storage terenkripsi. Owner menandatangani attestation yang belum kedaluwarsa.
6. File secret disiapkan owner langsung pada server, mode `0600`, direktori mode `0700`. Jangan kirim nilainya lewat chat, issue, Git, log, atau shell history.

## Persiapan host

Jalankan sebagai administrator server setelah persetujuan deployment:

```bash
sudo install -d -m 0700 /etc/absensi/secrets /etc/absensi/tls
sudo install -d -o 65532 -g 65532 -m 0700 /var/lib/absensi /var/backups/absensi
sudo cp deploy/.env.example /etc/absensi/deployment.env
sudo chmod 0600 /etc/absensi/deployment.env
```

Salin sertifikat, key, CA, dan attestation ke path dalam `deployment.env`; mode private key dan attestation `0600`. Ganti `ABSENSI_BIND_ADDRESS` dengan alamat VPN/LAN server. Verifikasi tidak ada route publik/NAT ke port 443.

Buat secret secara interaktif tanpa argumen command-line:

```bash
sudo sh -c 'umask 077; read -rsp "Keycloak DB password: " value; printf "%s" "$value" > /etc/absensi/secrets/keycloak-db-password'
sudo sh -c 'umask 077; read -rp "Keycloak DB user: " value; printf "%s" "$value" > /etc/absensi/secrets/keycloak-db-user'
sudo sh -c 'umask 077; read -rp "Keycloak bootstrap admin: " value; printf "%s" "$value" > /etc/absensi/secrets/keycloak-admin-user'
sudo sh -c 'umask 077; read -rsp "Keycloak bootstrap password: " value; printf "%s" "$value" > /etc/absensi/secrets/keycloak-admin-password'
```

Buat cookie secret dengan CSPRNG lokal:

```bash
sudo sh -c 'umask 077; openssl rand -base64 32 > /etc/absensi/secrets/oauth-cookie-secret'
```

## Validasi dan bootstrap Vault

```bash
set -a; . /etc/absensi/deployment.env; set +a
docker compose -f deploy/compose.yaml config -q
docker compose -f deploy/compose.yaml up -d vault
```

Vault sengaja mulai sealed. Inisialisasi sekali melalui shell lokal server, simpan unseal/recovery material pada media owner terpisah dan terenkripsi. Jangan masukkan ke repo/chat. Unseal melalui proses dual-control owner. Aktifkan KV v2 `secret/`, pasang `deploy/vault-app-policy.hcl`, lalu buat token service ber-TTL dengan `no_default_policy` dan policy tersebut saja. Tulis token ke `/etc/absensi/secrets/vault-app-token` mode `0600`. Rotasi token melalui maintenance terjadwal dan restart aplikasi; paket belum memiliki agent auto-renew.

Owner memasukkan nilai RTSP tanpa membuatnya muncul sebagai argumen, history, atau output:

```bash
read -rsp 'RTSP URL: ' RTSP_URL
vault kv put secret/absensi/rtsp url="$RTSP_URL"
unset RTSP_URL
openssl rand -base64 32 | vault kv put secret/absensi/backup key_b64=-
```

Gunakan terminal lokal server yang tidak direkam. Perintah contoh kedua perlu diverifikasi terhadap versi Vault CLI; bila stdin field tidak didukung, gunakan file sementara pada tmpfs mode `0600`, hapus setelah write, lalu audit key metadata tanpa membaca value.

## Bootstrap Keycloak

Naikkan database dan Keycloak. Login melalui URL HTTPS internal. Buat realm `absensi`, client API audience `absensi-api`, confidential client `absensi-dashboard`, redirect URI `https://<hostname>/oauth2/callback`, PKCE S256, serta role `operator`, `reviewer`, `admin`. Nonaktifkan direct access grant. Tambahkan protocol mapper yang memasukkan claim konstan `absensi.principal_type=user` pada access token dashboard, claim audience `absensi-api`, scope `dashboard:read`, dan realm roles. Untuk client kamera/ingest terpisah, mapper menetapkan `absensi.principal_type=machine`; jangan berikan role dashboard. Salin client secret langsung ke `/etc/absensi/secrets/oidc-client-secret` mode `0600`; jangan kirim ke chat.

Setelah instance aktif, tetapkan secara aktual:

- `ABSENSI_OIDC_ISSUER=https://<hostname>/realms/absensi`
- `ABSENSI_JWKS_URI=https://<hostname>/realms/absensi/protocol/openid-connect/certs`
- `ABSENSI_OIDC_AUDIENCE=absensi-api`

Hapus/nonaktifkan bootstrap admin setelah admin bernama dan recovery admin diuji.

## Start dan verifikasi

```bash
set -a; . /etc/absensi/deployment.env; set +a
docker compose -f deploy/compose.yaml build --pull app
docker compose -f deploy/compose.yaml up -d
docker compose -f deploy/compose.yaml ps
curl --fail --cacert /etc/absensi/tls/ca.crt https://$ABSENSI_HOSTNAME/health/live
curl --fail --cacert /etc/absensi/tls/ca.crt https://$ABSENSI_HOSTNAME/health/ready
```

Buka `https://<hostname>/dashboard`; redirect harus menuju login Keycloak. Uji terpisah role operator/reviewer/admin. `docker compose ... config` tidak boleh menampilkan nilai secret. Log aplikasi hanya boleh memuat field allowlist non-PII; audit tidak menyimpan token, RTSP, media, atau template biometrik.

## Backup, restore, retensi

Backup target `/var/backups/absensi/` wajib pada storage terenkripsi, permission owner-only. Backup memakai SQLite online backup, sealing WAL, manifest HMAC, dan verifikasi fail-closed. Restore memerlukan operator dan approver berbeda serta alasan. Lakukan restore drill ke path terpisah sebelum memakai hasil; jangan overwrite DB aktif.

Raw retention default 30 hari; processed 90 hari. Dedupe 10 detik, rate limit 100 request/menit/client, clock skew 30 detik, grace check-in 15 menit. Semua bisa dioverride melalui `deployment.env`; nilai kosong, noninteger, nol, atau raw > processed membuat startup gagal.

## Monitoring dan incident

Pantau health/readiness, container restarts, CPU/RAM/disk, queue depth, retry count, failure count, Keycloak DB, Vault sealed state, sertifikat, backup age/duration. Jangan log payload event, employee ID, token, URL RTSP, frame, atau template biometrik.

Jika secret diduga bocor: isolasi akses VPN, revoke/rotate token Vault atau client secret, audit akses, restart dependent service, verifikasi log non-PII. Jika upgrade gagal: `docker compose down`, kembalikan image digest/config terakhir, restore hanya dari backup bertanda tangan melalui dual control, jalankan smoke test. Jangan menghapus backup lama sampai restore dan checksum hasil terverifikasi.

## Blocker deployment

Runner saat ini tidak dapat menjangkau `192.168.1.250`; topologi VPN, DNS final, sertifikat internal, storage encryption aktual, firewall, dan secret RTSP belum tersedia. Karena itu paket hanya diuji lokal/sintetis; tidak ada klaim pilot nyata atau tanggal final kantor.
