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

### UID/GID per service dan ownership file

Docker secret file diberikan ke container apa adanya; tanpa ownership yang cocok, service gagal start dengan `Permission denied`. Nilai UID/GID di bawah harus sama persis dengan `user:` pada `deploy/compose.yaml`.

| Service | `user:` | File yang harus dimiliki |
|---|---|---|
| `app` | `65532:65532` | `/etc/absensi/secrets/vault-app-token`, `/etc/absensi/at-rest.json`, `/var/lib/absensi`, `/var/backups/absensi` |
| `keycloak` | `1000:0` | `keycloak-db-user`, `keycloak-db-password`, `keycloak-admin-user`, `keycloak-admin-password` |
| `keycloak-db` | `70:70` | `keycloak-db-user`, `keycloak-db-password` |
| `oauth2-proxy` | `65532:4000` | `oidc-client-secret` (grup `4000`), `oauth-cookie-secret` |
| `keycloak-bootstrap` | `1000:4000` | `keycloak-admin-user`, `keycloak-admin-password`, `oidc-client-secret` |
| `vault` | `100:1000` | volume `vault-data`, TLS key Vault |
| `proxy` | `1000:1000` | TLS key proxy |

Secret DB dibaca dua service dengan UID berbeda, jadi berikan group bersama dan mode `0640`:

```bash
sudo groupadd -f -g 4000 absensi-secrets
sudo chown 65532:65532 /etc/absensi/secrets/vault-app-token /etc/absensi/at-rest.json
sudo chown 65532:65532 /etc/absensi/secrets/oauth-cookie-secret
# oidc-client-secret dibaca oauth2-proxy (65532) dan keycloak-bootstrap (1000)
# lewat grup bersama 4000, jadi mode 0640 dengan grup itu — bukan 0600.
sudo chown 1000:4000 /etc/absensi/secrets/oidc-client-secret
sudo chmod 0640 /etc/absensi/secrets/oidc-client-secret
sudo chown 1000:4000 /etc/absensi/secrets/keycloak-db-user /etc/absensi/secrets/keycloak-db-password
sudo usermod -a -G absensi-secrets postgres 2>/dev/null || true
sudo chown 1000:1000 /etc/absensi/secrets/keycloak-admin-user /etc/absensi/secrets/keycloak-admin-password
sudo chmod 0640 /etc/absensi/secrets/keycloak-db-user /etc/absensi/secrets/keycloak-db-password
sudo chmod 0600 /etc/absensi/secrets/vault-app-token \
  /etc/absensi/secrets/oauth-cookie-secret /etc/absensi/secrets/keycloak-admin-user \
  /etc/absensi/secrets/keycloak-admin-password /etc/absensi/at-rest.json
sudo chmod 0700 /var/lib/absensi /var/backups/absensi
sudo chown 100:1000 /etc/absensi/tls/vault.key
sudo chown 1000:1000 /etc/absensi/tls/tls.key
sudo chmod 0600 /etc/absensi/tls/vault.key /etc/absensi/tls/tls.key
```

Jalankan blok ini **sebelum** `docker compose up`. Verifikasi dengan `stat -c '%u %g %a %n' /etc/absensi/secrets/*`; UID harus cocok dengan tabel, bukan `0`.

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

### Prasyarat host: swap (batas keamanan mlock)

`disable_mlock = true` pada `deploy/vault.hcl` adalah kompromi eksplisit: Vault
berjalan `read_only` dengan `cap_drop: [ALL]`, sehingga memori yang memuat kunci
unseal **dapat ter-swap ke disk**. Host wajib memenuhi salah satu opsi:

```bash
# Opsi A — swap dimatikan (disarankan)
sudo swapoff -a
swapon --show   # harus kosong

# Opsi B — swap terenkripsi
lsblk -o NAME,TYPE,MOUNTPOINT,FSTYPE | grep -i crypt
```

Verifikasi perilaku setelah stack jalan — `enabled: false` adalah hasil yang
diharapkan dari konfigurasi ini, bukan kegagalan:

```bash
docker compose -f deploy/compose.yaml logs vault | grep -i mlock
# Mlock: supported: true, enabled: false
```


```bash
set -a; . /etc/absensi/deployment.env; set +a
docker compose -f deploy/compose.yaml config -q
docker compose -f deploy/compose.yaml up -d vault
```

Vault sengaja mulai sealed. Container berjalan sebagai uid `100` gid `1000` (akun `vault` bawaan image) dengan `SKIP_CHOWN=true` dan `SKIP_SETCAP=true`, sehingga `read_only: true` dan `cap_drop: [ALL]` tetap berlaku.

**Batas keamanan mlock:** `vault.hcl` memakai `disable_mlock = true`, jadi memori Vault dapat ter-swap ke disk. Ini konsekuensi menjalankan container tanpa `IPC_LOCK`/`setcap`. Kompensasi wajib di server kantor: matikan swap (`swapoff -a` + hapus entri `fstab`) atau tempatkan swap pada partisi terenkripsi LUKS2. Verifikasi dengan `swapon --show` (kosong) atau `lsblk -o NAME,TYPE,FSTYPE` yang menunjukkan swap di atas `crypt`. Jangan nyatakan mlock aktif.

Inisialisasi sekali melalui shell lokal server, simpan unseal/recovery material pada media owner terpisah dan terenkripsi. Jangan masukkan ke repo/chat. Unseal melalui proses dual-control owner. Aktifkan KV v2 `secret/`, pasang `deploy/vault-app-policy.hcl`, lalu buat token service ber-TTL dengan `no_default_policy` dan policy tersebut saja. Tulis token ke `/etc/absensi/secrets/vault-app-token` mode `0600`. Rotasi token melalui maintenance terjadwal dan restart aplikasi; paket belum memiliki agent auto-renew.

Owner memasukkan nilai RTSP tanpa membuatnya muncul sebagai argumen, history, atau output:

```bash
read -rsp 'RTSP URL: ' RTSP_URL
vault kv put secret/absensi/rtsp url="$RTSP_URL"
unset RTSP_URL
openssl rand -base64 32 | vault kv put secret/absensi/backup key_b64=-
```

Gunakan terminal lokal server yang tidak direkam. Perintah contoh kedua perlu diverifikasi terhadap versi Vault CLI; bila stdin field tidak didukung, gunakan file sementara pada tmpfs mode `0600`, hapus setelah write, lalu audit key metadata tanpa membaca value.

## Bootstrap Keycloak

Realm diprovision otomatis oleh service `keycloak-bootstrap` (`deploy/keycloak-realm-bootstrap.sh`), idempoten dan dijalankan sekali setiap `up`:

```bash
docker compose -f deploy/compose.yaml up -d --wait
docker compose -f deploy/compose.yaml logs keycloak-bootstrap | tail -3
# realm_bootstrap=ok
```

Script membuat realm `absensi`, role `operator`/`reviewer`/`admin`, confidential client `absensi-dashboard` (PKCE S256, redirect `https://<hostname>/oauth2/callback`, direct access grant mati), mapper audience `absensi-api`, dan mapper claim `absensi.principal_type=user`. Semua kredensial dibaca dari file secret; tidak ada nilai yang muncul di argumen, log, atau `docker compose config`.

Yang masih manual di server: client kamera/ingest terpisah dengan `absensi.principal_type=machine` tanpa role dashboard, penetapan role ke user nyata, serta penonaktifan bootstrap admin setelah admin bernama dan recovery admin diuji.

Setelah instance aktif, tetapkan secara aktual:

- `ABSENSI_OIDC_ISSUER=https://<hostname>/realms/absensi`
- `ABSENSI_JWKS_URI=https://<hostname>/realms/absensi/protocol/openid-connect/certs`
- `ABSENSI_OIDC_AUDIENCE=absensi-api`

Hapus/nonaktifkan bootstrap admin setelah admin bernama dan recovery admin diuji.

## Start dan verifikasi

```bash
set -a; . /etc/absensi/deployment.env; set +a
docker compose -f deploy/compose.yaml build --pull app keycloak keycloak-bootstrap
docker compose -f deploy/compose.yaml up -d --wait   # harus exit 0
docker compose -f deploy/compose.yaml ps
curl --fail --cacert /etc/absensi/tls/ca.crt https://$ABSENSI_HOSTNAME/health/live
curl --fail --cacert /etc/absensi/tls/ca.crt https://$ABSENSI_HOSTNAME/health/ready
```

Urutan start yang benar: `vault` naik lebih dulu dan **harus di-unseal** sebelum `app`, karena `app` membaca RTSP/manifest key saat startup dan akan restart-loop bila Vault masih sealed.

Verifikasi end-to-end (OIDC, RBAC, persistence, backup/restore) memakai probe yang sama dengan yang dijalankan di runner:

```bash
bash deploy/synthetic-e2e-probe.sh /etc/absensi
# probe_pass=13 probe_fail=0
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
