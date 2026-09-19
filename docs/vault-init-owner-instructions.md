## Inisialisasi Vault — prosedur dual-control owner

Dokumen ini untuk **owner**, dieksekusi di **console lokal server** (Proxmox shell
atau SSH langsung), bukan oleh agent. Agent tidak boleh memegang unseal key,
recovery share, atau root token.

> Dokumen ini juga memuat **gate enkripsi at-rest** (§0b) — keputusan owner yang
> memblokir `app`, terpisah dari Vault. Jangan lewati; `app` menolak start tanpa
> salah satu jalur di §0b.

Prasyarat yang sudah selesai (diverifikasi agent 2026-09-19):

- `proxy`, `keycloak-db`, `keycloak`, `keycloak-bootstrap` (exit 0), `oauth2-proxy`, `vault` — semua healthy.
- Ownership secret sudah cocok dengan `compose.yaml` (file DB `70:4000 0640`,
  Keycloak masuk lewat `group_add: ["4000"]`); cek ulang:
  `bash /root/deploy/check-secret-ownership.sh /etc/absensi` → `ownership_check=ok`.
- **Belum selesai:** swap masih aktif (lihat §0a), storage belum terenkripsi
  (lihat §0b). Keduanya harus beres **sebelum** init.

Seluruh perintah `vault` di bawah dijalankan di dalam container dengan CA internal:

```bash
kv() { docker exec -e VAULT_CACERT=/run/tls/ca.crt -i absensi-cctv-vault-1 vault "$@"; }
kvt() { docker exec -e VAULT_CACERT=/run/tls/ca.crt -e VAULT_TOKEN="$VAULT_TOKEN" -i absensi-cctv-vault-1 vault "$@"; }
kv status    # Initialized=false Sealed=true
```

### 0a. Gate keamanan: swap (WAJIB sebelum init)

`vault.hcl` memakai `disable_mlock = true`, jadi memori yang memuat unseal key
**dapat ditulis ke swap dalam bentuk plaintext**. Swap host saat ini:
`/dev/dm-0` (LVM `pve-swap`), 7.6 G, terpakai ~895 MB, **tanpa layer `crypt`**.

Peringatan kapasitas: host punya 7.6 GiB RAM dengan ~3.5 GiB available dan
**5 LXC produksi lain sedang berjalan** (n8n, docker, immich, nginxproxymanager,
bybit-bot). `swapoff -a` harus memindahkan ~895 MB yang sedang ter-swap kembali
ke RAM dan berlaku untuk seluruh host, bukan hanya stack absensi — ada risiko
OOM-kill pada container lain. Karena itu agent **tidak** mengeksekusinya; owner
yang memutuskan dan menjalankan.

```bash
# Opsi A — matikan swap (paling sederhana, disarankan bila RAM cukup)
free -m                      # pastikan available > used-swap + margin
swapoff -a                   # dapat memakan waktu; pantau `free -m` di terminal lain
sed -i 's|^/dev/pve/swap|#&|' /etc/fstab
swapon --show                # harus KOSONG
# rollback bila host tertekan: sudo swapon /dev/pve/swap

# Opsi B — pindahkan swap ke LUKS2 (bila RAM tidak cukup untuk Opsi A)
swapoff /dev/pve/swap
cryptsetup luksFormat /dev/pve/swap          # passphrase disimpan owner
cryptsetup open /dev/pve/swap swap_crypt
mkswap /dev/mapper/swap_crypt && swapon /dev/mapper/swap_crypt
# /etc/crypttab: swap_crypt /dev/pve/swap none luks
# /etc/fstab:    /dev/mapper/swap_crypt none swap sw 0 0
lsblk -o NAME,TYPE,FSTYPE | grep -i crypt    # harus tampil
```

Lampirkan output `swapon --show` (kosong) atau `lsblk | grep crypt` sebagai bukti.

### 0b. Gate keamanan: enkripsi at-rest (WAJIB sebelum init — memblokir `app`)

`app` menolak start dengan
`SecurityPolicyError: at-rest encryption attestation does not confirm encryption`
bila tidak ada attestation valid. Saat ini `/etc/absensi/at-rest.json` **palsu**:
memakai field yang salah (`encryption_at_rest{...}` vs `encrypted_at_rest`/
`mechanism`/`attested_by`/`expires_at` di root — lihat
`docs/at-rest-encryption.attestation.example.json`) **dan** mengklaim `LUKS2`
padahal host tidak punya layer `crypt` sama sekali (`lsblk -o NAME,TYPE,FSTYPE`
→ kosong). Gate bekerja sesuai desain — jangan "perbaiki" nama field selagi
storage belum terenkripsi. Dua jalur yang sah, keduanya keputusan owner:

**Jalur A — enkripsi nyata (disarankan):** pindahkan volume data aplikasi ke
LUKS2, lalu tulis attestation yang jujur persis mengikuti template. Ini satu paket
dengan keputusan swap §0a: jalur LUKS2 di sana bisa dipakai untuk storage juga.

**Jalur B — opt-out tertulis untuk pilot data sintetis:** hanya sah selama sistem
berisi data sintetis. Tambahkan `ABSENSI_REQUIRE_ENCRYPTION_AT_REST=false` ke
`/etc/absensi/deployment.env`, lalu `docker compose up -d --wait app`. Perilaku
kontrolnya fail-closed: default `true` bila variabel tidak ada, hanya nilai
eksplisit `false`/`0`/`no`/`off` yang membuka jalur ini, dan typo (`falsse`)
ditolak dengan `ConfigError` saat startup sehingga kontrol tidak mati diam-diam.
Statusnya wajib terlihat di `/health/ready`:

```bash
docker exec absensi-cctv-app-1 python3 -c \
  "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8080/health/ready').read().decode())"
# {"status":"ready","policy":{"require_tls":true,"require_encryption_at_rest":false,"attested":false}}
```

`require_encryption_at_rest: false` di output itu adalah catatan terbuka bahwa
enkripsi belum aktif dan risikonya diterima — bukan kontrol yang seolah menyala.
Jangan tulis attestation palsu sebagai gantinya. Sebelum data karyawan nyata
masuk, kembalikan ke Jalur A.

Tanpa salah satu jalur, `app` tidak akan start — dan itu benar.

### 1. Init — dual-control, dua orang hadir

Jalankan di terminal lokal yang **tidak direkam**. 5 share, threshold 3:

```bash
kv operator init -key-shares=5 -key-threshold=3
```

Output memuat 5 **Unseal Key** dan 1 **Initial Root Token**. Ini satu-satunya
kesempatan melihatnya.

Aturan penyimpanan:

- Setiap share diberikan ke **pemegang berbeda**; jangan ada satu orang memegang ≥3.
- Simpan pada media terenkripsi terpisah (USB LUKS / password manager berbeda / amplop tersegel di brankas).
- **Jangan** ditulis ke repo, issue Multica, chat, email, screenshot, atau file di server ini.
- Catat siapa memegang share nomor berapa (tanpa nilainya) untuk audit.
- Bersihkan scrollback terminal setelah selesai.

### 2. Unseal — butuh 3 share dari 3 pemegang berbeda

```bash
kv operator unseal      # diminta 3x, tiap pemegang mengetik share-nya sendiri
kv status               # Sealed=false
```

Setelah host reboot, Vault kembali sealed dan langkah ini diulang. Belum ada
auto-unseal pada paket ini.

### 3. Enable KV v2 + pasang policy

```bash
export VAULT_TOKEN='<initial root token>'   # ketik manual, jangan paste ke script
kvt secrets enable -path=secret -version=2 kv
kvt policy write absensi-app - < /root/deploy/vault-app-policy.hcl
kvt policy read absensi-app
```

### 4. Isi secret aplikasi

`app` membaca nilai ini saat startup. **Gunakan nilai sintetis dulu** — RTSP
kamera nyata baru dimasukkan setelah probe e2e lulus dan ada dasar pemrosesan
data yang ditinjau owner.

```bash
# RTSP sintetis untuk uji (bukan kamera nyata)
kvt kv put secret/absensi/rtsp url="rtsp://127.0.0.1:8554/synthetic"

# kunci backup
kvt kv put secret/absensi/backup key_b64="$(openssl rand -base64 32)"

# nanti, saat owner siap memasukkan RTSP nyata tanpa masuk shell history:
#   read -rsp 'RTSP URL: ' RTSP_URL
#   kvt kv put secret/absensi/rtsp url="$RTSP_URL"
#   unset RTSP_URL
```

### 5. Token service ber-TTL untuk `app`

Root token **tidak** dipakai aplikasi. Buat token terbatas:

```bash
kvt token create -policy=absensi-app -no-default-policy -ttl=720h -renewable=true -field=token \
  > /tmp/vault-app-token.$$
install -o 65532 -g 65532 -m 0600 /tmp/vault-app-token.$$ /etc/absensi/secrets/vault-app-token
shred -u /tmp/vault-app-token.$$
stat -c '%u %g %a %n' /etc/absensi/secrets/vault-app-token   # 65532 65532 600
```

TTL 720 jam (30 hari): paket belum punya agent auto-renew, jadi rotasi masuk
jadwal maintenance — catat tanggal kedaluwarsa. Setelah token service terbukti
bekerja, cabut root token: `kvt token revoke -self`.

### 6. Start `app` + probe e2e

```bash
cd /root/deploy
set -a; . /etc/absensi/deployment.env; set +a
docker compose -f compose.yaml up -d --wait      # harus exit 0
docker compose -f compose.yaml ps
bash /root/deploy/synthetic-e2e-probe.sh /etc/absensi
# harapkan: probe_pass=13 probe_fail=0
```

Bila `app` restart-loop, cek `docker logs absensi-cctv-app-1` — penyebab paling
umum adalah Vault masih sealed atau token salah owner/mode.

### 7. Akses dashboard

Caddy bind `192.168.1.250:443` dengan hostname `absensi.office.local`. Client
butuh **dua** hal:

1. Resolusi nama — entri `hosts` (`192.168.1.250 absensi.office.local`) atau
   record DNS internal. Akses via IP langsung akan gagal TLS SNI/hostname.
2. CA internal (`/etc/absensi/tls/ca.crt`) terpasang di trust store client.

URL: `https://absensi.office.local/`

Keputusan yang masih terbuka untuk owner: tetap `absensi.office.local` + DNS
internal, atau pakai hostname Tailscale (perlu cert dan `ABSENSI_HOSTNAME` baru,
serta rebuild realm Keycloak karena redirect URI ikut berubah).
