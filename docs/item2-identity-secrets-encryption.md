# Item 2 — identity, secrets, and encryption policy

Local runtime only. No staging, no production, no real camera or biometric data.

## 1. OIDC/JWKS token verification

`attendance_backend.jwks` + `attendance_backend.auth`.

The verifier runs in one of two modes, chosen by `AuthConfig.key_resolver`:

- **Asymmetric (IdP) mode** — `key_resolver` is a `JwksCache`. Only `RS256`,
  `RS384`, `RS512`, `ES256`, `ES384`, and `EdDSA` are verifiable. Symmetric
  algorithms are refused outright in this mode, so a JWKS public key can never be
  replayed as an HMAC secret (the classic `alg` confusion attack).
- **Legacy HS256 mode** — `keys` is a `kid -> shared secret` mapping. Retained so
  the phase 1–3 suites keep running unchanged; not for production.

Enforced in both modes: `alg` allowlist, explicit `none` rejection, `iss`, `aud`,
`exp`, `nbf`, `grant_type` → principal type, and a human `sub` for user tokens.
In asymmetric mode `kid` is mandatory and a JWK's declared `alg` must match the
token header.

### Rotation and caching

`JwksCache(fetch, ttl_seconds=..., clock=...)`:

- keys are cached for `ttl_seconds`;
- a **known** `kid` is served from cache with no fetch;
- an **unknown** `kid` on a cached document triggers exactly one refresh, so a
  rotated-in key works without a restart; an optional `refresh_cooldown_seconds`
  bounds how often an unknown `kid` can drive traffic at the IdP;
- an unknown `kid` on a *just-fetched* document does not refetch.

### Fail-closed

Once the TTL elapses, keys are dropped before refetching. If the JWKS endpoint is
unreachable, **no token is accepted** — the cache never serves stale keys past
their TTL, because a revoked key must stop working. Cold start without a reachable
JWKS accepts nothing. Malformed documents (`{}`, non-list `keys`, symmetric `oct`
entries only) are rejected rather than partially trusted.

### What is owner-dependent

The `fetch` callable is not implemented here. It must be bound to the owner's
chosen IdP discovery document (`/.well-known/openid-configuration` → `jwks_uri`)
over TLS with certificate verification. Choosing the IdP — Google Workspace,
Microsoft Entra ID, or self-hosted Keycloak — remains an owner decision, as do
the real `iss`/`aud` values and the claim names for scopes/sites/event types
(currently the provisional `absensi.*` names).

## 2. Secret store

`attendance_backend.secret_store`.

`SecretStore` is an abstract contract: `get`, `put`, `rotate`, `version`. One
implementation ships: `EncryptedFileSecretStore`, AES-256-GCM, one AEAD box per
secret, name+version bound as additional authenticated data.

- The master key comes from `ABSENSI_SECRET_MASTER_KEY` (base64, 16/24/32 bytes),
  supplied by an approved mechanism — systemd-creds, a KMS-fed environment, or an
  operator-entered value. It is never written to the store file or to logs.
- The store file is written atomically at mode `0600`.
- `repr()`/`str()` never render secret material.
- Missing master key, wrong master key, tampered ciphertext, corrupt file, and
  unknown secret names all fail closed with no value returned.
- `rotate(name, value)` bumps the secret's version; the previous plaintext does
  not remain in the file.
- `rotate_master_key(new)` re-encrypts every secret; the old master key stops
  working immediately.

Replacing this with cloud KMS or HashiCorp Vault means implementing `SecretStore`
and changing one construction site. That choice is the owner's.

## 3. Encryption at rest and TLS

`attendance_backend.security_policy`.

This module does not implement encryption — the stdlib SQLite driver has no
at-rest encryption, and TLS termination belongs to the reverse proxy or WSGI
server. It refuses to run when the approved protections are not demonstrably in
place, so a forgotten setting cannot silently become the running configuration.

- `verify_storage(*paths)` requires a valid, unexpired at-rest attestation file
  (`encrypted_at_rest: true`, a named `mechanism`, a named `attested_by`, an
  `expires_at`), and rejects any database or backup file readable beyond its
  owner.
- `require_tls_environ(policy, environ)` refuses plaintext HTTP. A terminating
  proxy is accepted via `X-Forwarded-Proto: https` **only** when the deployment
  explicitly trusts that header.
- Both requirements can be switched off only explicitly, and `describe()` reports
  the resulting posture for health/log surfaces.

`docs/at-rest-encryption.attestation.example.json` is a template. The real file
is signed off by the owner and expires.

### Limit worth stating plainly

At-rest encryption is **attested, not measured**. The runtime cannot verify LUKS,
dm-crypt, or a KMS-backed volume from inside the process. Replace the attestation
check with a real device/KMS probe once the deployment target is chosen.

## Event contract

Untouched. The auth surface gained `AuthConfig.key_resolver` (optional, defaults
to `None`); every existing HS256 construction keeps working unchanged.

## Tests

```bash
uv run python -m unittest discover -v
```

`tests/test_security.py` — 28 tests: JWKS verification across RS256/ES256/EdDSA,
`alg=none`, symmetric-in-asymmetric-mode, wrong-key signatures, unknown `kid`,
rotation without restart, TTL caching, unreachable JWKS, cold start, malformed
documents, claim enforcement, allowlist narrowing; secret store roundtrip,
missing/wrong master key, tampering, unknown names, secret and master-key
rotation, repr/str leakage; policy attestation missing/denied/expired,
permissions, explicit opt-out, TLS refusal and acceptance, and backup signing
keys sourced from the store.
