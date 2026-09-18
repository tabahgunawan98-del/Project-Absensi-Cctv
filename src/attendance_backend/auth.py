"""JWT verification for the ingress boundary.

Authorization is derived only from verified token claims; request bodies never
grant authority. Two modes are supported: a JWKS-backed asymmetric mode
(`key_resolver`) for a real IdP, and the legacy HS256 shared-secret mode
(`keys`) retained for the phase 1-3 tests. In asymmetric mode symmetric
algorithms are refused outright, so a JWKS public key can never be replayed as
an HMAC secret.
"""

import base64
import binascii
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature

from .jwks import (
    ASYMMETRIC_ALGORITHMS,
    JwksUnavailable,
    UnsupportedKey,
    verify_asymmetric_signature,
)

# grant_type decides the principal kind: client-credentials tokens can never be
# users, so a service token cannot reach user-delegated endpoints.
GRANT_PRINCIPAL_TYPES = {"client_credentials": "machine", "authorization_code": "user"}


class TokenError(Exception):
    def __init__(self, code, title):
        super().__init__(title)
        self.code = code
        self.title = title


@dataclass(frozen=True)
class AuthConfig:
    issuer: str
    audience: str
    keys: dict  # kid -> shared secret (bytes); legacy HS256 mode only
    algorithms: frozenset = frozenset({"HS256"})
    clock_skew_seconds: int = 60  # provisional default; owner policy pending
    scope_claim: str = "scope"
    event_types_claim: str = "absensi.event_types"  # provisional claim name
    sites_claim: str = "absensi.sites"  # provisional claim name
    key_resolver: object = None  # JwksCache-like: .resolve(kid) -> (public_key, alg)

    @property
    def asymmetric_mode(self):
        return self.key_resolver is not None


@dataclass(frozen=True)
class Principal:
    principal_type: str
    subject: str | None
    client_id: str | None
    scopes: frozenset = field(default_factory=frozenset)
    event_types: frozenset = field(default_factory=frozenset)
    sites: frozenset = field(default_factory=frozenset)
    roles: frozenset = field(default_factory=frozenset)


def _decode(segment):
    try:
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (binascii.Error, ValueError) as error:
        raise TokenError("token_invalid", "Token segment is not base64url") from error


def _decode_json(segment):
    try:
        value = json.loads(_decode(segment))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TokenError("token_invalid", "Token segment is not JSON") from error
    if not isinstance(value, dict):
        raise TokenError("token_invalid", "Token segment must be a JSON object")
    return value


def _string_set(value):
    if isinstance(value, str):
        return frozenset(value.split())
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return frozenset(value)
    return frozenset()


def _get_absensi_claim(claims, key, expected_type):
    """Retrieve a claim from the nested `absensi` object or flat `absensi.key` format.

    Representing custom claims in a namespace is standard for many IdPs, while
    the dotted flat keys were used in early prototypes. This parser accepts both
    but rejects tokens where they conflict.
    """
    absensi = claims.get("absensi")
    val_nested = None
    if isinstance(absensi, dict):
        val_nested = absensi.get(key)

    val_flat = claims.get(f"absensi.{key}")

    if val_nested is not None and val_flat is not None and val_nested != val_flat:
        raise TokenError("token_invalid", f"Conflicting values for absensi.{key}")

    val = val_nested if val_nested is not None else val_flat

    if val is not None and not isinstance(val, expected_type):
        # Strict typing prevents coercion bugs in the security boundary.
        raise TokenError("token_invalid", f"Claim absensi.{key} must be {expected_type.__name__}")

    return val


def _seconds(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _verify_signature(parts, header, config):
    """Verify the JWT signature in whichever mode the config selects."""
    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in config.algorithms:
        raise TokenError("token_invalid", "Token algorithm is not allowed")
    # "none" can never be in an allowlist, but refuse it explicitly as well.
    if alg.lower() == "none":
        raise TokenError("token_invalid", "Unsecured tokens are not accepted")

    signing_input = f"{parts[0]}.{parts[1]}".encode()
    signature = _decode(parts[2])

    if config.asymmetric_mode:
        if alg not in ASYMMETRIC_ALGORITHMS:
            raise TokenError(
                "token_invalid", "Symmetric algorithms are not accepted in JWKS mode"
            )
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise TokenError("token_invalid", "Token has no key id")
        try:
            public_key, declared_alg = config.key_resolver.resolve(kid)
        except (JwksUnavailable, UnsupportedKey) as error:
            # Fail closed: an unreachable or unusable JWKS never grants access.
            raise TokenError("token_invalid", "Token key could not be verified") from error
        if isinstance(declared_alg, str) and declared_alg != alg:
            raise TokenError("token_invalid", "Token algorithm does not match its key")
        try:
            verify_asymmetric_signature(alg, public_key, signing_input, signature)
        except (InvalidSignature, UnsupportedKey) as error:
            raise TokenError("token_invalid", "Token signature mismatch") from error
        return

    if not alg.startswith("HS"):
        raise TokenError("token_invalid", "Token algorithm is not allowed")
    secret = config.keys.get(header.get("kid"))
    if secret is None:
        raise TokenError("token_invalid", "Token key id is unknown")
    expected = hmac.new(secret, signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, signature):
        raise TokenError("token_invalid", "Token signature mismatch")


def verify_token(token, config, now=None):
    """Return a Principal built exclusively from verified claims."""
    now = time.time() if now is None else now
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        raise TokenError("token_invalid", "Token must have three segments")

    header = _decode_json(parts[0])
    _verify_signature(parts, header, config)

    claims = _decode_json(parts[1])
    if claims.get("iss") != config.issuer:
        raise TokenError("token_invalid", "Token issuer is not accepted")
    audience = claims.get("aud")
    audience = [audience] if isinstance(audience, str) else audience
    if not isinstance(audience, list) or config.audience not in audience:
        raise TokenError("token_invalid", "Token audience is not accepted")

    expires_at = _seconds(claims.get("exp"))
    if expires_at is None or now >= expires_at + config.clock_skew_seconds:
        raise TokenError("token_invalid", "Token is expired or has no exp")
    not_before = _seconds(claims.get("nbf"))
    if not_before is not None and now + config.clock_skew_seconds < not_before:
        raise TokenError("token_invalid", "Token is not valid yet")

    principal_type = _get_absensi_claim(claims, "principal_type", str)
    if principal_type not in {"machine", "user"}:
        grant_type = claims.get("grant_type")
        principal_type = GRANT_PRINCIPAL_TYPES.get(grant_type) if isinstance(grant_type, str) else None
    if principal_type is None:
        raise TokenError("token_invalid", "Token principal type is not supported")
    subject = claims.get("sub") if isinstance(claims.get("sub"), str) else None
    if principal_type == "user" and not subject:
        raise TokenError("token_invalid", "User-delegated token needs a human subject")

    client_id = claims.get("client_id") if isinstance(claims.get("client_id"), str) else None
    realm_access = claims.get("realm_access")
    roles = _string_set(realm_access.get("roles")) if isinstance(realm_access, dict) else frozenset()
    return Principal(
        principal_type=principal_type,
        subject=subject,
        client_id=client_id,
        scopes=_string_set(claims.get(config.scope_claim)),
        event_types=_string_set(_get_absensi_claim(claims, "event_types", list)),
        sites=_string_set(_get_absensi_claim(claims, "sites", list)),
        roles=roles,
    )
