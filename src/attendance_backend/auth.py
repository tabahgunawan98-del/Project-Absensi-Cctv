"""JWT verification for the ingress boundary.

Authorization is derived only from verified token claims; request bodies never
grant authority. ponytail: HS256 with locally configured shared keys only —
owner IdP, JWKS rotation, RS256/EdDSA, and revocation stay blocked until the
owner picks an identity provider; add them in `_verify_signature` / key lookup.
"""

import base64
import binascii
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field

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
    keys: dict  # kid -> shared secret (bytes)
    algorithms: frozenset = frozenset({"HS256"})
    clock_skew_seconds: int = 60  # provisional default; owner policy pending
    scope_claim: str = "scope"
    event_types_claim: str = "absensi.event_types"  # provisional claim name
    sites_claim: str = "absensi.sites"  # provisional claim name


@dataclass(frozen=True)
class Principal:
    principal_type: str
    subject: str | None
    client_id: str | None
    scopes: frozenset = field(default_factory=frozenset)
    event_types: frozenset = field(default_factory=frozenset)
    sites: frozenset = field(default_factory=frozenset)


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


def _seconds(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def verify_token(token, config, now=None):
    """Return a Principal built exclusively from verified claims."""
    now = time.time() if now is None else now
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        raise TokenError("token_invalid", "Token must have three segments")

    header = _decode_json(parts[0])
    if header.get("alg") not in config.algorithms:
        raise TokenError("token_invalid", "Token algorithm is not allowed")
    secret = config.keys.get(header.get("kid"))
    if secret is None:
        raise TokenError("token_invalid", "Token key id is unknown")
    expected = hmac.new(secret, f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, _decode(parts[2])):
        raise TokenError("token_invalid", "Token signature mismatch")

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

    grant_type = claims.get("grant_type")
    principal_type = GRANT_PRINCIPAL_TYPES.get(grant_type) if isinstance(grant_type, str) else None
    if principal_type is None:
        raise TokenError("token_invalid", "Token grant type is not supported")
    subject = claims.get("sub") if isinstance(claims.get("sub"), str) else None
    if principal_type == "user" and not subject:
        raise TokenError("token_invalid", "User-delegated token needs a human subject")

    client_id = claims.get("client_id") if isinstance(claims.get("client_id"), str) else None
    return Principal(
        principal_type=principal_type,
        subject=subject,
        client_id=client_id,
        scopes=_string_set(claims.get(config.scope_claim)),
        event_types=_string_set(claims.get(config.event_types_claim)),
        sites=_string_set(claims.get(config.sites_claim)),
    )
