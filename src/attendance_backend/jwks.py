"""JWKS key resolution and asymmetric JWT signing/verification helpers.

No key material is ever read from the process environment here: the caller
supplies a fetch callable bound to the owner's approved JWKS endpoint. The cache
is fail-closed — a fetch failure never falls back to previously cached keys once
the TTL has elapsed, because a revoked key must stop working.
"""

import base64
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)


class JwksUnavailable(Exception):
    """The JWKS document could not be fetched or parsed."""


class UnsupportedKey(Exception):
    """A JWK entry uses a key type or curve this verifier does not accept."""


#: alg -> (key class, whether the alg is asymmetric)
ASYMMETRIC_ALGORITHMS = {
    "RS256": rsa.RSAPublicKey,
    "RS384": rsa.RSAPublicKey,
    "RS512": rsa.RSAPublicKey,
    "ES256": ec.EllipticCurvePublicKey,
    "ES384": ec.EllipticCurvePublicKey,
    "EdDSA": ed25519.Ed25519PublicKey,
}

_RSA_HASHES = {"RS256": hashes.SHA256, "RS384": hashes.SHA384, "RS512": hashes.SHA512}
_EC_HASHES = {"ES256": hashes.SHA256, "ES384": hashes.SHA384}
_EC_CURVES = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1}
_EC_COORDINATE_BYTES = {"ES256": 32, "ES384": 48}


def b64u_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64u_decode(segment):
    if isinstance(segment, str):
        segment = segment.encode()
    return base64.urlsafe_b64decode(segment + b"=" * (-len(segment) % 4))


def _int_to_bytes(value, length=None):
    length = length or (value.bit_length() + 7) // 8 or 1
    return value.to_bytes(length, "big")


def jwk_from_public_key(public_key, *, kid):
    """Render a public key as a JWK entry (used by tests and local tooling)."""
    if isinstance(public_key, rsa.RSAPublicKey):
        numbers = public_key.public_numbers()
        return {
            "kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
            "n": b64u_encode(_int_to_bytes(numbers.n)),
            "e": b64u_encode(_int_to_bytes(numbers.e)),
        }
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        numbers = public_key.public_numbers()
        curve = {"secp256r1": "P-256", "secp384r1": "P-384"}.get(public_key.curve.name)
        if curve is None:
            raise UnsupportedKey(f"unsupported EC curve: {public_key.curve.name}")
        size = (public_key.curve.key_size + 7) // 8
        return {
            "kty": "EC", "kid": kid, "use": "sig", "crv": curve,
            "alg": "ES256" if curve == "P-256" else "ES384",
            "x": b64u_encode(_int_to_bytes(numbers.x, size)),
            "y": b64u_encode(_int_to_bytes(numbers.y, size)),
        }
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        raw = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return {
            "kty": "OKP", "kid": kid, "use": "sig", "crv": "Ed25519",
            "alg": "EdDSA", "x": b64u_encode(raw),
        }
    raise UnsupportedKey("unsupported public key type")


def public_key_from_jwk(entry):
    if not isinstance(entry, dict):
        raise UnsupportedKey("JWK entry must be an object")
    kty = entry.get("kty")
    try:
        if kty == "RSA":
            n = int.from_bytes(b64u_decode(entry["n"]), "big")
            e = int.from_bytes(b64u_decode(entry["e"]), "big")
            return rsa.RSAPublicNumbers(e, n).public_key()
        if kty == "EC":
            curve = _EC_CURVES.get(entry.get("crv"))
            if curve is None:
                raise UnsupportedKey(f"unsupported EC curve: {entry.get('crv')}")
            x = int.from_bytes(b64u_decode(entry["x"]), "big")
            y = int.from_bytes(b64u_decode(entry["y"]), "big")
            return ec.EllipticCurvePublicNumbers(x, y, curve()).public_key()
        if kty == "OKP":
            if entry.get("crv") != "Ed25519":
                raise UnsupportedKey(f"unsupported OKP curve: {entry.get('crv')}")
            return ed25519.Ed25519PublicKey.from_public_bytes(b64u_decode(entry["x"]))
    except UnsupportedKey:
        raise
    except Exception as error:  # malformed base64/int/point
        raise UnsupportedKey("JWK entry is malformed") from error
    raise UnsupportedKey(f"unsupported key type: {kty}")


class JwksCache:
    """TTL cache over a JWKS fetch callable, with one refresh on unknown kid.

    ponytail: in-process cache for a single-node runtime. A multi-instance
    deployment wants a shared cache or a sidecar refresher; add that when the
    owner approves the deployment topology.
    """

    def __init__(self, fetch, *, ttl_seconds, clock, refresh_cooldown_seconds=0):
        if ttl_seconds <= 0:
            raise JwksUnavailable("JWKS cache TTL must be positive")
        self.fetch = fetch
        self.ttl_seconds = ttl_seconds
        self.clock = clock
        self.refresh_cooldown_seconds = refresh_cooldown_seconds
        self._keys = None
        self._fetched_at = None
        self._last_refresh_attempt = None

    def _load(self):
        try:
            document = self.fetch()
        except JwksUnavailable:
            raise
        except Exception as error:
            raise JwksUnavailable("JWKS endpoint is unreachable") from error
        if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
            raise JwksUnavailable("JWKS document is malformed")
        keys = {}
        for entry in document["keys"]:
            if not isinstance(entry, dict) or not isinstance(entry.get("kid"), str):
                continue
            try:
                keys[entry["kid"]] = (public_key_from_jwk(entry), entry.get("alg"))
            except UnsupportedKey:
                continue  # a document may legitimately carry keys we do not use
        if not keys:
            raise JwksUnavailable("JWKS document has no usable keys")
        self._keys = keys
        self._fetched_at = self.clock()

    def _fresh(self):
        return (
            self._keys is not None
            and self._fetched_at is not None
            and self.clock() - self._fetched_at < self.ttl_seconds
        )

    def resolve(self, kid):
        """Return (public_key, declared_alg) or raise JwksUnavailable.

        Stale keys are never served: once the TTL elapses a failed refresh
        propagates, so a revoked signing key stops being accepted.
        """
        just_loaded = False
        if not self._fresh():
            self._keys = None
            self._load()
            just_loaded = True
        if kid in self._keys:
            return self._keys[kid]
        if just_loaded:
            # The document was fetched moments ago; re-fetching cannot help and
            # would let an unknown kid drive traffic at the IdP.
            raise JwksUnavailable("unknown key id")

        now = self.clock()
        if (
            self._last_refresh_attempt is not None
            and now - self._last_refresh_attempt < self.refresh_cooldown_seconds
        ):
            raise JwksUnavailable("unknown key id and refresh is on cooldown")
        self._last_refresh_attempt = now
        self._load()
        if kid not in self._keys:
            raise JwksUnavailable("unknown key id after refresh")
        return self._keys[kid]


def verify_asymmetric_signature(alg, public_key, signing_input, signature):
    """Raise InvalidSignature / UnsupportedKey; return None when the signature is valid."""
    expected_type = ASYMMETRIC_ALGORITHMS.get(alg)
    if expected_type is None:
        raise UnsupportedKey(f"algorithm is not asymmetric: {alg}")
    if not isinstance(public_key, expected_type):
        raise InvalidSignature("key type does not match the token algorithm")

    if alg.startswith("RS"):
        public_key.verify(
            signature, signing_input, padding.PKCS1v15(), _RSA_HASHES[alg]()
        )
        return
    if alg.startswith("ES"):
        size = _EC_COORDINATE_BYTES[alg]
        if len(signature) != size * 2:
            raise InvalidSignature("ECDSA signature has the wrong length")
        r = int.from_bytes(signature[:size], "big")
        s = int.from_bytes(signature[size:], "big")
        public_key.verify(
            encode_dss_signature(r, s), signing_input, ec.ECDSA(_EC_HASHES[alg]())
        )
        return
    public_key.verify(signature, signing_input)


def sign_jwt(claims, key, *, kid, alg):
    """Sign a JWT. Test/tooling helper — the runtime only ever verifies."""
    header = {"alg": alg, "kid": kid, "typ": "JWT"}
    signing_input = "{}.{}".format(
        b64u_encode(json.dumps(header, separators=(",", ":")).encode()),
        b64u_encode(json.dumps(claims, separators=(",", ":")).encode()),
    ).encode()

    if alg.startswith("HS"):
        import hashlib
        import hmac

        signature = hmac.new(key, signing_input, hashlib.sha256).digest()
    elif alg.startswith("RS"):
        signature = key.sign(signing_input, padding.PKCS1v15(), _RSA_HASHES[alg]())
    elif alg.startswith("ES"):
        size = _EC_COORDINATE_BYTES[alg]
        der = key.sign(signing_input, ec.ECDSA(_EC_HASHES[alg]()))
        r, s = decode_dss_signature(der)
        signature = _int_to_bytes(r, size) + _int_to_bytes(s, size)
    elif alg == "EdDSA":
        signature = key.sign(signing_input)
    else:
        raise UnsupportedKey(f"unsupported signing algorithm: {alg}")
    return f"{signing_input.decode()}.{b64u_encode(signature)}"
