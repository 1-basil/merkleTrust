"""core/crypto.py — Canonical encoding, hashing and ECDSA P-256 signatures.

Everything MerkleTrust signs (baselines, audit blocks, reports) goes through
this module, so the rules are defined once:

* **What is signed** is the canonical JSON encoding of a payload: UTF-8, keys
  sorted, no insignificant whitespace, ASCII-escaped, NaN/Infinity rejected.
  Two semantically equal payloads always produce identical bytes.
* **Algorithm**: ECDSA over NIST P-256 with SHA-256 (``ECDSA-P256-SHA256``),
  signatures DER-encoded and Base64-wrapped. Signatures are normalised to
  *low-S* form and high-S signatures are rejected, so a valid signature cannot
  be re-encoded into a second valid one (malleability).
* **Key identity**: ``key_id = "mt-" + first 16 hex chars of SHA-256(SPKI DER)``.
  The ID is derived from the public key itself, so it cannot be relabelled.
* **Key management (prototype)**: the private key is loaded from a path given by
  configuration (optionally password-encrypted). In development only, a key is
  created outside the repository (``~/.merkletrust/keys``) if none is configured.
  Production refuses to start without an explicit key. A real deployment should
  keep the key in an HSM / cloud KMS and sign through its API.
* **Verification** never creates keys and never raises: it returns a
  ``VerificationResult`` with a reason, and failures are logged.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import math
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from core.config import Settings, get_settings

log = logging.getLogger("merkletrust.crypto")

ALGORITHM = "ECDSA-P256-SHA256"
# Order of the P-256 base point.
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
DEV_KEY_FILENAME = "signing_key.pem"


class KeyConfigurationError(RuntimeError):
    """Signing key missing, unreadable, or of the wrong type."""


# ------------------------------------------------------------ encoding ----

def canonical_json(payload: Any) -> bytes:
    """Deterministic byte encoding of a JSON-compatible payload."""
    _reject_non_finite(payload)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _reject_non_finite(value: Any) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("NaN/Infinity cannot be canonically encoded")
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise TypeError("canonical JSON requires string keys")
            _reject_non_finite(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _reject_non_finite(v)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_payload(payload: Any) -> str:
    """SHA-256 of the canonical encoding — the fingerprint of a JSON payload."""
    return sha256_hex(canonical_json(payload))


# ---------------------------------------------------------------- keys ----

def key_id_for(public_key: ec.EllipticCurvePublicKey) -> str:
    spki = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return "mt-" + hashlib.sha256(spki).hexdigest()[:16]


def public_key_pem(public_key: ec.EllipticCurvePublicKey) -> str:
    return public_key.public_bytes(serialization.Encoding.PEM,
                                   serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")


def _require_p256(key: Any, what: str) -> None:
    if not isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)) \
            or not isinstance(key.curve, ec.SECP256R1):
        raise KeyConfigurationError(f"{what} must be an ECDSA P-256 key")


def _to_low_s(der_sig: bytes) -> bytes:
    r, s = decode_dss_signature(der_sig)
    if s > P256_ORDER // 2:
        s = P256_ORDER - s
    return encode_dss_signature(r, s)


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    reason: str
    key_id: str | None = None

    def __bool__(self) -> bool:  # allows `if verify(...):`
        return self.valid


class Signer:
    """Holds the active private signing key."""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey):
        _require_p256(private_key, "signing key")
        self._private_key = private_key
        self.public_key = private_key.public_key()
        self.key_id = key_id_for(self.public_key)

    def sign_bytes(self, message: bytes) -> str:
        der_sig = self._private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return base64.b64encode(_to_low_s(der_sig)).decode("ascii")

    def sign(self, payload: Any) -> dict[str, str]:
        """Sign the canonical encoding of `payload`; returns a signature envelope."""
        return {"alg": ALGORITHM, "key_id": self.key_id, "signature": self.sign_bytes(canonical_json(payload))}


class KeyRing:
    """Public keys accepted for verification, indexed by key ID."""

    def __init__(self, public_keys: list[ec.EllipticCurvePublicKey] | None = None):
        self._keys: dict[str, ec.EllipticCurvePublicKey] = {}
        for key in public_keys or []:
            self.add(key)

    def add(self, public_key: ec.EllipticCurvePublicKey) -> str:
        _require_p256(public_key, "trusted key")
        kid = key_id_for(public_key)
        self._keys[kid] = public_key
        return kid

    def key_ids(self) -> list[str]:
        return sorted(self._keys)

    def get(self, key_id: str) -> ec.EllipticCurvePublicKey | None:
        return self._keys.get(key_id)

    def verify_bytes(self, message: bytes, signature_b64: Any, key_id: Any) -> VerificationResult:
        key = self._keys.get(key_id) if isinstance(key_id, str) else None
        if key is None:
            return _fail(f"unknown or untrusted signing key {key_id!r}", key_id)
        if not isinstance(signature_b64, str):
            return _fail("signature missing", key_id)
        try:
            der_sig = base64.b64decode(signature_b64, validate=True)
            _r, s = decode_dss_signature(der_sig)
        except (binascii.Error, ValueError):
            return _fail("signature is not valid Base64/DER", key_id)
        if s > P256_ORDER // 2:
            return _fail("non-canonical (high-S) signature rejected", key_id)
        try:
            key.verify(der_sig, message, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return _fail("signature does not match the signed data", key_id)
        return VerificationResult(True, "signature valid", key_id)

    def verify(self, payload: Any, envelope: Any) -> VerificationResult:
        """Verify a signature envelope produced by Signer.sign over `payload`."""
        if not isinstance(envelope, dict):
            return _fail("signature envelope missing", None)
        if envelope.get("alg") != ALGORITHM:
            return _fail(f"unsupported signature algorithm {envelope.get('alg')!r}", envelope.get("key_id"))
        try:
            message = canonical_json(payload)
        except (TypeError, ValueError) as exc:
            return _fail(f"payload cannot be canonically encoded ({exc})", envelope.get("key_id"))
        return self.verify_bytes(message, envelope.get("signature"), envelope.get("key_id"))


def _fail(reason: str, key_id: Any) -> VerificationResult:
    log.warning("signature verification failed: %s (key_id=%s)", reason, key_id)
    return VerificationResult(False, reason, key_id if isinstance(key_id, str) else None)


# ------------------------------------------------------ configuration ----

def load_private_key(path: Path, password: str | None = None) -> ec.EllipticCurvePrivateKey:
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise KeyConfigurationError(f"cannot read signing key at {path}: {exc.strerror}") from None
    try:
        key = serialization.load_pem_private_key(data, password=password.encode() if password else None)
    except (ValueError, TypeError) as exc:
        raise KeyConfigurationError(f"cannot load signing key at {path}: {exc}") from None
    _require_p256(key, "signing key")
    return key


def write_private_key(key: ec.EllipticCurvePrivateKey, path: Path, password: str | None = None) -> None:
    """Write a PKCS#8 PEM key with owner-only permissions where the OS supports it."""
    enc = (serialization.BestAvailableEncryption(password.encode()) if password
           else serialization.NoEncryption())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)


def load_signer(settings: Settings | None = None) -> Signer:
    settings = settings or get_settings()
    password = settings.signing_key_password.get_secret_value() if settings.signing_key_password else None
    if settings.signing_key_path:
        return Signer(load_private_key(settings.signing_key_path, password))
    if settings.is_production:
        raise KeyConfigurationError("MERKLETRUST_SIGNING_KEY_PATH must be set in production")
    dev_path = Path(settings.dev_key_dir) / DEV_KEY_FILENAME
    if not dev_path.exists():
        write_private_key(ec.generate_private_key(ec.SECP256R1()), dev_path)
        log.warning("created DEVELOPMENT signing key at %s — do not use in production", dev_path)
    return Signer(load_private_key(dev_path))


def load_keyring(signer: Signer, settings: Settings | None = None) -> KeyRing:
    settings = settings or get_settings()
    ring = KeyRing([signer.public_key])
    if settings.trusted_keys_dir:
        for pem in sorted(Path(settings.trusted_keys_dir).glob("*.pem")):
            try:
                key = serialization.load_pem_public_key(pem.read_bytes())
                ring.add(key)
            except (ValueError, KeyConfigurationError) as exc:
                raise KeyConfigurationError(f"invalid trusted key {pem.name}: {exc}") from None
    return ring


@lru_cache
def get_signer() -> Signer:
    return load_signer()


@lru_cache
def get_keyring() -> KeyRing:
    return load_keyring(get_signer())


def reset_key_cache() -> None:
    """For tests / key rotation: forget cached settings and keys."""
    get_settings.cache_clear()
    get_signer.cache_clear()
    get_keyring.cache_clear()
