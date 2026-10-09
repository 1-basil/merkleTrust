"""Tests for canonical encoding and ECDSA P-256 signing / verification."""

import base64
import math

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from core.config import Settings
from core.crypto import (ALGORITHM, P256_ORDER, KeyConfigurationError, KeyRing, Signer, canonical_json,
                         hash_payload, key_id_for, load_keyring, load_signer, write_private_key)

pytestmark = pytest.mark.unit

PAYLOAD = {"baseline_id": 7, "package": "com.merkletrust.demo", "files": [{"path": "classes.dex", "sha256": "ab" * 32}]}


@pytest.fixture
def signer():
    return Signer(ec.generate_private_key(ec.SECP256R1()))


@pytest.fixture
def ring(signer):
    return KeyRing([signer.public_key])


# ------------------------------------------------------------ encoding --

def test_canonical_json_is_order_independent():
    assert canonical_json({"b": 1, "a": [2, {"d": 1, "c": 2}]}) == b'{"a":[2,{"c":2,"d":1}],"b":1}'
    assert canonical_json({"a": 1, "b": 2}) == canonical_json({"b": 2, "a": 1})


def test_canonical_json_escapes_unicode():
    assert canonical_json({"name": "café"}) == b'{"name":"caf\\u00e9"}'


@pytest.mark.parametrize("bad", [{"x": math.nan}, {"x": [math.inf]}, {1: "int key"}])
def test_canonical_json_rejects_ambiguous_values(bad):
    with pytest.raises((ValueError, TypeError)):
        canonical_json(bad)


def test_hash_payload_changes_with_any_field():
    h = hash_payload(PAYLOAD)
    assert len(h) == 64
    assert hash_payload({**PAYLOAD, "baseline_id": 8}) != h


# ------------------------------------------------------------- signing --

def test_sign_and_verify(signer, ring):
    env = signer.sign(PAYLOAD)
    assert env["alg"] == ALGORITHM and env["key_id"] == signer.key_id
    result = ring.verify(PAYLOAD, env)
    assert result.valid and result.key_id == signer.key_id


def test_modified_payload_fails(signer, ring):
    env = signer.sign(PAYLOAD)
    tampered = {**PAYLOAD, "files": [{"path": "classes.dex", "sha256": "cd" * 32}]}
    result = ring.verify(tampered, env)
    assert not result.valid
    assert "does not match" in result.reason


def test_wrong_public_key_fails(signer):
    other = Signer(ec.generate_private_key(ec.SECP256R1()))
    assert not KeyRing([other.public_key]).verify(PAYLOAD, signer.sign(PAYLOAD)).valid


def test_relabelled_key_id_fails(signer, ring):
    """An attacker signs with their own key but claims our key ID."""
    attacker = Signer(ec.generate_private_key(ec.SECP256R1()))
    env = attacker.sign(PAYLOAD)
    env["key_id"] = signer.key_id
    assert not ring.verify(PAYLOAD, env).valid


@pytest.mark.parametrize("mutate", [
    lambda e: e.update(signature="not base64!!"),
    lambda e: e.update(signature=base64.b64encode(b"\x30\x02\x01\x01").decode()),
    lambda e: e.update(signature=None),
    lambda e: e.update(alg="RS256"),
    lambda e: e.update(key_id="mt-0000000000000000"),
    lambda e: e.pop("key_id"),
])
def test_invalid_envelopes_fail_without_raising(signer, ring, mutate):
    env = signer.sign(PAYLOAD)
    mutate(env)
    assert ring.verify(PAYLOAD, env).valid is False


def test_flipped_signature_bit_fails(signer, ring):
    env = signer.sign(PAYLOAD)
    sig = bytearray(base64.b64decode(env["signature"]))
    sig[-1] ^= 0x01
    env["signature"] = base64.b64encode(bytes(sig)).decode()
    assert not ring.verify(PAYLOAD, env).valid


def test_signatures_are_low_s_and_high_s_is_rejected(signer, ring):
    env = signer.sign(PAYLOAD)
    r, s = decode_dss_signature(base64.b64decode(env["signature"]))
    assert s <= P256_ORDER // 2
    malleated = encode_dss_signature(r, P256_ORDER - s)  # mathematically valid twin
    result = ring.verify(PAYLOAD, {**env, "signature": base64.b64encode(malleated).decode()})
    assert not result.valid and "high-S" in result.reason


def test_non_p256_keys_rejected():
    with pytest.raises(KeyConfigurationError):
        Signer(ec.generate_private_key(ec.SECP384R1()))
    with pytest.raises(KeyConfigurationError):
        KeyRing([ec.generate_private_key(ec.SECP384R1()).public_key()])


def test_key_id_is_derived_from_public_key(signer):
    assert key_id_for(signer.public_key) == signer.key_id
    assert signer.key_id.startswith("mt-") and len(signer.key_id) == 19


# ------------------------------------------------------- configuration --

def test_load_configured_encrypted_key(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    path = tmp_path / "k.pem"
    write_private_key(key, path, password="correct horse battery")
    s = load_signer(Settings(env="production", signing_key_path=path, signing_key_password="correct horse battery"))
    assert s.key_id == key_id_for(key.public_key())
    with pytest.raises(KeyConfigurationError):
        load_signer(Settings(env="production", signing_key_path=path, signing_key_password="wrong password!!"))


def test_production_requires_explicit_key(tmp_path):
    with pytest.raises(KeyConfigurationError, match="must be set in production"):
        load_signer(Settings(env="production", dev_key_dir=tmp_path))
    assert not any(tmp_path.iterdir())


def test_missing_key_file_is_reported(tmp_path):
    with pytest.raises(KeyConfigurationError, match="cannot read"):
        load_signer(Settings(env="production", signing_key_path=tmp_path / "missing.pem"))


def test_development_key_created_once_outside_repo(tmp_path):
    settings = Settings(env="development", dev_key_dir=tmp_path / "keys")
    first = load_signer(settings)
    second = load_signer(settings)
    assert first.key_id == second.key_id
    assert (tmp_path / "keys" / "signing_key.pem").exists()


def test_rotated_key_still_verifies_old_signatures(tmp_path):
    old = Signer(ec.generate_private_key(ec.SECP256R1()))
    old_env = old.sign(PAYLOAD)
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    (trusted / "old.pem").write_bytes(old.public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    new_key = tmp_path / "new.pem"
    write_private_key(ec.generate_private_key(ec.SECP256R1()), new_key)
    settings = Settings(env="production", signing_key_path=new_key, trusted_keys_dir=trusted)
    new = load_signer(settings)
    ring = load_keyring(new, settings)
    assert set(ring.key_ids()) == {old.key_id, new.key_id}
    assert ring.verify(PAYLOAD, old_env).valid
    assert ring.verify(PAYLOAD, new.sign(PAYLOAD)).valid


def test_generate_key_script_refuses_repo_paths(tmp_path):
    from scripts.generate_signing_key import REPO_ROOT, main
    assert main(["--out", str(REPO_ROOT / "data" / "x.pem")]) == 2
    assert not (REPO_ROOT / "data" / "x.pem").exists()
    assert main(["--out", str(tmp_path / "k.pem")]) == 0
    assert (tmp_path / "k.pem").exists() and (tmp_path / "k.pub.pem").exists()


def test_cloud_kms_provider_signing_and_verification():
    from core.crypto import CloudKmsProvider
    kms_provider = CloudKmsProvider(provider="mock", key_id="projects/test/keys/sign-1")
    signer = Signer(kms_provider)
    assert signer.provider.provider_type == "cloud_kms_mock"
    env = signer.sign(PAYLOAD)
    assert env["alg"] == "ECDSA-P256-SHA256"
    assert env["key_id"] == signer.key_id
    ring = KeyRing([signer.public_key])
    res = ring.verify(PAYLOAD, env)
    assert res.valid is True


def test_pkcs11_provider_signing_and_verification():
    from core.crypto import PKCS11Provider
    p11_provider = PKCS11Provider(token_label="YubiKey-Audit-01")
    signer = Signer(p11_provider)
    assert signer.provider.provider_type == "pkcs11"
    env = signer.sign(PAYLOAD)
    ring = KeyRing([signer.public_key])
    assert ring.verify(PAYLOAD, env).valid is True


def test_load_signer_with_kms_settings():
    settings = Settings(env="production", kms_provider="mock", kms_key_id="projects/p/keys/k1")
    signer = load_signer(settings)
    assert signer.provider.provider_type == "cloud_kms_mock"
    env = signer.sign(PAYLOAD)
    assert KeyRing([signer.public_key]).verify(PAYLOAD, env).valid is True
