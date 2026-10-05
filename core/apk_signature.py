"""core/apk_signature.py — APK signing certificate extraction and signature verification.

Implements, in pure Python on top of ``cryptography``:

* **APK Signature Scheme v2 / v3** (https://source.android.com/docs/security/features/apksigning/v2):
  locate the APK Signing Block, parse signers, verify the signature over
  ``signed data`` with the signer's public key, check that the public key
  matches the first certificate, and recompute the chunked content digest
  (1 MiB chunks over: entries | central directory | EOCD) to prove that no byte
  of the protected sections changed.
* **v1 (JAR) signing**: verify every entry digest in ``META-INF/MANIFEST.MF``,
  verify the ``.SF`` digests of the manifest, and verify the PKCS#7 signature
  over the ``.SF`` file. Entries not covered by the manifest are reported.
* **Stripping protection**: a v1 ``.SF`` that declares ``X-Android-APK-Signed: 2``
  while no v2 block exists means the v2 signature was stripped.

Limits (documented honestly): v3 key-rotation lineage is reported but not
validated; verity-only (0x0421/0x0423/0x0425) content digests and DSA keys are
reported as "unverifiable" rather than guessed.
"""

from __future__ import annotations

import base64
import hashlib
import re
import struct
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7

from core import der
from core.apk_archive import ApkArchive, ApkValidationError

APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
V2_BLOCK_ID = 0x7109871A
V3_BLOCK_ID = 0xF05368C0
V31_BLOCK_ID = 0x1B93AD61
CHUNK_SIZE = 1024 * 1024

# algorithm id -> (content digest hash, signature verifier kind, signature hash)
SIG_ALGORITHMS: dict[int, tuple[Any, str, Any]] = {
    0x0101: (hashes.SHA256, "rsa-pss", hashes.SHA256),
    0x0102: (hashes.SHA512, "rsa-pss", hashes.SHA512),
    0x0103: (hashes.SHA256, "rsa-pkcs1", hashes.SHA256),
    0x0104: (hashes.SHA512, "rsa-pkcs1", hashes.SHA512),
    0x0201: (hashes.SHA256, "ecdsa", hashes.SHA256),
    0x0202: (hashes.SHA512, "ecdsa", hashes.SHA512),
}
ALGORITHM_NAMES = {
    0x0101: "RSASSA-PSS with SHA2-256", 0x0102: "RSASSA-PSS with SHA2-512",
    0x0103: "RSASSA-PKCS1-v1_5 with SHA2-256", 0x0104: "RSASSA-PKCS1-v1_5 with SHA2-512",
    0x0201: "ECDSA with SHA2-256", 0x0202: "ECDSA with SHA2-512", 0x0301: "DSA with SHA2-256",
    0x0421: "RSASSA-PKCS1-v1_5 with SHA2-256 (verity)", 0x0423: "ECDSA with SHA2-256 (verity)",
    0x0425: "DSA with SHA2-256 (verity)",
}
# Preference order when a signer offers several algorithms (strongest first).
ALGORITHM_PREFERENCE = [0x0102, 0x0104, 0x0202, 0x0101, 0x0103, 0x0201]

V1_SIG_FILE_RE = re.compile(r"^META-INF/[^/]+\.(SF|RSA|DSA|EC)$", re.IGNORECASE)
JAR_DIGESTS = {"SHA-256": hashes.SHA256, "SHA-384": hashes.SHA384, "SHA-512": hashes.SHA512,
               "SHA1": hashes.SHA1, "SHA-1": hashes.SHA1}


class SignatureFormatError(ValueError):
    pass


# ------------------------------------------------------------------ certs --

def certificate_info(cert: x509.Certificate) -> dict[str, Any]:
    """Human- and machine-readable summary of an X.509 signing certificate."""
    der_bytes = cert.public_bytes(serialization.Encoding.DER)
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        key = {"algorithm": "RSA", "size": pub.key_size}
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        key = {"algorithm": "EC", "size": pub.curve.key_size, "curve": pub.curve.name}
    else:
        key = {"algorithm": type(pub).__name__.replace("PublicKey", "").lstrip("_"), "size": None}
    try:
        sig_alg = cert.signature_algorithm_oid._name
    except AttributeError:
        sig_alg = cert.signature_algorithm_oid.dotted_string
    now = datetime.now(timezone.utc)
    subject = cert.subject.rfc4514_string()
    return {
        "sha256": hashlib.sha256(der_bytes).hexdigest(),
        "sha1": hashlib.sha1(der_bytes).hexdigest(),
        "subject": subject,
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": format(cert.serial_number, "x"),
        "valid_from": cert.not_valid_before_utc.isoformat(),
        "valid_to": cert.not_valid_after_utc.isoformat(),
        "expired": cert.not_valid_after_utc < now,
        "not_yet_valid": cert.not_valid_before_utc > now,
        "signature_algorithm": sig_alg,
        "public_key": key,
        "self_signed": cert.issuer == cert.subject,
        "debug_certificate": "CN=Android Debug" in subject,
    }


def _verify_raw(pub, signature: bytes, message: bytes, kind: str, hash_cls) -> None:
    """Verify a signature; raises InvalidSignature or SignatureFormatError."""
    if kind == "ecdsa":
        if not isinstance(pub, ec.EllipticCurvePublicKey):
            raise SignatureFormatError("algorithm/key mismatch (expected EC key)")
        pub.verify(signature, message, ec.ECDSA(hash_cls()))
    elif kind in ("rsa-pkcs1", "rsa-pss"):
        if not isinstance(pub, rsa.RSAPublicKey):
            raise SignatureFormatError("algorithm/key mismatch (expected RSA key)")
        pad = (padding.PKCS1v15() if kind == "rsa-pkcs1"
               else padding.PSS(mgf=padding.MGF1(hash_cls()), salt_length=hash_cls.digest_size))
        pub.verify(signature, message, pad, hash_cls())
    else:
        raise SignatureFormatError(f"unsupported signature kind {kind}")


# ------------------------------------------------------- zip structure ----

def _find_eocd(data: bytes) -> int:
    end = len(data)
    for pos in range(end - 22, max(-1, end - 22 - 65535 - 1), -1):
        if data[pos:pos + 4] == b"PK\x05\x06":
            (comment_len,) = struct.unpack_from("<H", data, pos + 20)
            if pos + 22 + comment_len == end:
                return pos
    raise SignatureFormatError("ZIP end-of-central-directory record not found")


def locate_signing_block(data: bytes) -> dict[str, Any] | None:
    """Return offsets of the APK Signing Block and its id->value pairs, or None."""
    eocd = _find_eocd(data)
    cd_size, cd_off = struct.unpack_from("<II", data, eocd + 12)
    if cd_off == 0xFFFFFFFF:
        raise SignatureFormatError("ZIP64 archives are not supported")
    if cd_off + cd_size != eocd:
        raise SignatureFormatError("central directory is not immediately followed by EOCD")
    if cd_off < 32 or data[cd_off - 16:cd_off] != APK_SIG_BLOCK_MAGIC:
        return None
    (size_footer,) = struct.unpack_from("<Q", data, cd_off - 24)
    block_start = cd_off - size_footer - 8
    if block_start < 0 or size_footer < 24:
        raise SignatureFormatError("APK Signing Block size out of range")
    (size_header,) = struct.unpack_from("<Q", data, block_start)
    if size_header != size_footer:
        raise SignatureFormatError("APK Signing Block header/footer sizes differ")
    pairs: dict[int, bytes] = {}
    pos, end = block_start + 8, cd_off - 24
    while pos < end:
        if pos + 12 > end:
            raise SignatureFormatError("truncated ID-value pair")
        (length,) = struct.unpack_from("<Q", data, pos)
        if length < 4 or pos + 8 + length > end:
            raise SignatureFormatError("ID-value pair length out of range")
        (pair_id,) = struct.unpack_from("<I", data, pos + 8)
        pairs[pair_id] = data[pos + 12:pos + 8 + length]
        pos += 8 + length
    return {"block_offset": block_start, "cd_offset": cd_off, "cd_size": cd_size,
            "eocd_offset": eocd, "pairs": pairs}


def content_digest(data: bytes, loc: dict[str, Any], hash_cls) -> bytes:
    """Chunked APK content digest as defined by APK Signature Scheme v2."""
    eocd = bytearray(data[loc["eocd_offset"]:])
    struct.pack_into("<I", eocd, 16, loc["block_offset"])  # CD offset -> signing block offset
    sections = [memoryview(data)[:loc["block_offset"]],
                memoryview(data)[loc["cd_offset"]:loc["cd_offset"] + loc["cd_size"]],
                memoryview(bytes(eocd))]
    chunk_digests = []
    for section in sections:
        for start in range(0, len(section), CHUNK_SIZE):
            chunk = section[start:start + CHUNK_SIZE]
            h = hashlib.new(hash_cls.name)
            h.update(b"\xa5" + struct.pack("<I", len(chunk)))
            h.update(chunk)
            chunk_digests.append(h.digest())
    top = hashlib.new(hash_cls.name)
    top.update(b"\x5a" + struct.pack("<I", len(chunk_digests)))
    for d in chunk_digests:
        top.update(d)
    return top.digest()


# ---------------------------------------------------------------- v2/v3 ----

def _lp(buf: bytes, pos: int) -> tuple[bytes, int]:
    if pos + 4 > len(buf):
        raise SignatureFormatError("truncated length-prefixed field")
    (n,) = struct.unpack_from("<I", buf, pos)
    if pos + 4 + n > len(buf):
        raise SignatureFormatError("length-prefixed field exceeds buffer")
    return buf[pos + 4:pos + 4 + n], pos + 4 + n


def _lp_seq(buf: bytes) -> list[bytes]:
    items, pos = [], 0
    while pos < len(buf):
        item, pos = _lp(buf, pos)
        items.append(item)
    return items


def _verify_scheme_block(data: bytes, loc: dict[str, Any], value: bytes, version: int) -> dict[str, Any]:
    """Verify every signer of a v2 (version=2) or v3 (version=3) block."""
    result: dict[str, Any] = {"present": True, "verified": False, "signers": [], "errors": [],
                              "algorithms": []}
    digest_cache: dict[str, bytes] = {}
    try:
        signers_seq, _ = _lp(value, 0)
        signers = _lp_seq(signers_seq)
        if not signers:
            raise SignatureFormatError("no signers")
        for signer in signers:
            signed_data, pos = _lp(signer, 0)
            if version == 3:
                pos += 8  # min/max SDK
            signatures_raw, pos = _lp(signer, pos)
            public_key_der, pos = _lp(signer, pos)

            sigs = {}
            for item in _lp_seq(signatures_raw):
                (alg,) = struct.unpack_from("<I", item, 0)
                sig, _ = _lp(item, 4)
                sigs[alg] = sig
            result["algorithms"].extend(ALGORITHM_NAMES.get(a, hex(a)) for a in sigs)
            chosen = next((a for a in ALGORITHM_PREFERENCE if a in sigs), None)
            if chosen is None:
                result["errors"].append("no supported signature algorithm (verity/DSA only): unverifiable")
                result["unverifiable"] = True
                continue
            digests_raw, p = _lp(signed_data, 0)
            certs_raw, p = _lp(signed_data, p)
            certs = [x509.load_der_x509_certificate(c) for c in _lp_seq(certs_raw)]
            if not certs:
                result["errors"].append("signer has no certificates")
                continue
            result.setdefault("claimed_certificate", certificate_info(certs[0]))

            digest_hash, kind, sig_hash = SIG_ALGORITHMS[chosen]
            pub = serialization.load_der_public_key(public_key_der)
            try:
                _verify_raw(pub, sigs[chosen], signed_data, kind, sig_hash)
            except InvalidSignature:
                result["errors"].append("signature over signed data is INVALID")
                continue

            digests = {}
            for item in _lp_seq(digests_raw):
                (alg,) = struct.unpack_from("<I", item, 0)
                digests[alg], _ = _lp(item, 4)
            if set(digests) != set(sigs):
                result["errors"].append("digest and signature algorithm lists differ")
                continue
            cert_pub = certs[0].public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            if cert_pub != public_key_der:
                result["errors"].append("signer public key does not match its certificate")
                continue

            key = digest_hash.name
            if key not in digest_cache:
                digest_cache[key] = content_digest(data, loc, digest_hash)
            if digest_cache[key] != digests[chosen]:
                result["errors"].append("APK content digest mismatch — protected bytes were modified")
                continue
            result["signers"].append({"algorithm": ALGORITHM_NAMES[chosen],
                                      "certificate": certificate_info(certs[0]),
                                      "_cert": certs[0]})
    except (SignatureFormatError, ValueError, struct.error) as exc:
        result["errors"].append(f"malformed signature block: {exc}")
    result["verified"] = bool(result["signers"]) and not result["errors"]
    return result


# ------------------------------------------------------------------- v1 ----

def _manifest_sections(raw: bytes) -> list[tuple[bytes, dict[str, str]]]:
    """Split a JAR manifest into (raw section bytes, attributes) preserving bytes exactly."""
    sections: list[tuple[bytes, dict[str, str]]] = []
    lines = raw.splitlines(keepends=True)
    current_raw = b""
    attrs: dict[str, str] = {}
    last_key = None
    for line in lines:
        current_raw += line
        stripped = line.rstrip(b"\r\n")
        if not stripped:
            if attrs or current_raw.strip():
                sections.append((current_raw, attrs))
            current_raw, attrs, last_key = b"", {}, None
            continue
        text = stripped.decode("utf-8", errors="replace")
        if text.startswith(" ") and last_key:
            attrs[last_key] += text[1:]
        elif ":" in text:
            k, v = text.split(":", 1)
            last_key = k.strip()
            attrs[last_key] = v.strip()
    if current_raw.strip():
        sections.append((current_raw, attrs))
    return sections


def _digest_attr(attrs: dict[str, str], suffix: str) -> tuple[str, str] | None:
    for alg in JAR_DIGESTS:
        key = f"{alg}-Digest{suffix}"
        if key in attrs:
            return alg, attrs[key]
    return None


def _b64_digest(alg: str, data: bytes) -> str:
    return base64.b64encode(hashlib.new(JAR_DIGESTS[alg].name, data).digest()).decode()


def verify_v1(archive: ApkArchive) -> dict[str, Any]:
    sig_files = [n for n in archive.names() if V1_SIG_FILE_RE.match(n)]
    sf_names = [n for n in sig_files if n.upper().endswith(".SF")]
    result: dict[str, Any] = {"present": bool(sf_names), "verified": False, "signers": [], "errors": [],
                              "mismatched_entries": [], "missing_entries": [], "unsigned_entries": [],
                              "apk_signed_claims": []}
    if not sf_names:
        return result
    if not archive.has("META-INF/MANIFEST.MF"):
        result["errors"].append("META-INF/MANIFEST.MF missing")
        return result

    mf_raw = archive.read("META-INF/MANIFEST.MF")
    mf_sections = _manifest_sections(mf_raw)
    mf_by_name = {attrs["Name"]: (raw, attrs) for raw, attrs in mf_sections[1:] if "Name" in attrs}

    # 1. Every manifest entry digest must match the archive content.
    for name, (_raw, attrs) in mf_by_name.items():
        dig = _digest_attr(attrs, "")
        if dig is None:
            continue
        if not archive.has(name):
            result["missing_entries"].append(name)
            continue
        alg, expected = dig
        if _b64_digest(alg, archive.read(name)) != expected:
            result["mismatched_entries"].append(name)

    # 2. Every non-signature entry must be covered by the manifest.
    for entry in archive.files():
        n = entry.name
        if n == "META-INF/MANIFEST.MF" or V1_SIG_FILE_RE.match(n) or n.startswith("META-INF/SIG-"):
            continue
        if n not in mf_by_name:
            result["unsigned_entries"].append(n)

    if result["mismatched_entries"]:
        result["errors"].append(f"{len(result['mismatched_entries'])} file(s) do not match their signed digest")
    if result["missing_entries"]:
        result["errors"].append(f"{len(result['missing_entries'])} signed file(s) are missing")
    if result["unsigned_entries"]:
        result["errors"].append(f"{len(result['unsigned_entries'])} file(s) are not covered by the signature")

    # 3. Each .SF must match the manifest and carry a valid PKCS#7 signature.
    for sf_name in sf_names:
        base = sf_name[:-3]
        block_name = next((n for n in sig_files if n.upper() in
                           (f"{base}.RSA".upper(), f"{base}.EC".upper(), f"{base}.DSA".upper())), None)
        if block_name is None:
            result["errors"].append(f"{sf_name}: signature block file missing")
            continue
        sf_raw = archive.read(sf_name)
        sf_sections = _manifest_sections(sf_raw)
        sf_main = sf_sections[0][1] if sf_sections else {}
        claims = sf_main.get("X-Android-APK-Signed", "")
        result["apk_signed_claims"] = sorted({int(c) for c in re.findall(r"\d+", claims)})

        whole = _digest_attr(sf_main, "-Manifest")
        manifest_ok = whole is not None and _b64_digest(whole[0], mf_raw) == whole[1]
        if not manifest_ok:
            # Fall back to per-section digests, as the JAR spec allows.
            section_ok = True
            for _raw, attrs in sf_sections[1:]:
                name = attrs.get("Name")
                dig = _digest_attr(attrs, "")
                if not name or not dig or name not in mf_by_name:
                    section_ok = False
                    break
                if _b64_digest(dig[0], mf_by_name[name][0]) != dig[1]:
                    section_ok = False
                    break
            manifest_ok = section_ok and len(sf_sections) > 1
        if not manifest_ok:
            result["errors"].append(f"{sf_name}: digest of MANIFEST.MF does not match")

        block = archive.read(block_name)
        try:
            certs = pkcs7.load_der_pkcs7_certificates(block)
            infos = der.parse_pkcs7_signer_infos(block)
        except (ValueError, der.DerError) as exc:
            result["errors"].append(f"{block_name}: malformed PKCS#7 ({exc})")
            continue
        if not infos:
            result["errors"].append(f"{block_name}: no SignerInfo")
            continue
        si = infos[0]
        cert = next((c for c in certs if c.serial_number == si.serial_number
                     and c.issuer.public_bytes() == si.issuer_der), None)
        if cert is None:
            result["errors"].append(f"{block_name}: signer certificate not found")
            continue
        result.setdefault("claimed_certificate", certificate_info(cert))
        hash_cls = JAR_DIGESTS.get(si.digest_algorithm)
        if hash_cls is None:
            result["errors"].append(f"{block_name}: unsupported digest {si.digest_algorithm}")
            continue
        if si.signed_attrs_der is not None:
            if si.message_digest != hashlib.new(hash_cls.name, sf_raw).digest():
                result["errors"].append(f"{block_name}: messageDigest does not match {sf_name}")
                continue
            signed_bytes = si.signed_attrs_der
        else:
            signed_bytes = sf_raw
        pub = cert.public_key()
        kind = "ecdsa" if isinstance(pub, ec.EllipticCurvePublicKey) else "rsa-pkcs1" \
            if isinstance(pub, rsa.RSAPublicKey) else "unsupported"
        try:
            _verify_raw(pub, si.signature, signed_bytes, kind, hash_cls)
        except InvalidSignature:
            result["errors"].append(f"{block_name}: PKCS#7 signature over {sf_name} is INVALID")
            continue
        except SignatureFormatError as exc:
            result["errors"].append(f"{block_name}: {exc}")
            result["unverifiable"] = True
            continue
        result["signers"].append({"algorithm": f"{si.digest_algorithm} with {kind.upper()}",
                                  "certificate": certificate_info(cert), "_cert": cert})

    result["verified"] = bool(result["signers"]) and not result["errors"]
    return result


# ------------------------------------------------------------- overall ----

def verify_apk(archive: ApkArchive, target_sdk: int | None = None) -> dict[str, Any]:
    """Verify all signature schemes present in the APK.

    ``target_sdk`` enables Android's install policy check: apps targeting
    API 30+ must carry a v2 or later signature (a valid v1-only signature is
    then rejected by the platform, and by apksigner).

    Returns {"status": "verified"|"invalid"|"unsigned"|"unverifiable",
             "schemes": {"v1": ..., "v2": ..., "v3": ...},
             "certificate": <primary signer certificate info or {}>,
             "errors": [...]}
    """
    with open(archive.path, "rb") as fh:
        data = fh.read()

    schemes: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    try:
        loc = locate_signing_block(data)
    except SignatureFormatError as exc:
        loc = None
        errors.append(f"APK structure: {exc}")

    empty = {"present": False, "verified": False, "signers": [], "errors": []}
    pairs = loc["pairs"] if loc else {}
    schemes["v2"] = _verify_scheme_block(data, loc, pairs[V2_BLOCK_ID], 2) if V2_BLOCK_ID in pairs else dict(empty)
    schemes["v3"] = _verify_scheme_block(data, loc, pairs[V3_BLOCK_ID], 3) if V3_BLOCK_ID in pairs else dict(empty)
    if V31_BLOCK_ID in pairs:
        schemes["v3"]["v31_present"] = True
    try:
        schemes["v1"] = verify_v1(archive)
    except ApkValidationError as exc:
        schemes["v1"] = {**empty, "present": True, "errors": [str(exc)]}

    v1 = schemes["v1"]
    if 2 in v1.get("apk_signed_claims", []) and not schemes["v2"]["present"]:
        errors.append("v1 signature declares a v2 signature that is missing (signature stripping)")
    if 3 in v1.get("apk_signed_claims", []) and not schemes["v3"]["present"]:
        errors.append("v1 signature declares a v3 signature that is missing (signature stripping)")

    present = [k for k in ("v1", "v2", "v3") if schemes[k]["present"]]
    if target_sdk is not None and target_sdk >= 30 and present == ["v1"]:
        errors.append(f"policy: targetSdkVersion {target_sdk} requires APK Signature Scheme v2 or later; "
                      "only a v1 signature is present")
    for k in present:
        errors.extend(f"{k}: {e}" for e in schemes[k]["errors"])

    # All verified schemes must agree on the signer certificate.
    fingerprints = {s["certificate"]["sha256"] for k in present for s in schemes[k]["signers"]}
    if len(fingerprints) > 1 and not schemes["v3"]["present"]:
        errors.append("signature schemes disagree about the signing certificate")

    primary = None
    for k in ("v3", "v2", "v1"):
        if schemes[k]["signers"]:
            primary = schemes[k]["signers"][0]["certificate"]
            break
    certificate_verified = primary is not None and not errors
    if primary is None:
        primary = next((schemes[k]["claimed_certificate"] for k in ("v3", "v2", "v1")
                        if schemes[k].get("claimed_certificate")), None)

    if not present:
        # A corrupt signing block is not the same as "no signature at all".
        status = "invalid" if errors else "unsigned"
    elif errors:
        unverifiable_only = all(schemes[k].get("unverifiable") for k in present if schemes[k]["errors"])
        status = "unverifiable" if unverifiable_only and not any("INVALID" in e or "mismatch" in e or
                                                                 "stripping" in e or e.startswith("policy:")
                                                                 for e in errors) else "invalid"
    else:
        status = "verified"

    for k in present:
        for s in schemes[k]["signers"]:
            s.pop("_cert", None)
    return {
        "status": status,
        "schemes_present": present,
        "schemes": schemes,
        "certificate": primary or {},
        "certificate_verified": certificate_verified,
        "errors": errors,
    }
