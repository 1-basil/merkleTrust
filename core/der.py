"""core/der.py — Minimal ASN.1 DER reader for PKCS#7 SignedData.

The ``cryptography`` package can extract certificates from PKCS#7 but cannot
verify a PKCS#7 signature. JAR (APK v1) signatures need exactly that, so this
module walks just enough DER to obtain the SignerInfo fields; the actual
signature verification is still performed by ``cryptography``.

Only definite-length DER is accepted (what jarsigner/apksigner emit).
"""

from __future__ import annotations

from dataclasses import dataclass

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
DIGEST_OIDS = {
    "1.3.14.3.2.26": "SHA-1",
    "2.16.840.1.101.3.4.2.1": "SHA-256",
    "2.16.840.1.101.3.4.2.2": "SHA-384",
    "2.16.840.1.101.3.4.2.3": "SHA-512",
}


class DerError(ValueError):
    pass


@dataclass
class Tlv:
    tag: int
    content: bytes
    raw: bytes  # full encoding including tag and length

    def children(self) -> list["Tlv"]:
        return parse_all(self.content)


def parse_one(data: bytes, pos: int = 0) -> tuple[Tlv, int]:
    if pos + 2 > len(data):
        raise DerError("truncated TLV")
    tag = data[pos]
    if tag & 0x1F == 0x1F:
        raise DerError("multi-byte tags unsupported")
    length = data[pos + 1]
    hdr = 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4:
            raise DerError("indefinite or oversized length")
        if pos + 2 + n > len(data):
            raise DerError("truncated length")
        length = int.from_bytes(data[pos + 2:pos + 2 + n], "big")
        hdr += n
    end = pos + hdr + length
    if end > len(data):
        raise DerError("length exceeds buffer")
    return Tlv(tag, data[pos + hdr:end], data[pos:end]), end


def parse_all(data: bytes) -> list[Tlv]:
    out, pos = [], 0
    while pos < len(data):
        tlv, pos = parse_one(data, pos)
        out.append(tlv)
    return out


def decode_oid(content: bytes) -> str:
    if not content:
        raise DerError("empty OID")
    first = content[0]
    parts = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    value = 0
    for b in content[1:]:
        value = (value << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(value)
            value = 0
    return ".".join(map(str, parts))


@dataclass
class SignerInfo:
    serial_number: int
    issuer_der: bytes
    digest_algorithm: str
    signed_attrs_der: bytes | None      # re-tagged as SET (0x31) for verification
    message_digest: bytes | None
    signature_algorithm_oid: str
    signature: bytes


def parse_pkcs7_signer_infos(data: bytes) -> list[SignerInfo]:
    """Return SignerInfos from a DER PKCS#7 ContentInfo(SignedData)."""
    content_info, _ = parse_one(data)
    ci = content_info.children()
    if len(ci) < 2 or decode_oid(ci[0].content) != OID_SIGNED_DATA:
        raise DerError("not PKCS#7 SignedData")
    signed_data = ci[1].children()[0].children()   # [0] EXPLICIT -> SEQUENCE
    signer_set = signed_data[-1]
    if signer_set.tag != 0x31:
        raise DerError("SignerInfos SET not found")

    result = []
    for si in signer_set.children():
        f = si.children()
        idx = 1
        sid = f[idx]
        idx += 1
        if sid.tag != 0x30:
            raise DerError("only issuerAndSerialNumber signer identifiers are supported")
        issuer, serial = sid.children()[0], sid.children()[1]
        digest_oid = decode_oid(f[idx].children()[0].content)
        idx += 1
        signed_attrs = None
        message_digest = None
        if f[idx].tag == 0xA0:
            attrs = f[idx]
            signed_attrs = b"\x31" + attrs.raw[1:]
            for attr in attrs.children():
                parts = attr.children()
                if decode_oid(parts[0].content) == OID_MESSAGE_DIGEST:
                    message_digest = parts[1].children()[0].content
            idx += 1
        sig_alg_oid = decode_oid(f[idx].children()[0].content)
        idx += 1
        signature = f[idx].content
        result.append(SignerInfo(
            serial_number=int.from_bytes(serial.content, "big", signed=True),
            issuer_der=issuer.raw,
            digest_algorithm=DIGEST_OIDS.get(digest_oid, digest_oid),
            signed_attrs_der=signed_attrs,
            message_digest=message_digest,
            signature_algorithm_oid=sig_alg_oid,
            signature=signature,
        ))
    return result
