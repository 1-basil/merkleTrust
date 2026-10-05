"""core/pcap.py — Minimal packet-capture reader for the dynamic engine.

The Android emulator can write everything the guest sends and receives to a
classic libpcap file (``adb emu network capture start <file>``). This module
reads just enough of that file to answer "who did the app talk to?":

* DNS queries and their A/AAAA answers (UDP port 53);
* the server name in TLS ClientHello messages (SNI), which names the HTTPS
  host even though the traffic itself is encrypted;
* the Host header of plain-text HTTP requests;
* per-connection flows (protocol, endpoints, packets, bytes).

Supported link types: Ethernet (1), raw IP (101) and Linux cooked capture
(113); IPv4 and IPv6; TCP and UDP. pcapng is not supported (the emulator
writes classic pcap).

The capture is untrusted input produced while running an untrusted app, so the
reader never raises on malformed data: a broken packet is skipped, and limits
bound the work done for very large files.

Pure functions only: no network, no state.
"""

from __future__ import annotations

import ipaddress
import struct
from typing import Any

MAX_PACKETS = 200_000
MAX_EVENTS = 500

LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_LINUX_SLL = 1, 101, 113
_MAGIC = {b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
          b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9)}
_DNS_TYPES = {1: "A", 28: "AAAA", 5: "CNAME"}


def read_pcap(data: bytes) -> list[dict[str, Any]]:
    """Decode a classic pcap file into IP packets.

    Each packet is {"ts", "proto": "tcp"|"udp", "src", "sport", "dst", "dport",
    "length", "payload"}. Non-IP and non-TCP/UDP packets are skipped.
    """
    if len(data) < 24 or data[:4] not in _MAGIC:
        return []
    endian, unit = _MAGIC[data[:4]]
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    packets, pos = [], 24
    while pos + 16 <= len(data) and len(packets) < MAX_PACKETS:
        sec, frac, incl, _orig = struct.unpack(endian + "IIII", data[pos:pos + 16])
        frame = data[pos + 16:pos + 16 + incl]
        pos += 16 + incl
        if len(frame) < incl:
            break
        ip = _link_payload(frame, linktype)
        pkt = _parse_ip(ip) if ip is not None else None
        if pkt is not None:
            pkt["ts"] = round(sec + frac * unit, 6)
            packets.append(pkt)
    return packets


def _link_payload(frame: bytes, linktype: int) -> bytes | None:
    if linktype == LINKTYPE_RAW:
        return frame
    if linktype == LINKTYPE_ETHERNET:
        offset, ethertype = 14, frame[12:14]
        while ethertype == b"\x81\x00" and len(frame) >= offset + 4:  # 802.1Q VLAN tags
            ethertype, offset = frame[offset + 2:offset + 4], offset + 4
    elif linktype == LINKTYPE_LINUX_SLL:
        offset, ethertype = 16, frame[14:16]
    else:
        return None
    return frame[offset:] if ethertype in (b"\x08\x00", b"\x86\xdd") else None


def _parse_ip(ip: bytes) -> dict[str, Any] | None:
    if not ip:
        return None
    version = ip[0] >> 4
    if version == 4 and len(ip) >= 20:
        ihl = (ip[0] & 0x0F) * 4
        total = struct.unpack("!H", ip[2:4])[0] or len(ip)
        proto, src, dst = ip[9], ipaddress.IPv4Address(ip[12:16]), ipaddress.IPv4Address(ip[16:20])
        body = ip[ihl:total]
    elif version == 6 and len(ip) >= 40:
        proto, src, dst = ip[6], ipaddress.IPv6Address(ip[8:24]), ipaddress.IPv6Address(ip[24:40])
        body = ip[40:40 + struct.unpack("!H", ip[4:6])[0]]
    else:
        return None
    if proto == 6 and len(body) >= 20:
        sport, dport = struct.unpack("!HH", body[:4])
        payload = body[(body[12] >> 4) * 4:]
        name = "tcp"
    elif proto == 17 and len(body) >= 8:
        sport, dport = struct.unpack("!HH", body[:4])
        payload = body[8:]
        name = "udp"
    else:
        return None
    return {"proto": name, "src": str(src), "sport": sport, "dst": str(dst), "dport": dport,
            "length": len(ip), "payload": payload}


# ------------------------------------------------------------------ DNS --

def _dns_name(msg: bytes, pos: int, depth: int = 0) -> tuple[str, int]:
    """Read a (possibly compressed) domain name; returns (name, position after it)."""
    labels, end = [], None
    while True:
        if pos >= len(msg) or depth > 20:
            raise ValueError("bad name")
        length = msg[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(msg):
                raise ValueError("bad pointer")
            pointer = ((length & 0x3F) << 8) | msg[pos + 1]
            end = pos + 2 if end is None else end
            pos, depth = pointer, depth + 1
            continue
        labels.append(msg[pos + 1:pos + 1 + length].decode("ascii", "replace"))
        pos += 1 + length
    return ".".join(labels).lower(), (end if end is not None else pos)


def parse_dns(msg: bytes) -> dict[str, Any] | None:
    """Decode a DNS message: {"id", "response", "queries": [name], "answers": [{name, type, value}]}."""
    try:
        ident, flags, qd, an = struct.unpack("!HHHH", msg[:8])
        pos, queries, answers = 12, [], []
        for _ in range(min(qd, 10)):
            name, pos = _dns_name(msg, pos)
            queries.append(name)
            pos += 4
        for _ in range(min(an, 50)):
            name, pos = _dns_name(msg, pos)
            rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", msg[pos:pos + 10])
            rdata, rpos = msg[pos + 10:pos + 10 + rdlen], pos + 10
            pos += 10 + rdlen
            if rtype == 1 and rdlen == 4:
                value = str(ipaddress.IPv4Address(rdata))
            elif rtype == 28 and rdlen == 16:
                value = str(ipaddress.IPv6Address(rdata))
            elif rtype == 5:
                value = _dns_name(msg, rpos)[0]
            else:
                continue
            answers.append({"name": name, "type": _DNS_TYPES[rtype], "value": value})
        return {"id": ident, "response": bool(flags & 0x8000), "queries": queries, "answers": answers}
    except (ValueError, struct.error, IndexError):
        return None


# ------------------------------------------------------------- TLS / HTTP --

def tls_sni(payload: bytes) -> str | None:
    """Server name from a TLS ClientHello record, if this payload starts one."""
    try:
        if len(payload) < 43 or payload[0] != 0x16 or payload[1] != 0x03 or payload[5] != 0x01:
            return None
        pos = 9 + 2 + 32                                    # record + handshake headers, version, random
        pos += 1 + payload[pos]                             # session id
        pos += 2 + struct.unpack("!H", payload[pos:pos + 2])[0]   # cipher suites
        pos += 1 + payload[pos]                             # compression methods
        end = pos + 2 + struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2
        while pos + 4 <= min(end, len(payload)):
            ext_type, ext_len = struct.unpack("!HH", payload[pos:pos + 4])
            if ext_type == 0:                               # server_name
                name_len = struct.unpack("!H", payload[pos + 7:pos + 9])[0]
                return payload[pos + 9:pos + 9 + name_len].decode("ascii").lower() or None
            pos += 4 + ext_len
    except (struct.error, IndexError, UnicodeDecodeError):
        return None
    return None


def http_host(payload: bytes) -> str | None:
    """Host header of a plain-text HTTP request, if this payload starts one."""
    if payload[:8].split(b" ")[0] not in (b"GET", b"POST", b"PUT", b"HEAD", b"DELETE", b"PATCH", b"OPTIONS"):
        return None
    for line in payload[:4096].split(b"\r\n")[1:]:
        if not line:
            break
        key, _, value = line.partition(b":")
        if key.strip().lower() == b"host":
            return value.strip().decode("ascii", "replace").lower() or None
    return None


# --------------------------------------------------------------- summary --

def summarize(packets: list[dict[str, Any]]) -> dict[str, Any]:
    """Flows, DNS lookups, TLS server names and HTTP hosts seen in a capture.

    A flow is keyed by the endpoint that opened it: the first packet's source
    is the client. Answers from DNS responses are attached to the matching
    query so that IP addresses in flows can be mapped back to host names.
    """
    flows: dict[tuple, dict[str, Any]] = {}
    dns: dict[tuple, dict[str, Any]] = {}
    for p in packets:
        fwd = (p["proto"], p["src"], p["sport"], p["dst"], p["dport"])
        rev = (p["proto"], p["dst"], p["dport"], p["src"], p["sport"])
        key = rev if rev in flows else fwd
        flow = flows.get(key)
        if flow is None and len(flows) < MAX_EVENTS:
            flow = flows[key] = {"ts": p["ts"], "proto": p["proto"], "src_ip": key[1], "src_port": key[2],
                                 "dst_ip": key[3], "dst_port": key[4], "host": "", "sni": "", "http_host": "",
                                 "packets": 0, "bytes": 0}
        if flow is not None:
            flow["packets"] += 1
            flow["bytes"] += p["length"]
            if p["proto"] == "tcp" and p["payload"] and key == fwd:
                flow["sni"] = flow["sni"] or (tls_sni(p["payload"]) or "")
                flow["http_host"] = flow["http_host"] or (http_host(p["payload"]) or "")
        if p["proto"] == "udp" and 53 in (p["sport"], p["dport"]):
            msg = parse_dns(p["payload"])
            if msg and msg["queries"]:
                client = (p["dst"], p["dport"]) if msg["response"] else (p["src"], p["sport"])
                entry = dns.setdefault((msg["id"], msg["queries"][0], client),
                                       {"ts": p["ts"], "query": msg["queries"][0], "answers": []})
                for a in msg["answers"]:
                    if a["type"] != "CNAME" and a["value"] not in entry["answers"]:
                        entry["answers"].append(a["value"])

    names: dict[str, str] = {}
    for d in dns.values():
        for ip in d["answers"]:
            names.setdefault(ip, d["query"])
    flow_list = sorted(flows.values(), key=lambda f: f["ts"])
    for f in flow_list:
        f["host"] = f["sni"] or f["http_host"] or names.get(f["dst_ip"], "")
    return {"flows": flow_list, "dns": sorted(dns.values(), key=lambda d: d["ts"])[:MAX_EVENTS],
            "ip_names": names}
