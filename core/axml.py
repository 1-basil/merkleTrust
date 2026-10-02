"""core/axml.py — Pure-Python Android Binary XML (AXML) manifest parser.

Parses the compiled ``AndroidManifest.xml`` found in every real APK.

Format (frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h):
every chunk starts with ResChunk_header {u16 type, u16 headerSize, u32 size}.
A start-element chunk is followed by ResXMLTree_attrExt and an array of
ResXMLTree_attribute {u32 ns, u32 name, u32 rawValue, Res_value typedValue},
where Res_value is {u16 size, u8 res0, u8 dataType, u32 data}.

Attribute names are resolved through the resource-ID map when available (so
obfuscators that blank the name strings do not defeat the parser), falling back
to the string pool name.

A plain-text XML fallback is kept for synthetic test archives only; such
manifests are reported with ``format == "text"`` because Android itself would
refuse to install them.
"""

from __future__ import annotations

import struct
import xml.etree.ElementTree as ET
from typing import Any

RES_XML_TYPE = 0x0003
RES_STRING_POOL_TYPE = 0x0001
RES_XML_RESOURCE_MAP_TYPE = 0x0180
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103

TYPE_REFERENCE = 0x01
TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

UTF8_FLAG = 1 << 8
NO_INDEX = 0xFFFFFFFF
MAX_STRINGS = 200_000
ANDROID_NS = "http://schemas.android.com/apk/res/android"

# android.R.attr resource IDs for the attributes we care about.
ANDROID_ATTR_IDS = {
    0x01010003: "name",
    0x01010006: "permission",
    0x01010009: "protectionLevel",
    0x0101000F: "debuggable",
    0x01010010: "exported",
    0x0101020C: "minSdkVersion",
    0x0101021B: "versionCode",
    0x0101021C: "versionName",
    0x01010270: "targetSdkVersion",
    0x01010272: "testOnly",
    0x01010280: "allowBackup",
    0x010104EC: "usesCleartextTraffic",
    0x01010527: "networkSecurityConfig",
    0x01010018: "authorities",
    0x0101001B: "grantUriPermissions",
}

COMPONENT_TAGS = {"activity": "activities", "activity-alias": "activities", "service": "services",
                  "receiver": "receivers", "provider": "providers"}


class AxmlError(ValueError):
    """Raised when a binary manifest is structurally invalid."""


def _decode_string_pool(data: bytes, offset: int) -> list[str]:
    try:
        (_t, header_size, size, count, _styles, flags, strings_start, _styles_start) = struct.unpack_from(
            "<HHIIIIII", data, offset)
    except struct.error:
        raise AxmlError("truncated string pool header") from None
    if count > MAX_STRINGS or offset + size > len(data):
        raise AxmlError("string pool size out of range")
    is_utf8 = bool(flags & UTF8_FLAG)
    offsets_base = offset + header_size
    data_base = offset + strings_start
    strings: list[str] = []
    for i in range(count):
        (rel,) = struct.unpack_from("<I", data, offsets_base + i * 4)
        pos = data_base + rel
        try:
            if is_utf8:
                _, pos = _read_len8(data, pos)        # length in UTF-16 units (unused)
                n, pos = _read_len8(data, pos)        # length in bytes
                strings.append(data[pos:pos + n].decode("utf-8", errors="replace"))
            else:
                n, pos = _read_len16(data, pos)
                strings.append(data[pos:pos + n * 2].decode("utf-16-le", errors="replace"))
        except (IndexError, struct.error):
            strings.append("")
    return strings


def _read_len8(data: bytes, pos: int) -> tuple[int, int]:
    n = data[pos]
    if n & 0x80:
        return ((n & 0x7F) << 8) | data[pos + 1], pos + 2
    return n, pos + 1


def _read_len16(data: bytes, pos: int) -> tuple[int, int]:
    (n,) = struct.unpack_from("<H", data, pos)
    if n & 0x8000:
        (lo,) = struct.unpack_from("<H", data, pos + 2)
        return ((n & 0x7FFF) << 16) | lo, pos + 4
    return n, pos + 2


def iter_elements(data: bytes):
    """Yield (event, tag, attrs) for each start/end element of a binary XML document.

    attrs maps attribute name -> python value (str, int, bool, or '@0x7f...' for references).
    """
    if len(data) < 8:
        raise AxmlError("file too small")
    xml_type, _hdr, total = struct.unpack_from("<HHI", data, 0)
    if xml_type != RES_XML_TYPE:
        raise AxmlError("not a binary XML document")
    end = min(total, len(data))

    strings: list[str] = []
    res_ids: list[int] = []
    offset = 8
    while offset + 8 <= end:
        ctype, header_size, csize = struct.unpack_from("<HHI", data, offset)
        if csize < 8 or offset + csize > end:
            raise AxmlError(f"invalid chunk size at offset {offset}")

        if ctype == RES_STRING_POOL_TYPE:
            strings = _decode_string_pool(data, offset)
        elif ctype == RES_XML_RESOURCE_MAP_TYPE:
            n = (csize - header_size) // 4
            res_ids = list(struct.unpack_from(f"<{n}I", data, offset + header_size))
        elif ctype == RES_XML_START_ELEMENT_TYPE:
            ext = offset + header_size
            _ns, name_idx, attr_start, attr_size, attr_count = struct.unpack_from("<IIHHH", data, ext)
            tag = _string(strings, name_idx)
            attrs: dict[str, Any] = {}
            for i in range(attr_count):
                a = ext + attr_start + i * attr_size
                if a + 20 > offset + csize:
                    raise AxmlError("attribute outside element chunk")
                _ans, aname, raw, _vsize, _res0, vtype, vdata = struct.unpack_from("<IIIHBBI", data, a)
                name = ANDROID_ATTR_IDS.get(res_ids[aname]) if aname < len(res_ids) else None
                name = name or _string(strings, aname)
                attrs[name] = _typed_value(strings, raw, vtype, vdata)
            yield "start", tag, attrs
        elif ctype == RES_XML_END_ELEMENT_TYPE:
            _ns, name_idx = struct.unpack_from("<II", data, offset + header_size)
            yield "end", _string(strings, name_idx), {}
        offset += csize


def _string(strings: list[str], idx: int) -> str:
    return strings[idx] if 0 <= idx < len(strings) else ""


def _typed_value(strings: list[str], raw: int, vtype: int, vdata: int) -> Any:
    if vtype == TYPE_STRING:
        return _string(strings, raw if raw != NO_INDEX else vdata)
    if vtype == TYPE_INT_BOOLEAN:
        return vdata != 0
    if vtype in (TYPE_INT_DEC, TYPE_INT_HEX):
        return vdata
    if vtype == TYPE_REFERENCE:
        return f"@0x{vdata:08x}"
    if raw != NO_INDEX:
        return _string(strings, raw)
    return vdata


def _empty_result(fmt: str) -> dict[str, Any]:
    return {
        "format": fmt,
        "package_name": "",
        "version_name": "",
        "version_code": None,
        "min_sdk": None,
        "target_sdk": None,
        "permissions": [],
        "declared_permissions": [],
        "application": {},
        "components": {"activities": [], "services": [], "receivers": [], "providers": []},
        "component_details": [],
    }


def _qualify(name: str, package: str) -> str:
    if name.startswith("."):
        return package + name
    if "." not in name and package:
        return f"{package}.{name}"
    return name


def _as_bool(v: Any) -> bool | None:
    if isinstance(v, bool):
        return v
    if isinstance(v, str) and v.lower() in ("true", "false"):
        return v.lower() == "true"
    return None


def _as_int(v: Any) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    try:
        return int(str(v))
    except (TypeError, ValueError):
        return None


def _build(events, fmt: str) -> dict[str, Any]:
    """Turn a stream of (event, tag, attrs) into the structured manifest model."""
    result = _empty_result(fmt)
    stack: list[str] = []
    current_component: dict[str, Any] | None = None
    for event, tag, attrs in events:
        if event == "end":
            if stack:
                stack.pop()
            if tag in COMPONENT_TAGS and current_component is not None:
                current_component = None
            continue
        parent = stack[-1] if stack else None
        stack.append(tag)

        if tag == "manifest":
            result["package_name"] = str(attrs.get("package", ""))
            result["version_name"] = str(attrs.get("versionName", "") or "")
            result["version_code"] = _as_int(attrs.get("versionCode"))
        elif tag == "uses-sdk":
            result["min_sdk"] = _as_int(attrs.get("minSdkVersion"))
            result["target_sdk"] = _as_int(attrs.get("targetSdkVersion"))
        elif tag in ("uses-permission", "uses-permission-sdk-23"):
            p = str(attrs.get("name", ""))
            if p and p not in result["permissions"]:
                result["permissions"].append(p)
        elif tag == "permission":
            level = attrs.get("protectionLevel", 0)
            result["declared_permissions"].append({"name": str(attrs.get("name", "")), "protection_level": level})
        elif tag == "application" and parent == "manifest":
            app = result["application"]
            for key in ("debuggable", "allowBackup", "usesCleartextTraffic", "testOnly"):
                if key in attrs:
                    app[key] = _as_bool(attrs[key])
            if "networkSecurityConfig" in attrs:
                app["networkSecurityConfig"] = str(attrs["networkSecurityConfig"])
            if "name" in attrs:
                app["name"] = _qualify(str(attrs["name"]), result["package_name"])
        elif tag in COMPONENT_TAGS and parent == "application":
            name = _qualify(str(attrs.get("name", "")), result["package_name"])
            if not name:
                continue
            current_component = {
                "type": tag if tag != "activity-alias" else "activity",
                "name": name,
                "exported": _as_bool(attrs.get("exported")),
                "permission": str(attrs["permission"]) if "permission" in attrs else None,
                "has_intent_filter": False,
            }
            if tag == "provider":
                current_component["authorities"] = str(attrs.get("authorities", ""))
                current_component["grantUriPermissions"] = _as_bool(attrs.get("grantUriPermissions"))
            result["component_details"].append(current_component)
            bucket = result["components"][COMPONENT_TAGS[tag]]
            if name not in bucket:
                bucket.append(name)
        elif tag == "intent-filter" and current_component is not None:
            current_component["has_intent_filter"] = True

    # Effective export state: explicit flag wins; otherwise (pre-Android 12
    # semantics) a component with an intent filter is exported.
    for comp in result["component_details"]:
        explicit = comp["exported"]
        comp["exported_effective"] = explicit if explicit is not None else comp["has_intent_filter"]
    return result


def _iter_text_xml(text: str):
    root = ET.fromstring(text)

    def strip(attrs: dict) -> dict:
        out = {}
        for k, v in attrs.items():
            key = k.split("}")[-1].split(":")[-1]
            out[key] = v
        return out

    def walk(el):
        tag = el.tag.split("}")[-1]
        yield "start", tag, strip(el.attrib)
        for child in el:
            yield from walk(child)
        yield "end", tag, {}

    yield from walk(root)


def parse_manifest(data: bytes) -> dict[str, Any]:
    """Parse AndroidManifest.xml bytes. Raises AxmlError if unparseable."""
    if len(data) >= 8 and struct.unpack_from("<H", data, 0)[0] == RES_XML_TYPE:
        try:
            return _build(iter_elements(data), "binary")
        except struct.error as exc:
            raise AxmlError(f"truncated binary XML ({exc})") from None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise AxmlError("manifest is neither binary AXML nor UTF-8 text") from None
    if "<manifest" not in text:
        raise AxmlError("manifest root element not found")
    try:
        return _build(_iter_text_xml(text), "text")
    except ET.ParseError as exc:
        raise AxmlError(f"invalid text manifest ({exc})") from None


def parse_manifest_xml(data: bytes) -> dict[str, Any]:
    """Backward-compatible wrapper: never raises, returns an empty model on failure."""
    try:
        return parse_manifest(data)
    except AxmlError as exc:
        result = _empty_result("invalid")
        result["error"] = str(exc)
        return result
