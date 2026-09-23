"""core/axml.py — Pure Python Android Binary XML (AXML) parser.

Extracts package name, version, SDK constraints, permissions, and components
from AndroidManifest.xml without external dependencies.
"""

import struct
from typing import Any

CHUNK_STRING_POOL = 0x001C0001
CHUNK_RESOURCE_IDS = 0x00080180
CHUNK_START_NAMESPACE = 0x00100100
CHUNK_END_NAMESPACE = 0x00100101
CHUNK_START_TAG = 0x00100102
CHUNK_END_TAG = 0x00100103
CHUNK_TEXT = 0x00100104


class StringPool:
    def __init__(self, data: bytes, offset: int):
        self.strings: list[str] = []
        if offset + 28 > len(data):
            return

        chunk_type, header_size, size, string_count, style_count, flags, strings_start, styles_start = struct.unpack(
            "<IIIIIIII", data[offset:offset + 32]
        )

        is_utf8 = bool(flags & (1 << 8))
        offsets_start = offset + 28  # offset table starts after header
        string_data_start = offset + strings_start

        offsets = []
        for i in range(string_count):
            off_pos = offsets_start + i * 4
            if off_pos + 4 <= len(data):
                offsets.append(struct.unpack("<I", data[off_pos:off_pos + 4])[0])

        for off in offsets:
            str_pos = string_data_start + off
            if str_pos >= len(data):
                self.strings.append("")
                continue

            try:
                if is_utf8:
                    # UTF-8: length prefix followed by utf-8 bytes
                    # First 1 or 2 bytes: character count, next 1 or 2 bytes: byte count
                    u8len, char_skip = self._read_length8(data, str_pos)
                    byte_len, byte_skip = self._read_length8(data, str_pos + char_skip)
                    start = str_pos + char_skip + byte_skip
                    end = start + byte_len
                    self.strings.append(data[start:end].decode("utf-8", errors="replace"))
                else:
                    # UTF-16
                    u16len, skip = self._read_length16(data, str_pos)
                    start = str_pos + skip
                    end = start + u16len * 2
                    self.strings.append(data[start:end].decode("utf-16-le", errors="replace"))
            except Exception:
                self.strings.append("")

    def _read_length8(self, data: bytes, pos: int) -> tuple[int, int]:
        if pos >= len(data):
            return 0, 0
        val = data[pos]
        if val & 0x80:
            if pos + 1 < len(data):
                val = ((val & 0x7F) << 8) | data[pos + 1]
                return val, 2
            return val & 0x7F, 1
        return val, 1

    def _read_length16(self, data: bytes, pos: int) -> tuple[int, int]:
        if pos + 2 > len(data):
            return 0, 0
        val = struct.unpack("<H", data[pos:pos + 2])[0]
        if val & 0x8000:
            if pos + 4 <= len(data):
                high = val & 0x7FFF
                low = struct.unpack("<H", data[pos + 2:pos + 4])[0]
                return (high << 16) | low, 4
            return val & 0x7FFF, 2
        return val, 2

    def get(self, idx: int) -> str:
        if 0 <= idx < len(self.strings):
            return self.strings[idx]
        return ""


def parse_manifest_xml(axml_bytes: bytes) -> dict[str, Any]:
    """Parse binary AndroidManifest.xml and extract structured information."""
    result: dict[str, Any] = {
        "package_name": "",
        "version_name": "",
        "version_code": 0,
        "min_sdk": 1,
        "target_sdk": 1,
        "permissions": [],
        "components": {
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
        },
    }

    if len(axml_bytes) < 8:
        return result

    magic, file_size = struct.unpack("<II", axml_bytes[:8])
    if magic != 0x00080003:
        # Fallback: maybe it's plain text XML
        try:
            text = axml_bytes.decode("utf-8")
            if "<manifest" in text:
                import xml.etree.ElementTree as ET
                root = ET.fromstring(text)
                pkg = root.attrib.get("package", "")
                result["package_name"] = pkg
                result["version_name"] = root.attrib.get("android:versionName", "")
                result["version_code"] = int(root.attrib.get("android:versionCode", 0) or 0)
                for child in root:
                    tag_c = child.tag.split("}")[-1]
                    if tag_c == "uses-permission":
                        name = child.attrib.get("{http://schemas.android.com/apk/res/android}name") or child.attrib.get("android:name", "")
                        if name and name not in result["permissions"]:
                            result["permissions"].append(name)
                    elif tag_c == "uses-sdk":
                        min_s = child.attrib.get("{http://schemas.android.com/apk/res/android}minSdkVersion") or child.attrib.get("android:minSdkVersion")
                        if min_s:
                            result["min_sdk"] = int(min_s)
                        tgt_s = child.attrib.get("{http://schemas.android.com/apk/res/android}targetSdkVersion") or child.attrib.get("android:targetSdkVersion")
                        if tgt_s:
                            result["target_sdk"] = int(tgt_s)
                    elif tag_c == "application":
                        for comp in child:
                            tag_clean = comp.tag.split("}")[-1]
                            c_name = comp.attrib.get("{http://schemas.android.com/apk/res/android}name") or comp.attrib.get("android:name", "")
                            if c_name:
                                if c_name.startswith("."):
                                    c_name = f"{pkg}{c_name}"
                                elif "." not in c_name and pkg:
                                    c_name = f"{pkg}.{c_name}"

                                if tag_clean == "activity":
                                    result["components"]["activities"].append(c_name)
                                elif tag_clean == "service":
                                    result["components"]["services"].append(c_name)
                                elif tag_clean == "receiver":
                                    result["components"]["receivers"].append(c_name)
                                elif tag_clean == "provider":
                                    result["components"]["providers"].append(c_name)
                return result
        except Exception:
            pass
        return result

    offset = 8
    string_pool: StringPool | None = None
    tag_stack: list[str] = []

    while offset < len(axml_bytes):
        if offset + 8 > len(axml_bytes):
            break
        chunk_type, chunk_size = struct.unpack("<II", axml_bytes[offset:offset + 8])
        if chunk_size < 8 or offset + chunk_size > len(axml_bytes):
            break

        if chunk_type == CHUNK_STRING_POOL:
            string_pool = StringPool(axml_bytes, offset)
        elif chunk_type == CHUNK_START_TAG:
            if string_pool:
                # header(8) + line_number(4) + comment(4) + ns_idx(4) + name_idx(4) + flags(4) + attr_count(2) + id_idx(2) + class_idx(2) + style_idx(2)
                tag_meta = axml_bytes[offset + 8:offset + 36]
                if len(tag_meta) >= 28:
                    line_num, comment, ns_idx, name_idx, flags, attr_count, id_idx, class_idx, style_idx = struct.unpack(
                        "<IIIIHHHHH", tag_meta[:26] + b"\x00\x00"
                    )
                    tag_name = string_pool.get(name_idx)
                    tag_stack.append(tag_name)

                    attrs_start = offset + 36
                    attrs = {}
                    for i in range(attr_count):
                        attr_pos = attrs_start + i * 20
                        if attr_pos + 20 <= offset + chunk_size:
                            ans_idx, aname_idx, val_str_idx, val_type, val_data = struct.unpack(
                                "<IIIIH", axml_bytes[attr_pos:attr_pos + 18]
                            )
                            # Actually unpack: ns(4), name(4), raw_value(4), size(2)+res(1)+type(1), data(4)
                            ans, aname, raw_val, type_info, data_val = struct.unpack(
                                "<IIIBB I", axml_bytes[attr_pos:attr_pos + 20]
                            )[:5]
                            attr_name = string_pool.get(aname)
                            # String value or int value
                            if type_info == 0x03:  # TYPE_STRING
                                attr_val = string_pool.get(raw_val)
                            elif type_info == 0x10 or type_info == 0x11:  # TYPE_INT_DEC / TYPE_INT_HEX
                                attr_val = data_val
                            elif type_info == 0x12:  # TYPE_INT_BOOLEAN
                                attr_val = bool(data_val != 0)
                            else:
                                attr_val = string_pool.get(raw_val) if raw_val != 0xFFFFFFFF else data_val
                            attrs[attr_name] = attr_val

                    # Process tag
                    if tag_name == "manifest":
                        result["package_name"] = str(attrs.get("package", ""))
                        if "versionName" in attrs:
                            result["version_name"] = str(attrs.get("versionName", ""))
                        if "versionCode" in attrs:
                            try:
                                result["version_code"] = int(attrs.get("versionCode", 0))
                            except Exception:
                                pass
                    elif tag_name == "uses-sdk":
                        if "minSdkVersion" in attrs:
                            try:
                                result["min_sdk"] = int(attrs.get("minSdkVersion", 1))
                            except Exception:
                                pass
                        if "targetSdkVersion" in attrs:
                            try:
                                result["target_sdk"] = int(attrs.get("targetSdkVersion", 1))
                            except Exception:
                                pass
                    elif tag_name == "uses-permission":
                        perm_name = str(attrs.get("name", ""))
                        if perm_name and perm_name not in result["permissions"]:
                            result["permissions"].append(perm_name)
                    elif tag_name in ("activity", "service", "receiver", "provider"):
                        comp_name = str(attrs.get("name", ""))
                        if comp_name:
                            # Normalize relative component name
                            if comp_name.startswith("."):
                                comp_name = result["package_name"] + comp_name
                            elif "." not in comp_name and result["package_name"]:
                                comp_name = f"{result['package_name']}.{comp_name}"

                            target_list = result["components"].get(tag_name + "s")
                            if target_list is not None and comp_name not in target_list:
                                target_list.append(comp_name)

        elif chunk_type == CHUNK_END_TAG:
            if tag_stack:
                tag_stack.pop()

        offset += chunk_size

    return result
