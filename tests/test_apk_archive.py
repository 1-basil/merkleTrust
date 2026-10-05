"""Security tests for the hardened APK archive reader."""

from pathlib import Path
import os
import warnings
import zipfile

import pytest

from core.apk_archive import ApkArchive, ApkValidationError, unsafe_name_reason

pytestmark = [pytest.mark.unit, pytest.mark.security]


def _zip(path, entries, compression=zipfile.ZIP_DEFLATED):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # zipfile warns on duplicate names
        with zipfile.ZipFile(path, "w", compression) as zf:
            for name, data in entries:
                zf.writestr(name, data)
    return str(path)


MANIFEST = ("AndroidManifest.xml", b"<manifest package='x.y'/>")


def test_real_apk_opens(fixture_apk):
    with ApkArchive(fixture_apk("signed_v1v2_ec.apk")) as apk:
        assert apk.has("AndroidManifest.xml")
        assert apk.has("classes.dex")
        assert apk.report.prefix_bytes == 0
        assert apk.read("classes.dex").startswith(b"dex\n")


def test_not_a_zip(tmp_path):
    p = tmp_path / "x.apk"
    p.write_bytes(b"not a zip at all")
    with pytest.raises(ApkValidationError, match="Not a valid ZIP"):
        ApkArchive(str(p))


def test_empty_file(tmp_path):
    p = tmp_path / "x.apk"
    p.write_bytes(b"")
    with pytest.raises(ApkValidationError, match="empty"):
        ApkArchive(str(p))


def test_oversized_file(fixture_apk):
    with pytest.raises(ApkValidationError, match="maximum size"):
        ApkArchive(fixture_apk("signed_v1v2_ec.apk"), limits={"max_file_bytes": 100})


@pytest.mark.parametrize("name", ["../evil.so", "lib/../../evil", "/etc/passwd", "C:/win.ini",
                                  "a\\b.dex", "bad\x00name"])
def test_unsafe_entry_names_rejected(tmp_path, name):
    # zipfile normalises names on write, so write a placeholder and patch the raw bytes.
    placeholder = "Q" * len(name.encode())
    p = _zip(tmp_path / "x.apk", [MANIFEST, (placeholder, b"x")])
    raw = Path(p).read_bytes().replace(placeholder.encode(), name.encode())
    Path(p).write_bytes(raw)
    with pytest.raises(ApkValidationError, match="Unsafe entry name"):
        ApkArchive(p)


def test_safe_names_accepted():
    for name in ("classes.dex", "res/layout/main.xml", "lib/arm64-v8a/libx.so", "assets/..hidden"):
        assert unsafe_name_reason(name) is None


def test_duplicate_entries_rejected(tmp_path):
    p = _zip(tmp_path / "x.apk", [MANIFEST, ("classes.dex", b"one"), ("classes.dex", b"two")])
    with pytest.raises(ApkValidationError, match="Duplicate entry"):
        ApkArchive(p)


def test_missing_manifest(tmp_path):
    p = _zip(tmp_path / "x.apk", [("classes.dex", b"x")])
    with pytest.raises(ApkValidationError, match="AndroidManifest.xml"):
        ApkArchive(p)
    with ApkArchive(p, require_manifest=False) as apk:
        assert apk.names() == ["classes.dex"]


def test_zip_bomb_ratio_rejected(tmp_path):
    p = _zip(tmp_path / "x.apk", [MANIFEST, ("assets/bomb.bin", b"\x00" * (4 * 1024 * 1024))])
    with pytest.raises(ApkValidationError, match="compression ratio"):
        ApkArchive(p)


def test_too_many_entries(tmp_path):
    p = _zip(tmp_path / "x.apk", [MANIFEST] + [(f"assets/{i}", b"x") for i in range(20)])
    with pytest.raises(ApkValidationError, match="too many entries"):
        ApkArchive(p, limits={"max_entries": 10})


def test_total_uncompressed_limit(tmp_path):
    p = _zip(tmp_path / "x.apk", [MANIFEST, ("assets/a", os.urandom(5000))])
    with pytest.raises(ApkValidationError, match="total uncompressed"):
        ApkArchive(p, limits={"max_total_uncompressed": 1000})


def test_read_cap_enforced(fixture_apk):
    with ApkArchive(fixture_apk("signed_v1v2_ec.apk")) as apk:
        with pytest.raises(ApkValidationError, match="read limit"):
            apk.read("classes.dex", max_bytes=10)


def test_prepended_data_reported(tmp_path, fixture_apk):
    data = Path(fixture_apk("unsigned.apk")).read_bytes()
    p = tmp_path / "janus.apk"
    p.write_bytes(b"dex\n035\x00" + b"\x00" * 120 + data)
    with ApkArchive(str(p)) as apk:
        assert apk.report.prefix_bytes > 0
        assert apk.report.warnings


def test_corrupt_entry_detected_on_read(tmp_path):
    p = _zip(tmp_path / "x.apk", [MANIFEST, ("assets/data.txt", b"A" * 200)], compression=zipfile.ZIP_STORED)
    raw = bytearray(Path(p).read_bytes())
    pos = raw.index(b"A" * 200)
    raw[pos] = ord("B")  # content changed, CRC not updated
    Path(p).write_bytes(bytes(raw))
    with ApkArchive(p) as apk:
        with pytest.raises(ApkValidationError, match="corrupt"):
            apk.read("assets/data.txt")
