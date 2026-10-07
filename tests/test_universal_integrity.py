"""Universal content integrity: detection, chunk Merkle commitment, format analysers
(image, media, web, PDF), category-aware scoring and sealing of non-APK files."""

import io
import struct
import wave
import zlib

import pytest

from core import analyzers, scoring
from core.analyzers import document, image, media, web
from core.contracts import JobContext
from core.detector import detect_content_type, sniff
from core.integrity import compute_chunks
from core.integrity import run as integrity_run
from core.merkle import build_tree, root

pytestmark = pytest.mark.unit

ZIP_PAYLOAD = b"PK\x03\x04" + b"\x14\x00" + b"\x00" * 24 + b"evil.sh"


# ------------------------------------------------------------ builders --

def _png_chunk(ctype: bytes, body: bytes, crc: int | None = None) -> bytes:
    crc = zlib.crc32(ctype + body) & 0xFFFFFFFF if crc is None else crc
    return struct.pack(">I", len(body)) + ctype + body + struct.pack(">I", crc)


def make_png(extra_chunks: bytes = b"", bad_crc: bool = False) -> bytes:
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)
    idat = zlib.compress(b"\x00\x00")
    return (b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", ihdr) + extra_chunks
            + _png_chunk(b"IDAT", idat, crc=0xDEADBEEF if bad_crc else None) + _png_chunk(b"IEND", b""))


def make_exif(gps: bool = True, serial: str | None = None) -> bytes:
    """Little-endian TIFF: IFD0 (Make, optional serial, GPS pointer) + GPS IFD (lat/lon)."""
    entries0 = [(0x010F, 2, 6, b"Canon\x00")]
    if serial:
        entries0.append((0xC62F, 2, len(serial) + 1, serial.encode() + b"\x00"))
    if gps:
        entries0.append((0x8825, 4, 1, None))   # pointer patched below
    ifd0_off = 8
    ifd0_size = 2 + 12 * len(entries0) + 4
    data_off = ifd0_off + ifd0_size
    blob, out_entries = b"", []
    for tag, typ, count, value in entries0:
        if value is not None and len(value) > 4:
            out_entries.append((tag, typ, count, struct.pack("<I", data_off + len(blob))))
            blob += value
        else:
            out_entries.append((tag, typ, count, value))
    gps_off = data_off + len(blob)

    def rationals(*pairs):
        return b"".join(struct.pack("<II", a, b) for a, b in pairs)
    gps_entries = [(1, 2, 2, b"N\x00\x00\x00"), (2, 5, 3, rationals((12, 1), (58, 1), (0, 1))),
                   (3, 2, 2, b"E\x00\x00\x00"), (4, 5, 3, rationals((77, 1), (35, 1), (0, 1)))]
    gps_data_off = gps_off + 2 + 12 * len(gps_entries) + 4
    gps_blob, gps_out = b"", []
    for tag, typ, count, value in gps_entries:
        if len(value) > 4:
            gps_out.append((tag, typ, count, struct.pack("<I", gps_data_off + len(gps_blob))))
            gps_blob += value
        else:
            gps_out.append((tag, typ, count, value))

    def ifd(entries):
        raw = struct.pack("<H", len(entries))
        for tag, typ, count, value in entries:
            if value is None:
                value = struct.pack("<I", gps_off)
            raw += struct.pack("<HHI", tag, typ, count) + value.ljust(4, b"\x00")
        return raw + b"\x00\x00\x00\x00"
    tiff = b"II*\x00" + struct.pack("<I", ifd0_off) + ifd(out_entries) + blob
    if gps:
        tiff += ifd(gps_out) + gps_blob
    return tiff


def make_jpeg(exif: bytes | None = None, trailing: bytes = b"") -> bytes:
    def seg(marker: int, body: bytes) -> bytes:
        return bytes([0xFF, marker]) + struct.pack(">H", len(body) + 2) + body
    out = b"\xff\xd8" + seg(0xE0, b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00")
    if exif is not None:
        out += seg(0xE1, b"Exif\x00\x00" + exif)
    out += seg(0xDB, b"\x00" + bytes(64))
    out += seg(0xC0, b"\x08\x00\x01\x00\x01\x01\x01\x11\x00")
    out += seg(0xDA, b"\x01\x01\x00\x00\x3f\x00")
    out += b"\x12\x34\xff\x00\x56\xff\xd0\x78"   # entropy data with a stuffed byte and a restart marker
    return out + b"\xff\xd9" + trailing


def make_gif(trailing: bytes = b"") -> bytes:
    header = b"GIF89a" + struct.pack("<HH", 1, 1) + b"\x80\x00\x00" + b"\x00\x00\x00\xff\xff\xff"
    image_block = b"\x2c" + struct.pack("<HHHH", 0, 0, 1, 1) + b"\x00" + b"\x02\x02\x44\x01\x00"
    return header + image_block + b"\x3b" + trailing


def make_webp(trailing: bytes = b"") -> bytes:
    vp8 = b"VP8 " + struct.pack("<I", 10) + bytes(10)
    return b"RIFF" + struct.pack("<I", 4 + len(vp8)) + b"WEBP" + vp8 + trailing


def _box(btype: bytes, body: bytes) -> bytes:
    return struct.pack(">I", 8 + len(body)) + btype + body


def make_mp4(trailing: bytes = b"", extra: bytes = b"") -> bytes:
    ftyp = _box(b"ftyp", b"isom\x00\x00\x02\x00isomiso2mp41")
    moov = _box(b"moov", _box(b"mvhd", bytes(100)))
    mdat = _box(b"mdat", bytes(256))
    return ftyp + moov + extra + mdat + trailing


def make_wav(trailing: bytes = b"") -> bytes:
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(8000)
        w.writeframes(bytes(1600))
    return buf.getvalue() + trailing


def make_mp3(frames: int = 10, trailing: bytes = b"", id3v1: bool = False) -> bytes:
    frame = b"\xff\xfb\x90\x00" + bytes(413)   # MPEG-1 Layer III, 128 kbps, 44.1 kHz -> 417 bytes
    id3 = b"ID3\x03\x00\x00\x00\x00\x00\x0a" + bytes(10)
    tail = (b"TAG" + bytes(125)) if id3v1 else b""
    return id3 + frame * frames + trailing + tail


def make_mkv(trailing: bytes = b"") -> bytes:
    ebml = b"\x1a\x45\xdf\xa3" + b"\x84" + b"\x42\x82\x81\x00"[:4]
    segment = b"\x18\x53\x80\x67" + b"\x88" + bytes(8)
    return ebml + segment + trailing


CLEAN_HTML = b"""<!DOCTYPE html>
<html><head>
<link rel="canonical" href="https://example.org/login">
<script src="https://cdn.example.net/lib.js" integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC" crossorigin="anonymous"></script>
<script src="/static/app.js"></script>
<script>document.getElementById('x').textContent = 'hi'; el.innerHTML = "";</script>
</head><body>
<form action="/session" method="post"><input type="password" name="p"></form>
</body></html>"""

RISKY_HTML = b"""<!DOCTYPE html>
<html><head>
<script src="https://cdn.example.net/jquery.js"></script>
<link rel="stylesheet" href="//fonts.example.com/a.css">
<script>var p = location.hash.slice(1); eval(p); document.write(p); box.innerHTML = p;</script>
</head><body onload="eval(atob('YWxlcnQoMSk='))">
<form action="http://collect.example.com/steal" method="post"><input type="password" name="pw"></form>
</body></html>"""


def _ids(findings):
    return {f["id"] for f in findings}


def _ctx(tmp_path, data: bytes, name: str, prior=None):
    path = tmp_path / name
    path.write_bytes(data)
    mime, category = detect_content_type(str(path))
    return JobContext(target_path=str(path), workspace=str(tmp_path), prior=prior or {},
                      mime_type=mime, file_category=category, config={"chunk_size": 65536})


# ------------------------------------------------------------ contract --

def test_job_context_aliases_target_and_apk_path(tmp_path):
    a = JobContext(apk_path="x.apk", workspace=str(tmp_path), prior={})
    assert a.target_path == "x.apk" and a.file_category == "apk"
    b = JobContext(target_path="y.png", workspace=str(tmp_path), file_category="image")
    assert b.apk_path == "y.png" and b.prior == {}
    with pytest.raises(TypeError):
        JobContext(apk_path="x.apk")


# ----------------------------------------------------------- detection --

@pytest.mark.parametrize("data,name,expected", [
    (make_png(), "a.bin", ("image/png", "image")),
    (make_jpeg(), "a.bin", ("image/jpeg", "image")),
    (make_gif(), "a.bin", ("image/gif", "image")),
    (make_webp(), "a.bin", ("image/webp", "image")),
    (make_mp4(), "a.bin", ("video/mp4", "video")),
    (make_mkv(), "a.bin", ("video/x-matroska", "video")),
    (make_wav(), "a.bin", ("audio/wav", "audio")),
    (make_mp3(), "a.bin", ("audio/mpeg", "audio")),
    (b"%PDF-1.7\n%%EOF\n", "a.bin", ("application/pdf", "doc")),
    (CLEAN_HTML, "a.bin", ("text/html", "web")),
    (b"function f() { return 1; }", "a.js", ("application/javascript", "web")),
    (b"function f() { return 1; }", "a.txt", ("text/plain", "unknown")),
    (b"MZ\x90\x00\x03", "a.png", ("application/octet-stream", "unknown")),   # extension is not trusted
])
def test_detects_by_magic_bytes(tmp_path, data, name, expected):
    p = tmp_path / name
    p.write_bytes(data)
    assert detect_content_type(str(p)) == expected


def test_detects_apk(fixture_apk):
    assert detect_content_type(fixture_apk("signed_v1v2_ec.apk")) == \
        ("application/vnd.android.package-archive", "apk")


def test_sniff_mp4_audio_brand():
    assert sniff(b"\x00\x00\x00\x18ftypM4A \x00\x00\x00\x00") == ("audio/mp4", "audio")


# ----------------------------------------------------------- integrity --

def test_non_apk_integrity_builds_chunk_merkle_tree(tmp_path):
    data = make_png() + bytes(150_000)           # spans three 64 KB chunks
    ctx = _ctx(tmp_path, data, "big.png")
    report = integrity_run("job-img", ctx)
    expected_chunks = compute_chunks(data, 65536)
    assert report["status"] == "ok" and report["chunk_count"] == 3
    assert report["chunks"] == expected_chunks
    assert report["chunk_merkle_root"] == root(build_tree([c["hash"] for c in expected_chunks]))
    assert report["file_count"] == 1 and report["files"][0]["category"] == "image"
    assert len(report["merkle_root"]) == 64
    assert report["file_category"] == "image" and report["mime_type"] == "image/png"
    assert (tmp_path / "integrity.json").exists()


def test_apk_integrity_unchanged_by_default(fixture_apk, tmp_path):
    ctx = JobContext(apk_path=fixture_apk("signed_v1v2_ec.apk"), workspace=str(tmp_path), prior={})
    report = integrity_run("job-apk", ctx)
    assert report["file_count"] > 1 and "file_category" not in report


# --------------------------------------------------------------- image --

def test_clean_png_has_no_findings():
    findings, details = image.analyze(make_png())
    assert findings == [] and details["chunk_types"] == ["IDAT", "IEND", "IHDR"]


def test_png_polyglot_payload_detected():
    findings, _ = image.analyze(make_png() + b"hidden message appended after IEND" * 3)
    assert _ids(findings) == {"IMG_POLYGLOT_PAYLOAD"}
    assert findings[0]["severity"] == "high"


def test_png_with_appended_zip_is_critical():
    findings, _ = image.analyze(make_png() + ZIP_PAYLOAD)
    f = next(f for f in findings if f["id"] == "IMG_POLYGLOT_PAYLOAD")
    assert f["severity"] == "critical" and "ZIP archive" in f["evidence"]


def test_png_zero_padding_is_not_a_payload():
    assert image.analyze(make_png() + b"\x00" * 4)[0] == []


def test_png_bad_crc_detected():
    findings, _ = image.analyze(make_png(bad_crc=True))
    assert _ids(findings) == {"IMG_CORRUPT_CHUNK"} and "CRC mismatch in chunk IDAT" in findings[0]["evidence"]


def test_png_truncated_chunk_detected():
    findings, _ = image.analyze(make_png()[:-6])
    assert "IMG_CORRUPT_CHUNK" in _ids(findings)


def test_png_exif_gps_detected():
    findings, details = image.analyze(make_png(_png_chunk(b"eXIf", make_exif(gps=True, serial="SN12345678"))))
    assert _ids(findings) == {"IMG_PRIVACY_EXIF_GPS", "IMG_PRIVACY_EXIF_SERIAL"}
    gps = next(f for f in findings if f["id"] == "IMG_PRIVACY_EXIF_GPS")
    assert "12.97, 77.58" in gps["evidence"]
    serial = next(f for f in findings if f["id"] == "IMG_PRIVACY_EXIF_SERIAL")
    assert "SN12345678" not in serial["evidence"] and serial["evidence"].endswith("5678")
    assert details["exif"]["make"] == "Canon"


def test_jpeg_clean_and_trailing_payload():
    clean, details = image.analyze(make_jpeg())
    assert clean == [] and details["end_offset"] == len(make_jpeg())
    findings, _ = image.analyze(make_jpeg(trailing=b"<script>alert(1)</script>"))
    f = next(f for f in findings if f["id"] == "IMG_POLYGLOT_PAYLOAD")
    assert f["severity"] == "critical" and "HTML script" in f["evidence"]


def test_jpeg_exif_gps_detected():
    findings, _ = image.analyze(make_jpeg(exif=make_exif(gps=True)))
    assert _ids(findings) == {"IMG_PRIVACY_EXIF_GPS"}


def test_jpeg_exif_without_gps_is_clean():
    assert image.analyze(make_jpeg(exif=make_exif(gps=False)))[0] == []


def test_jpeg_truncated_detected():
    findings, _ = image.analyze(make_jpeg()[:-2])
    assert "IMG_CORRUPT_CHUNK" in _ids(findings)


def test_gif_and_webp_trailing_payload():
    assert image.analyze(make_gif())[0] == []
    assert "IMG_POLYGLOT_PAYLOAD" in _ids(image.analyze(make_gif(b"appended secret data!!"))[0])
    assert image.analyze(make_webp())[0] == []
    assert "IMG_POLYGLOT_PAYLOAD" in _ids(image.analyze(make_webp(b"appended secret data!!"))[0])


# --------------------------------------------------------------- media --

def test_clean_mp4_has_no_findings():
    findings, details = media.analyze(make_mp4())
    assert findings == [] and [b["type"] for b in details["boxes"]] == ["ftyp", "moov", "mdat"]


def test_mp4_trailing_payload_detected():
    findings, _ = media.analyze(make_mp4(trailing=b"\xde\xad\xbe\xef" * 64))
    f = next(f for f in findings if f["id"] == "MEDIA_CONTAINER_ANOMALY")
    assert f["severity"] == "high" and "after the final MP4 atom" in f["evidence"]


def test_mp4_appended_zip_is_critical():
    findings, _ = media.analyze(make_mp4(trailing=ZIP_PAYLOAD))
    assert any(f["id"] == "MEDIA_CONTAINER_ANOMALY" and f["severity"] == "critical" for f in findings)


def test_mp4_unknown_box_and_hidden_free_box():
    findings, _ = media.analyze(make_mp4(extra=_box(b"zzzz", b"data")))
    assert any("unrecognised top-level box 'zzzz'" in f["evidence"] for f in findings)
    findings, _ = media.analyze(make_mp4(extra=_box(b"free", b"MZ\x90\x00" + bytes(20))))
    assert any(f["severity"] == "critical" and "Windows executable" in f["evidence"] for f in findings)


def test_mp4_truncated_box_detected():
    findings, _ = media.analyze(make_mp4()[:-50])
    assert any(f["id"] == "MEDIA_CONTAINER_ANOMALY" and "past the end of the file" in f["evidence"]
               for f in findings)


def test_clean_wav_has_no_findings():
    findings, details = media.analyze(make_wav())
    assert findings == [] and details["audio"]["sample_rate"] == 8000


def test_wav_trailing_payload_detected():
    findings, _ = media.analyze(make_wav(trailing=b"secret exfiltrated data" * 4))
    assert _ids(findings) == {"AUDIO_TRAILING_PAYLOAD"}


def test_wav_truncated_reported_as_anomaly():
    findings, _ = media.analyze(make_wav()[:-100])
    assert _ids(findings) == {"MEDIA_CONTAINER_ANOMALY"}


def test_mp3_clean_with_id3v1_and_trailing_payload():
    clean, details = media.analyze(make_mp3(id3v1=True))
    assert clean == [] and details["frames"] == 10 and details["trailers"] == ["ID3v1"]
    findings, _ = media.analyze(make_mp3(trailing=b"hidden payload bytes" * 10))
    assert _ids(findings) == {"AUDIO_TRAILING_PAYLOAD"}


def test_mkv_trailing_payload_detected():
    assert media.analyze(make_mkv())[0] == []
    findings, _ = media.analyze(make_mkv(trailing=b"\x00\x01appended data past segment"))
    assert "MEDIA_CONTAINER_ANOMALY" in _ids(findings)


# ----------------------------------------------------------------- web --

def test_clean_html_has_no_findings():
    findings, details = web.analyze(CLEAN_HTML)
    assert findings == [] and details["page_host"] == "example.org"


def test_risky_html_findings():
    findings, details = web.analyze(RISKY_HTML)
    assert _ids(findings) == {"WEB_MISSING_SRI", "WEB_DANGEROUS_INLINE_SCRIPT", "WEB_INSECURE_FORM_ACTION"}
    by_id = {f["id"]: f for f in findings}
    assert "jquery.js" in by_id["WEB_MISSING_SRI"]["evidence"]
    assert "fonts.example.com" in by_id["WEB_MISSING_SRI"]["evidence"]
    evidence = by_id["WEB_DANGEROUS_INLINE_SCRIPT"]["evidence"]
    assert "eval()" in evidence and "document.write()" in evidence and "innerHTML" in evidence
    assert "onload" in evidence
    assert by_id["WEB_INSECURE_FORM_ACTION"]["severity"] == "high"
    assert details["resources_missing_sri"] == 2


def test_off_domain_password_form_flagged():
    html = (b'<html><head><base href="https://bank.example"></head><body>'
            b'<form action="https://login.attacker.test/p"><input type="password"></form></body></html>')
    findings, _ = web.analyze(html)
    f = next(f for f in findings if f["id"] == "WEB_INSECURE_FORM_ACTION")
    assert "attacker.test" in f["evidence"] and f["severity"] == "high"


def test_javascript_file_scanned():
    findings, _ = web.analyze(b"const x = new Function('return 1');\nsetTimeout(\"run()\", 10);",
                              "application/javascript")
    assert _ids(findings) == {"WEB_DANGEROUS_INLINE_SCRIPT"}
    assert web.analyze(b"export const f = (a) => a + 1;", "application/javascript")[0] == []


# ----------------------------------------------------------------- PDF --

def test_pdf_clean_and_active_content():
    clean = b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n"
    assert document.analyze_pdf(clean)[0] == []
    risky = (b"%PDF-1.4\n1 0 obj << /Type /Catalog /OpenAction 2 0 R /Names << /EmbeddedFiles 3 0 R >> >> endobj\n"
             b"2 0 obj << /S /J#61vaScript /JS (app.alert(1)) >> endobj\n%%EOF\n" + ZIP_PAYLOAD)
    findings, details = document.analyze_pdf(risky)
    assert _ids(findings) == {"DOC_PDF_ACTIVE_CONTENT", "DOC_PDF_AUTO_ACTION", "DOC_PDF_EMBEDDED_FILE",
                              "DOC_TRAILING_PAYLOAD"}
    assert details["keywords"]["JavaScript"] == 1   # found despite the #61 escape


def test_pdf_javascript_inside_compressed_object_stream():
    hidden = zlib.compress(b"<< /S /JavaScript /JS (app.alert(1)) >>")
    pdf = (b"%PDF-1.5\n5 0 obj << /Type /ObjStm /N 1 /First 0 /Filter /FlateDecode /Length "
           + str(len(hidden)).encode() + b" >>\nstream\n" + hidden + b"\nendstream\nendobj\n%%EOF\n")
    findings, details = document.analyze_pdf(pdf)
    assert "DOC_PDF_ACTIVE_CONTENT" in _ids(findings) and details["object_streams"] == 1


# ------------------------------------------------- engine + scoring --

def test_content_engine_dispatch_and_report_shape(tmp_path):
    ctx = _ctx(tmp_path, make_png() + ZIP_PAYLOAD, "poly.png")
    report = analyzers.run("job-x", ctx)
    assert report["engine"] == "content" and report["analyzer"] == "image" and report["status"] == "ok"
    assert {"job_id", "engine", "status", "findings"} <= set(report)
    assert "CONTENT_ANALYZED" in _ids(report["findings"])
    assert (tmp_path / "content.json").exists()


def test_scoring_non_apk_content(tmp_path):
    ctx = _ctx(tmp_path, make_png() + ZIP_PAYLOAD, "poly.png")
    prior = {"integrity": integrity_run("j", ctx)}
    prior["content"] = analyzers.run("j", ctx)
    score = scoring.run("j", JobContext(target_path=ctx.target_path, workspace=str(tmp_path), prior=prior))
    assert score["analysis_complete"] and score["integrity"]["status"] == "NOT_APPLICABLE"
    assert score["risk"]["level"] in ("HIGH", "CRITICAL") and score["verdict"]["code"] == "HIGH_RISK"
    assert "content_sha256" in score["inputs"]

    clean_ctx = _ctx(tmp_path, make_png(), "clean.png")
    prior = {"integrity": integrity_run("k", clean_ctx), "content": analyzers.run("k", clean_ctx)}
    clean = scoring.run("k", JobContext(target_path=clean_ctx.target_path, workspace=str(tmp_path), prior=prior))
    assert clean["risk"]["score"] == 0 and clean["verdict"]["code"] == "CLEAN"
    assert "app" not in clean["verdict"]["summary"]


def test_scoring_content_missing_analyser_is_analysis_failed(tmp_path):
    ctx = _ctx(tmp_path, make_png(), "a.png")
    prior = {"integrity": integrity_run("j", ctx)}
    score = scoring.run("j", JobContext(target_path=ctx.target_path, workspace=str(tmp_path), prior=prior))
    assert score["verdict"]["code"] == "ANALYSIS_FAILED" and score["missing_engines"] == ["content"]


# ------------------------------------------------- full pipeline --

@pytest.mark.integration
@pytest.mark.parametrize("name,data,expect", [
    ("photo.png", make_png() + ZIP_PAYLOAD, "IMG_POLYGLOT_PAYLOAD"),
    ("clip.mp4", make_mp4(trailing=b"\xde\xad" * 100), "MEDIA_CONTAINER_ANOMALY"),
    ("page.html", RISKY_HTML, "WEB_MISSING_SRI"),
])
def test_pipeline_seals_non_apk_content(db, tmp_path, name, data, expect):
    from core import audit, repository
    from core.crypto import get_keyring
    from core.orchestrator import run_job

    path = tmp_path / name
    path.write_bytes(data)
    reports = run_job(str(path), job_id=f"job-{name}", root=str(tmp_path / "jobs"), db_session=db)
    assert set(reports) == {"integrity", "content", "score", "repository"}

    integ = reports["integrity"]
    assert integ["chunk_merkle_root"] == root(build_tree([c["hash"] for c in compute_chunks(data)]))
    assert expect in _ids(reports["content"]["findings"])
    score = reports["score"]
    assert score["analysis_complete"] and isinstance(score["risk"]["score"], int)
    assert expect in {c["finding_id"] for c in score["risk"]["contributions"]}

    repo = reports["repository"]
    assert repo["signature"] and repo["block_hash"] and repo["key_id"]
    db.expire_all()
    proof = repository.verify_job_report(db, f"job-{name}", reports)
    assert proof["valid"], proof["reasons"]
    assert audit.verify_chain(audit.all_blocks(db), get_keyring())["valid"]
    import json
    block = audit.events_for_subject(db, f"job-{name}", ("ANALYSIS_COMPLETED",))[-1]
    sealed = json.loads(block.payload_json)
    assert sealed["chunk_merkle_root"] == integ["chunk_merkle_root"]
    assert sealed["file_category"] == reports["content"]["file_category"]


@pytest.mark.integration
def test_pipeline_unknown_file_still_fails_as_invalid_apk(db, tmp_path):
    from core.orchestrator import run_job
    path = tmp_path / "junk.apk"
    path.write_bytes(b"definitely not a zip")
    reports = run_job(str(path), root=str(tmp_path / "jobs"), db_session=db)
    assert "integrity" not in reports and reports["score"]["verdict"]["code"] == "ANALYSIS_FAILED"
    assert "static" not in reports and "tamper" in reports   # APK path ran, as before


# ------------------------------------------------------------- API --

@pytest.mark.api
def test_api_accepts_content_upload_and_rejects_mismatch(db, tmp_path):
    from fastapi.testclient import TestClient

    from api.main import create_app
    from api.ratelimit import limiter
    from api.security import create_user
    from core.config import get_settings

    create_user(db, "carol", "correct-horse-battery", "analyst")
    db.commit()
    limiter.reset()
    with TestClient(create_app(get_settings())) as c:
        token = c.post("/api/v1/auth/login", json={"username": "carol", "password": "correct-horse-battery"})
        h = {"Authorization": f"Bearer {token.json()['access_token']}"}
        r = c.post("/api/v1/scans", headers=h, files={"file": ("cat.png", make_png() + ZIP_PAYLOAD)})
        assert r.status_code == 202, r.text
        scan = c.get(f"/api/v1/scans/{r.json()['id']}", headers=h).json()
        assert scan["status"] == "done" and scan["result"]["verdict"] == "HIGH_RISK"
        assert scan["engines"]["content"]["status"] == "ok"
        assert scan["engines"]["static"]["status"] == "skipped"

        bad = c.post("/api/v1/scans", headers=h, files={"file": ("cat.png", b"MZ\x90\x00 not a png")})
        assert bad.status_code == 422 and bad.json()["error"]["code"] == "invalid_content"
        apk_only = c.post("/api/v1/baselines", headers=h, files={"file": ("cat.png", make_png())})
        assert apk_only.status_code in (403, 415)
