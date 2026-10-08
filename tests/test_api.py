"""REST API: authentication, authorization, secure upload, job processing, baselines,
audit chain, error format, security headers, CORS, rate limiting, migrations."""

import io
import json
import os
import stat
import zipfile
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from api.main import create_app
from api.ratelimit import limiter
from api.security import create_user
from core.config import get_settings
from db.models import AuthSession, Job, User

pytestmark = pytest.mark.api

PASSWORD = "correct-horse-battery"


@pytest.fixture
def make_client(db):
    """Build a TestClient for an app with optional settings overrides (fresh DB per test)."""
    clients = []

    def _make(**overrides):
        limiter.reset()
        settings = get_settings().model_copy(update=overrides) if overrides else get_settings()
        c = TestClient(create_app(settings))
        c.__enter__()
        clients.append(c)
        return c

    yield _make
    for c in clients:
        c.__exit__(None, None, None)


@pytest.fixture
def client(make_client):
    return make_client()


@pytest.fixture
def users(db):
    create_user(db, "alice", PASSWORD, "admin")
    create_user(db, "bob", PASSWORD, "analyst")
    db.commit()


def auth(client, username):
    r = client.post("/api/v1/auth/login", json={"username": username, "password": PASSWORD})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def upload(client, headers, path, name=None, url="/api/v1/scans"):
    with open(path, "rb") as fh:
        return client.post(url, headers=headers, files={"file": (name or os.path.basename(path), fh.read(),
                                                                 "application/octet-stream")})


# ------------------------------------------------------------ auth --

def test_login_me_logout(client, users):
    h = auth(client, "bob")
    assert client.get("/api/v1/auth/me", headers=h).json() == {"username": "bob", "role": "analyst"}
    assert client.post("/api/v1/auth/logout", headers=h).status_code == 204
    assert client.get("/api/v1/auth/me", headers=h).status_code == 401


@pytest.mark.parametrize("username,password", [("bob", "wrong-password!"), ("nobody", PASSWORD)])
def test_bad_credentials_get_one_generic_message(client, users, username, password):
    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert r.status_code == 401
    assert r.json()["error"]["message"] == "Incorrect username or password."


@pytest.mark.parametrize("header", [None, "Bearer", "Bearer not-a-real-token", "Basic Ym9iOnB3", "bearer " + "x" * 300])
def test_invalid_tokens_rejected(client, users, header):
    r = client.get("/api/v1/auth/me", headers={"Authorization": header} if header else {})
    assert r.status_code == 401 and r.headers["WWW-Authenticate"] == "Bearer"


def test_expired_session_rejected(client, users, db):
    h = auth(client, "bob")
    for s in db.scalars(select(AuthSession)):
        s.expires_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=1)
    db.commit()
    assert client.get("/api/v1/auth/me", headers=h).status_code == 401


def test_disabled_user_rejected(client, users, db):
    h = auth(client, "bob")
    db.scalars(select(User).where(User.username == "bob")).one().active = False
    db.commit()
    assert client.get("/api/v1/auth/me", headers=h).status_code == 401


def test_secrets_are_not_stored_in_clear(client, users, db):
    token = auth(client, "bob")["Authorization"].split()[1]
    user = db.scalars(select(User).where(User.username == "bob")).one()
    assert PASSWORD not in user.password_hash and user.password_hash.startswith("scrypt$")
    assert all(token not in s.token_hash for s in db.scalars(select(AuthSession)))


def test_login_rate_limited(make_client, users):
    c = make_client(login_rate_per_minute=3)
    for _ in range(3):
        c.post("/api/v1/auth/login", json={"username": "bob", "password": "nope-nope-nope"})
    r = c.post("/api/v1/auth/login", json={"username": "bob", "password": PASSWORD})
    assert r.status_code == 429 and int(r.headers["Retry-After"]) > 0


def test_logins_are_audited(client, users):
    client.post("/api/v1/auth/login", json={"username": "bob", "password": "wrong-password!"})
    h = auth(client, "bob")
    events = [b["event_type"] for b in client.get("/api/v1/audit/blocks", headers=h).json()["items"]]
    assert "LOGIN_FAILED" in events and "USER_LOGIN" in events


# ------------------------------------------------------- authorization --

PROTECTED = [("get", "/api/v1/scans"), ("post", "/api/v1/scans"), ("get", "/api/v1/baselines"),
             ("post", "/api/v1/baselines"), ("get", "/api/v1/audit/blocks"), ("post", "/api/v1/audit/verify"),
             ("get", "/api/v1/dashboard/summary"), ("post", "/api/v1/audit/demo/tamper")]


@pytest.mark.parametrize("method,path", PROTECTED)
def test_endpoints_require_authentication(client, method, path):
    assert getattr(client, method)(path).status_code == 401


@pytest.mark.parametrize("method,path,body", [
    ("post", "/api/v1/baselines/1/approve", {}),
    ("post", "/api/v1/baselines/1/revoke", {"reason": "because"}),
    ("post", "/api/v1/baselines/1/reject", {"reason": "because"}),
    ("post", "/api/v1/audit/demo/tamper", {"block_index": 1}),
    ("post", "/api/v1/audit/demo/restore", None),
])
def test_analyst_cannot_perform_admin_actions(client, users, method, path, body):
    r = getattr(client, method)(path, headers=auth(client, "bob"), json=body)
    assert r.status_code == 403


def test_analyst_cannot_enroll_baseline(client, users, fixture_apk):
    r = upload(client, auth(client, "bob"), fixture_apk("signed_v1v2_ec.apk"), url="/api/v1/baselines")
    assert r.status_code == 403


# ------------------------------------------------------------- uploads --

def test_upload_runs_analysis(client, users, fixture_apk):
    h = auth(client, "bob")
    r = upload(client, h, fixture_apk("signed_v1v2_ec.apk"))
    assert r.status_code == 202
    scan = client.get(f"/api/v1/scans/{r.json()['id']}", headers=h).json()
    assert scan["status"] == "done"
    assert scan["submitted_by"] == "bob" and scan["package_name"] == "com.merkletrust.demo"
    assert scan["result"]["verdict"] == "NO_BASELINE"
    assert all(e["status"] in ("ok", "partial") for e in scan["engines"].values())
    assert client.get("/api/v1/scans", headers=h).json()["total"] == 1


def _bomb():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", b"x")
        z.writestr("assets/bomb", b"\0" * (5 * 1024 * 1024))
    return buf.getvalue()


@pytest.mark.parametrize("name,content,status,code", [
    ("app.apk", b"definitely not a zip", 422, "invalid_apk"),
    ("app.apk", b"", 422, "invalid_request"),
    ("app.exe", b"PK\x03\x04", 415, "unsupported_media_type"),
    ("bomb.apk", None, 422, "invalid_apk"),
])
def test_bad_uploads_rejected(client, users, name, content, status, code):
    content = _bomb() if content is None else content
    r = client.post("/api/v1/scans", headers=auth(client, "bob"), files={"file": (name, content)})
    assert r.status_code == status and r.json()["error"]["code"] == code
    assert client.get("/api/v1/scans", headers=auth(client, "bob")).json()["total"] == 0


def test_oversized_upload_rejected(make_client, users):
    c = make_client(max_upload_mb=1)
    r = c.post("/api/v1/scans", headers=auth(c, "bob"), files={"file": ("big.apk", b"\0" * (3 * 1024 * 1024))})
    assert r.status_code == 413 and r.json()["error"]["code"] == "payload_too_large"


def test_filename_cannot_escape_quarantine(client, users, fixture_apk):
    h = auth(client, "bob")
    r = upload(client, h, fixture_apk("signed_v1v2_ec.apk"), name="../../../etc/evil<script>.apk")
    assert r.status_code == 202
    assert r.json()["filename"] == "evil_script_.apk"
    stored = get_settings().quarantine_dir / f"{r.json()['apk_sha256']}.apk"
    assert stored.exists()
    assert not stat.S_IMODE(stored.stat().st_mode) & stat.S_IWUSR  # read-only


@pytest.mark.parametrize("scan_id", ["not-a-uuid", "..%2F..%2Fetc", "00000000-0000-0000-0000-000000000000"])
def test_unknown_scan_ids(client, users, scan_id):
    r = client.get(f"/api/v1/scans/{scan_id}/report", headers=auth(client, "bob"))
    assert r.status_code == 404


def test_report_before_completion_is_conflict(client, users, db):
    from db.models import ApkFile
    db.add(ApkFile(sha256="a" * 64, filename="x.apk", file_size=1, quarantine_path="x"))
    db.add(Job(id="11111111-1111-1111-1111-111111111111", apk_sha256="a" * 64, status="queued", workspace="w"))
    db.commit()
    r = client.get("/api/v1/scans/11111111-1111-1111-1111-111111111111/report", headers=auth(client, "bob"))
    assert r.status_code == 409 and r.json()["error"]["code"] == "not_ready"


def test_queue_full_returns_503(make_client, users, fixture_apk):
    c = make_client(job_execution="thread", max_queued_jobs=0)
    r = upload(c, auth(c, "bob"), fixture_apk("signed_v1v2_ec.apk"))
    assert r.status_code == 503


# -------------------------------------------- baseline + scan full flow --

def test_full_flow_through_the_api(client, users, fixture_apk, tmp_path):
    admin, analyst = auth(client, "alice"), auth(client, "bob")

    enrolled = upload(client, admin, fixture_apk("signed_v1v2_ec.apk"), url="/api/v1/baselines")
    assert enrolled.status_code == 201
    bid = enrolled.json()["baseline"]["id"]
    assert enrolled.json()["baseline"]["status"] == "pending"
    approved = client.post(f"/api/v1/baselines/{bid}/approve", headers=admin, json={"note": "release 1.2.0"})
    assert approved.json()["status"] == "approved"
    assert client.get(f"/api/v1/baselines/{bid}/verify", headers=analyst).json()["valid"] is True

    clean_id = upload(client, analyst, fixture_apk("signed_v1v2_ec.apk")).json()["id"]
    assert client.get(f"/api/v1/scans/{clean_id}", headers=analyst).json()["result"]["verdict"] == "CLEAN"

    resigned_id = upload(client, analyst, fixture_apk("signed_v2v3_rsa.apk")).json()["id"]
    resigned = client.get(f"/api/v1/scans/{resigned_id}", headers=analyst).json()["result"]
    assert resigned["integrity_status"] == "CERTIFICATE_CHANGED" and resigned["verdict"] == "HIGH_RISK"

    report = client.get(f"/api/v1/scans/{resigned_id}/report", headers=analyst).json()
    assert report["reports"]["tamper"]["baseline_id"] == bid

    verified = client.post(f"/api/v1/scans/{resigned_id}/verify", headers=analyst).json()
    assert verified["valid"] is True and verified["checks"]["report_hash_matches"] is True

    # per-file Merkle proof against the trusted root
    from scripts.apk_mutations import rewrite_zip
    src = fixture_apk("signed_v1v2_ec.apk")
    patched = rewrite_zip(src, tmp_path / "p.apk",
                          modify={"classes.dex": zipfile.ZipFile(src).read("classes.dex") + b"\0x"})
    patched_id = upload(client, analyst, patched).json()["id"]
    p = client.get(f"/api/v1/scans/{patched_id}/files/proof", headers=analyst, params={"path": "classes.dex"}).json()
    assert p["current_file_verified"] is False and p["baseline_sha256"] != p["current_sha256"]
    p_ok = client.get(f"/api/v1/scans/{clean_id}/files/proof", headers=analyst, params={"path": "classes.dex"}).json()
    assert p_ok["current_file_verified"] is True

    # state machine errors are 409, unknown ids 404
    assert client.post(f"/api/v1/baselines/{bid}/approve", headers=admin, json={}).status_code == 409
    assert client.post("/api/v1/baselines/999/approve", headers=admin, json={}).status_code == 404
    assert client.post(f"/api/v1/baselines/{bid}/revoke", headers=admin, json={"reason": "rotated"}).status_code == 200

    summary = client.get("/api/v1/dashboard/summary", headers=analyst).json()
    assert summary["applications"]["analyzed"] == 1
    assert summary["baselines"]["revoked"] == 1
    assert summary["audit_chain"]["valid"] is True


def test_invalid_apk_cannot_become_baseline(client, users, fixture_apk):
    r = upload(client, auth(client, "alice"), fixture_apk("unsigned.apk"), url="/api/v1/baselines")
    assert r.status_code == 422 and r.json()["error"]["code"] == "baseline_rejected"


def test_tampered_report_fails_verification(client, users, fixture_apk):
    h = auth(client, "bob")
    sid = upload(client, h, fixture_apk("signed_v1v2_ec.apk")).json()["id"]
    path = get_settings().jobs_dir / sid / "merged.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["reports"]["score"]["risk"]["score"] = 99  # was 0
    path.write_text(json.dumps(data), encoding="utf-8")
    r = client.post(f"/api/v1/scans/{sid}/verify", headers=h).json()
    assert r["valid"] is False and r["checks"]["report_hash_matches"] is False


# --------------------------------------------------------- audit chain --

def test_audit_demo_tamper_and_restore(client, users, fixture_apk):
    admin = auth(client, "alice")
    upload(client, admin, fixture_apk("signed_v1v2_ec.apk"))
    chain = client.post("/api/v1/audit/verify", headers=admin).json()
    assert chain["valid"] is True
    target = 2
    t = client.post("/api/v1/audit/demo/tamper", headers=admin, json={"block_index": target, "mode": "rewrite_block"})
    assert t.status_code == 200
    assert t.json()["valid"] is False and t.json()["first_invalid_index"] == target
    assert client.post("/api/v1/audit/demo/tamper", headers=admin, json={"block_index": 1}).status_code == 409
    blocks = client.get("/api/v1/audit/blocks", headers=admin).json()
    assert blocks["chain"]["valid"] is False
    r = client.post("/api/v1/audit/demo/restore", headers=admin).json()
    assert r["restored_blocks"] == [target] and r["valid"] is True
    assert client.post("/api/v1/audit/verify", headers=admin).json()["valid"] is True


def test_audit_head_keys_and_proofs(client, users):
    h = auth(client, "bob")
    head = client.get("/api/v1/audit/head", headers=h).json()
    assert head["head"]["index"] >= 1 and head["signature"]["alg"] == "ECDSA-P256-SHA256"
    keys = client.get("/api/v1/audit/keys", headers=h).json()["keys"]
    assert keys[0]["public_key_pem"].startswith("-----BEGIN PUBLIC KEY-----")
    assert "PRIVATE" not in json.dumps(keys)
    p = client.get("/api/v1/audit/blocks/1/proof", headers=h).json()
    assert p["index"] == 1 and p["merkle_root"]
    assert client.get("/api/v1/audit/blocks/9999", headers=h).status_code == 404


def test_demo_disabled_in_production(make_client, users):
    c = make_client(env="production", enable_demo=None, signing_key_path=None)
    r = c.post("/api/v1/audit/demo/tamper", headers=auth(c, "alice"), json={"block_index": 1})
    assert r.status_code == 403


# ------------------------------------------- errors, headers, CORS --

def test_error_format_and_request_id(client):
    r = client.get("/api/v1/scans/x", headers={"Authorization": "Bearer nope"})
    body = r.json()["error"]
    assert set(body) == {"code", "message", "request_id"} and body["request_id"] == r.headers["X-Request-ID"]


def test_validation_errors_do_not_echo_input(client):
    r = client.post("/api/v1/auth/login", json={"username": "", "password": "secret-value-xyz"})
    assert r.status_code == 422 and "secret-value-xyz" not in r.text
    assert r.json()["error"]["details"][0]["location"].startswith("body")


def test_internal_errors_are_generic(make_client, users, monkeypatch):
    c = make_client()
    import api.routers.dashboard as dash
    monkeypatch.setattr(dash.audit, "all_blocks", lambda db: (_ for _ in ()).throw(RuntimeError("db secret path")))
    c2 = TestClient(c.app, raise_server_exceptions=False)
    r = c2.get("/api/v1/dashboard/summary", headers=auth(c, "bob"))
    assert r.status_code == 500 and r.json()["error"]["code"] == "internal_error"
    assert "secret" not in r.text and "Traceback" not in r.text


def test_security_headers(client):
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    for header in ("Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"):
        assert header in r.headers
    assert r.headers["Cache-Control"] == "no-store"
    assert "script-src 'self'" in r.headers["Content-Security-Policy"]


def test_cors_closed_by_default(client):
    r = client.options("/api/v1/health", headers={"Origin": "https://evil.example",
                                                  "Access-Control-Request-Method": "GET"})
    assert "access-control-allow-origin" not in r.headers


def test_cors_allow_list_without_credentials(make_client):
    c = make_client(cors_origins=["https://dashboard.example"])
    ok = c.get("/api/v1/health", headers={"Origin": "https://dashboard.example"})
    assert ok.headers["access-control-allow-origin"] == "https://dashboard.example"
    assert "access-control-allow-credentials" not in ok.headers
    bad = c.get("/api/v1/health", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in bad.headers


def test_docs_hidden_in_production(make_client):
    assert make_client().get("/api/docs").status_code == 200
    assert make_client(env="production").get("/api/docs").status_code == 404


# ----------------------------------------------- migrations, recovery --

def test_migrations_match_models(tmp_path):
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext
    from sqlalchemy import create_engine

    from db.database import Base
    from db.migrations import upgrade_database
    engine = create_engine(f"sqlite:///{(tmp_path / 'm.db').as_posix()}")
    upgrade_database(engine)
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn, opts={"compare_type": True}), Base.metadata)
    assert diff == []


def test_interrupted_jobs_marked_failed_on_startup(db, make_client):
    from db.models import ApkFile
    db.add(ApkFile(sha256="b" * 64, filename="x.apk", file_size=1, quarantine_path="x"))
    db.add(Job(id="22222222-2222-2222-2222-222222222222", apk_sha256="b" * 64, status="running", workspace="w"))
    db.commit()
    make_client()
    db.expire_all()
    job = db.get(Job, "22222222-2222-2222-2222-222222222222")
    assert job.status == "failed" and "restart" in job.error_message


def test_health_needs_no_auth(client):
    assert client.get("/api/v1/health").json()["status"] == "ok"


def test_dashboard_is_served_with_strict_csp(client):
    page = client.get("/")
    assert page.status_code == 200 and '<script type="module" src="/static/js/app.js">' in page.text
    assert "<script>" not in page.text and "onclick=" not in page.text   # nothing inline: CSP needs no 'unsafe-inline'
    js = client.get("/static/js/app.js")
    assert js.status_code == 200 and "javascript" in js.headers["content-type"]
    assert client.get("/static/css/app.css").status_code == 200


def test_react_app_is_served_under_app(make_client, tmp_path, monkeypatch):
    import api.main
    (tmp_path / "assets").mkdir()
    (tmp_path / "index.html").write_text("<!doctype html><div id=root></div>", encoding="utf-8")
    (tmp_path / "assets" / "app.js").write_text("console.log(1)", encoding="utf-8")
    (tmp_path.parent / "secret.txt").write_text("secret", encoding="utf-8")
    monkeypatch.setattr(api.main, "WEBAPP_DIST", tmp_path)
    client = make_client()
    assert "id=root" in client.get("/app").text
    assert "id=root" in client.get("/app/chain").text           # client-side route -> index.html
    js = client.get("/app/assets/app.js")
    assert js.status_code == 200 and "javascript" in js.headers["content-type"]
    assert "secret" not in client.get("/app/..%2fsecret.txt").text  # no escape from the build folder
    assert client.get("/app").headers["Content-Security-Policy"].startswith("default-src 'self'")


def test_frontend_never_injects_html():
    """Data from APKs is attacker-controlled: the UI must build DOM nodes, not HTML strings."""
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent / "frontend" / "js"
    for f in root.rglob("*.js"):
        code = "\n".join(line for line in f.read_text(encoding="utf-8").splitlines() if not line.strip().startswith("//"))
        for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
            assert sink not in code, f"{f.name} uses {sink}"


def test_baseline_routes(client, users, fixture_apk):
    admin, analyst = auth(client, "alice"), auth(client, "bob")
    first = upload(client, admin, fixture_apk("signed_v1v2_ec.apk"), url="/api/v1/baselines").json()["baseline"]
    dup = upload(client, admin, fixture_apk("signed_v1v2_ec.apk"), url="/api/v1/baselines")
    assert dup.status_code == 422 and "already baseline" in dup.json()["error"]["message"]

    assert [b["id"] for b in client.get("/api/v1/baselines", headers=analyst, params={"status": "pending"}).json()["items"]] == [first["id"]]
    assert client.get("/api/v1/baselines", headers=analyst, params={"status": "bogus"}).status_code == 422
    assert client.get("/api/v1/baselines", headers=analyst, params={"package": "nope"}).json()["items"] == []

    detail = client.get(f"/api/v1/baselines/{first['id']}", headers=analyst, params={"include_files": True}).json()
    assert any(f["path"] == "classes.dex" for f in detail["files"]) and "profile" in detail
    assert client.get("/api/v1/baselines/999", headers=analyst).status_code == 404
    assert client.get("/api/v1/baselines/999/verify", headers=analyst).status_code == 404

    proof = client.get(f"/api/v1/baselines/{first['id']}/files/proof", headers=analyst, params={"path": "classes.dex"}).json()
    assert proof["verified"] is True and proof["root"] == first["merkle_root"]
    assert client.get(f"/api/v1/baselines/{first['id']}/files/proof", headers=analyst,
                      params={"path": "nope.dex"}).status_code == 404

    short = client.post(f"/api/v1/baselines/{first['id']}/reject", headers=admin, json={"reason": "x"})
    assert short.status_code == 422                                    # reason too short
    rejected = client.post(f"/api/v1/baselines/{first['id']}/reject", headers=admin, json={"reason": "wrong build"})
    assert rejected.json()["status"] == "rejected"
    assert client.post(f"/api/v1/baselines/{first['id']}/revoke", headers=admin,
                       json={"reason": "cannot revoke a rejected one"}).status_code == 409
