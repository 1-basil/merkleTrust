"""api/main.py — MerkleTrust REST API (FastAPI application factory).

    /api/v1/auth/...        sign in / out
    /api/v1/scans/...       upload APKs, follow analysis, read & verify reports
    /api/v1/baselines/...   trusted baselines (admin manages, everyone reads)
    /api/v1/audit/...       audit trail — Cryptographically Linked Blockchain Simulation
    /api/v1/dashboard/...   summary for the web dashboard
    /api/v1/health          liveness (no auth)
    /                       web dashboard (static files)

Cross-cutting protections: bearer-token authentication with roles, request-size
limit enforced while the body streams in, upload validation, rate limiting on
login/upload, CORS allow-list without credentials, security headers (CSP etc.),
request IDs in every response and log line, one JSON error format with no
stack traces.

Run:  uvicorn api.main:app --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from api.errors import install_error_handlers
from api.jobs import JobRunner
from api.routers import audit as audit_router
from api.routers import auth, baselines, dashboard, scans
from core.config import Settings, get_settings
from core.crypto import get_keyring, get_signer
from core.logging_setup import configure_logging, request_id_var
from db.database import init_db

log = logging.getLogger("merkletrust.api")
REPO_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIR = REPO_ROOT / "frontend"

CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
       "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; object-src 'none'; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


class BodyTooLarge(Exception):
    pass


class BodySizeLimit:
    """ASGI middleware: reject request bodies above the limit while they stream in
    (Content-Length is checked up front; chunked bodies are counted)."""

    def __init__(self, app, max_bytes: int):
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        for name, value in scope.get("headers", []):
            if name == b"content-length" and value.isdigit() and int(value) > self.max_bytes:
                response = JSONResponse({"error": {"code": "payload_too_large", "message":
                                         "The request is larger than allowed.", "request_id": None}}, 413)
                return await response(scope, receive, send)
        seen = 0

        async def limited_receive():
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > self.max_bytes:
                    raise BodyTooLarge()
            return message

        return await self.app(scope, limited_receive, send)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    runner = JobRunner(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        configure_logging(settings.log_level, settings.log_json)
        get_signer(), get_keyring()  # fail fast on a missing/invalid signing key
        if settings.auto_migrate:
            init_db()
        runner.recover_interrupted()
        runner.start()
        log.info("MerkleTrust API started (env=%s, demo=%s)", settings.env, settings.demo_enabled)
        yield
        runner.shutdown()

    app = FastAPI(
        title="MerkleTrust API",
        description="Android APK integrity verification, cryptographic audit and threat detection.",
        version="2.0.0",
        lifespan=lifespan,
        docs_url=None if settings.is_production else "/api/docs",
        redoc_url=None,
        openapi_url=None if settings.is_production else "/api/openapi.json",
    )
    app.state.job_runner = runner
    app.state.settings = settings
    install_error_handlers(app)

    @app.exception_handler(BodyTooLarge)
    async def too_large(_request: Request, _exc: BodyTooLarge):
        return JSONResponse({"error": {"code": "payload_too_large", "message": "The request is larger than allowed.",
                                       "request_id": request_id_var.get()}}, status_code=413)

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        rid = uuid.uuid4().hex[:16]
        token = request_id_var.set(rid)
        start = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
        finally:
            log.info("request", extra={"method": request.method, "path": request.url.path, "status": status,
                                       "duration_ms": round((time.perf_counter() - start) * 1000, 1),
                                       "user": getattr(request.state, "username", None)})
            request_id_var.reset(token)
        response.headers["X-Request-ID"] = rid
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = CSP
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    if settings.cors_origins:
        app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=False,
                           allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type"],
                           max_age=600)
    app.add_middleware(BodySizeLimit, max_bytes=(settings.max_upload_mb + 1) * 1024 * 1024)

    for router in (auth.router, scans.router, baselines.router, audit_router.router, dashboard.router):
        app.include_router(router, prefix="/api/v1")

    if FRONTEND_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

        @app.get("/", include_in_schema=False)
        def index():
            return FileResponse(FRONTEND_DIR / "index.html")

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="127.0.0.1", port=8000)
