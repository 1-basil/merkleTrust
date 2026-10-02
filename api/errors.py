"""api/errors.py — One error format for every failure.

    {"error": {"code": "not_found", "message": "Scan not found", "request_id": "…"}}

Validation errors add "details" (field location + message, never the submitted
value). Unexpected exceptions are logged with their stack trace server-side and
returned as a generic 500 — internals are never exposed to clients.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from core.logging_setup import request_id_var

log = logging.getLogger("merkletrust.api")

STATUS_CODES = {400: "bad_request", 401: "unauthorized", 403: "forbidden", 404: "not_found",
                405: "method_not_allowed", 409: "conflict", 413: "payload_too_large",
                415: "unsupported_media_type", 422: "invalid_request", 429: "rate_limited",
                503: "service_unavailable"}


class ApiError(HTTPException):
    """Raise with a stable machine-readable code and a user-safe message."""

    def __init__(self, status_code: int, message: str, code: str | None = None, headers: dict | None = None):
        super().__init__(status_code=status_code, detail=message, headers=headers)
        self.code = code or STATUS_CODES.get(status_code, "error")


def _body(code: str, message: str, details=None) -> dict:
    err = {"code": code, "message": message, "request_id": request_id_var.get()}
    if details is not None:
        err["details"] = details
    return {"error": err}


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(StarletteHTTPException)
    async def http_error(_request: Request, exc: StarletteHTTPException):
        code = getattr(exc, "code", None) or STATUS_CODES.get(exc.status_code, "error")
        message = exc.detail if isinstance(exc.detail, str) else "Request failed"
        return JSONResponse(_body(code, message), status_code=exc.status_code, headers=getattr(exc, "headers", None))

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, exc: RequestValidationError):
        details = [{"location": ".".join(str(p) for p in e.get("loc", ())), "message": e.get("msg", "")}
                   for e in exc.errors()]
        return JSONResponse(_body("invalid_request", "The request is invalid.", details), status_code=422)

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, exc: Exception):
        log.exception("unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse(_body("internal_error", "An internal error occurred. Quote the request id if you "
                                                    "report this."), status_code=500)
