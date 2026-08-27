"""Phase 21 Workstream C payload, CORS and security-header tests."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient


SERVER_ROOT = Path(__file__).resolve().parents[1]

if str(SERVER_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVER_ROOT))

MAIN_PATH = SERVER_ROOT / "main.py"

spec = importlib.util.spec_from_file_location(
    "sentinel_application_main",
    MAIN_PATH,
)

if spec is None or spec.loader is None:
    raise RuntimeError(
        "Unable to load SENTINEL application main module"
    )

main = importlib.util.module_from_spec(spec)
spec.loader.exec_module(main)


def build_body_limit_app(
    *,
    max_bytes: int = 32,
) -> FastAPI:
    app = FastAPI()
    app.add_middleware(
        main.JSONBodyLimitMiddleware,
        max_bytes=max_bytes,
    )

    @app.post("/echo")
    async def echo(request: Request):
        return {
            "body": (await request.body()).decode(
                "utf-8",
                errors="replace",
            )
        }

    return app


def test_json_body_within_limit_reaches_route() -> None:
    response = TestClient(
        build_body_limit_app(max_bytes=64)
    ).post(
        "/echo",
        content=b'{"message":"ok"}',
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 200
    assert response.json()["body"] == '{"message":"ok"}'


def test_json_body_over_limit_returns_413_before_route() -> None:
    response = TestClient(
        build_body_limit_app(max_bytes=16)
    ).post(
        "/echo",
        content=b'{"message":"' + (b"x" * 32) + b'"}',
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json() == {
        "detail": "JSON request body exceeds the 1 MB limit"
    }


def test_multipart_body_is_not_subject_to_json_cap() -> None:
    response = TestClient(
        build_body_limit_app(max_bytes=16)
    ).post(
        "/echo",
        files={
            "file": (
                "events.csv",
                b"x" * 128,
                "text/csv",
            )
        },
    )

    assert response.status_code == 200
    assert "multipart/form-data" in response.request.headers[
        "content-type"
    ]


def test_main_app_oversized_json_returns_413_with_security_headers() -> None:
    payload = b'{"raw_text":"' + (
        b"x" * (main.MAX_JSON_BODY_BYTES + 1)
    ) + b'"}'

    with TestClient(main.app) as client:
        response = client.post(
            "/api/upload",
            content=payload,
            headers={
                "Content-Type": "application/json",
            },
        )

    assert response.status_code == 413
    assert response.json() == {
        "detail": "JSON request body exceeds the 1 MB limit"
    }
    assert (
        response.headers["x-content-type-options"]
        == "nosniff"
    )
    assert response.headers["x-frame-options"] == "DENY"


def test_security_headers_are_added_to_normal_responses() -> None:
    with TestClient(main.app) as client:
        response = client.get("/api/health")

    assert response.status_code == 200
    assert (
        response.headers["x-content-type-options"]
        == "nosniff"
    )
    assert response.headers["x-frame-options"] == "DENY"


def test_cors_allows_only_configured_frontend_origin() -> None:
    frontend_url = os.environ["FRONTEND_URL"]

    with TestClient(main.app) as client:
        allowed = client.options(
            "/api/auth/login",
            headers={
                "Origin": frontend_url,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers":
                    "authorization,content-type",
            },
        )

        denied = client.options(
            "/api/auth/login",
            headers={
                "Origin": "https://untrusted.example",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers":
                    "authorization,content-type",
            },
        )

    assert allowed.status_code == 200
    assert (
        allowed.headers["access-control-allow-origin"]
        == frontend_url
    )
    assert (
        allowed.headers["access-control-allow-credentials"]
        == "true"
    )

    allowed_methods = {
        value.strip()
        for value in allowed.headers[
            "access-control-allow-methods"
        ].split(",")
    }
    assert allowed_methods == set(
        main.ALLOWED_CORS_METHODS
    )

    allowed_headers = (
        allowed.headers[
            "access-control-allow-headers"
        ].lower()
    )
    assert "authorization" in allowed_headers
    assert "content-type" in allowed_headers

    assert (
        "access-control-allow-origin"
        not in denied.headers
    )


def test_cors_rejects_unapproved_method() -> None:
    frontend_url = os.environ["FRONTEND_URL"]

    with TestClient(main.app) as client:
        response = client.options(
            "/api/auth/login",
            headers={
                "Origin": frontend_url,
                "Access-Control-Request-Method": "PATCH",
            },
        )

    assert response.status_code == 400
