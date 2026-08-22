"""Phase 15 rate-limiting configuration tests."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import os
from pathlib import Path
import sys
from types import SimpleNamespace

from bson import ObjectId
from fastapi.security import HTTPAuthorizationCredentials
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
import pytest

SERVER_DIR = Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

os.environ.setdefault("MONGO_URI", "mongodb://unused-test-host:27017/sentinel")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-for-tests")

from config.rate_limit import (  # noqa: E402
    RATE_LIMITS,
    get_ip_key,
    get_user_id_key,
    limiter,
)
from main import app  # noqa: E402
from middleware import auth as auth_middleware  # noqa: E402
from routers import auth as auth_router  # noqa: E402


EXPECTED_LIMITS = {
    "auth_register": "5/15minutes",
    "auth_login": "5/15minutes",
    "upload": "10/hour",
    "investigation_list": "60/15minutes",
    "investigation_detail": "60/15minutes",
    "investigation_delete": "20/15minutes",
    "incident_get": "60/15minutes",
    "incident_regenerate": "5/hour",
    "kb_setup": "2/day",
    "kb_status": "30/15minutes",
    "health": "30/minute",
}

ROUTE_LIMIT_KEYS = {
    ("POST", "/api/auth/register"): "auth_register",
    ("POST", "/api/auth/login"): "auth_login",
    ("POST", "/api/upload"): "upload",
    ("GET", "/api/investigations"): "investigation_list",
    ("GET", "/api/investigations/{investigation_id}"): "investigation_detail",
    ("DELETE", "/api/investigations/{investigation_id}"): "investigation_delete",
    ("GET", "/api/incident/{investigation_id}"): "incident_get",
    ("POST", "/api/incident/{investigation_id}/regenerate"): "incident_regenerate",
    ("POST", "/api/kb/setup"): "kb_setup",
    ("GET", "/api/kb/status"): "kb_status",
    ("GET", "/api/health"): "health",
}


def _route(method: str, path: str):
    for route in app.routes:
        if route.path == path and method in (route.methods or set()):
            return route
    raise AssertionError(f"Route not found: {method} {path}")


def _limiter_key_for_endpoint(endpoint) -> str:
    return f"{endpoint.__module__}.{endpoint.__name__}"


def test_limiter_is_attached_to_app_state_as_singleton() -> None:
    assert app.state.limiter is limiter


def test_slowapi_middleware_is_present() -> None:
    assert any(
        middleware.cls is SlowAPIMiddleware
        for middleware in app.user_middleware
    )


def test_rate_limit_exceeded_handler_is_registered() -> None:
    assert app.exception_handlers[RateLimitExceeded] is _rate_limit_exceeded_handler


def test_rate_limit_constants_match_phase_15_contract() -> None:
    assert RATE_LIMITS == EXPECTED_LIMITS


@pytest.mark.parametrize(
    ("method", "path", "limit_name"),
    [
        ("POST", "/api/auth/register", "auth_register"),
        ("POST", "/api/auth/login", "auth_login"),
    ],
)
def test_auth_routes_have_limiter_decorator(
    method: str,
    path: str,
    limit_name: str,
) -> None:
    route = _route(method, path)
    endpoint_key = _limiter_key_for_endpoint(route.endpoint)

    assert hasattr(route.endpoint, "__wrapped__")
    assert endpoint_key in limiter._route_limits
    assert limiter._route_limits[endpoint_key]
    assert RATE_LIMITS[limit_name] == EXPECTED_LIMITS[limit_name]


def test_upload_route_has_limiter_decorator() -> None:
    route = _route("POST", "/api/upload")
    endpoint_key = _limiter_key_for_endpoint(route.endpoint)

    assert hasattr(route.endpoint, "__wrapped__")
    assert endpoint_key in limiter._route_limits
    assert limiter._route_limits[endpoint_key]
    assert RATE_LIMITS["upload"] == "10/hour"


def test_regenerate_route_has_limiter_decorator() -> None:
    route = _route(
        "POST",
        "/api/incident/{investigation_id}/regenerate",
    )
    endpoint_key = _limiter_key_for_endpoint(route.endpoint)

    assert hasattr(route.endpoint, "__wrapped__")
    assert endpoint_key in limiter._route_limits
    assert limiter._route_limits[endpoint_key]
    assert RATE_LIMITS["incident_regenerate"] == "5/hour"


@pytest.mark.parametrize(
    ("method", "path", "limit_name"),
    list(
        (method, path, limit_name)
        for (method, path), limit_name in ROUTE_LIMIT_KEYS.items()
    ),
)
def test_every_phase_15_route_is_decorated_in_correct_order(
    method: str,
    path: str,
    limit_name: str,
) -> None:
    route = _route(method, path)
    endpoint = route.endpoint
    endpoint_key = _limiter_key_for_endpoint(endpoint)

    # Correct ordering is @router.* outermost, @limiter.limit immediately
    # below it. In that order FastAPI registers SlowAPI's wrapped endpoint.
    assert hasattr(endpoint, "__wrapped__"), (
        f"{method} {path} is not registered with the SlowAPI wrapper; "
        "check decorator ordering"
    )
    assert endpoint_key in limiter._route_limits
    assert limiter._route_limits[endpoint_key]
    assert RATE_LIMITS[limit_name] == EXPECTED_LIMITS[limit_name]


def test_authenticated_user_key_uses_verified_user_id_not_token_prefix() -> None:
    app_state = SimpleNamespace(limiter=limiter)
    request_a = SimpleNamespace(
        state=SimpleNamespace(authenticated_user_id="6a876e9796ee58ac429052c1"),
        app=SimpleNamespace(state=app_state),
        headers={"Authorization": "Bearer eyJhbGciOiJI-first-token"},
    )
    request_b = SimpleNamespace(
        state=SimpleNamespace(authenticated_user_id="6a876e9796ee58ac429052c1"),
        app=SimpleNamespace(state=app_state),
        headers={"Authorization": "Bearer completely-different-token"},
    )

    expected = "user:6a876e9796ee58ac429052c1"
    assert get_user_id_key(request_a) == expected
    assert get_user_id_key(request_b) == expected


def test_user_key_falls_back_to_client_ip_on_main_app() -> None:
    request = SimpleNamespace(
        state=SimpleNamespace(),
        app=SimpleNamespace(state=SimpleNamespace(limiter=limiter)),
        client=SimpleNamespace(host="203.0.113.42"),
    )

    assert get_user_id_key(request) == "203.0.113.42"
    assert get_ip_key(request) == "203.0.113.42"


def test_get_current_user_places_verified_identity_on_request_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("JWT_SECRET", "phase-15-auth-state-secret")
    user_id = ObjectId()
    token = auth_router.create_access_token(str(user_id))
    document = {
        "_id": user_id,
        "username": "rate_limit_user",
        "email": "rate-limit@example.co.za",
        "hashed_password": "unused",
        "is_admin": False,
        "created_at": datetime.now(timezone.utc),
    }

    class FakeUsers:
        def find_one(self, query):
            return document if query == {"_id": user_id} else None

    class FakeDatabase:
        def __getitem__(self, name):
            assert name == "users"
            return FakeUsers()

    monkeypatch.setattr(
        auth_middleware,
        "get_database",
        lambda: FakeDatabase(),
    )

    credentials = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials=token,
    )
    request = SimpleNamespace(state=SimpleNamespace())

    user = asyncio.run(
        auth_middleware.get_current_user(credentials, request)
    )

    assert user.id == user_id
    assert request.state.authenticated_user_id == str(user_id)