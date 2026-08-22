"""Shared SENTINEL rate-limiting configuration."""

from __future__ import annotations

from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address


RATE_LIMITS = {
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


def get_ip_key(request: Request) -> str:
    """Return the client IP, isolated per app when the singleton is not wired."""
    remote = get_remote_address(request)
    installed_limiter = getattr(request.app.state, "limiter", None)

    if installed_limiter is limiter:
        return remote

    # Routers are also mounted into isolated FastAPI apps by the test suite.
    # Namespacing those apps prevents their independent request streams from
    # sharing the singleton limiter's in-memory counters.
    return f"app:{id(request.app)}:ip:{remote}"


def get_user_id_key(request: Request) -> str:
    """Rate-limit by verified authenticated user ID, falling back to client IP."""
    user_id = getattr(request.state, "authenticated_user_id", None)
    if user_id:
        return f"user:{user_id}"
    return get_ip_key(request)


# Singleton shared by the application and every router.
limiter = Limiter(key_func=get_remote_address)