"""SENTINEL FastAPI application entry point."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone
import importlib
import logging
import os

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from config.rate_limit import limiter

load_dotenv()

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("sentinel.api")

REQUIRED_STARTUP_VARIABLES = (
    "JWT_SECRET",
    "MONGO_URI",
    "FRONTEND_URL",
)
DEFAULT_GENERATION_PROVIDER = "mock"
DEFAULT_EMEDDING_PROVIDER = "none"

MAX_JSON_BODY_BYTES = 1 * 1024 * 1024
ALLOWED_CORS_METHODS = ["GET", "POST", "DELETE", "OPTIONS"]
ALLOWED_CORS_HEADERS = ["Authorization", "Content-Type", "Accept"]

GEMINI_PLACEHOLDER_VALUES = {
    "your-gemini-api-key-here",
    "your-gemini-api-key",
    "replace-with-your-gemini-api-key",
    "<gemini-api-key>",
    "<your-gemini-api-key>",
}

ROUTER_PREFIXES = {
    "upload": "/api/upload",
    "analysis": "/api/investigations",
    "incident": "/api/incident",
    "kb": "/api/kb",
}


def _normalised_provider(name: str, default: str) -> str:
    value = os.getenv(name, "").strip().lower()
    return value or default


def _gemini_key_is_missing_or_placeholder() -> bool:
    value = os.getenv("GEMINI_API_KEY", "").strip()
    if not value:
        return True
    return value.lower() in GEMINI_PLACEHOLDER_VALUES


def validate_startup_configuration() -> dict[str, str]:
    """Validate required configuration and report active AI providers.

    MONGO_URI and JWT_SECRET are required security/runtime inputs.
    FRONTEND_URL is also required because it defines the only browser
    origin permitted by CORS.

    Optional AI providers remain fail-soft. Gemini selection without a
    usable key is logged as a warning rather than aborting startup so
    SENTINEL's mock/fallback paths remain available.
    """
    missing = [
        name
        for name in REQUIRED_STARTUP_VARIABLES
        if not os.getenv(name, "").strip()
    ]
    if missing:
        names = ", ".join(missing)
        logger.critical(
            "Missing required environment variables: %s",
            names,
        )
        raise RuntimeError(
            f"Missing required environment variables: {names}"
        )

    generation_provider = _normalised_provider(
        "AI_GENERATION_PROVIDER",
        DEFAULT_GENERATION_PROVIDER,
    )
    embedding_provider = _normalised_provider(
        "AI_EMBEDDING_PROVIDER",
        DEFAULT_EMEDDING_PROVIDER,
    )

    logger.info(
        "AI providers active | generation=%s embedding=%s",
        generation_provider,
        embedding_provider,
    )

    if (
        "gemini" in {generation_provider, embedding_provider}
        and _gemini_key_is_missing_or_placeholder()
    ):
        logger.warning(
            "Gemini provider selected but GEMINI_API_KEY is missing "
            "or still set to a placeholder value; Gemini calls may "
            "fall back to the configured safe path."
        )

    return {
        "generation_provider": generation_provider,
        "embedding_provider": embedding_provider,
    }


class JSONBodyLimitMiddleware:
    """Cap JSON request bodies without consuming multipart upload streams.

    JSON requests are buffered up to MAX_JSON_BODY_BYTES before reaching
    FastAPI. Multipart/form-data and other content types bypass this
    middleware entirely and retain their route-specific limits.
    """

    def __init__(
        self,
        app,
        *,
        max_bytes: int = MAX_JSON_BODY_BYTES,
    ) -> None:
        self.app = app
        self.max_bytes = max_bytes

    @staticmethod
    def _is_json_content_type(scope: dict) -> bool:
        headers = {
            key.lower(): value
            for key, value in scope.get("headers", [])
        }
        raw_content_type = headers.get(b"content-type", b"")
        content_type = raw_content_type.decode(
            "latin-1",
            errors="ignore",
        ).split(";", 1)[0].strip().lower()

        return (
            content_type == "application/json"
            or content_type.endswith("+json")
        )

    async def __call__(self, scope, receive, send) -> None:
        if (
            scope.get("type") != "http"
            or not self._is_json_content_type(scope)
        ):
            await self.app(scope, receive, send)
            return

        headers = {
            key.lower(): value
            for key, value in scope.get("headers", [])
        }
        raw_length = headers.get(b"content-length")

        if raw_length:
            try:
                content_length = int(raw_length)
            except (TypeError, ValueError):
                content_length = None

            if (
                content_length is not None
                and content_length > self.max_bytes
            ):
                response = JSONResponse(
                    status_code=413,
                    content={
                        "detail": "JSON request body exceeds the 1 MB limit"
                    },
                )
                await response(scope, receive, send)
                return

        messages: list[dict] = []
        body_size = 0

        while True:
            message = await receive()
            messages.append(message)

            if message.get("type") == "http.disconnect":
                break

            if message.get("type") != "http.request":
                continue

            body_size += len(message.get("body", b""))
            if body_size > self.max_bytes:
                response = JSONResponse(
                    status_code=413,
                    content={
                        "detail": "JSON request body exceeds the 1 MB limit"
                    },
                )
                await response(scope, receive, send)
                return

            if not message.get("more_body", False):
                break

        index = 0

        async def replay_receive():
            nonlocal index

            if index < len(messages):
                message = messages[index]
                index += 1
                return message

            return {
                "type": "http.request",
                "body": b"",
                "more_body": False,
            }

        await self.app(scope, replay_receive, send)


class SecurityHeadersMiddleware:
    """Add baseline browser security headers to every HTTP response."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_security_headers(message):
            if message.get("type") == "http.response.start":
                headers = list(message.get("headers", []))
                header_names = {
                    key.lower()
                    for key, _ in headers
                }

                if b"x-content-type-options" not in header_names:
                    headers.append(
                        (b"x-content-type-options", b"nosniff")
                    )

                if b"x-frame-options" not in header_names:
                    headers.append(
                        (b"x-frame-options", b"DENY")
                    )

                message = {
                    **message,
                    "headers": headers,
                }

            await send(message)

        await self.app(
            scope,
            receive,
            send_with_security_headers,
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    validate_startup_configuration()
    logger.info(
        "SENTINEL API online | %s",
        datetime.now(timezone.utc).isoformat(),
    )
    yield
    logger.info("SENTINEL API offline")


app = FastAPI(
    title="SENTINEL API",
    version="1.0.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(
    RateLimitExceeded,
    _rate_limit_exceeded_handler,
)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(
    JSONBodyLimitMiddleware,
    max_bytes=MAX_JSON_BODY_BYTES,
)

# Safe-by-default at import time. Lifespan validation refuses to start
# the application when FRONTEND_URL is missing.
frontend_url = os.getenv("FRONTEND_URL", "").strip()
app.add_middleware(
    CORSMiddleware,
    allow_origins=[frontend_url] if frontend_url else [],
    allow_credentials=True,
    allow_methods=ALLOWED_CORS_METHODS,
    allow_headers=ALLOWED_CORS_HEADERS,
)
app.add_middleware(SecurityHeadersMiddleware)


@app.exception_handler(Exception)
async def unhandled_exception_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    logger.exception(
        "Unhandled request failure | method=%s path=%s",
        request.method,
        request.url.path,
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


def include_router(module_name: str) -> None:
    try:
        module = importlib.import_module(
            f"routers.{module_name}"
        )
        app.include_router(
            module.router,
            prefix=ROUTER_PREFIXES.get(
                module_name,
                "",
            ),
        )
        logger.info(
            "Loaded router: %s",
            module_name,
        )
    except ModuleNotFoundError as exc:
        if exc.name == f"routers.{module_name}":
            logger.info(
                "Router '%s' not found. Skipping.",
                module_name,
            )
            return
        logger.exception(
            "Router '%s' has a missing dependency: %s",
            module_name,
            exc.name,
        )
    except AttributeError:
        logger.exception(
            "Router '%s' has no router object.",
            module_name,
        )
    except Exception:
        logger.exception(
            "Could not load router '%s'.",
            module_name,
        )


for router_name in [
    "health",
    "auth",
    "upload",
    "analysis",
    "incident",
    "kb",
]:
    include_router(router_name)
