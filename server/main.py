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

REQUIRED_STARTUP_VARIABLES = ("JWT_SECRET", "MONGO_URI")
ROUTER_PREFIXES = {
    "upload": "/api/upload",
    "analysis": "/api/investigations",
    "incident": "/api/incident",
    "kb": "/api/kb",
}


def validate_startup_configuration() -> None:
    missing = [
        name for name in REQUIRED_STARTUP_VARIABLES
        if not os.getenv(name, "").strip()
    ]
    if missing:
        names = ", ".join(missing)
        logger.critical("Missing required environment variables: %s", names)
        raise RuntimeError(f"Missing required environment variables: {names}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    validate_startup_configuration()
    logger.info(
        "SENTINEL API online | %s",
        datetime.now(timezone.utc).isoformat(),
    )
    yield
    logger.info("SENTINEL API offline")


app = FastAPI(title="SENTINEL API", version="1.0.0", lifespan=lifespan)

app.state.limiter = limiter
app.add_exception_handler(
    RateLimitExceeded,
    _rate_limit_exceeded_handler,
)
app.add_middleware(SlowAPIMiddleware)

frontend_url = os.getenv("FRONTEND_URL", "http://localhost:5173")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[frontend_url],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
        module = importlib.import_module(f"routers.{module_name}")
        app.include_router(
            module.router,
            prefix=ROUTER_PREFIXES.get(module_name, ""),
        )
        logger.info("Loaded router: %s", module_name)
    except ModuleNotFoundError as exc:
        if exc.name == f"routers.{module_name}":
            logger.info("Router '%s' not found. Skipping.", module_name)
            return
        logger.exception(
            "Router '%s' has a missing dependency: %s",
            module_name,
            exc.name,
        )
    except AttributeError:
        logger.exception("Router '%s' has no router object.", module_name)
    except Exception:
        logger.exception("Could not load router '%s'.", module_name)


for router_name in [
    "health",
    "auth",
    "upload",
    "analysis",
    "incident",
    "kb",
]:
    include_router(router_name)