"""SENTINEL API health endpoint."""

from datetime import datetime, timezone
import os

from fastapi import APIRouter, Request

from config.rate_limit import RATE_LIMITS, get_ip_key, limiter


router = APIRouter(prefix="/api", tags=["Health"])


@router.get("/health")
@limiter.limit(RATE_LIMITS["health"], key_func=get_ip_key)
async def health_check(request: Request):
    """Report service availability and the configured AI providers."""
    return {
        "status": "online",
        "service": "SENTINEL API",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "generation_provider": (
            os.getenv("AI_GENERATION_PROVIDER", "mock").strip().lower()
            or "mock"
        ),
        "embedding_provider": (
            os.getenv("AI_EMBEDDING_PROVIDER", "none").strip().lower()
            or "none"
        ),
    }