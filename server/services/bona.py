"""Public BONA service entry point.

Provider-specific generation logic lives under services.ai_providers. Keeping
this module thin preserves the original public interface for pipeline callers.
"""

from __future__ import annotations

from typing import Any

from services.ai_providers.provider_factory import get_generation_provider
from services.ai_providers.reporting import BONA_PERSONA


def generate_incident_report(
    investigation_data: dict[str, Any],
) -> dict[str, Any]:
    """Generate a BONA incident report through the configured provider."""
    provider = get_generation_provider()
    return provider.generate_incident_report(investigation_data)