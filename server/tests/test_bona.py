"""Unit tests for the public BONA service entry point."""

from pathlib import Path
import sys

SERVER_DIR = Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from services import bona


class FakeGenerationProvider:
    def __init__(self):
        self.calls = []

    def generate_incident_report(self, investigation_data):
        self.calls.append(investigation_data)
        return {
            "generated_by": "BONA",
            "mock": False,
            "marker": "delegated",
        }

    def provider_name(self):
        return "fake"


def test_bona_persona_is_public():
    assert isinstance(bona.BONA_PERSONA, str)
    assert "BONA" in bona.BONA_PERSONA


def test_generate_incident_report_delegates_to_factory(monkeypatch):
    provider = FakeGenerationProvider()
    monkeypatch.setattr(
        bona,
        "get_generation_provider",
        lambda: provider,
    )
    investigation = {"threat_summary": {"event_count": 3}}

    result = bona.generate_incident_report(investigation)

    assert result["marker"] == "delegated"
    assert provider.calls == [investigation]


def test_default_mock_provider_returns_isolated_reports(monkeypatch):
    monkeypatch.setenv("AI_GENERATION_PROVIDER", "mock")

    first = bona.generate_incident_report({})
    first["incident_next_steps"].append("MUTATED")

    second = bona.generate_incident_report({})

    assert second["generated_by"] == "BONA"
    assert second["mock"] is True
    assert "MUTATED" not in second["incident_next_steps"]
