"""Phase 21 Workstream A startup-configuration tests."""

import logging

import pytest

import main


def install_required_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "MONGO_URI",
        "mongodb://localhost:27017/sentinel_test",
    )
    monkeypatch.setenv(
        "JWT_SECRET",
        "sentinel-test-secret",
    )
    monkeypatch.setenv(
        "FRONTEND_URL",
        "http://localhost:5173",
    )


def test_frontend_url_is_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_required_environment(monkeypatch)
    monkeypatch.delenv(
        "FRONTEND_URL",
        raising=False,
    )

    with pytest.raises(
        RuntimeError,
        match="FRONTEND_URL",
    ):
        main.validate_startup_configuration()


def test_provider_defaults_are_mock_and_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_required_environment(monkeypatch)
    monkeypatch.delenv(
        "AI_GENERATION_PROVIDER",
        raising=False,
    )
    monkeypatch.delenv(
        "AI_EMBEDDING_PROVIDER",
        raising=False,
    )

    result = main.validate_startup_configuration()

    assert result == {
        "generation_provider": "mock",
        "embedding_provider": "none",
    }


@pytest.mark.parametrize(
    ("generation_provider", "embedding_provider"),
    [
        ("gemini", "none"),
        ("mock", "gemini"),
    ],
)
def test_gemini_selection_without_key_logs_warning(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    generation_provider: str,
    embedding_provider: str,
) -> None:
    install_required_environment(monkeypatch)
    monkeypatch.setenv(
        "AI_GENERATION_PROVIDER",
        generation_provider,
    )
    monkeypatch.setenv(
        "AI_EMBEDDING_PROVIDER",
        embedding_provider,
    )
    monkeypatch.delenv(
        "GEMINI_API_KEY",
        raising=False,
    )

    with caplog.at_level(
        logging.WARNING,
        logger="sentinel.api",
    ):
        main.validate_startup_configuration()

    assert (
        "GEMINI_API_KEY is missing"
        in caplog.text
    )


def test_placeholder_gemini_key_logs_warning(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    install_required_environment(monkeypatch)
    monkeypatch.setenv(
        "AI_GENERATION_PROVIDER",
        "gemini",
    )
    monkeypatch.setenv(
        "AI_EMBEDDING_PROVIDER",
        "none",
    )
    monkeypatch.setenv(
        "GEMINI_API_KEY",
        "your-gemini-api-key-here",
    )

    with caplog.at_level(
        logging.WARNING,
        logger="sentinel.api",
    ):
        main.validate_startup_configuration()

    assert (
        "placeholder value"
        in caplog.text
    )


def test_real_gemini_key_does_not_log_key_warning(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    install_required_environment(monkeypatch)
    monkeypatch.setenv(
        "AI_GENERATION_PROVIDER",
        "gemini",
    )
    monkeypatch.setenv(
        "AI_EMBEDDING_PROVIDER",
        "none",
    )
    monkeypatch.setenv(
        "GEMINI_API_KEY",
        "test-real-looking-key",
    )

    with caplog.at_level(
        logging.WARNING,
        logger="sentinel.api",
    ):
        main.validate_startup_configuration()

    assert "GEMINI_API_KEY" not in caplog.text
