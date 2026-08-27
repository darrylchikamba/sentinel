"""Phase 21 Workstream B scalar input-validation tests."""

import pytest
from pydantic import ValidationError

from models.user import UserCreate, UserLogin


def test_registration_normalises_email_to_lowercase() -> None:
    payload = UserCreate(
        username="SOC_Analyst1",
        email=" Analyst@Example.CO.ZA ",
        password="password123",
    )

    assert payload.email == "analyst@example.co.za"


def test_login_normalises_email_to_lowercase() -> None:
    payload = UserLogin(
        email=" Analyst@Example.CO.ZA ",
        password="anything",
    )

    assert payload.email == "analyst@example.co.za"


def test_username_rejects_non_alphanumeric_or_underscore_characters() -> None:
    with pytest.raises(
        ValidationError,
        match="letters, numbers and underscores",
    ):
        UserCreate(
            username="soc-admin",
            email="analyst@example.co.za",
            password="password123",
        )


def test_registration_password_requires_at_least_eight_characters() -> None:
    with pytest.raises(ValidationError):
        UserCreate(
            username="soc_admin",
            email="analyst@example.co.za",
            password="short",
        )
