"""Pydantic models for SENTINEL user accounts."""

from __future__ import annotations

from datetime import datetime, timezone
import re

from bson import ObjectId
from pydantic import BaseModel, ConfigDict, Field, field_validator

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]+$")
EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


class UserCreate(BaseModel):
    """Validated registration payload."""

    username: str = Field(min_length=3, max_length=30)
    email: str
    password: str = Field(min_length=8)

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        username = value.strip()
        if not USERNAME_PATTERN.fullmatch(username):
            raise ValueError(
                "Username may contain only letters, numbers and underscores"
            )
        return username

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        email = value.strip().lower()
        if not EMAIL_PATTERN.fullmatch(email):
            raise ValueError("Enter a valid email address")
        return email


class UserLogin(BaseModel):
    """Validated login payload."""

    email: str
    password: str

    @field_validator("email")
    @classmethod
    def normalise_email(cls, value: str) -> str:
        email = value.strip().lower()
        if not EMAIL_PATTERN.fullmatch(email):
            raise ValueError("Enter a valid email address")
        return email


class UserInDB(BaseModel):
    """Internal stored-user representation including MongoDB identity."""

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        populate_by_name=True,
        extra="ignore",
    )

    id: ObjectId | None = Field(default=None, alias="_id")
    username: str
    email: str
    hashed_password: str
    is_admin: bool = False
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class UserResponse(BaseModel):
    """Safe user representation returned by the API."""

    model_config = ConfigDict(extra="ignore")

    username: str
    email: str
    is_admin: bool
    created_at: datetime


class AuthResponse(BaseModel):
    """JWT and password-free user details."""

    access_token: str
    token_type: str = "bearer"
    user: UserResponse