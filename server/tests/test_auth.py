"""Isolated authentication tests with no live MongoDB connection."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sys

import jwt
from bson import ObjectId
from fastapi.security import HTTPAuthorizationCredentials
import pytest

SERVER_DIR = Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))
os.environ.setdefault("MONGO_URI", "mongodb://unused-test-host:27017/sentinel")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-for-tests")

from middleware import auth as auth_middleware  # noqa: E402
from models.user import UserInDB  # noqa: E402
from routers import auth as auth_router  # noqa: E402


def test_password_hashing_and_verification() -> None:
    hashed = auth_router.hash_password("CorrectHorse1")
    assert hashed != "CorrectHorse1"
    assert auth_router.verify_password("CorrectHorse1", hashed) is True
    assert auth_router.verify_password("WrongPassword", hashed) is False


def test_jwt_creation_and_decoding(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JWT_SECRET", "isolated-jwt-test-secret")
    user_id = str(ObjectId())
    token = auth_router.create_access_token(user_id)
    payload = auth_router.decode_access_token(token)
    assert payload["sub"] == user_id
    assert "exp" in payload


def test_token_expiry_detection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JWT_SECRET", "isolated-jwt-test-secret")
    expired_payload = {
        "sub": str(ObjectId()),
        "exp": datetime.now(timezone.utc) - timedelta(seconds=1),
    }
    token = jwt.encode(
        expired_payload,
        os.environ["JWT_SECRET"],
        algorithm=auth_router.JWT_ALGORITHM,
    )
    with pytest.raises(jwt.ExpiredSignatureError):
        auth_router.decode_access_token(token)


def test_get_current_user_queries_database_by_object_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("JWT_SECRET", "isolated-jwt-test-secret")
    user_id = ObjectId()
    token = auth_router.create_access_token(str(user_id))
    expected_query = {"_id": user_id}
    document = {
        "_id": user_id,
        "username": "soc_analyst",
        "email": "analyst@example.co.za",
        "hashed_password": "not-used-by-this-test",
        "is_admin": False,
        "created_at": datetime.now(timezone.utc),
    }

    class FakeUsersCollection:
        def __init__(self) -> None:
            self.queries = []

        def find_one(self, query):
            self.queries.append(query)
            return document if query == expected_query else None

    class FakeDatabase:
        def __init__(self, users) -> None:
            self.users = users
            self.requested_collections = []

        def __getitem__(self, name):
            self.requested_collections.append(name)
            assert name == "users"
            return self.users

    fake_users = FakeUsersCollection()
    fake_database = FakeDatabase(fake_users)
    database_calls = 0

    def fake_get_database():
        nonlocal database_calls
        database_calls += 1
        return fake_database

    monkeypatch.setattr(auth_middleware, "get_database", fake_get_database)
    credentials = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials=token,
    )
    user = asyncio.run(auth_middleware.get_current_user(credentials))

    assert isinstance(user, UserInDB)
    assert user.id == user_id
    assert user.username == "soc_analyst"
    assert database_calls == 1
    assert fake_database.requested_collections == ["users"]
    assert fake_users.queries == [{"_id": ObjectId(str(user_id))}]
    assert fake_users.queries[0] == expected_query