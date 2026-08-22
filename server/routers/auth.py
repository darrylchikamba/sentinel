"""Registration, login, password and JWT helpers."""

from datetime import datetime, timedelta, timezone
import os
from typing import Any

import jwt
from bson import ObjectId
from fastapi import APIRouter, HTTPException, Request, status
from passlib.context import CryptContext

from config.database import get_database
from config.rate_limit import RATE_LIMITS, get_ip_key, limiter
from models.user import AuthResponse, UserCreate, UserInDB, UserLogin, UserResponse


JWT_ALGORITHM = "HS256"
JWT_EXPIRY_DAYS = 7
PASSWORD_CONTEXT = CryptContext(schemes=["bcrypt"], deprecated="auto")

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


def get_jwt_secret() -> str:
    """Return the configured JWT secret or fail without exposing its value."""
    secret = os.getenv("JWT_SECRET", "").strip()
    if not secret:
        raise RuntimeError("JWT_SECRET environment variable is missing")
    return secret


def hash_password(password: str) -> str:
    """Hash a password with bcrypt."""
    return PASSWORD_CONTEXT.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against its stored bcrypt hash."""
    try:
        return PASSWORD_CONTEXT.verify(password, hashed_password)
    except (TypeError, ValueError):
        return False


def create_access_token(
    user_id: str,
    *,
    expires_delta: timedelta | None = None,
) -> str:
    """Create an HS256 JWT for a MongoDB user identifier."""
    expiry = datetime.now(timezone.utc) + (
        expires_delta or timedelta(days=JWT_EXPIRY_DAYS)
    )
    payload = {"sub": str(user_id), "exp": expiry}
    return jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and validate an access token."""
    payload = jwt.decode(
        token,
        get_jwt_secret(),
        algorithms=[JWT_ALGORITHM],
        options={"require": ["sub", "exp"]},
    )
    if not str(payload.get("sub", "")).strip():
        raise jwt.InvalidTokenError("Token subject is missing")
    return payload


def _auth_response(user: UserInDB, user_id: ObjectId | str) -> AuthResponse:
    return AuthResponse(
        access_token=create_access_token(str(user_id)),
        user=UserResponse.model_validate(user.model_dump()),
    )


@router.post(
    "/register",
    response_model=AuthResponse,
    status_code=status.HTTP_201_CREATED,
)
@limiter.limit(RATE_LIMITS["auth_register"], key_func=get_ip_key)
def register_user(request: Request, payload: UserCreate) -> AuthResponse:
    """Create a user after enforcing unique username and email values."""
    database = get_database()
    users = database["users"]

    if users.find_one({"username": payload.username}) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username is already registered",
        )

    if users.find_one({"email": payload.email}) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email address is already registered",
        )

    user = UserInDB(
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password),
    )
    document = user.model_dump()
    result = users.insert_one(document)

    return _auth_response(user, result.inserted_id)


@router.post("/login", response_model=AuthResponse)
@limiter.limit(RATE_LIMITS["auth_login"], key_func=get_ip_key)
def login_user(request: Request, payload: UserLogin) -> AuthResponse:
    """Authenticate without revealing whether the email or password failed."""
    database = get_database()
    users = database["users"]
    document = users.find_one({"email": payload.email})

    invalid_credentials = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid email or password",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if document is None:
        raise invalid_credentials

    hashed_password = document.get("hashed_password")
    if not isinstance(hashed_password, str) or not verify_password(
        payload.password,
        hashed_password,
    ):
        raise invalid_credentials

    try:
        user = UserInDB.model_validate(document)
        user_id = document["_id"]
    except (KeyError, TypeError, ValueError):
        raise invalid_credentials from None

    return _auth_response(user, user_id)