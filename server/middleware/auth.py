"""FastAPI authentication and authorisation dependencies."""

from __future__ import annotations

from bson import ObjectId
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt

from config.database import get_database
from models.user import UserInDB
from routers.auth import decode_access_token


bearer_scheme = HTTPBearer(auto_error=False)


def _unauthorised() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    request: Request = None,
) -> UserInDB:
    """Validate a bearer token and load its active MongoDB user."""
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _unauthorised()

    try:
        payload = decode_access_token(credentials.credentials)
        user_id = ObjectId(str(payload["sub"]))
    except (jwt.PyJWTError, TypeError, ValueError):
        raise _unauthorised() from None

    database = get_database()
    document = database["users"].find_one({"_id": user_id})
    if document is None:
        raise _unauthorised()

    try:
        user = UserInDB.model_validate(document)
    except (TypeError, ValueError):
        raise _unauthorised() from None

    if request is not None:
        request.state.authenticated_user_id = str(user.id)

    return user


async def get_admin_user(
    current_user: UserInDB = Depends(get_current_user),
) -> UserInDB:
    """Require an authenticated administrator."""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator access required",
        )
    return current_user