"""Investigation retrieval, pagination and deletion routes."""

import math
from typing import Literal

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pymongo import ASCENDING, DESCENDING

from config.database import get_database
from config.rate_limit import RATE_LIMITS, get_ip_key, limiter
from middleware.auth import get_current_user
from models.investigation import InvestigationDetailResponse, InvestigationResponse
from models.user import UserInDB


router = APIRouter()

SortBy = Literal[
    "created_at",
    "high_threat_count",
    "event_count",
    "attack_clusters",
]
SortOrder = Literal["asc", "desc"]


def _validate_object_id(investigation_id: str) -> ObjectId:
    if not ObjectId.is_valid(investigation_id):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid investigation ID format",
        )
    return ObjectId(investigation_id)


def _normalise_investigation_document(document: dict) -> dict:
    result = dict(document)
    mongo_id = result.pop("_id", None)
    result["investigation_id"] = str(mongo_id)
    return result


@router.get("")
@limiter.limit(RATE_LIMITS["investigation_list"], key_func=get_ip_key)
def list_investigations(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=10, ge=1, le=50),
    sort_by: SortBy = Query(default="created_at"),
    sort_order: SortOrder = Query(default="desc"),
    current_user: UserInDB = Depends(get_current_user),
) -> dict:
    collection = get_database()["investigations"]
    ownership_query = {"user_id": str(current_user.id)}
    total = int(collection.count_documents(ownership_query))
    total_pages = math.ceil(total / page_size) if total else 0

    mongo_order = ASCENDING if sort_order == "asc" else DESCENDING
    projection = {"events": 0}
    cursor = (
        collection.find(ownership_query, projection)
        .sort(sort_by, mongo_order)
        .skip((page - 1) * page_size)
        .limit(page_size)
    )

    investigations = [
        InvestigationResponse.model_validate(
            _normalise_investigation_document(document)
        ).model_dump(mode="json")
        for document in cursor
    ]

    return {
        "investigations": investigations,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
    }


@router.get("/{investigation_id}")
@limiter.limit(RATE_LIMITS["investigation_detail"], key_func=get_ip_key)
def get_investigation(
    request: Request,
    investigation_id: str,
    current_user: UserInDB = Depends(get_current_user),
) -> InvestigationDetailResponse:
    object_id = _validate_object_id(investigation_id)
    document = get_database()["investigations"].find_one(
        {
            "_id": object_id,
            "user_id": str(current_user.id),
        }
    )
    if document is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )
    return InvestigationDetailResponse.model_validate(
        _normalise_investigation_document(document)
    )


@router.delete("/{investigation_id}")
@limiter.limit(RATE_LIMITS["investigation_delete"], key_func=get_ip_key)
def delete_investigation(
    request: Request,
    investigation_id: str,
    current_user: UserInDB = Depends(get_current_user),
) -> dict[str, str]:
    object_id = _validate_object_id(investigation_id)
    result = get_database()["investigations"].delete_one(
        {
            "_id": object_id,
            "user_id": str(current_user.id),
        }
    )
    if result.deleted_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )
    return {"message": "Investigation deleted"}