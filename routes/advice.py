
from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from database import advices
from routes.project import get_access_token, get_user_from_token
from utils.responses import SuccessResponse


class AdviceStep(BaseModel):
    order: int
    title: str
    description: str
    reason: str
    crops: list[str]


def format_advice(advice: dict) -> dict:
    advice["id"] = str(advice.pop("_id"))
    steps = [
        AdviceStep.model_validate(step)
        for step in advice.get("steps", [])
    ]
    advice["steps"] = [
        step.model_dump()
        for step in sorted(steps, key=lambda step: step.order)
    ]
    return advice


router = APIRouter(
    prefix="/advice",
    tags=["Advice"]
)

@router.get("/", response_model=SuccessResponse)
async def get_advices(
    token: str = Depends(get_access_token)
):
    current_user = await get_user_from_token(token)

    cursor = advices.find({
        "created_by": str(current_user["_id"])
    }).sort("created_at", -1)

    results = []

    async for advice in cursor:
        results.append(format_advice(advice))

    return SuccessResponse(data={"advices": results})


@router.delete("/{advice_id}", response_model=SuccessResponse)
async def delete_advice(
    advice_id: str,
    token: str = Depends(get_access_token)
):
    current_user = await get_user_from_token(token)

    if not ObjectId.is_valid(advice_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid advice ID."
        )

    result = await advices.delete_one({
        "_id": ObjectId(advice_id),
        "created_by": str(current_user["_id"])
    })

    if result.deleted_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Advice not found."
        )

    return SuccessResponse(data={"message": "Advice deleted successfully."})
