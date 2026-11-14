
from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, status

from database import risks
from routes.project import get_access_token, get_user_from_token
from utils.responses import SuccessResponse


router = APIRouter(
    prefix="/risk",
    tags=["Risk"]
)


@router.get("/", response_model=SuccessResponse)
async def get_risks(
    token: str = Depends(get_access_token)
):
    current_user = await get_user_from_token(token)

    cursor = risks.find({
        "created_by": str(current_user["_id"])
    }).sort("created_at", -1)

    results = []

    async for risk_data in cursor:
        risk_data["id"] = str(risk_data.pop("_id"))
        results.append(risk_data)

    return SuccessResponse(data={"risks": results})


@router.delete("/{risk_id}", response_model=SuccessResponse)
async def delete_risk(
    risk_id: str,
    token: str = Depends(get_access_token)
):
    current_user = await get_user_from_token(token)

    if not ObjectId.is_valid(risk_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid risk ID."
        )

    result = await risks.delete_one({
        "_id": ObjectId(risk_id),
        "created_by": str(current_user["_id"])
    })

    if result.deleted_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Risk not found."
        )

    return SuccessResponse(data={"message": "Risk deleted successfully."})
