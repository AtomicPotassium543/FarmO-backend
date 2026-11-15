
from datetime import datetime, timezone
from typing import Any

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from database import farms, plants, projects
from routes.project import get_access_token, get_project, get_user_from_token

from utils.properties import load_property_schema, validate_properties
from utils.responses import SuccessResponse

router = APIRouter(prefix="/projects/{project_id}/farms", tags=["Farms"])

class FarmCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    properties: dict[str, Any] = Field(default_factory=dict)


class FarmUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=100)
    properties: dict[str, Any] | None = None


def format_farm(farm: dict) -> dict:
    props = farm.get("properties", {})
    return {
        "id": str(farm["_id"]),
        "project_id": str(farm.get("project_id", "")),
        "name": farm["name"],
        "owner_id": str(farm.get("owner_id", "")),
        "properties": props,
        "latitude": props.get("latitude") if props.get("latitude") is not None else farm.get("latitude"),
        "longitude": props.get("longitude") if props.get("longitude") is not None else farm.get("longitude"),
        "farmer_priority": props.get("farmer_priority") or farm.get("farmer_priority"),
        "water_availability": props.get("water_availability") or farm.get("water_availability"),
        "equipment_limitation": props.get("equipment_limitation") or farm.get("equipment_limitation"),
        "market_preference": props.get("market_preference") or farm.get("market_preference"),
        "human_judgment_acknowledged": props.get("human_judgment_acknowledged", True),
        "created_at": farm["created_at"],
        "updated_at": farm["updated_at"]
    }


async def get_farm(
    farm_id: str,
    project_id: str,
    user_id: str,
    owner_only: bool = False
):
    if not ObjectId.is_valid(farm_id):
        raise HTTPException(status_code=400, detail="Invalid farm ID")

    project = await get_project(project_id, user_id, owner_only=owner_only)

    farm = await farms.find_one({
        "_id": ObjectId(farm_id),
        "project_id": str(project["_id"])
    })

    if not farm:
        raise HTTPException(status_code=404, detail="Farm not found")

    return farm


@router.post("/", response_model=SuccessResponse)
async def create_farm(
    project_id: str,
    data: FarmCreate,
    token: str = Depends(get_access_token)
):
    user = await get_user_from_token(token)
    user_id = str(user["_id"])
    project = await get_project(project_id, user_id, owner_only=True)

    try:
        schema = load_property_schema("farm.yaml")
        properties = validate_properties(data.properties, schema)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error))

    now = datetime.now(timezone.utc)

    farm = {
        "project_id": str(project["_id"]),
        "name": data.name,
        "owner_id": str(user["_id"]),
        "properties": properties,
        "created_at": now,
        "updated_at": now
    }

    result = await farms.insert_one(farm)
    farm["_id"] = result.inserted_id

    await projects.update_one(
        {"_id": project["_id"]},
        {
            "$addToSet": {"farm_ids": str(result.inserted_id)},
            "$set": {"updated_at": now}
        }
    )

    return SuccessResponse(data=format_farm(farm))


@router.get("/", response_model=SuccessResponse)
async def list_farms(
    project_id: str,
    token: str = Depends(get_access_token)
):
    user = await get_user_from_token(token)
    project = await get_project(project_id, str(user["_id"]))

    cursor = farms.find({"project_id": str(project["_id"])}).sort(
        "created_at", -1
    )

    return SuccessResponse(data=[format_farm(farm) async for farm in cursor])


@router.get("/{farm_id}", response_model=SuccessResponse)
async def read_farm(
    project_id: str,
    farm_id: str,
    token: str = Depends(get_access_token)
):
    user = await get_user_from_token(token)
    farm = await get_farm(farm_id, project_id, str(user["_id"]))
    return SuccessResponse(data=format_farm(farm))


@router.patch("/{farm_id}", response_model=SuccessResponse)
async def update_farm(
    project_id: str,
    farm_id: str,
    data: FarmUpdate,
    token: str = Depends(get_access_token)
):
    user = await get_user_from_token(token)
    farm = await get_farm(
        farm_id,
        project_id,
        str(user["_id"]),
        owner_only=True
    )

    updates = data.model_dump(exclude_unset=True)

    if not updates:
        raise HTTPException(status_code=400, detail="No changes provided")

    if "name" in updates:
        if updates["name"] is None:
            raise HTTPException(status_code=400, detail="Farm name cannot be null")

    if "properties" in updates:
        if updates["properties"] is None:
            raise HTTPException(status_code=400, detail="Properties cannot be null")

        try:
            schema = load_property_schema("farm.yaml")
            new_properties = validate_properties(
                updates["properties"],
                schema,
                partial=True
            )
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error))

        updates.pop("properties")
        updates["properties"] = {
            **farm.get("properties", {}),
            **new_properties
        }

    updates["updated_at"] = datetime.now(timezone.utc)

    await farms.update_one(
        {"_id": farm["_id"]},
        {"$set": updates}
    )

    updated_farm = await farms.find_one({"_id": farm["_id"]})
    return SuccessResponse(data=format_farm(updated_farm))


@router.delete("/{farm_id}", response_model=SuccessResponse)
async def delete_farm(
    project_id: str,
    farm_id: str,
    token: str = Depends(get_access_token)
):
    user = await get_user_from_token(token)
    farm = await get_farm(
        farm_id,
        project_id,
        str(user["_id"]),
        owner_only=True
    )

    now = datetime.now(timezone.utc)

    await plants.delete_many({"farm_id": str(farm["_id"])})
    await farms.delete_one({"_id": farm["_id"]})

    await projects.update_one(
        {"_id": ObjectId(project_id)},
        {
            "$pull": {"farm_ids": str(farm["_id"])},
            "$set": {"updated_at": now}
        }
    )

    return SuccessResponse(
        data={"message": "Farm and its plants deleted successfully"}
    )
