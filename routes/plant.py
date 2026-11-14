
from datetime import datetime, timezone
from typing import Any

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from database import farms, plants
from routes.project import get_access_token, get_project, get_user_from_token
from utils.properties import load_property_schema, validate_properties
from utils.responses import SuccessResponse


router = APIRouter(
    prefix="/projects/{project_id}/farms/{farm_id}/plants",
    tags=["Plants"]
)


class PlantCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    properties: dict[str, Any] = Field(default_factory=dict)


class PlantUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=100)
    properties: dict[str, Any] | None = None


def format_plant(plant: dict) -> dict:
    return {
        "id": str(plant["_id"]),
        "project_id": plant["project_id"],
        "farm_id": plant["farm_id"],
        "name": plant["name"],
        "owner_id": plant["owner_id"],
        "properties": plant.get("properties", {}),
        "created_at": plant["created_at"],
        "updated_at": plant["updated_at"]
    }


async def get_farm_and_project(
    project_id: str,
    farm_id: str,
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

    return farm, project


async def get_plant(
    plant_id: str,
    project_id: str,
    farm_id: str,
    user_id: str,
    owner_only: bool = False
):
    if not ObjectId.is_valid(plant_id):
        raise HTTPException(status_code=400, detail="Invalid plant ID")

    farm, project = await get_farm_and_project(
        project_id,
        farm_id,
        user_id,
        owner_only
    )

    plant = await plants.find_one({
        "_id": ObjectId(plant_id),
        "farm_id": str(farm["_id"]),
        "project_id": str(project["_id"])
    })

    if not plant:
        raise HTTPException(status_code=404, detail="Plant not found")

    return plant


@router.post("/", response_model=SuccessResponse)
async def create_plant(
    project_id: str,
    farm_id: str,
    data: PlantCreate,
    token: str = Depends(get_access_token)
):
    user = await get_user_from_token(token)
    user_id = str(user["_id"])
    farm, project = await get_farm_and_project(
        project_id,
        farm_id,
        user_id,
        owner_only=True
    )

    try:
        schema = load_property_schema("plant.yaml")
        properties = validate_properties(data.properties, schema)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error))

    now = datetime.now(timezone.utc)

    plant = {
        "project_id": str(project["_id"]),
        "farm_id": str(farm["_id"]),
        "name": data.name,
        "owner_id": str(user["_id"]),
        "properties": properties,
        "created_at": now,
        "updated_at": now
    }

    result = await plants.insert_one(plant)
    plant["_id"] = result.inserted_id

    return SuccessResponse(data=format_plant(plant))


@router.get("/", response_model=SuccessResponse)
async def list_plants(
    project_id: str,
    farm_id: str,
    token: str = Depends(get_access_token)
):
    user = await get_user_from_token(token)
    farm, project = await get_farm_and_project(
        project_id,
        farm_id,
        str(user["_id"])
    )

    cursor = plants.find({
        "project_id": str(project["_id"]),
        "farm_id": str(farm["_id"])
    }).sort("created_at", -1)

    return SuccessResponse(data=[format_plant(plant) async for plant in cursor])


@router.get("/{plant_id}", response_model=SuccessResponse)
async def read_plant(
    project_id: str,
    farm_id: str,
    plant_id: str,
    token: str = Depends(get_access_token)
):
    user = await get_user_from_token(token)
    plant = await get_plant(
        plant_id,
        project_id,
        farm_id,
        str(user["_id"])
    )

    return SuccessResponse(data=format_plant(plant))


@router.patch("/{plant_id}", response_model=SuccessResponse)
async def update_plant(
    project_id: str,
    farm_id: str,
    plant_id: str,
    data: PlantUpdate,
    token: str = Depends(get_access_token)
):
    user = await get_user_from_token(token)
    plant = await get_plant(
        plant_id,
        project_id,
        farm_id,
        str(user["_id"]),
        owner_only=True
    )

    updates = data.model_dump(exclude_unset=True)

    if not updates:
        raise HTTPException(status_code=400, detail="No changes provided")

    if "name" in updates and updates["name"] is None:
        raise HTTPException(status_code=400, detail="Plant name cannot be null")

    if "properties" in updates:
        if updates["properties"] is None:
            raise HTTPException(status_code=400, detail="Properties cannot be null")

        try:
            schema = load_property_schema("plant.yaml")
            new_properties = validate_properties(
                updates["properties"],
                schema,
                partial=True
            )
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error))

        updates["properties"] = {
            **plant.get("properties", {}),
            **new_properties
        }

    updates["updated_at"] = datetime.now(timezone.utc)

    await plants.update_one(
        {"_id": plant["_id"]},
        {"$set": updates}
    )

    updated_plant = await plants.find_one({"_id": plant["_id"]})
    return SuccessResponse(data=format_plant(updated_plant))


@router.delete("/{plant_id}", response_model=SuccessResponse)
async def delete_plant(
    project_id: str,
    farm_id: str,
    plant_id: str,
    token: str = Depends(get_access_token)
):
    user = await get_user_from_token(token)
    plant = await get_plant(
        plant_id,
        project_id,
        farm_id,
        str(user["_id"]),
        owner_only=True
    )

    await plants.delete_one({"_id": plant["_id"]})

    return SuccessResponse(data={"message": "Plant deleted successfully"})
