from datetime import datetime, timezone

from bson import ObjectId
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from database import projects, users
from utils.auth import decode_token
from utils.responses import SuccessResponse


router = APIRouter(prefix="/projects", tags=["Projects"])

# Request schemas

class Project(BaseModel):
    name: str = Field(min_length=3, max_length=100)
    description: str | None = Field(default=None, max_length=2000)
    summary: str | None = None
    region: str | None = None
    climate_zone: str | None = None
    climateZone: str | None = None
    budget_usd: float | None = None
    budgetUsd: float | None = None
    equipment: list[str] | None = None
    accommodations: list[dict] | None = None


class ProjectCollaborator(BaseModel):
    account_id: str

class ProjectFarm(BaseModel):
    farm_id: str


# Helper functions

def format_project(project: dict) -> dict:
    return {
        "id": str(project["_id"]),
        "name": project["name"],
        "description": project.get("description"),
        "summary": project.get("summary") or project.get("description", ""),
        "region": project.get("region", "Cedar Valley"),
        "climate_zone": project.get("climate_zone") or project.get("climateZone", "NW"),
        "climateZone": project.get("climateZone") or project.get("climate_zone", "NW"),
        "budget_usd": project.get("budget_usd") or project.get("budgetUsd", 10000),
        "budgetUsd": project.get("budgetUsd") or project.get("budget_usd", 10000),
        "equipment": project.get("equipment", []),
        "accommodations": project.get("accommodations", []),
        "owner_id": str(project["owner_id"]),
        "collaborators": [
            str(collaborator)
            for collaborator in project.get("collaborators", [])
        ],
        "farm_ids": project.get("farm_ids", []),
        "created_at": project["created_at"],
        "updated_at": project["updated_at"]
    }


def get_access_token(request: Request) -> str:
    authorization = request.headers.get("Authorization", "")
    scheme, _, token = authorization.partition(" ")

    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=401,
            detail="Authentication required."
        )

    return token


async def get_user_from_token(token: str) -> dict:
    try:
        payload = decode_token(token)
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid access token."
        )

    if payload.get("type") != "access" or not payload.get("sub"):
        raise HTTPException(
            status_code=401,
            detail="A valid access token is required."
        )

    user = await users.find_one({"_id": payload["sub"]})

    if not user:
        raise HTTPException(
            status_code=401,
            detail="User associated with token was not found."
        )

    return user


async def get_project(project_id: str, user_id: str, owner_only: bool = False):
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID")

    project = await projects.find_one({"_id": ObjectId(project_id)})

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    is_owner = str(project["owner_id"]) == user_id
    is_collaborator = user_id in {
        str(collaborator)
        for collaborator in project.get("collaborators", [])
    }

    if owner_only and not is_owner:
        raise HTTPException(status_code=403, detail="Owner permission required")
    if not owner_only and not is_owner and not is_collaborator:
        raise HTTPException(status_code=403, detail="You do not have access to this project")

    return project


# Create a project

@router.post("/", response_model=SuccessResponse)
async def create_project(
    data: Project,
    token: str = Depends(get_access_token)
):
    user = await get_user_from_token(token)
    now = datetime.now(timezone.utc)

    project = {
        "name": data.name,
        "description": data.description,
        "summary": data.summary or data.description,
        "region": data.region or "Cedar Valley",
        "climate_zone": data.climate_zone or data.climateZone or "NW",
        "budget_usd": data.budget_usd or data.budgetUsd or 10000,
        "equipment": data.equipment or [],
        "accommodations": data.accommodations or [],
        "owner_id": user["_id"],
        "collaborators": [],
        "farm_ids": [],
        "created_at": now,
        "updated_at": now
    }

    result = await projects.insert_one(project)
    project["_id"] = result.inserted_id

    return SuccessResponse(data=format_project(project))


# List accessible projects

@router.get("/", response_model=SuccessResponse)
async def list_projects(token: str = Depends(get_access_token)):
    user = await get_user_from_token(token)
    user_id = str(user["_id"])
    owner_ids: list[str | ObjectId] = [user_id]
    if ObjectId.is_valid(user_id):
        owner_ids.append(ObjectId(user_id))

    cursor = projects.find({
        "$or": [
            {"owner_id": {"$in": owner_ids}},
            {"collaborators": user_id}
        ]
    }).sort("updated_at", -1)

    return SuccessResponse(
        data=[format_project(project) async for project in cursor]
    )


# Get a project

@router.get("/{project_id}", response_model=SuccessResponse)
async def read_project(
    project_id: str,
    token: str = Depends(get_access_token)
):
    user = await get_user_from_token(token)
    project = await get_project(project_id, str(user["_id"]))
    return SuccessResponse(data=format_project(project))


# Edit project data

@router.patch("/{project_id}", response_model=SuccessResponse)
async def update_project(
    project_id: str,
    data: Project,
    token: str = Depends(get_access_token)
):
    user = await get_user_from_token(token)
    project = await get_project(project_id, str(user["_id"]), owner_only=True)

    updates = data.model_dump(exclude_unset=True)

    if not updates:
        raise HTTPException(status_code=400, detail="No changes provided")

    if "name" in updates and updates["name"] is None:
        raise HTTPException(status_code=400, detail="Project name cannot be null")

    updates["updated_at"] = datetime.now(timezone.utc)

    await projects.update_one(
        {"_id": project["_id"]},
        {"$set": updates}
    )

    updated_project = await projects.find_one({"_id": project["_id"]})
    return SuccessResponse(data=format_project(updated_project))


# Delete a project

@router.delete("/{project_id}", response_model=SuccessResponse)
async def delete_project(
    project_id: str,
    token: str = Depends(get_access_token)
):
    user = await get_user_from_token(token)
    project = await get_project(project_id, str(user["_id"]), owner_only=True)

    await projects.delete_one({"_id": project["_id"]})

    return SuccessResponse(data={"message": "Project deleted successfully"})


# Add a collaborator

@router.post("/{project_id}/collaborators", response_model=SuccessResponse)
async def add_collaborator(
    project_id: str,
    data: ProjectCollaborator,
    token: str = Depends(get_access_token)
):
    user = await get_user_from_token(token)
    project = await get_project(project_id, str(user["_id"]), owner_only=True)

    account = await users.find_one({"_id": data.account_id})

    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    if data.account_id == str(project["owner_id"]):
        raise HTTPException(status_code=400, detail="Project owner cannot be a collaborator")

    if data.account_id in {
        str(collaborator)
        for collaborator in project.get("collaborators", [])
    }:
        raise HTTPException(status_code=409, detail="Account is already a collaborator")

    await projects.update_one(
        {"_id": project["_id"]},
        {
            "$addToSet": {"collaborators": data.account_id},
            "$set": {"updated_at": datetime.now(timezone.utc)}
        }
    )

    return SuccessResponse(data={"message": "Collaborator added successfully"})


# Remove a collaborator

@router.delete(
    "/{project_id}/collaborators/{account_id}",
    response_model=SuccessResponse
)
async def remove_collaborator(
    project_id: str,
    account_id: str,
    token: str = Depends(get_access_token)
):
    user = await get_user_from_token(token)
    project = await get_project(project_id, str(user["_id"]), owner_only=True)

    if account_id not in {
        str(collaborator)
        for collaborator in project.get("collaborators", [])
    }:
        raise HTTPException(status_code=404, detail="Collaborator not found")

    await projects.update_one(
        {"_id": project["_id"]},
        {
            "$pull": {"collaborators": account_id},
            "$set": {"updated_at": datetime.now(timezone.utc)}
        }
    )

    return SuccessResponse(data={"message": "Collaborator removed successfully"})


# Add a farm

@router.post("/{project_id}/farms", response_model=SuccessResponse)
async def add_farm(
    project_id: str,
    data: ProjectFarm,
    token: str = Depends(get_access_token)
):
    user = await get_user_from_token(token)
    project = await get_project(project_id, str(user["_id"]), owner_only=True)

    if data.farm_id in project.get("farm_ids", []):
        raise HTTPException(status_code=409, detail="Farm is already associated with this project")

    await projects.update_one(
        {"_id": project["_id"]},
        {
            "$addToSet": {"farm_ids": data.farm_id},
            "$set": {"updated_at": datetime.now(timezone.utc)}
        }
    )

    return SuccessResponse(data={"message": "Farm added successfully"})


# Remove a farm

@router.delete("/{project_id}/farms/{farm_id}", response_model=SuccessResponse)
async def remove_farm(
    project_id: str,
    farm_id: str,
    token: str = Depends(get_access_token)
):
    user = await get_user_from_token(token)
    project = await get_project(project_id, str(user["_id"]), owner_only=True)

    if farm_id not in project.get("farm_ids", []):
        raise HTTPException(status_code=404, detail="Farm not associated with this project")

    await projects.update_one(
        {"_id": project["_id"]},
        {
            "$pull": {"farm_ids": farm_id},
            "$set": {"updated_at": datetime.now(timezone.utc)}
        }
    )

    return SuccessResponse(data={"message": "Farm removed successfully"})