from typing import Any

from pydantic import BaseModel


class SuccessResponse(BaseModel):
    data: Any


class ErrorResponse(BaseModel):
    error: str
