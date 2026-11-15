import logging
import os

from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from starlette.exceptions import HTTPException as StarletteHTTPException

from routes.auth import router as auth_router
from routes.project import router as project_router
from routes.farm import router as farm_router
from routes.plant import router as plant_router
from routes.advice import router as advice_router
from routes.risk import router as risk_router
from utils.responses import ErrorResponse, SuccessResponse

load_dotenv()

app = FastAPI(title="Farmo API")

# Dev ports are always allowed so a local Vite instance can reach the API even
# when CORS_ORIGINS in .env is stale.
default_origins = (
    "http://localhost:5173,http://localhost:5178,"
    "http://127.0.0.1:5173,http://127.0.0.1:5178"
)
cors_origins = sorted(
    {o.strip() for o in f"{os.getenv('CORS_ORIGINS', '')},{default_origins}".split(",") if o.strip()}
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/v1/health")
async def health():
    return SuccessResponse(data={"status": "ok", "app": "Farmo API", "version": os.getenv("APP_VERSION", "1.0.0")})

@app.exception_handler(StarletteHTTPException)
async def handle_http_exception(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(error=str(exc.detail)).model_dump(),
        headers=exc.headers
    )


@app.exception_handler(RequestValidationError)
async def handle_validation_exception(request, exc):
    # Keep the error shape stable for the client, but name the offending field
    # so a 422 is actionable rather than a mystery.
    errors = exc.errors()
    message = "Request validation failed."
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.get("loc", []) if part != "body")
        message = f"Request validation failed: {location} — {first.get('msg', '')}".strip()
    return JSONResponse(
        status_code=422,
        content=ErrorResponse(error=message).model_dump()
    )


@app.exception_handler(Exception)
async def handle_unexpected_exception(request, exc):
    logging.getLogger(__name__).exception(
        "Unhandled error in request %s",
        request.url.path,
        exc_info=exc
    )
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(error="Internal server error.").model_dump()
    )


app.include_router(auth_router, prefix="/api/v1")
app.include_router(project_router, prefix="/api/v1")
app.include_router(farm_router, prefix="/api/v1")
app.include_router(plant_router, prefix="/api/v1")
app.include_router(advice_router, prefix="/api/v1")
app.include_router(risk_router, prefix="/api/v1")