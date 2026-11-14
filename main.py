import logging

from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from starlette.exceptions import HTTPException as StarletteHTTPException

from routes.auth import router as auth_router
from routes.project import router as project_router
from routes.farm import router as farm_router
from routes.plant import router as plant_router
from routes.advice import router as advice_router
from routes.risk import router as risk_router
from utils.responses import ErrorResponse

load_dotenv()

app = FastAPI()

@app.exception_handler(StarletteHTTPException)
async def handle_http_exception(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(error=str(exc.detail)).model_dump(),
        headers=exc.headers
    )


@app.exception_handler(RequestValidationError)
async def handle_validation_exception(request, exc):
    return JSONResponse(
        status_code=422,
        content=ErrorResponse(error="Request validation failed.").model_dump()
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