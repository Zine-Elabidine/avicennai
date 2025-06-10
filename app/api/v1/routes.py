from fastapi import APIRouter

from app.api.v1.endpoints import engine

api_router = APIRouter()

api_router.include_router(engine.router, prefix="/engine", tags=["engine"])