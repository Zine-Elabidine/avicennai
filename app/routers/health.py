# app/routers/health.py
from fastapi import APIRouter, Depends
from app.dependencies import common_dependencies

router = APIRouter()

@router.get("/health")
async def health_check(deps: dict = Depends(common_dependencies)):
    return {"status": "ok"}
