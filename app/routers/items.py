# app/routers/items.py
from fastapi import APIRouter, Depends
from app.models import Item
from app.dependencies import common_dependencies

router = APIRouter()

@router.post("/items")
async def create_item(item: Item, deps: dict = Depends(common_dependencies)):
    # Here you can add logic to store/process the item using deps['db']
    return {"message": "Item created successfully", "item": item.dict()}
