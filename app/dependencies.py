# app/dependencies.py

from fastapi import Depends

# For demonstration, we don't have actual dependencies besides security and DB
from app.database import get_db
from app.security import get_api_key

# Example of a dependency that ensures the request has a valid API key and returns DB session
def common_dependencies(api_key: str = Depends(get_api_key), db=Depends(get_db)):
    # This is just a placeholder to show how dependencies might be combined.
    return {"api_key": api_key, "db": db}
