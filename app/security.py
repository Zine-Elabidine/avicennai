# app/security.py
import os
from fastapi import Security, HTTPException
from fastapi.security import APIKeyHeader

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def get_api_key(api_key: str = Security(api_key_header)):
    expected_api_key = os.getenv("API_KEY", "your-secret-api-key")
    if api_key == expected_api_key:
        return api_key
    else:
        raise HTTPException(status_code=403, detail="Could not validate API KEY")
