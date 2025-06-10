from fastapi import Depends, Security

from app.core.security import get_api_key
from app.engine.processor import EngineProcessor


def get_engine_processor(api_key: str = Security(get_api_key)):
    """
    Dependency to get an instance of the EngineProcessor.
    This ensures the API key is validated before allowing access.
    """
    return EngineProcessor()