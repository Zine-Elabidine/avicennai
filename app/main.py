from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
import time
import logging

from app.core.config import settings
from app.api.v1.routes import api_router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("avicennai")

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="AvicennAI Engine API for LLM and Agent actions",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    debug=settings.DEBUG
)

# Set CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API router
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """
    Middleware to log requests and timing information.
    """
    request_id = request.headers.get("X-Request-ID", "unknown")
    start_time = time.time()
    
    logger.info(f"Request started - ID: {request_id} - Path: {request.url.path}")
    
    response = await call_next(request)
    
    process_time = time.time() - start_time
    logger.info(f"Request completed - ID: {request_id} - Time: {process_time:.4f}s")
    
    # Add processing time header
    response.headers["X-Process-Time"] = str(process_time)
    return response


@app.get("/")
async def root():
    """
    Root endpoint that returns basic information about the API.
    """
    return {
        "message": "Welcome to AvicennAI Engine API",
        "version": "1.0.0",
        "documentation": f"/docs",
        "health": "operational"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
