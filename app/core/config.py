from typing import Optional, List
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    API_KEY: str
    ENVIRONMENT: str
    DEBUG: bool = False
    PROJECT_NAME: str = "AvicennaI Engine API"
    API_V1_STR: str = "/api/v1"
    
    # LLM Configuration
    DEFAULT_LLM_MODEL: str = "llama-3.3-70b"
    LLM_REQUEST_TIMEOUT: int = 60  # seconds
    
    # Agent Configuration
    DEFAULT_AGENT: str = "avicennai"
    AGENT_REQUEST_TIMEOUT: int = 120  # seconds
    OPENROUTER_API_KEY: str
    GROQ_API_KEY: str
    GEMINI_API_KEY: str
    GROQ_BASE_URL: str = "https://api.groq.com/openai/v1"
    OPENROUTER_BASE_URL: str = "https://openrouter.ai/api/v1"
    ANTHROPIC_BASE_URL: str = "https://api.anthropic.com/v1/"
    GROQ_LLAMA_3_3_70B: str = "llama-3.3-70b-versatile"
    FIREWORKS_LLAMA_3_1_405B: str = "accounts/fireworks/models/llama-v3p1-405b-instruct"
    ANTHROPIC_CLAUDE_3_5_HAIKU: str = "claude-3-5-haiku-latest"
    
    # Rate limiting
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_REQUESTS: int = 100  # requests per minute
    
    # Celery Configuration
    CELERY_BROKER_URL: str = "amqp://guest:guest@rabbitmq:5672//"
    CELERY_RESULT_BACKEND: str = "redis://redis:6379/0"
    WORKER_CONCURRENCY: int = 4
    
    # Task timeouts
    LLM_TASK_TIMEOUT: int = 300  # seconds
    AGENT_TASK_TIMEOUT: int = 600  # seconds
    
    # TheHive Configuration
    THEHIVE_API_URL: Optional[str] = None
    THEHIVE_API_KEY: Optional[str] = None
    THEHIVE_VERIFY_SSL: Optional[bool] = True
    
    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()