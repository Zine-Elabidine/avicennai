from celery import Celery
from app.core.config import settings

celery_app = Celery(
    "avicennai_worker",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.tasks.llm_tasks", "app.tasks.agent_tasks"]
)

# Optional configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    worker_concurrency=settings.WORKER_CONCURRENCY,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_track_started=True,
)

# Optional: Configure task routing
celery_app.conf.task_routes = {
    "app.tasks.llm_tasks.*": {"queue": "llm_queue"},
    "app.tasks.agent_tasks.*": {"queue": "agent_queue"},
}