import json
from typing import Dict, Any, Optional
from celery import shared_task

from app.core.celery_app import celery_app
from app.core.config import settings


@shared_task(
    bind=True,
    name="process_llm_request",
    max_retries=3,
    soft_time_limit=settings.LLM_TASK_TIMEOUT,
    time_limit=settings.LLM_TASK_TIMEOUT + 30
)
def process_llm_request(self, model: str, prompt: str, additional_params: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Process an LLM request asynchronously.
    
    Args:
        model: The LLM model to use
        prompt: The prompt to process
        additional_params: Additional parameters for the request
        
    Returns:
        The LLM response as a dictionary
    """
    try:
        params = additional_params or {}
        
        # Implement actual LLM API call here
        # For example with OpenAI:
        # from openai import OpenAI
        # client = OpenAI(api_key="your-api-key")
        # 
        # response = client.chat.completions.create(
        #     model=model,
        #     messages=[{"role": "user", "content": prompt}],
        #     temperature=params.get("temperature", 0.7),
        # )
        # return response.choices[0].message.content
        
        # For now, we'll return a placeholder
        result = {
            "text": f"LLM Response from {model}: Processed '{prompt[:50]}...'",
            "model": model,
            "tokens": len(prompt) // 4,  # Rough estimate
            "params": params
        }
        
        return result
    except Exception as e:
        # Log the error and retry
        self.retry(exc=e, countdown=2 ** self.request.retries)


@shared_task(
    bind=True,
    name="process_batch_llm_requests",
    max_retries=2,
    soft_time_limit=settings.LLM_TASK_TIMEOUT * 2,
    time_limit=settings.LLM_TASK_TIMEOUT * 2 + 60
)
def process_batch_llm_requests(self, requests: list) -> list:
    """
    Process multiple LLM requests in batch.
    
    Args:
        requests: List of request dictionaries with model, prompt, and params
        
    Returns:
        List of LLM responses
    """
    results = []
    
    for req in requests:
        try:
            # Process each request individually
            result = process_llm_request.apply_async(
                args=[req.get("model"), req.get("prompt")],
                kwargs={"additional_params": req.get("additional_params", {})}
            ).get(timeout=settings.LLM_REQUEST_TIMEOUT)
            
            results.append({
                "request_id": req.get("id", "unknown"),
                "result": result,
                "status": "success"
            })
        except Exception as e:
            results.append({
                "request_id": req.get("id", "unknown"),
                "error": str(e),
                "status": "error"
            })
    
    return results