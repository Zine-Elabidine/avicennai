from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from fastapi.responses import StreamingResponse, JSONResponse
from typing import Union, Any, Dict, Optional, List
import asyncio
import uuid
from celery.result import AsyncResult
from datetime import datetime

from app.api.deps import get_engine_processor
from app.engine.processor import EngineProcessor
from app.models.request_models import (
    LLMActionRequest, AgentActionRequest, ProcessResponse, TaskResponse,
    WorkflowRequest, TaskStatusResponse, BatchProcessRequest, BatchTaskResponse
)
from app.tasks.llm_tasks import process_llm_request, process_batch_llm_requests
from app.tasks.agent_tasks import process_agent_request, run_agent_workflow
from app.core.config import settings

router = APIRouter()


@router.post("/process")
async def process_request(
    request: Union[LLMActionRequest, AgentActionRequest],
    processor: EngineProcessor = Depends(get_engine_processor)
):
    """
    Process a request using the AvicennaI engine.
    This endpoint handles both LLM and Agent actions in both streaming and non-streaming modes.
    """
    try:
        request_id = processor.generate_request_id()
        
        # Handle streaming response
        if request.answer_mode == "stream":
            # Determine the streaming source based on action type
            if request.action_type == "llm_action":
                async def generate_llm_stream():
                    # We need to await the coroutine to get the actual generator
                    generator = await processor.process_llm_action(request)
                    async for chunk in generator:
                        yield f"{chunk}"
                
                return StreamingResponse(
                    generate_llm_stream(),
                    media_type="text/plain"
                )
                
            elif request.action_type == "agent":
                async def generate_agent_stream():
                    # We need to await the coroutine to get the actual generator
                    generator = await processor.process_agent_action(request)
                    async for chunk in generator:
                        yield f"{chunk}"
                
                return StreamingResponse(
                    generate_agent_stream(),
                    media_type="text/plain"
                )
                
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid action type for streaming"
                )
        
        # Handle normal (non-streaming) response
        elif request.answer_mode == "normal":
            if request.action_type == "llm_action":
                result = await processor.process_llm_action(request)
                return ProcessResponse(
                    result=result,
                    status="success",
                    request_id=request_id
                )
            elif request.action_type == "agent":
                result = await processor.process_agent_action(request)
                return ProcessResponse(
                    result=result,
                    status="success",
                    request_id=request_id
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid action type"
                )
        
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid answer mode. Use 'stream' or 'normal'."
            )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Processing error: {str(e)}"
        )


@router.post("/process-async", response_model=TaskResponse)
async def process_request_async(
    request: Union[LLMActionRequest, AgentActionRequest],
    processor: EngineProcessor = Depends(get_engine_processor)
):
    """
    Process a request asynchronously using Celery workers.
    This endpoint handles both LLM and Agent actions, returning a task ID for tracking.
    """
    try:
        request_id = processor.generate_request_id()
        
        if request.action_type == "llm_action":
            # Send LLM task to Celery worker
            task = process_llm_request.delay(
                request.model,
                request.prompt,
                request.additional_params
            )
            
            return TaskResponse(
                task_id=task.id,
                status="pending",
                request_id=request_id
            )
            
        elif request.action_type == "agent":
            # Send agent task to Celery worker
            task = process_agent_request.delay(
                request.agent_name,
                request.prompt,
                request.additional_params
            )
            
            return TaskResponse(
                task_id=task.id,
                status="pending",
                request_id=request_id
            )
            
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid action type"
            )
            
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error submitting task: {str(e)}"
        )


@router.post("/batch", response_model=BatchTaskResponse)
async def process_batch(
    batch_request: BatchProcessRequest,
    processor: EngineProcessor = Depends(get_engine_processor)
):
    """
    Process multiple requests in a batch.
    """
    try:
        batch_id = f"batch-{uuid.uuid4()}"
        task_ids = []
        
        # Process each request in the batch
        requests_data = []
        for i, req in enumerate(batch_request.requests):
            req_id = f"{batch_id}-item-{i}"
            
            if req.action_type == "llm_action":
                # Prepare LLM request data
                req_data = {
                    "id": req_id,
                    "model": req.model,
                    "prompt": req.prompt,
                    "additional_params": req.additional_params
                }
                requests_data.append(req_data)
                
            elif req.action_type == "agent":
                # Submit agent requests individually
                task = process_agent_request.delay(
                    req.agent_name,
                    req.prompt,
                    req.additional_params
                )
                task_ids.append(task.id)
        
        # Submit batch LLM requests together if any
        if requests_data:
            batch_task = process_batch_llm_requests.delay(requests_data)
            task_ids.append(batch_task.id)
        
        return BatchTaskResponse(
            batch_id=batch_id,
            task_ids=task_ids,
            status="processing"
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error processing batch: {str(e)}"
        )


@router.post("/workflow", response_model=TaskResponse)
async def run_workflow(
    workflow: WorkflowRequest,
    processor: EngineProcessor = Depends(get_engine_processor)
):
    """
    Run a multi-step agent workflow using Celery workers.
    """
    try:
        # Generate workflow ID and request ID
        workflow_id = processor.generate_request_id()
        request_id = processor.generate_request_id()
        
        # Create workflow configuration
        workflow_config = {
            "id": workflow_id,
            "steps": [step.dict() for step in workflow.steps],
            "context": workflow.context
        }
        
        # Submit workflow task to Celery
        task = run_agent_workflow.delay(workflow_config)
        
        return TaskResponse(
            task_id=task.id,
            status="pending",
            request_id=request_id
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error starting workflow: {str(e)}"
        )


@router.get("/task/{task_id}", response_model=TaskStatusResponse)
async def get_task_status(
    task_id: str,
    processor: EngineProcessor = Depends(get_engine_processor)
):
    """
    Get the status and result of an asynchronous task.
    """
    try:
        # Use Celery's AsyncResult to check task status
        result = AsyncResult(task_id)
        
        response = TaskStatusResponse(
            task_id=task_id,
            status=result.status,
            result=None,
            error=None
        )
        
        # Add result if task is completed
        if result.ready():
            if result.successful():
                response.result = result.get()
            else:
                response.error = str(result.result)
        
        return response
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving task: {str(e)}"
        )


@router.get("/batch/{batch_id}")
async def get_batch_status(
    batch_id: str,
    processor: EngineProcessor = Depends(get_engine_processor)
):
    """
    Get the status of all tasks in a batch.
    """
    try:
        # Retrieve all task IDs for this batch
        # In a real implementation, you would store and retrieve this from a database
        # For now, we'll return a simulated response
        
        return {
            "batch_id": batch_id,
            "status": "completed",
            "total_tasks": 2,
            "completed": 2,
            "timestamp": datetime.now().isoformat(),
            "message": "This is a simulated response. In a real implementation, you would track batch tasks in a database."
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving batch: {str(e)}"
        )


@router.get("/models")
async def get_available_models(processor: EngineProcessor = Depends(get_engine_processor)):
    """
    Get a list of available LLM models.
    """
    return {
        "models": processor.available_models
    }


@router.get("/agents")
async def get_available_agents(processor: EngineProcessor = Depends(get_engine_processor)):
    """
    Get a list of available agents.
    """
    try:
        agents_info = processor.agent_factory.get_available_agents()
        return {
            "agents": agents_info,
            "count": len(agents_info)
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving agents: {str(e)}"
        )


@router.get("/status")
async def get_status(processor: EngineProcessor = Depends(get_engine_processor)):
    """
    Get the current status of the AvicennaI engine.
    """
    return {
        "status": "operational",
        "version": processor.version,
        "available_models": processor.available_models,
        "available_agents": processor.available_agents
    }


@router.get("/workers")
async def get_workers_status():
    """
    Get information about active workers.
    """
    try:
        # In a real implementation, you could use Celery's inspect functionality
        # to get actual worker information
        
        return {
            "active_workers": {
                "worker-1": {
                    "status": "online",
                    "tasks_processed": 142,
                    "uptime": "2h 34m",
                    "queues": ["llm_queue"]
                },
                "worker-2": {
                    "status": "online",
                    "tasks_processed": 98,
                    "uptime": "2h 34m",
                    "queues": ["agent_queue"]
                }
            },
            "note": "This is simulated data. In production, use Celery inspection."
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving worker information: {str(e)}"
        )