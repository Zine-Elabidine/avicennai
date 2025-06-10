from typing import Dict, Optional, Literal, Any, Union, List, Annotated
from pydantic import BaseModel, Field, RootModel


class LLMActionRequest(BaseModel):
    """
    Model for LLM action request.
    """
    action_type: Literal["llm_action"] = Field(..., description="Type of action to perform")
    model: str = Field(..., description="LLM model to use for processing")
    prompt: str = Field(..., description="The prompt to be processed by the model")
    answer_mode: Literal["stream", "normal"] = Field(..., description="Response mode (stream or normal)")
    additional_params: Dict[str, Any] = Field(default_factory=dict, description="Additional parameters for the LLM")
    context: Dict[str, Any] = Field(default_factory=dict, description="Context information for the request")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "action_type": "llm_action",
                "model": "llama-3.3-70b",
                "prompt": "You are a helpful assistant...",
                "answer_mode": "stream",
                "additional_params": {},
                "context": {}
            }
        }
    }


class AgentActionRequest(BaseModel):
    """
    Model for Agent action request.
    """
    action_type: Literal["agent"] = Field(..., description="Type of action to perform")
    agent_name: str = Field(..., description="Name of the agent to use")
    prompt: str = Field(..., description="The prompt to be processed by the agent")
    answer_mode: Literal["stream", "normal"] = Field(..., description="Response mode (stream or normal)")
    additional_params: Dict[str, Any] = Field(default_factory=dict, description="Additional parameters for the agent")
    #context: Dict[str, Any] = Field(default_factory=dict, description="Context information for the request")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "action_type": "agent",
                "agent_name": "avicennai",
                "prompt": "You are a helpful assistant...",
                "answer_mode": "normal",
                "additional_params": {}
                #"context": {}
            }
        }
    }


# In Pydantic v2, we use discriminated unions for this type of model
ActionRequest = Annotated[
    Union[LLMActionRequest, AgentActionRequest],
    Field(discriminator="action_type")
]


"""
class ProcessResponse(BaseModel):
    result: str = Field(..., description="The result of the processing")
    status: str = Field(..., description="The status of the processing")
    request_id: str = Field(..., description="Unique identifier for the request")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "result": "I'm an AI assistant. How can I help you today?",
                "status": "success",
                "request_id": "a1b2c3d4-e5f6-7890-abcd-1234567890ab"
            }
        }
    }
"""

class ProcessResponse(BaseModel):
    """
    Model for process response.
    """
    result: Any = Field(..., description="The result of the processing (can be string, dict, list, etc.)")
    status: str = Field(..., description="The status of the processing")
    request_id: str = Field(..., description="Unique identifier for the request")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "result": {
                    "text": "I'm an AI assistant. How can I help you today?",
                    "metadata": {
                        "tokens": 10,
                        "model": "llama-3.3-70b",
                        "processing_time": 0.231
                    }
                },
                "status": "success",
                "request_id": "a1b2c3d4-e5f6-7890-abcd-1234567890ab"
            }
        }
    }

class TaskResponse(BaseModel):
    """
    Model for task response.
    """
    task_id: str = Field(..., description="The task ID for tracking")
    status: str = Field(..., description="The status of the task (pending, started, success, failure)")
    request_id: str = Field(..., description="Unique identifier for the original request")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "task_id": "a1b2c3d4-e5f6-7890-abcd-1234567890ab",
                "status": "pending",
                "request_id": "req-1234567890"
            }
        }
    }


class WorkflowStep(BaseModel):
    """
    Model for a workflow step.
    """
    agent: str = Field(..., description="The agent to use for this step")
    prompt: str = Field(..., description="The prompt for this step")
    params: Dict[str, Any] = Field(default_factory=dict, description="Parameters for this step")


class WorkflowRequest(BaseModel):
    """
    Model for workflow requests.
    """
    steps: List[WorkflowStep] = Field(..., description="The steps in the workflow")
    context: Dict[str, Any] = Field(default_factory=dict, description="Initial context for the workflow")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "steps": [
                    {
                        "agent": "avicennai",
                        "prompt": "Research the topic of artificial intelligence",
                        "params": {"use_tools": True}
                    },
                    {
                        "agent": "avicennai",
                        "prompt": "Summarize the research findings",
                        "params": {}
                    }
                ],
                "context": {"topic": "artificial intelligence"}
            }
        }
    }


class TaskStatusResponse(BaseModel):
    """
    Model for task status response.
    """
    task_id: str = Field(..., description="The task ID")
    status: str = Field(..., description="Current status of the task")
    result: Optional[Dict[str, Any]] = Field(None, description="Task result if completed")
    error: Optional[str] = Field(None, description="Error message if task failed")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "task_id": "a1b2c3d4-e5f6-7890-abcd-1234567890ab",
                "status": "SUCCESS",
                "result": {"text": "Task result here"},
                "error": None
            }
        }
    }


class BatchProcessRequest(BaseModel):
    """
    Model for batch processing multiple requests.
    """
    requests: List[Union[LLMActionRequest, AgentActionRequest]] = Field(
        ..., description="List of requests to process in batch"
    )
    wait_for_results: bool = Field(
        False, description="Whether to wait for all results before returning"
    )
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "requests": [
                    {
                        "action_type": "llm_action",
                        "model": "llama-3.3-70b",
                        "prompt": "First prompt",
                        "answer_mode": "normal",
                        "additional_params": {},
                        "context": {}
                    },
                    {
                        "action_type": "agent",
                        "agent_name": "avicennai",
                        "prompt": "Second prompt",
                        "answer_mode": "normal",
                        "additional_params": {},
                        "context": {}
                    }
                ],
                "wait_for_results": False
            }
        }
    }


class BatchTaskResponse(BaseModel):
    """
    Model for batch task response.
    """
    batch_id: str = Field(..., description="Unique identifier for the batch")
    task_ids: List[str] = Field(..., description="List of task IDs in the batch")
    status: str = Field(..., description="Status of the batch request")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "batch_id": "batch-1234567890",
                "task_ids": [
                    "task-1234567890",
                    "task-0987654321"
                ],
                "status": "processing"
            }
        }
    }