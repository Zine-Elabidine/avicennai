from typing import Dict, Any, Optional
import json
import uuid
from celery import shared_task

from app.core.celery_app import celery_app
from app.core.config import settings
from app.engine.agents.factory import AgentFactory


@shared_task(
    bind=True,
    name="process_agent_request",
    max_retries=3,
    soft_time_limit=settings.AGENT_TASK_TIMEOUT,
    time_limit=settings.AGENT_TASK_TIMEOUT + 60
)
def process_agent_request(self, agent_name: str, prompt: str, additional_params: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Process an agent request asynchronously.
    
    Args:
        agent_name: The name of the agent to use
        prompt: The prompt to process
        additional_params: Additional parameters for the agent
        
    Returns:
        The agent's response as a dictionary
    """
    try:
        # Initialize the agent
        agent_factory = AgentFactory()
        agent = agent_factory.create_agent(agent_name, config=additional_params)
        
        # In real async code, we would call:
        # result = await agent.process(prompt, additional_params)
        #
        # But Celery tasks can't be async, so we have to handle this differently
        # For now, we'll just return a simulated response
        
        # Simulate agent processing
        thinking = _generate_thinking(prompt)
        
        use_tools = additional_params.get("use_tools", True)
        
        if use_tools:
            tool_results = _simulate_tool_usage(prompt, agent_name)
            final_response = f"After analyzing '{prompt[:30]}...', I found: {tool_results}"
        else:
            final_response = f"I've considered '{prompt[:30]}...'. {thinking}"
        
        # Return result as a dictionary
        return {
            "text": final_response,
            "agent": agent_name,
            "tools_used": ["search", "calculator"] if use_tools else [],
            "thinking": thinking
        }
    except Exception as e:
        # Log the error and retry
        self.retry(exc=e, countdown=3 ** self.request.retries)


@shared_task(
    bind=True,
    name="run_agent_workflow",
    max_retries=2,
    soft_time_limit=settings.AGENT_TASK_TIMEOUT * 3,
    time_limit=settings.AGENT_TASK_TIMEOUT * 3 + 60
)
def run_agent_workflow(self, workflow_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run a multi-step agent workflow.
    
    Args:
        workflow_config: Configuration for the workflow including steps
        
    Returns:
        The results of the workflow
    """
    workflow_id = workflow_config.get("id", str(uuid.uuid4()))
    steps = workflow_config.get("steps", [])
    context = workflow_config.get("context", {})
    
    results = {
        "workflow_id": workflow_id,
        "steps_completed": 0,
        "total_steps": len(steps),
        "step_results": [],
        "final_result": ""
    }
    
    # Process each step sequentially, passing context between steps
    for i, step in enumerate(steps):
        try:
            # Get step configuration
            agent_name = step.get("agent", settings.DEFAULT_AGENT)
            prompt = step.get("prompt")
            
            # Add context to additional params
            params = step.get("params", {})
            params["context"] = context
            
            # Process the step
            step_result = process_agent_request.apply_async(
                args=[agent_name, prompt],
                kwargs={"additional_params": params}
            ).get(timeout=settings.AGENT_REQUEST_TIMEOUT)
            
            # Update context with this step's result
            context[f"step_{i+1}_result"] = step_result.get("text", "")
            
            # Add to results
            results["steps_completed"] += 1
            results["step_results"].append({
                "step_number": i + 1,
                "agent": agent_name,
                "result": step_result,
                "status": "success"
            })
        except Exception as e:
            # Record failure but continue with workflow
            results["step_results"].append({
                "step_number": i + 1,
                "agent": agent_name if 'agent_name' in locals() else "unknown",
                "error": str(e),
                "status": "error"
            })
    
    # Generate final result
    if results["steps_completed"] == results["total_steps"]:
        final_text = "Workflow completed successfully. "
        
        # Combine results from all steps
        if results["step_results"]:
            final_text += "Final summary: " + " ".join(
                [step["result"]["text"][:100] + "..." for step in results["step_results"] if step["status"] == "success"]
            )
    else:
        final_text = f"Workflow partially completed ({results['steps_completed']}/{results['total_steps']} steps)."
    
    results["final_result"] = final_text
    return results


# Helper functions for the agent tasks
def _generate_thinking(prompt: str) -> str:
    """
    Generate simulated thinking for the agent.
    
    Args:
        prompt: The prompt to process
        
    Returns:
        Simulated thinking text
    """
    # This is just a placeholder simulation
    return (
        "After careful consideration, I've identified the key aspects of your request "
        "and determined the most effective approach to address it comprehensively. "
        "Taking into account the context and implicit requirements, I've formulated a response "
        "that should provide you with the information you need."
    )


def _simulate_tool_usage(prompt: str, agent_name: str) -> str:
    """
    Simulate tool usage by the agent.
    
    Args:
        prompt: The prompt that might trigger tool usage
        agent_name: The name of the agent
        
    Returns:
        Simulated tool results
    """
    # This is just a placeholder simulation
    if "calculate" in prompt.lower() or "math" in prompt.lower():
        return "The calculation result is 42."
    elif "find" in prompt.lower() or "search" in prompt.lower():
        return "I found several relevant resources that address your query."
    else:
        return f"Based on my analysis as {agent_name}, I've compiled comprehensive information to answer your question."