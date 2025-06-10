import uuid
from typing import Dict, Any, Union, Optional, AsyncGenerator
import asyncio

from app.models.request_models import LLMActionRequest, AgentActionRequest
from app.engine.agents.factory import AgentFactory


class EngineProcessor:
    """
    Core processor for the AvicennaI engine.
    This class handles the main processing logic of the engine.
    """
    
    def __init__(self):
        self.version = "1.0.0"
        self.available_models = ["llama-4.scout-17b", "claude-3-opus", "gpt-4o"]
        self.agent_factory = AgentFactory()
        self.available_agents = list(self.agent_factory.get_available_agents().keys())

    async def process_llm_action(self, request: LLMActionRequest) -> Union[str, AsyncGenerator[str, None]]:
        """
        Process LLM action request.
        
        Args:
            request: The LLM action request
            
        Returns:
            Response string for normal mode or AsyncGenerator for streaming
        """
        # Validate model
        if request.model not in self.available_models:
            raise ValueError(f"Model {request.model} not supported. Available models: {', '.join(self.available_models)}")
        
        # For non-streaming mode, return a string response
        if request.answer_mode == "normal":
            return f"LLM Response from {request.model}: Processed prompt: \"{request.prompt[:50]}...\""
        
        # For streaming mode, return an async generator
        else:
            return self._stream_llm_response(request)
    
    async def process_agent_action(self, request: AgentActionRequest) -> Union[str, AsyncGenerator[str, None]]:
        """
        Process agent action request by dispatching to the appropriate agent.
        
        Args:
            request: The agent action request
            
        Returns:
            Response string for normal mode or AsyncGenerator for streaming
        """
        try:
            # Create the requested agent
            agent = self.agent_factory.create_agent(
                request.agent_name, 
                config=request.additional_params
            )
            
            # Process with the agent based on answer mode
            if request.answer_mode == "normal":
                return await agent.process(request.prompt, request.additional_params)
            else:
                # For streaming, return the async generator directly
                return agent.stream(request.prompt, request.additional_params)
                
        except Exception as e:
            import traceback
            traceback.print_exc()
            raise RuntimeError(f"Error in agent processing: {str(e)}")
    
    async def _stream_llm_response(self, request: LLMActionRequest) -> AsyncGenerator[str, None]:
        """
        Stream a simulated LLM response.
        
        Args:
            request: The LLM action request
            
        Yields:
            Chunks of the response
        """
        # This is a simulated streaming response
        chunks = [
            f"Processing with {request.model}...\n",
            "Analyzing your query...\n",
            f"Based on your prompt: \"{request.prompt[:30]}...\"\n",
            "Here is my response:\n",
            "This is a simulated LLM response for demonstration purposes."
        ]
        
        for chunk in chunks:
            yield chunk
            await asyncio.sleep(0.5)  # Simulate processing time
    
    def generate_request_id(self) -> str:
        """
        Generate a unique request ID.
        
        Returns:
            A unique ID string
        """
        return str(uuid.uuid4())