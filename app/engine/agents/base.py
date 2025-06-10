from abc import ABC, abstractmethod
from typing import Dict, Any, AsyncGenerator, Union


class BaseAgent(ABC):
    """
    Abstract base class for all agents in the AvicennaI engine.
    All agent implementations should inherit from this class.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the agent with configuration.
        
        Args:
            config: Configuration dictionary for the agent
        """
        self.config = config or {}
        self.name = "base"
        self.version = "1.0.0"
    
    @abstractmethod
    async def process(self, prompt: str, additional_params: Dict[str, Any] = None) -> str:
        """
        Process a prompt with the agent and return a response.
        
        Args:
            prompt: The prompt to process
            additional_params: Additional parameters for processing
            
        Returns:
            The agent's response
        """
        pass
    
    @abstractmethod
    async def stream(self, prompt: str, additional_params: Dict[str, Any] = None) -> AsyncGenerator[str, None]:
        """
        Process a prompt with the agent and stream the response.
        
        Args:
            prompt: The prompt to process
            additional_params: Additional parameters for processing
            
        Returns:
            AsyncGenerator that yields response chunks
        """
        # This is not an actual implementation - the concrete classes must override this
        # Just yielding an empty string to define this as a proper async generator
        if False:  # This ensures the method is treated as an async generator but never executes this code
            yield ""
    
    def get_info(self) -> Dict[str, Any]:
        """
        Get information about the agent.
        
        Returns:
            Dictionary with agent information
        """
        return {
            "name": self.name,
            "version": self.version,
            "capabilities": self.get_capabilities()
        }
    
    @abstractmethod
    def get_capabilities(self) -> Dict[str, Any]:
        """
        Get the capabilities of the agent.
        
        Returns:
            Dictionary with capability information
        """
        pass