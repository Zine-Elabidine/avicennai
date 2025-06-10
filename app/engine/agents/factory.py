from typing import Dict, Any, Optional

from app.engine.agents.base import BaseAgent
from app.engine.agents.avicennai_agent import AvicennaIAgent, L1SOCAnalyst, DetectionAndResponseEngineerAgent

class AgentFactory:
    """
    Factory for creating agent instances.
    """
    
    def __init__(self):
        """
        Initialize the agent factory.
        """
        self._agents = {
            "avicennai": AvicennaIAgent,
            "detection_engineer": DetectionAndResponseEngineerAgent,
            "soc": L1SOCAnalyst
        }
    
    def create_agent(self, agent_name: str, config: Optional[Dict[str, Any]] = None) -> BaseAgent:
        """
        Create an instance of the specified agent.
        
        Args:
            agent_name: Name of the agent to create
            config: Configuration for the agent
            
        Returns:
            An instance of the requested agent
        """
        if agent_name not in self._agents:
            raise ValueError(f"Unknown agent: {agent_name}")
        
        agent_class = self._agents[agent_name]
        config = config or {}
        
        return agent_class(config)
    
    def get_available_agents(self) -> Dict[str, Dict[str, Any]]:
        """
        Get a dictionary of available agents and their capabilities.
        
        Returns:
            A dictionary mapping agent names to their capabilities
        """
        agents_info = {}
        
        for agent_name, agent_class in self._agents.items():
            # Create a temporary instance to get capabilities
            temp_agent = agent_class()
            agents_info[agent_name] = temp_agent.get_capabilities()
        
        return agents_info

def get_available_agent_types() -> Dict[str, Dict[str, Any]]:
    """
    Get a dictionary of available agent types and their capabilities.
    
    Returns:
        A dictionary mapping agent types to their capabilities
    """
    return {
        "avicennai": {
            "description": "General-purpose reasoning agent",
            "capabilities": ["reasoning", "tools"]
        },
        "detection_engineer": {
            "description": "Agent specialized in creating detection rules",
            "capabilities": ["rule_generation"]
        },
        "soc": {
            "description": "Security Operations Center analyst agent",
            "capabilities": ["investigation", "threat_analysis"]
        }
    }