<<<<<<< HEAD
# AvicennAI Engine

## Description

AvicennAI Vinci Logic SOC Assistant
=======
# AvicennaI API

A modular FastAPI application for the AvicennaI engine with API key authentication and Docker support.

## Features

- API key authentication
- Support for LLM and Agent actions
- Streaming and normal response modes
- Docker and Docker Compose integration
- Modular architecture for easy extension
- SOC agent with TheHive and SentinelOne integration

## Getting Started

### Prerequisites

- Docker and Docker Compose
- Python 3.11+ (for local development)

### Installation

1. Clone the repository
2. Configure your API key in the `.env` file
3. Build and start the Docker container:

```bash
docker-compose up --build
```

## API Usage

The API supports two main types of requests, each of which can use either `stream` or `normal` answer modes:

### 1. LLM Action

```json
{
    "action_type": "llm_action",
    "model": "llama-3.3-70b",
    "prompt": "You are a helpful assistant...",
    "answer_mode": "stream",  // or "normal"
    "additional_params": {},
    "context": {}
}
```

### 2. Agent Action

```json
{
    "action_type": "agent",
    "agent_name": "avicennai",
    "prompt": "You are a helpful assistant...",
    "answer_mode": "normal",  // or "stream"
    "additional_params": {},
    "context": {}
}
```

### 3. SOC Agent Action

```json
{
  "action_type": "agent",
  "agent_name": "soc",
  "prompt": "# Alert title: 'BatTamper' malware was detected ....",
  "answer_mode": "stream", # or normal
  "additional_params": {}
}
```

### API Endpoints

- `POST /api/v1/engine/process` - Process a request (supports both streaming and non-streaming)
- `GET /api/v1/engine/models` - Get available LLM models
- `GET /api/v1/engine/agents` - Get available agents
- `GET /api/v1/engine/status` - Get engine status

### Authentication

All requests must include the API key in the `X-API-Key` header:

```bash
curl -X POST "http://localhost:8000/api/v1/engine/process" \
     -H "X-API-Key: your_secret_api_key_here" \
     -H "Content-Type: application/json" \
     -d '{
         "action_type": "llm_action",
         "model": "llama-3.3-70b",
         "prompt": "You are a helpful assistant...",
         "answer_mode": "normal",
         "additional_params": {},
         "context": {}
     }'
```

## Development

### Project Structure

```
avicennai_agent/
├── app/                              # Main application package
│   ├── main.py                       # FastAPI application entry point
│   ├── core/                         # Core application components
│   │   ├── config.py                 # Application configuration
│   │   ├── security.py               # Authentication and security
│   │   └── celery_app.py             # Celery configuration for async tasks
│   ├── api/                          # API endpoints
│   │   └── v1/                       # API version 1
│   │       ├── routes.py             # API route definitions
│   │       └── endpoints/            # API endpoint implementations
│   ├── engine/                       # Core engine functionality
│   │   ├── processor.py              # Request processing logic
│   │   └── agents/                   # Agent implementations
│   │       ├── base.py               # Base agent class
│   │       ├── factory.py            # Agent factory pattern
│   │       ├── avicennai_agent.py    # AvicennaI agent implementation
│   │       ├── detection_engineering.py # SOC detection engineering agent
│   │       ├── prompt_loader.py      # Prompt management for agents
│   │       ├── prompts/              # Prompt templates for agents
│   │       └── tools/                # Tool implementations for agents
│   ├── models/                       # Data models and schemas
│   │   └── request_models.py         # Request/response data models
│   └── tasks/                        # Async task definitions
├── docker-compose.yml                # Docker Compose configuration
├── Dockerfile                        # Docker image definition
├── requirements.txt                  # Python dependencies
└── example_request.json              # Example API request
```

## Key Components

### API Layer
- `app/api/v1/endpoints/engine.py`: Handles API requests for engine processing
- `app/api/v1/routes.py`: Defines API routes

### Engine Core
- `app/engine/processor.py`: Core request processing logic
- `app/engine/agents/factory.py`: Factory for creating agent instances

### Agent System
- `app/engine/agents/base.py`: Abstract base class for all agents
- `app/engine/agents/avicennai_agent.py`: Main AvicennaI agent implementation
- `app/engine/agents/detection_engineering.py`: SOC detection engineering agent

### Data Models
- `app/models/request_models.py`: Pydantic models for request/response validation

### Deployment
- `docker-compose.yml`: Multi-container Docker setup with:
  - API service
  - Specialized workers for LLM and agent tasks
  - RabbitMQ for message queuing
  - Redis for caching and results
  - Flower for task monitoring

### Streaming vs Normal Response Mode

The API supports both streaming and non-streaming responses:

- **Streaming (`answer_mode: "stream"`)**: Responses are delivered in chunks using HTTP streaming. This is ideal for real-time interactions where you want to show partial results as they become available.

- **Normal (`answer_mode: "normal"`)**: The response is delivered as a complete JSON object once processing is finished.

Both LLM and Agent actions support both response modes, giving you flexibility in how you interact with the API.

## Security Notes

- Change the default API key in the `.env` file before deployment
- Consider implementing rate limiting for production use
- Enable HTTPS in production

## License

This project is licensed under the MIT License.

# Extending the AvicennaI Engine with Custom Agents

This guide explains how to extend the AvicennaI engine with custom agents using the provided architecture.

## Overview of the Agent Architecture

The agent system follows a modular design with these key components:

1. **BaseAgent**: Abstract base class that defines the interface for all agents
2. **Concrete Agents**: Implementations of specific agents (e.g., AvicennaIAgent)
3. **AgentFactory**: Factory pattern to create and manage agent instances
4. **EngineProcessor**: Core class that dispatches requests to the appropriate agents

## Creating a New Agent

To create a new agent, follow these steps:

### 1. Create a New Agent Class

Create a new file in `app/engine/agents/` for your agent, e.g., `researcher_agent.py`:

```python
from typing import Dict, Any, AsyncGenerator
from app.engine.agents.base import BaseAgent

class ResearcherAgent(BaseAgent):
    """
    Agent specialized in research tasks and information gathering.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.name = "researcher"
        self.version = "1.0.0"
    
    async def process(self, prompt: str, additional_params: Dict[str, Any] = None) -> str:
        # Implement your research agent logic here
        return f"Research results for: {prompt[:50]}..."
    
    async def stream(self, prompt: str, additional_params: Dict[str, Any] = None) -> AsyncGenerator[str, None]:
        # Implement streaming logic here
        yield "Starting research process...\n"
        yield f"Research results for: {prompt[:50]}..."
    
    def get_capabilities(self) -> Dict[str, Any]:
        return {
            "research": True,
            "information_gathering": True,
            "citation": True,
            "streaming": True,
            "max_tokens": 8000
        }
```

### 2. Register the Agent in the Factory

Update `app/engine/agents/factory.py` to include your new agent:

```python
def _register_agents(self):
    """
    Register all available agents.
    """
    self._agents = {
        "avicennai": AvicennaIAgent,
        "researcher": ResearcherAgent,  # Add your new agent here
    }
    
def get_available_agents(self) -> Dict[str, str]:
    """
    Get the names of all available agents.
    """
    return {
        "avicennai": "General purpose reasoning agent with tool use capabilities",
        "researcher": "Specialized agent for research and information gathering",  # Add description
    }
```

Don't forget to import your new agent:

```python
from app.engine.agents.researcher_agent import ResearcherAgent
```

### 3. Update the __init__.py File

Update `app/engine/agents/__init__.py` to export your new agent:

```python
from app.engine.agents.factory import AgentFactory
from app.engine.agents.base import BaseAgent
from app.engine.agents.avicennai_agent import AvicennaIAgent
from app.engine.agents.researcher_agent import ResearcherAgent

__all__ = ["AgentFactory", "BaseAgent", "AvicennaIAgent", "ResearcherAgent"]
```

## Using Your New Agent

Your new agent will now be automatically available through the API. The `EngineProcessor` will handle the routing based on the `agent_name` field in the request.

Example request:

```json
{
    "action_type": "agent",
    "agent_name": "researcher",
    "prompt": "Find information about the history of AI",
    "answer_mode": "normal",
    "additional_params": {
        "depth": "comprehensive",
        "max_sources": 5
    },
    "context": {}
}
```

## Adding Tools to Your Agent

For agents that need to use tools, you can implement a tool system in your agent:

```python
def _initialize_tools(self):
    return [
        {
            "name": "web_search",
            "description": "Search the web for information"
        },
        {
            "name": "citation_manager",
            "description": "Manage citations for research"
        }
    ]

def _execute_tool(self, tool_name: str, params: Dict[str, Any]):
    if tool_name == "web_search":
        # Implement web search logic
        return {"results": ["Result 1", "Result 2"]}
    elif tool_name == "citation_manager":
        # Implement citation manager logic
        return {"citations": ["Citation 1", "Citation 2"]}
    else:
        raise ValueError(f"Unknown tool: {tool_name}")
```

## Best Practices

1. **Agent Specialization**: Each agent should have a clear purpose and specialized capabilities
2. **Configuration**: Make agents configurable through the `additional_params` dictionary
3. **Error Handling**: Implement robust error handling in your agent implementations
4. **Streaming Support**: All agents should support both regular and streaming responses
5. **Testing**: Create tests for your agent behaviors

## TheHive Integration

The application integrates with TheHive for SOC case management. To configure TheHive:

### Using an existing TheHive instance on your host machine

1. Update your `.env` file with the following settings:

```
# TheHive API Configuration
THEHIVE_API_URL=http://host.docker.internal:9000/api
THEHIVE_API_KEY=your_api_key_here
THEHIVE_VERIFY_SSL=false
```

The special DNS name `host.docker.internal` allows Docker containers to access services running on the host machine.

2. Make sure your TheHive instance is running and accessible at `http://localhost:9000` on your host machine.

3. If you're using Docker Desktop on Windows or macOS, `host.docker.internal` should work out of the box. For Linux hosts, you may need to add the `--add-host` flag to your docker-compose command:

```bash
docker-compose up --add-host=host.docker.internal:host-gateway
```

### For local development (without Docker)

If running the application directly on your host (not in Docker), use:

```
THEHIVE_API_URL=http://localhost:9000/api
```

### To obtain an API key from TheHive

1. Log in to TheHive web interface
2. Go to your user profile
3. Create a new API key
4. Copy the key to your `.env` file

The application uses TheHive4py to interact with TheHive API. See `app/engine/agents/tools/thehive4api_tools.py` for available functions.
>>>>>>> 911b303 (mvp commit)
