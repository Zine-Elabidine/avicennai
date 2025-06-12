import asyncio
from typing import Dict, Any, AsyncGenerator, List, Optional
import json
import logging
import os

from langgraph.prebuilt import create_react_agent

from app.engine.agents.base import BaseAgent
from app.engine.agents.config import agent_config
from app.engine.agents.utils import init_llm_model, dict_to_llm_text, classify_intent_for_rule_generation
from app.engine.agents.detection_engineering import STAGE_LLM_CONFIG, RULE_TEMPLATES
from app.engine.agents.prompt_loader import (
    format_metadata_prompt,
    format_detection_prompt,
    format_investigation_prompt,
    format_playbook_prompt
)
from app.engine.agents.tools.toolsv0 import virustotal_lookup, websearch, websearch_threat, url_content_analysis
from app.engine.agents.tools.thehive4api_tools import (
    thehive_get_case, thehive_create_case, thehive_update_case,
    thehive_add_observable, thehive_create_task, thehive_flag_case
)

class DetectionAndResponseEngineerAgent(BaseAgent):

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.name = "DetectionAndResponseEngineerAgent"
        self.version = "0.0.1"
        self.llm_model_name = "llama-4.scout-17b"
        self.available_tools = []
        self.agent_config = {"recursion_limit": 80}
        self.system_prompt = ""
        
        # Add conversational capabilities
        self.chat_history = []
        self.conversational_llm_name = "models/gemini-2.5-flash-preview-05-20"
        self.conversational_system_prompt = """You are a helpful cybersecurity detection engineering assistant. 

You can help with:
- General cybersecurity questions and concepts
- Explaining detection techniques and methodologies  
- Discussing threat hunting approaches
- Providing guidance on security operations
- Explaining SIEM technologies and best practices
- Discussing cybersecurity frameworks and compliance

You are in CONVERSATION mode. Your role is to have helpful discussions about cybersecurity topics, explain concepts, and answer questions. You should NOT generate detection rules yourself - that's handled by a separate specialized pipeline.

Keep responses concise but informative. Focus on education and guidance rather than rule generation."""

    async def process(self, prompt: str = "", additional_params: Dict[str, Any] = None) -> str:
        additional_params = additional_params or {}
        
        # Extract user prompt from chat_history if available, fallback to prompt parameter
        user_prompt = self._extract_user_prompt_from_chat_history(additional_params, prompt)
        if not user_prompt:
            return "No user message found to process."
        
        # Add user prompt to chat history
        self.chat_history.append({"role": "user", "content": user_prompt})
        
        # Always classify intent first
        wants_rule = classify_intent_for_rule_generation(user_prompt)
        
        if wants_rule:
            # Rule generation mode - use provided rule_type or default to query
            if not additional_params.get("rule_type"):
                additional_params["rule_type"] = "query"
            response = await self._generate_detection_rule(user_prompt, additional_params)
        else:
            # Conversation mode
            response = await self._handle_conversation(user_prompt, additional_params)
        
        # Add assistant response to chat history
        self.chat_history.append({"role": "assistant", "content": response})
        
        # Keep chat history manageable
        if len(self.chat_history) > 20:
            self.chat_history = self.chat_history[-20:]
        
        return response

    async def _generate_detection_rule(self, prompt: str, additional_params: Dict[str, Any]) -> str:
        """Generate detection rule using the existing modular pipeline"""
        rule_type = additional_params.get("rule_type", "query")
        current_rule = additional_params.get("current_rule", "")
        prompt_type = additional_params.get("prompt_type", "create")

        # === METADATA GENERATION ===
        metadata_model_name = STAGE_LLM_CONFIG["metadata"]
        metadata_model = init_llm_model(metadata_model_name)
        metadata_prompt = format_metadata_prompt(prompt, current_rule, prompt_type)
        metadata_response = metadata_model.invoke([("user", metadata_prompt)])
        metadata_yaml = metadata_response.content.strip()

        # === DETECTION GENERATION ===
        detection_model_name = STAGE_LLM_CONFIG["detection"]
        detection_model = init_llm_model(detection_model_name)
        detection_template = RULE_TEMPLATES["sections"]["detection"].get(rule_type, "")
        detection_prompt = format_detection_prompt(
            user_prompt=prompt,
            rule_type=rule_type,
            metadata_yaml=metadata_yaml,
            detection_template=detection_template,
            current_rule=current_rule,
            prompt_type=prompt_type
        )
        detection_response = detection_model.invoke([("user", detection_prompt)])
        detection_yaml = detection_response.content.strip()

        # === INVESTIGATION GENERATION ===
        investigation_model_name = STAGE_LLM_CONFIG["investigation"]
        investigation_model = init_llm_model(investigation_model_name)
        investigation_template = RULE_TEMPLATES["sections"]["investigation"].get(rule_type, "")
        investigation_prompt = format_investigation_prompt(
            user_prompt=prompt,
            rule_type=rule_type,
            metadata_yaml=metadata_yaml,
            detection_yaml=detection_yaml,
            investigation_template=investigation_template,
            current_rule=current_rule,
            prompt_type=prompt_type
        )
        investigation_response = investigation_model.invoke([("user", investigation_prompt)])
        investigation_yaml = investigation_response.content.strip()
        
        # === PLAYBOOK GENERATION ===
        playbook_model_name = STAGE_LLM_CONFIG["playbook"]
        playbook_model = init_llm_model(playbook_model_name)
        playbook_template = RULE_TEMPLATES["sections"]["playbook"].get(rule_type, "")
        playbook_prompt = format_playbook_prompt(
            user_prompt=prompt,
            rule_type=rule_type,
            metadata_yaml=metadata_yaml,
            detection_yaml=detection_yaml,
            investigation_yaml=investigation_yaml,
            playbook_template=playbook_template,
            current_rule=current_rule,
            prompt_type=prompt_type
        )
        playbook_response = playbook_model.invoke([("user", playbook_prompt)])
        playbook_yaml = playbook_response.content.strip()

        # === CONCATENATE FINAL RULE ===
        final_yaml = f"\n{metadata_yaml}\n\n{detection_yaml}\n\n{investigation_yaml}\n\n{playbook_yaml}"
        print(final_yaml)
        return final_yaml

    async def _handle_conversation(self, prompt: str, additional_params: Dict[str, Any]) -> str:
        """Handle general conversation with chat history context"""
        conversational_model = init_llm_model(self.conversational_llm_name)
        
        # Build conversation context
        messages = [("system", self.conversational_system_prompt)]
        
        # Add recent chat history for context (excluding the current prompt we just added)
        for msg in self.chat_history[:-1]:  # Exclude the last message (current prompt)
            if msg["role"] == "user":
                messages.append(("user", msg["content"]))
            else:
                messages.append(("assistant", msg["content"]))
        
        # Add the current prompt as the final user message
        messages.append(("user", prompt))
        
        response = conversational_model.invoke(messages)
        return response.content.strip()

    async def stream(self, prompt: str = "", additional_params: Dict[str, Any] = None) -> AsyncGenerator[str, None]:
        """
        Stream response chunks from the Detection and Response Engineer agent.
        """
        additional_params = additional_params or {}
        
        # Extract user prompt from chat_history if available, fallback to prompt parameter
        user_prompt = self._extract_user_prompt_from_chat_history(additional_params, prompt)
        if not user_prompt:
            yield "No user message found to process."
            return
        
        # Add user prompt to chat history
        self.chat_history.append({"role": "user", "content": user_prompt})
        
        # Always classify intent first
        wants_rule = classify_intent_for_rule_generation(user_prompt)
        
        if wants_rule:
            # Rule generation mode - use provided rule_type or default to query
            if not additional_params.get("rule_type"):
                additional_params["rule_type"] = "query"
            async for chunk in self._stream_rule_generation(user_prompt, additional_params):
                yield chunk
        else:
            # Stream conversation
            async for chunk in self._stream_conversation(user_prompt, additional_params):
                yield chunk

    async def _stream_rule_generation(self, prompt: str, additional_params: Dict[str, Any]) -> AsyncGenerator[str, None]:
        """Stream the rule generation process"""
        rule_type = additional_params.get("rule_type", "query")
        current_rule = additional_params.get("current_rule", "")
        prompt_type = additional_params.get("prompt_type", "create")
        chunk_size = 100
        
        # Send YAML document start marker
        yield "```yaml\n"
        await asyncio.sleep(0.1)
        
        # === METADATA GENERATION ===
        metadata_model_name = STAGE_LLM_CONFIG["metadata"]
        metadata_model = init_llm_model(metadata_model_name)
        metadata_prompt = format_metadata_prompt(prompt, current_rule, prompt_type)
        metadata_response = metadata_model.invoke([("user", metadata_prompt)])
        metadata_yaml = metadata_response.content.strip()
        
        # Stream metadata in chunks
        for i in range(0, len(metadata_yaml), chunk_size):
            yield metadata_yaml[i:i + chunk_size]
            await asyncio.sleep(0.1)
        
        # Add a separator between sections
        yield "\n\n"
        await asyncio.sleep(0.1)
        
        # === DETECTION GENERATION ===
        detection_model_name = STAGE_LLM_CONFIG["detection"]
        detection_model = init_llm_model(detection_model_name)
        detection_template = RULE_TEMPLATES["sections"]["detection"].get(rule_type, "")
        detection_prompt = format_detection_prompt(
            user_prompt=prompt,
            rule_type=rule_type,
            metadata_yaml=metadata_yaml,
            detection_template=detection_template,
            current_rule=current_rule,
            prompt_type=prompt_type
        )
        detection_response = detection_model.invoke([("user", detection_prompt)])
        detection_yaml = detection_response.content.strip()
        
        # Stream detection in chunks
        for i in range(0, len(detection_yaml), chunk_size):
            yield detection_yaml[i:i + chunk_size]
            await asyncio.sleep(0.1)
        
        # Add a separator between sections
        yield "\n\n"
        await asyncio.sleep(0.1)
        
        # === INVESTIGATION GENERATION ===
        investigation_model_name = STAGE_LLM_CONFIG["investigation"]
        investigation_model = init_llm_model(investigation_model_name)
        investigation_template = RULE_TEMPLATES["sections"]["investigation"].get(rule_type, "")
        investigation_prompt = format_investigation_prompt(
            user_prompt=prompt,
            rule_type=rule_type,
            metadata_yaml=metadata_yaml,
            detection_yaml=detection_yaml,
            investigation_template=investigation_template,
            current_rule=current_rule,
            prompt_type=prompt_type
        )
        investigation_response = investigation_model.invoke([("user", investigation_prompt)])
        investigation_yaml = investigation_response.content.strip()
        
        # Stream investigation in chunks
        for i in range(0, len(investigation_yaml), chunk_size):
            yield investigation_yaml[i:i + chunk_size]
            await asyncio.sleep(0.1)
        
        # Add a separator between sections
        yield "\n\n"
        await asyncio.sleep(0.1)
        
        # === PLAYBOOK GENERATION ===
        playbook_model_name = STAGE_LLM_CONFIG["playbook"]
        playbook_model = init_llm_model(playbook_model_name)
        playbook_template = RULE_TEMPLATES["sections"]["playbook"].get(rule_type, "")
        playbook_prompt = format_playbook_prompt(
            user_prompt=prompt,
            rule_type=rule_type,
            metadata_yaml=metadata_yaml,
            detection_yaml=detection_yaml,
            investigation_yaml=investigation_yaml,
            playbook_template=playbook_template,
            current_rule=current_rule,
            prompt_type=prompt_type
        )
        playbook_response = playbook_model.invoke([("user", playbook_prompt)])
        playbook_yaml = playbook_response.content.strip()
        
        # Stream playbook in chunks
        for i in range(0, len(playbook_yaml), chunk_size):
            yield playbook_yaml[i:i + chunk_size]
            await asyncio.sleep(0.1)
            
        yield "\n```"
        
        # Build the complete rule for chat history
        final_yaml = f"{metadata_yaml}\n\n{detection_yaml}\n\n{investigation_yaml}\n\n{playbook_yaml}"
        complete_response = f"I created a detection rule for credential dumping. Here's what was generated:\n\n```yaml\n{final_yaml}\n```"
        
        # Update chat history with the complete response including the rule content
        self.chat_history.append({"role": "assistant", "content": complete_response})
        
        # Keep chat history manageable
        if len(self.chat_history) > 20:
            self.chat_history = self.chat_history[-20:]

    async def _stream_conversation(self, prompt: str, additional_params: Dict[str, Any]) -> AsyncGenerator[str, None]:
        """Stream general conversation responses"""
        conversational_model = init_llm_model(self.conversational_llm_name)
        
        # Build conversation context
        messages = [("system", self.conversational_system_prompt)]
        
        # Add recent chat history for context (excluding the current prompt we just added)
        for msg in self.chat_history[:-1]:  # Exclude the last message (current prompt)
            if msg["role"] == "user":
                messages.append(("user", msg["content"]))
            else:
                messages.append(("assistant", msg["content"]))
        
        # Add the current prompt as the final user message
        messages.append(("user", prompt))
        
        # Stream the response
        response = ""
        async for chunk in conversational_model.astream(messages):
            if hasattr(chunk, 'content') and chunk.content:
                response += chunk.content
                yield chunk.content
                await asyncio.sleep(0.05)
        
        # Add the complete response to chat history
        self.chat_history.append({"role": "assistant", "content": response})
        
        # Keep chat history manageable
        if len(self.chat_history) > 20:
            self.chat_history = self.chat_history[-20:]

    def clear_chat_history(self):
        """Clear the chat history"""
        self.chat_history = []
        print("💬 Chat history cleared.")

    def _extract_user_prompt_from_chat_history(self, additional_params: Dict[str, Any], fallback_prompt: str = "") -> str:
        """
        Extract the last user message from history in additional_params.
        
        Args:
            additional_params: Dictionary that may contain history
            fallback_prompt: Fallback prompt if no history found
            
        Returns:
            User prompt string or empty string if not found
        """
        # Check if history exists in additional_params
        chat_history = additional_params.get("history", [])
        
        if chat_history and isinstance(chat_history, list):
            # Find the last user message
            for message in reversed(chat_history):
                if isinstance(message, dict) and message.get("role") == "user":
                    return message.get("content", "")
        
        # Fallback to the prompt parameter if no history or no user message found
        return fallback_prompt

    def get_capabilities(self) -> Dict[str, Any]:
        return {
            "role": "Detection and Response Engineer",
            "conversational": True,
            "rule_generation": True,
            "chat_history": True,
            "rule_types": [
                "query",
                "code", 
                "lucene_spark",
                "threat_match",
                "source_monitor", 
                "advanced_threshold"
            ],
            "streaming": True,
            "max_tokens": 8000,
            "chat_history_length": len(self.chat_history)
        }


class L1SOCAnalyst(BaseAgent):

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.name = "L1SOCAnalyst"
        self.version = "0.0.1"
        self.llm_model_name = "models/gemini-2.5-flash-preview-05-20" 
        
        # Add standard tools
        self.available_tools = [
            websearch, 
            websearch_threat, 
            virustotal_lookup,
            url_content_analysis,
            thehive_get_case,
            thehive_create_case,
            thehive_update_case,
            thehive_add_observable,
            thehive_create_task,
            thehive_flag_case
        ]
        
        self.agent_config = {"recursion_limit": 80}
        
        # Load the L1SOC analyst system prompt
        personas_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "agents", "prompts")
        l1_analyst_file = os.path.join(personas_dir, "L1analyst.md")
        
        # Read the system prompt from file
        with open(l1_analyst_file, "r", encoding="utf-8") as f:
            self.system_prompt = f.read()

    async def process(self, prompt: str, additional_params: Dict[str, Any] = None) -> str:
        additional_params = additional_params or {}
        
        # Print processing information
        print(f"Processing request with L1SOCAnalyst")
        
        # Initialize model and agent
        model = init_llm_model(self.llm_model_name)
        agent = create_react_agent(model, tools=self.available_tools, prompt=self.system_prompt)
        
        # Prepare additional context if provided
        context_prompt = ""
        if additional_params:
            context_params = additional_params
            if context_params:
                context_prompt = f"\n\nAdditional Context:\n{dict_to_llm_text(context_params)}\n\n"

        # For security alerts, add explicit instruction to create a case
        if "alert" in prompt.lower() or "incident" in prompt.lower() or "malware" in prompt.lower():
            context_prompt += "\nThis appears to be a security alert. Please follow the complete investigation workflow and document your findings thoroughly.\n"

        # Combine prompt with context
        prepared_prompt = f"{context_prompt}{prompt}"

        # Invoke the agent
        inputs = {"messages": [("user", prepared_prompt)]}
        response = agent.invoke(inputs, config=self.agent_config)

        return response['messages'][-1].content

    async def stream(self, prompt: str, additional_params: Dict[str, Any] = None) -> AsyncGenerator[str, None]:
        """
        Stream response chunks from the SOC analyst agent.
        """
        params = additional_params or {}

        final_response = await self.process(prompt, params)
        chunk_size = 100

        # Yield in chunks
        for i in range(0, len(final_response), chunk_size):
            yield final_response[i:i + chunk_size]
            await asyncio.sleep(0.1)
    
    def get_capabilities(self) -> Dict[str, Any]:
        return {
            "role": "SOC L1 Analyst",
            "tools": self.available_tools,
            "streaming": False,
            "max_tokens": 4000
        }


class AvicennaIAgent(BaseAgent):
    """
    AvicennaI main reasoning agent implementation.
    This agent specializes in handling complex reasoning tasks.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the AvicennaI agent.
        
        Args:
            config: Configuration for the agent
        """
        super().__init__(config)
        self.name = "avicennai"
        self.version = "1.0.0"
        self.tools = self._initialize_tools()
        
    def _initialize_tools(self) -> List[Dict[str, Any]]:
        """
        Initialize tools available to the agent.
        
        Returns:
            List of tool configurations
        """
        return [
            {
                "name": "search",
                "description": "Search for information on the web",
                "parameters": {
                    "query": "The search query"
                }
            },
            {
                "name": "calculator",
                "description": "Perform mathematical calculations",
                "parameters": {
                    "expression": "The mathematical expression to evaluate"
                }
            }
        ]
    
    async def process(self, prompt: str, additional_params: Dict[str, Any] = None) -> str:
        """
        Process a prompt with the AvicennaI agent.
        
        Args:
            prompt: The prompt to process
            additional_params: Additional parameters for processing
            
        Returns:
            The agent's response
        """
        params = additional_params or {}
        
        # In a real implementation, you would:
        # 1. Prepare the prompt with system instructions
        # 2. Call an LLM with appropriate tools
        # 3. Parse and execute tool calls
        # 4. Return the final response
        
        # This is a placeholder implementation
        use_tools = params.get("use_tools", True)
        max_iterations = params.get("max_iterations", 3)
        
        # Simulate agent reasoning process
        thinking = self._generate_thinking(prompt)
        
        if use_tools:
            # Simulate tool usage
            tool_results = self._simulate_tool_usage(prompt, max_iterations)
            final_response = f"After analyzing your request: '{prompt[:30]}...', I found the following: {tool_results}"
        else:
            final_response = f"I've considered your request: '{prompt[:30]}...'. {thinking}"
        
        return final_response
    
    async def stream(self, prompt: str, additional_params: Dict[str, Any] = None) -> AsyncGenerator[str, None]:
        """
        Process a prompt with the AvicennaI agent and stream the response.
        This function must be properly implemented as an async generator.
        
        Args:
            prompt: The prompt to process
            additional_params: Additional parameters for processing
            
        Yields:
            Chunks of the agent's response
        """
        params = additional_params or {}
        use_tools = params.get("use_tools", True)
        
        # First chunk
        yield "Analyzing your request...\n\n"
        await asyncio.sleep(0.5)  # Small delay
        
        if use_tools:
            # Second chunk
            yield "I'll need to use some tools to answer this effectively.\n"
            await asyncio.sleep(0.5)
            
            # Subsequent chunks with steps
            steps = [
                "First, I need to understand the core of your question.",
                "Let me search for some relevant information.",
                "Processing search results...",
                "Applying reasoning to compile the answer.",
                "Here's what I found:"
            ]
            
            for step in steps:
                yield f"{step}\n"
                await asyncio.sleep(0.5)
            
            # Final response chunks
            yield f"Based on my analysis of '{prompt[:30]}...', I determined that: "
            await asyncio.sleep(0.3)
            
            conclusion = self._generate_thinking(prompt)
            chunk_size = 20
            for i in range(0, len(conclusion), chunk_size):
                yield conclusion[i:i+chunk_size]
                await asyncio.sleep(0.1)
        else:
            # Direct response chunks
            response = await self.process(prompt, additional_params)
            chunk_size = 15
            for i in range(0, len(response), chunk_size):
                yield response[i:i+chunk_size]
                await asyncio.sleep(0.1)
    
    def get_capabilities(self) -> Dict[str, Any]:
        """
        Get capabilities of the AvicennaI agent.
        
        Returns:
            Dictionary of capabilities
        """
        return {
            "reasoning": True,
            "tools": [tool["name"] for tool in self.tools],
            "contexts_supported": ["general", "academic", "research"],
            "streaming": True,
            "max_tokens": 4000
        }
    
    def _generate_thinking(self, prompt: str) -> str:
        """
        Generate simulated thinking for the agent.
        In a real implementation, this would be generated by an LLM.
        
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
    
    def _simulate_tool_usage(self, prompt: str, max_iterations: int) -> str:
        """
        Simulate tool usage by the agent.
        In a real implementation, this would actually call external tools or APIs.
        
        Args:
            prompt: The prompt that might trigger tool usage
            max_iterations: Maximum number of tool calls to simulate
            
        Returns:
            Simulated tool results
        """
        # This is just a placeholder simulation
        if "calculate" in prompt.lower() or "math" in prompt.lower():
            return "The calculation result is 42."
        elif "find" in prompt.lower() or "search" in prompt.lower():
            return "I found several relevant resources that address your query."
        else:
            return "Based on my analysis, I've compiled comprehensive information to answer your question."