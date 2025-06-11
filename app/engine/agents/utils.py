from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI
from app.engine.agents.config import agent_config
import logging


def init_llm_model(model_name="models/gemini-2.5-flash-preview-05-20", temperature=0):
    """
    Initialize an LLM model based on the model name.
    
    Args:
        model_name: The name of the model to initialize
        temperature: Temperature setting for the model
        
    Returns:
        Initialized LLM model instance
    """
    try:
        if model_name == "llama-4.scout-17b":
            model = ChatOpenAI(
                base_url=agent_config.GROQ_BASE_URL,
                api_key=agent_config.GROQ_API_KEY,
                model="meta-llama/llama-4-scout-17b-16e-instruct",
                temperature=temperature
            )
            print("Using GROQ LLM model: llama-4.scout-17b")
            return model

        elif model_name == "models/gemini-2.5-flash-preview-05-20":
            model = ChatGoogleGenerativeAI(
                google_api_key=agent_config.GEMINI_API_KEY,
                model="models/gemini-2.5-flash-preview-05-20",
                temperature=temperature
            )
            print("Using Gemini LLM model: models/gemini-2.5-flash-preview-05-20")
            return model

        else:
            print(f"Unsupported model name: {model_name}")
            raise RuntimeError(f"Unsupported model name: {model_name}")

    except Exception as e:
        print(f"Error configuring LLM: {str(e)}")
        raise RuntimeError("Failed to configure LLM with both primary and fallback options")


def dict_to_llm_text(additional_params: dict) -> str:
    """
    Transforms a dictionary into a human-readable text representation suitable for LLMs.
    
    Args:
        additional_params: A dictionary of parameters with any types of values
        
    Returns:
        A string representation of the dictionary formatted for LLM consumption
    """
    result = []
    
    for key, value in additional_params.items():
        # Format the value based on its type
        if isinstance(value, str):
            formatted_value = f'"{value}"'
        elif isinstance(value, (list, tuple)):
            items = [f'"{item}"' if isinstance(item, str) else str(item) for item in value]
            formatted_value = f'[{", ".join(items)}]'
        elif isinstance(value, dict):
            # Handle nested dictionaries with proper formatting
            nested_items = []
            for k, v in value.items():
                if isinstance(v, str):
                    nested_items.append(f"{k}: \"{v}\"")
                elif isinstance(v, (list, tuple)):
                    items_str = []
                    for i in v:
                        if isinstance(i, str):
                            items_str.append(f'"{i}"')
                        else:
                            items_str.append(str(i))
                    nested_items.append(f"{k}: [{', '.join(items_str)}]")
                else:
                    nested_items.append(f"{k}: {v}")
            formatted_value = f"{{{', '.join(nested_items)}}}"
        elif value is None:
            formatted_value = 'None'
        else:
            formatted_value = str(value)
        
        result.append(f"{key}: {formatted_value}")
    
    return "\n".join(result)


def classify_intent_for_rule_generation(user_prompt: str) -> bool:
    """
    Simple intent classifier to determine if the user wants to generate a detection rule.
    
    Args:
        user_prompt: The user's input prompt
        
    Returns:
        bool: True if user wants rule generation, False for general conversation
    """
    try:
        # Use a fast, small model for intent classification
        classifier_model = init_llm_model("llama-4.scout-17b", temperature=0)
        
        classification_prompt = f"""You are an intent classifier for a cybersecurity detection engineering assistant.

Determine if the user wants to generate a detection rule or just have a general conversation.

User input: "{user_prompt}"

RULE GENERATION INDICATORS:
- Asking to create, generate, build, write, develop any detection rule
- Mentioning specific threats, IOCs, or attack patterns to detect
- Requesting detection for specific behaviors or activities

CONVERSATION INDICATORS:
- Greetings, general questions, clarifications, explanations
- Asking about cybersecurity concepts or methodologies
- Casual conversation or requests for information

EXAMPLES:
- "Hello" → conversation
- "What is MITRE ATT&CK?" → conversation  
- "Create a rule for detecting malware" → rule_generation
- "Generate detection for PowerShell attacks" → rule_generation
- "Can you explain what we just created?" → conversation
- "Build a rule to catch credential dumping" → rule_generation

Respond with ONLY ONE WORD: "rule_generation" or "conversation" """

        response = classifier_model.invoke([("user", classification_prompt)])
        result = response.content.strip().lower()
        
        # Return True if user wants rule generation
        if "rule_generation" in result:
            return True
        elif "conversation" in result:
            return False
        else:
            # Default to conversation mode if response is unclear
            return False
        
    except Exception as e:
        print(f"Error in intent classification: {str(e)}")
        # Default to conversation mode on error
        return False