from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI
from app.engine.agents.config import agent_config
import logging



def init_llm_model(model_name="models/gemini-2.5-flash-preview-05-20", temperature=0):

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