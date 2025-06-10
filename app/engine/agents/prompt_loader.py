import os
from typing import Dict, Any, Optional

def get_prompt_path(prompt_name: str) -> str:
    """
    Get the full path to a prompt file.
    
    Args:
        prompt_name: Name of the prompt file without .md extension
        
    Returns:
        Full path to the prompt file
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    prompts_dir = os.path.join(base_dir, "prompts")
    return os.path.join(prompts_dir, f"{prompt_name}.md")

def load_prompt(prompt_name: str) -> str:
    """
    Load a prompt from a file.
    
    Args:
        prompt_name: Name of the prompt file without .md extension
        
    Returns:
        Content of the prompt file
    """
    prompt_path = get_prompt_path(prompt_name)
    with open(prompt_path, "r", encoding="utf-8") as f:
        return f.read()

def load_metadata_prompt() -> str:
    """Load the metadata section prompt template."""
    return load_prompt("detection_metadata")

def load_detection_prompt() -> str:
    """Load the detection section prompt template."""
    return load_prompt("detection_section")

def load_investigation_prompt() -> str:
    """Load the investigation section prompt template."""
    return load_prompt("investigation_section")

def load_playbook_prompt() -> str:
    """Load the playbook section prompt template."""
    return load_prompt("playbook_section")

def format_metadata_prompt(user_prompt: str) -> str:
    """
    Format the metadata prompt with user input.
    
    Args:
        user_prompt: User's request for rule generation
        
    Returns:
        Formatted metadata prompt
    """
    template = load_metadata_prompt()
    return template.replace("{{user_prompt}}", user_prompt)

def format_detection_prompt(
    user_prompt: str, 
    rule_type: str, 
    metadata_yaml: Optional[str] = None,
    detection_template: Optional[str] = None
) -> str:
    """
    Format the detection prompt with user input and context.
    
    Args:
        user_prompt: User's request for rule generation
        rule_type: Type of detection rule
        metadata_yaml: Generated metadata YAML (optional)
        detection_template: Template for the detection section (optional)
        
    Returns:
        Formatted detection prompt
    """
    template = load_detection_prompt()
    
    # Replace placeholders
    prompt = template.replace("{{user_prompt}}", user_prompt)
    prompt = prompt.replace("{{rule_type}}", rule_type)
    
    # Add metadata block if provided
    metadata_block = ""
    if metadata_yaml:
        metadata_block = f"""
### EXISTING METADATA
Use this metadata to inform your detection logic:
{metadata_yaml}
"""
    prompt = prompt.replace("{{metadata_block}}", metadata_block)
    
    # Add detection template if provided
    if detection_template:
        prompt = prompt.replace("{{detection_template}}", detection_template)
    else:
        prompt = prompt.replace("{{detection_template}}", "")
    
    return prompt

def format_investigation_prompt(
    user_prompt: str, 
    rule_type: str, 
    metadata_yaml: Optional[str] = None, 
    detection_yaml: Optional[str] = None,
    investigation_template: Optional[str] = None
) -> str:
    """
    Format the investigation prompt with user input and context.
    
    Args:
        user_prompt: User's request for rule generation
        rule_type: Type of detection rule
        metadata_yaml: Generated metadata YAML (optional)
        detection_yaml: Generated detection YAML (optional)
        investigation_template: Template for the investigation section (optional)
        
    Returns:
        Formatted investigation prompt
    """
    template = load_investigation_prompt()
    
    # Replace placeholders
    prompt = template.replace("{{user_prompt}}", user_prompt)
    prompt = prompt.replace("{{rule_type}}", rule_type)
    
    # Build context block
    context_block = ""
    if metadata_yaml:
        context_block += f"""
### EXISTING METADATA
Use this metadata to inform your investigation logic:
{metadata_yaml}
"""
    
    if detection_yaml:
        context_block += f"""
### EXISTING DETECTION
Use this detection section to inform your investigation logic:
{detection_yaml}
"""
    
    prompt = prompt.replace("{{context_block}}", context_block)
    
    # Add investigation template if provided
    if investigation_template:
        prompt = prompt.replace("{{investigation_template}}", investigation_template)
    else:
        prompt = prompt.replace("{{investigation_template}}", "")
    
    return prompt

def format_playbook_prompt(
    user_prompt: str, 
    rule_type: str, 
    metadata_yaml: Optional[str] = None, 
    detection_yaml: Optional[str] = None,
    investigation_yaml: Optional[str] = None,
    playbook_template: Optional[str] = None
) -> str:
    """
    Format the playbook prompt with user input and context.
    
    Args:
        user_prompt: User's request for rule generation
        rule_type: Type of detection rule
        metadata_yaml: Generated metadata YAML (optional)
        detection_yaml: Generated detection YAML (optional)
        investigation_yaml: Generated investigation YAML (optional)
        playbook_template: Template for the playbook section (optional)
        
    Returns:
        Formatted playbook prompt
    """
    template = load_playbook_prompt()
    
    # Replace placeholders
    prompt = template.replace("{{user_prompt}}", user_prompt)
    prompt = prompt.replace("{{rule_type}}", rule_type)
    
    # Build context block
    context_block = ""
    if metadata_yaml:
        context_block += f"""
### EXISTING METADATA
Use this metadata to inform your playbook actions:
{metadata_yaml}
"""
    
    if detection_yaml:
        context_block += f"""
### EXISTING DETECTION
Use this detection section to inform your playbook actions:
{detection_yaml}
"""
    
    if investigation_yaml:
        context_block += f"""
### EXISTING INVESTIGATIONS
Use these investigations to inform your playbook actions:
{investigation_yaml}
"""
    
    prompt = prompt.replace("{{context_block}}", context_block)
    
    # Add playbook template if provided
    if playbook_template:
        prompt = prompt.replace("{{playbook_template}}", playbook_template)
    else:
        prompt = prompt.replace("{{playbook_template}}", "")
    
    return prompt 