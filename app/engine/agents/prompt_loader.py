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

def format_metadata_prompt(user_prompt: str, current_rule: str = "", prompt_type: str = "create") -> str:
    """
    Format the metadata prompt with user input and context.
    
    Args:
        user_prompt: User's request for rule generation
        current_rule: Existing rule YAML (for updates)
        prompt_type: Either 'create' or 'update'
        
    Returns:
        Formatted metadata prompt
    """
    template = load_metadata_prompt()
    prompt = template.replace("{{user_prompt}}", user_prompt)
    
    # Build current rule context block
    current_rule_block = ""
    if prompt_type == "update" and current_rule:
        current_rule_block = f"""
### CURRENT RULE
You are UPDATING an existing rule. Here is the current complete rule:

```yaml
{current_rule}
```

**CRITICAL INSTRUCTIONS FOR UPDATES:**
- ONLY modify the metadata section IF the user's request specifically mentions metadata fields (title, description, severity, tags, author, etc.)
- If the user's request does NOT mention metadata changes, you MUST generate the metadata section EXACTLY as it appears in the current rule above
- DO NOT change the title, description, UUID, capabilities, or any other metadata fields unless explicitly requested
- DO NOT make assumptions about what needs to be changed - only change what the user specifically asks for
- Preserve all existing field values, formatting, and structure
"""
    elif prompt_type == "create":
        current_rule_block = """
### TASK
You are CREATING a new detection rule metadata section from scratch.
"""
    
    prompt = prompt.replace("{{current_rule_block}}", current_rule_block)
    return prompt

def format_detection_prompt(
    user_prompt: str, 
    rule_type: str, 
    metadata_yaml: Optional[str] = None,
    detection_template: Optional[str] = None,
    current_rule: str = "",
    prompt_type: str = "create"
) -> str:
    """
    Format the detection prompt with user input and context.
    
    Args:
        user_prompt: User's request for rule generation
        rule_type: Type of detection rule
        metadata_yaml: Generated metadata YAML (optional)
        detection_template: Template for the detection section (optional)
        current_rule: Existing rule YAML (for updates)
        prompt_type: Either 'create' or 'update'
        
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
    
    # Build current rule context block
    current_rule_block = ""
    if prompt_type == "update" and current_rule:
        current_rule_block = f"""
### CURRENT RULE
You are UPDATING an existing rule. Here is the current complete rule:

```yaml
{current_rule}
```

**CRITICAL INSTRUCTIONS FOR UPDATES:**
- ONLY modify the detection section IF the user's request specifically mentions detection fields (query, frequency, indices, exclusions, etc.)
- If the user's request does NOT mention detection changes, you MUST generate the detection section EXACTLY as it appears in the current rule above
- When adding exclusions: PRESERVE the existing query, frequency, indices, and all other detection fields - only ADD the exclusions section
- When modifying query: PRESERVE all other fields (frequency, indices, lifetime, etc.) unless specifically requested to change them
- DO NOT change field values, formatting, or structure unless explicitly requested
- Focus ONLY on the detection section - other sections are handled separately
"""
    elif prompt_type == "create":
        current_rule_block = """
### TASK
You are CREATING a new detection section from scratch.
"""
    
    prompt = prompt.replace("{{current_rule_block}}", current_rule_block)
    
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
    investigation_template: Optional[str] = None,
    current_rule: str = "",
    prompt_type: str = "create"
) -> str:
    """
    Format the investigation prompt with user input and context.
    
    Args:
        user_prompt: User's request for rule generation
        rule_type: Type of detection rule
        metadata_yaml: Generated metadata YAML (optional)
        detection_yaml: Generated detection YAML (optional)
        investigation_template: Template for the investigation section (optional)
        current_rule: Existing rule YAML (for updates)
        prompt_type: Either 'create' or 'update'
        
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
    
    # Build current rule context block
    current_rule_block = ""
    if prompt_type == "update" and current_rule:
        current_rule_block = f"""
### CURRENT RULE
You are UPDATING an existing rule. Here is the current complete rule:

```yaml
{current_rule}
```

**CRITICAL INSTRUCTIONS FOR UPDATES:**
- ONLY modify the investigation section IF the user's request specifically mentions investigation changes (new queries, different context, modified descriptions)
- If the user's request does NOT mention investigation changes, you MUST generate the investigation section EXACTLY as it appears in the current rule above
- DO NOT change investigation names, queries, descriptions, or any other investigation fields unless explicitly requested
- DO NOT add new investigations unless specifically requested
- DO NOT modify existing investigations unless specifically requested
- Preserve all existing field values, formatting, and structure exactly as shown in the current rule
- Focus ONLY on the investigation section - other sections are handled separately
"""
    elif prompt_type == "create":
        current_rule_block = """
### TASK
You are CREATING a new investigation section from scratch.
"""
    
    context_block += current_rule_block
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
    playbook_template: Optional[str] = None,
    current_rule: str = "",
    prompt_type: str = "create"
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
        current_rule: Existing rule YAML (for updates)
        prompt_type: Either 'create' or 'update'
        
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
    
    # Build current rule context block
    current_rule_block = ""
    if prompt_type == "update" and current_rule:
        current_rule_block = f"""
### CURRENT RULE
You are UPDATING an existing rule. Here is the current complete rule:

```yaml
{current_rule}
```

**CRITICAL INSTRUCTIONS FOR UPDATES:**
- ONLY modify the playbook section IF the user's request specifically mentions playbook changes (new actions, different notifications, modified tickets)
- If the user's request does NOT mention playbook changes, you MUST generate the playbook section EXACTLY as it appears in the current rule above
- DO NOT change action names, types, parameters, or any other playbook fields unless explicitly requested
- DO NOT add new actions unless specifically requested
- DO NOT modify existing actions unless specifically requested  
- Preserve all existing field values, formatting, and structure exactly as shown in the current rule
- Focus ONLY on the playbook section - other sections are handled separately
"""
    elif prompt_type == "create":
        current_rule_block = """
### TASK
You are CREATING a new playbook section from scratch.
"""
    
    context_block += current_rule_block
    prompt = prompt.replace("{{context_block}}", context_block)
    
    # Add playbook template if provided
    if playbook_template:
        prompt = prompt.replace("{{playbook_template}}", playbook_template)
    else:
        prompt = prompt.replace("{{playbook_template}}", "")
    
    return prompt 