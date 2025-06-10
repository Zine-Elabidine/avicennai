RULE_TEMPLATES = {
    # Complete templates (original structure maintained for backward compatibility)
    "complete": {
        "query": """title: [Descriptive name for your rule]
rule_id: [unique-identifier]
tdr: [optional-tracking-id]
severity: [low|medium|high|critical]
version: 1.0
effort_level: elementary
confidence: [low|medium|high]
maturity: [production|experimental|development]
enabled: true
learning_mode: false
capabilities:
  - [MITRE ATT&CK Technique or other categorization]
  - [Additional capability]
author: [Your Name]
creation_date: '[YYYY/MM/DD]'
updated_date: '[YYYY/MM/DD]'
description: |
  [Detailed description of what this rule detects, why it's important, 
  and any context that would help an analyst understand the alert]
references:
  - [URL to relevant documentation, research, or threat intel]
  - [Additional reference URL]
tags:
  - [relevant tag]
  - [additional tag]

# Detection Section
type: query
frequency: 15m
depth: 1h
timestamp_override: 'event.ingested'
integration: [windows|linux|fortinet|etc]
indices:
  - [index-pattern-1]
  - [index-pattern-2]
query: '[Lucene query to identify suspicious activity]'

# Optional Exclusions
exclusions:
  exclusion_1:
    query: '[Lucene query to exclude false positives]'
    date: YYYY/MM/DD
    note: '[Explanation for this exclusion]'
    author: [Your Name]

# Fields to group matches for deduplication
group_match:
  - [field1]
  - [field2]
lifetime: 1h

# Investigation Section
investigations:
  [investigation_name]:
    type: query
    query: '[Investigation query with {{ hit_context["field"] }}]'
    description: "[Description of what this investigation provides]"
    per_hit_description: "[Template for each result with {{ investigation['hit']['field'] }}]"
    fallback: "[Message when no results are found]"
    depth: 1h
    indices:
      - [index-pattern]
    group_match:
      - [field1]
      - [field2]

# Playbook Section
playbook:
  - name: [action_name]
    type: [thehive_soc|processor|email_html|signal]
    params:
      title: "[Alert title with {{ hit_context['field'] }}]"
      description: |
        [Detailed description with {{ hit_context['field'] }} 
        and {{ investigations['investigation_name']['report'] }}]
      [additional_params]: [values]
    mode: single""",
        
        "advanced_threshold": """title: [Descriptive name for your rule]
rule_id: [unique-identifier]
tdr: [optional-tracking-id]
severity: [low|medium|high|critical]
version: 1.0
effort_level: elementary
confidence: [low|medium|high]
maturity: [production|experimental|development]
enabled: true
learning_mode: false
capabilities:
  - [MITRE ATT&CK Technique or other categorization]
  - [Additional capability]
author: [Your Name]
creation_date: '[YYYY/MM/DD]'
updated_date: '[YYYY/MM/DD]'
description: |
  [Detailed description of the behavioral anomaly this rule detects, 
  including what thresholds are considered suspicious and why]
references:
  - [URL to relevant documentation, research, or threat intel]
  - [Additional reference URL]
tags:
  - [relevant tag]
  - [additional tag]

# Detection Section
type: advanced_threshold
frequency: 15m
depth: 15m
timestamp_override: 'event.ingested'
integration: [windows|linux|fortinet|etc]
indices:
  - [index-pattern-1]
  - [index-pattern-2]
query: '[Base Lucene query to filter relevant events]'

# Aggregation Configuration
aggregation:
  terms:
    field: [primary_grouping_field]
    cardinality:
      field: [field_to_count_unique_values]
      threshold: [numeric_threshold]

# Optional for Nested Terms
#    terms:
#      field: [secondary_grouping_field]
#      cardinality:
#        field: [field_to_count_unique_values]
#        threshold: [numeric_threshold]

# Optional Exclusions
exclusions:
  exclusion_1:
    query: '[Lucene query to exclude false positives]'
    date: YYYY/MM/DD
    note: '[Explanation for this exclusion]'
    author: [Your Name]

lifetime: 4h

# Investigation Section
investigations:
  [investigation_name]:
    type: query
    query: '[Investigation query with {{ hit_context["field"] }}]'
    description: "[Description of what this investigation provides]"
    per_hit_description: "[Template for each result with {{ investigation['hit']['field'] }}]"
    fallback: "[Message when no results are found]"
    depth: 1h
    indices:
      - [index-pattern]
    group_match:
      - [field1]
      - [field2]

# Playbook Section
playbook:
  - name: count_of_hits
    type: processor
    params:
      type: count
    mode: group

  - name: [action_name]
    type: [thehive_soc|processor|email_html|signal]
    params:
      title: "[Alert title with {{ hit_context['field'] }}]"
      description: |
        [Detailed description with {{ hit_context['field'] }} 
        and {{ investigations['investigation_name']['report'] }}]
      [additional_params]: [values]
    mode: [single|group]
    if: "[Optional condition for execution]" """,
        
        "source_monitor": """title: [Missing data source name]
rule_id: [unique-identifier]
severity: [low|medium|high|critical]
version: 1.0
effort_level: elementary
confidence: [low|medium|high]
maturity: [production|experimental|development]
enabled: true
learning_mode: false
capabilities:
  - [Capability category]
  - [Additional capability]
author: [Your Name]
creation_date: '[YYYY/MM/DD]'
updated_date: '[YYYY/MM/DD]'
description: |
  [Description of why this data source is important to monitor
  and what impact its absence might have]
references:
  - [URL to relevant documentation]
tags:
  - [relevant tag]
  - [additional tag]

# Detection Section
type: source_monitor
integration: [windows|linux|fortinet|etc]
frequency: 1h
depth: 1h
timestamp_override: 'event.ingested'
indices:
  - [index-pattern]
query: '[Base query to identify relevant events]'
source_file: '[Path to file listing expected sources]'
match_field: '[Field to match against sources list]'
lifetime: 12h

# Playbook Section
playbook:
  - name: count_of_hits
    type: processor
    params:
      type: count
    mode: group

  - name: notify_single_source
    type: [thehive_soc|email_html]
    params:
      title: "[Data source outage alert for {{ hit_context['match_field'] }}]"
      description: |
        [Detailed description of the outage with {{ hit_context['match_field'] }}]
      [additional_params]: [values]
    mode: single
    if: "{{g_playbook['count_of_hits']['value'] }} == 1"

  - name: notify_multiple_sources
    type: [thehive_soc|email_html]
    params:
      title: "[Multiple data source outages alert]"
      description: |
        [Description of multiple outages with
        {% for item in grouped_hits_context %}
          - {{ item.hit_context['match_field'] }}
        {% endfor %}]
      [additional_params]: [values]
    mode: group
    if: "{{g_playbook['count_of_hits']['value'] }} > 1" """,
        
        "threat_match": """title: Detection using IOC from [Source]
uuid: [unique-identifier]
version_uuid: [version-identifier]
severity: medium
version: 1.0
effort_level: elementary
confidence: high
maturity: production
enabled: true
learning_mode: false
capabilities:
  - Threat Detection
author: [Your Name]
creation_date: '[YYYY/MM/DD]'
updated_date: '[YYYY/MM/DD]'
description: Detect communication with known malicious [indicator type]
integration: 'TI'
threat_timestamp_override: event.ingested
note: '[Optional notes about the detection]'
false_positives: '[Known false positive scenarios]'
references:
  - [URL to threat intelligence source]
tags:
  - CTI
  - [Source name]

# Rule Configuration
type: threat_match
rule_type: threat_match
frequency: 60m
lifetime: 2h
threat_timestamp_override: ingest_timestamp

# Threat Intelligence Configuration
threat_indicator_indices: 
  - [threat-intel-index-pattern]
threat_indicator_query: "observable_type:[type] AND NOT observable_value:[exclusion-pattern]"
threat_indicator_depth: 14d
threat_indicator_group_match:
  - [threat_field_name]

# Event Source Configuration
indices:
  - [log-index-pattern]
query: "[field]:*"
group_match:
  - '[field]'
  - '[context_field]'
depth: 6d

# Field Mapping
threat_mapping_entries:
  - field: [threat_field_name]
    value: [event_field_name]

# Optional Exclusions
exclusions:
  exclusion_1:
    query: '[exclusion query]'
    date: YYYY/MM/DD
    note: '[reason for exclusion]'
    author: [author name]

# Investigations
investigations:
  additional_context:
    type: query
    query: [field]:{{hit_context['threat_context']['threat_field_name']}} AND [context_field]:{{hit_context['data_context']['context_field']}}
    description: "Additional context:"
    per_hit_description: "- {{ investigation['hit']['field'] }} from {{ investigation['hit']['context_field'] }}"
    fallback: "No additional context found."
    depth: 7d
    indices:
      - [log-index-pattern]
    group_match:
      - [field]

# Response Actions
playbook:
  - name: create_ticket
    type: thehive_soc
    params:
      title: "Threat Intelligence Match - {{hit_context['data_context']['context_field']}} to {{hit_context['threat_context']['threat_field_name']}}"
      description: |
        A potential threat has been detected where {{hit_context['data_context']['context_field']}} has communicated with {{hit_context['threat_context']['threat_field_name']}}, which is identified as malicious in our threat intelligence feeds.
        
        {{investigations['additional_context']['report']}}
        
        Recommended actions:
        1. Investigate the affected system
        2. Check for additional indicators of compromise
        3. Block communication with the malicious indicator if verified
      tlp: 3
      pap: 3
      severity: 2
      flag: False
      tags:
       - "XDR"
       - "CTI"
       - "[Source name]"
    mode: single""",
        
        "code": """title: Custom Detection Logic - [Detection Name]
uuid: [unique-identifier]
version_uuid: [version-identifier]
severity: medium
enabled: true
learning_mode: false
description: |
  This rule uses custom Python code to detect [description of what you're detecting].
  
  [Add any additional context about the detection logic]

# Rule Configuration
type: code
frequency: 15m
# Optional: Use cron syntax for scheduled execution
# cron: '0 */6 * * *'
lifetime: 30m

# Script Configuration
image: default_python
file: code/[script_filename].py
program: python
sha256: [script_hash]
data_sharing_method: shared_file

# Optional: Deduplication configuration
group_match:
  - [field1]
  - [field2]

# Optional: Parameters passed to the script
params:
  - name: threshold
    value: 5
  - name: time_window
    value: 300

# Data queries for the script
queries:
  auth_events:
    language: lucene
    description: 'Authentication events for analysis'
    query: event.category:authentication AND (event.outcome:success OR event.outcome:failure)
    depth: 1d
    indices:
      - [index-pattern]
    group_match:
      - user.name
      - host.name
  network_events:
    language: lucene
    description: 'Network connection events'
    query: event.category:network AND event.type:connection
    depth: 1d
    indices:
      - [index-pattern]
    group_match:
      - source.ip
      - destination.ip

# Investigations for additional context
investigations:
  user_context:
    type: query
    query: user.name:{{hit_context['user.name']}} AND event.category:authentication
    description: "Recent authentication activity for the user:"
    per_hit_description: "- {{ investigation['hit']['@timestamp'] }}: {{ investigation['hit']['event.action'] }} from {{ investigation['hit']['source.ip'] }}"
    fallback: "No recent authentication activity found."
    depth: 7d
    indices:
      - [index-pattern]
    group_match:
      - user.name

# Response Actions
playbook:
  - name: create_ticket
    type: thehive_soc
    params:
      title: "Custom Detection - {{hit_context['detection_name']}}"
      description: |
        A security event was detected by custom detection logic:
        
        {{hit_context['description']}}
        
        Details:
        - User: {{hit_context['user.name']}}
        - Host: {{hit_context['host.name']}}
        - Severity: {{hit_context['severity']}}
        
        Additional context:
        {{investigations['user_context']['report']}}
        
        Recommended actions:
        {{hit_context['recommendations']}}
      tlp: 3
      pap: 3
      severity: 2
      flag: False
      tags:
       - "XDR"
       - "Custom Detection"
    mode: single""",
        
        "lucene_spark": """title: Complex Event Correlation - [Correlation Name]
uuid: [unique-identifier]
version_uuid: [version-identifier]
severity: medium
enabled: true
learning_mode: false
description: |
  This rule correlates multiple event types to detect [description of pattern being detected].
  
  [Additional context about why this correlation is important]

# Rule Configuration
type: lucene_spark
frequency: 30m
lifetime: 5m

# Source Data Queries
source_queries:
  primary_events:
    query: [lucene query for first event type]
    depth: 24h
    indices:
      - [index-pattern]
  secondary_events:
    query: [lucene query for second event type]
    depth: 24h
    indices:
      - [index-pattern]
  # Add additional queries as needed
  tertiary_events:
    query: [lucene query for third event type]
    depth: 24h
    indices:
      - [index-pattern]

# Correlation Logic
spark_query: |
  WITH primary_data AS (
      SELECT 
          [fields],
          [calculated_fields]
      FROM primary_events_view
      WHERE [conditions]
      GROUP BY [grouping_fields]
  ),
  secondary_data AS (
      SELECT 
          [fields],
          [calculated_fields]
      FROM secondary_events_view
      WHERE [conditions]
  ),
  tertiary_data AS (
      SELECT 
          [fields],
          [calculated_fields]
      FROM tertiary_events_view
      WHERE [conditions]
  )
  SELECT 
      p.[field1] AS correlation_key,
      p.[field2] AS primary_value,
      s.[field3] AS secondary_value,
      t.[field4] AS tertiary_value,
      [calculated_fields]
  FROM primary_data p
  JOIN secondary_data s ON p.[join_field] = s.[join_field]
  JOIN tertiary_data t ON p.[join_field] = t.[join_field]
  WHERE [correlation_conditions]
      AND [time_window_conditions]
  GROUP BY [grouping_fields]
  ORDER BY [ordering_field];

# Investigations for additional context
investigations:
  primary_context:
    type: query
    query: [field]:{{hit_context['correlation_key']}} AND [additional_conditions]
    description: "Primary event details:"
    per_hit_description: "- {{ investigation['hit']['@timestamp'] }}: {{ investigation['hit']['event.action'] }}"
    fallback: "No additional details found."
    depth: 24h
    indices:
      - [index-pattern]
    group_match:
      - [field]
  
  secondary_context:
    type: query
    query: [field]:{{hit_context['correlation_key']}} AND [additional_conditions]
    description: "Secondary event details:"
    per_hit_description: "- {{ investigation['hit']['@timestamp'] }}: {{ investigation['hit']['event.action'] }}"
    fallback: "No additional details found."
    depth: 24h
    indices:
      - [index-pattern]
    group_match:
      - [field]

# Response Actions
playbook:
  - name: create_ticket
    type: thehive_soc
    params:
      title: "Correlated Activity - {{hit_context['correlation_key']}}"
      description: |
        A complex pattern of activity has been detected through event correlation:
        
        Key entity: {{hit_context['correlation_key']}}
        Primary indicator: {{hit_context['primary_value']}}
        Secondary indicator: {{hit_context['secondary_value']}}
        Tertiary indicator: {{hit_context['tertiary_value']}}
        
        This pattern may indicate [description of the security implication].
        
        Additional context:
        
        {{investigations['primary_context']['report']}}
        
        {{investigations['secondary_context']['report']}}
        
        Recommended actions:
        1. Investigate the activity related to {{hit_context['correlation_key']}}
        2. Determine if this is a legitimate pattern or potentially malicious
        3. [Additional recommendations]
      tlp: 3
      pap: 3
      severity: 2
      flag: False
      tags:
       - "XDR"
       - "Correlation"
       - "[Specific technique or tactic]"
    mode: single"""
    },
    
    # Section-specific templates
    "sections": {
        "metadata": {
            "query": """title: [Descriptive name for your rule]
rule_id: [unique-identifier]
tdr: [optional-tracking-id]
severity: [low|medium|high|critical]
version: 1.0
effort_level: elementary
confidence: [low|medium|high]
maturity: [production|experimental|development]
enabled: true
learning_mode: false
capabilities:
  - [MITRE ATT&CK Technique or other categorization]
  - [Additional capability]
author: [Your Name]
creation_date: '[YYYY/MM/DD]'
updated_date: '[YYYY/MM/DD]'
description: |
  [Detailed description of what this rule detects, why it's important, 
  and any context that would help an analyst understand the alert]
references:
  - [URL to relevant documentation, research, or threat intel]
  - [Additional reference URL]
tags:
  - [relevant tag]
  - [additional tag]""",
            
            "advanced_threshold": """title: [Descriptive name for your rule]
rule_id: [unique-identifier]
tdr: [optional-tracking-id]
severity: [low|medium|high|critical]
version: 1.0
effort_level: elementary
confidence: [low|medium|high]
maturity: [production|experimental|development]
enabled: true
learning_mode: false
capabilities:
  - [MITRE ATT&CK Technique or other categorization]
  - [Additional capability]
author: [Your Name]
creation_date: '[YYYY/MM/DD]'
updated_date: '[YYYY/MM/DD]'
description: |
  [Detailed description of the behavioral anomaly this rule detects, 
  including what thresholds are considered suspicious and why]
references:
  - [URL to relevant documentation, research, or threat intel]
  - [Additional reference URL]
tags:
  - [relevant tag]
  - [additional tag]""",
            
            "source_monitor": """title: [Missing data source name]
rule_id: [unique-identifier]
severity: [low|medium|high|critical]
version: 1.0
effort_level: elementary
confidence: [low|medium|high]
maturity: [production|experimental|development]
enabled: true
learning_mode: false
capabilities:
  - [Capability category]
  - [Additional capability]
author: [Your Name]
creation_date: '[YYYY/MM/DD]'
updated_date: '[YYYY/MM/DD]'
description: |
  [Description of why this data source is important to monitor
  and what impact its absence might have]
references:
  - [URL to relevant documentation]
tags:
  - [relevant tag]
  - [additional tag]""",
            
            "threat_match": """title: Detection using IOC from [Source]
uuid: [unique-identifier]
version_uuid: [version-identifier]
severity: medium
version: 1.0
effort_level: elementary
confidence: high
maturity: production
enabled: true
learning_mode: false
capabilities:
  - Threat Detection
author: [Your Name]
creation_date: '[YYYY/MM/DD]'
updated_date: '[YYYY/MM/DD]'
description: Detect communication with known malicious [indicator type]
integration: 'TI'
threat_timestamp_override: event.ingested
note: '[Optional notes about the detection]'
false_positives: '[Known false positive scenarios]'
references:
  - [URL to threat intelligence source]
tags:
  - CTI
  - [Source name]""",
            
            "code": """title: Custom Detection Logic - [Detection Name]
uuid: [unique-identifier]
version_uuid: [version-identifier]
severity: medium
enabled: true
learning_mode: false
description: |
  This rule uses custom Python code to detect [description of what you're detecting].
  
  [Add any additional context about the detection logic]""",
            
            "lucene_spark": """title: Complex Event Correlation - [Correlation Name]
uuid: [unique-identifier]
version_uuid: [version-identifier]
severity: medium
enabled: true
learning_mode: false
description: |
  This rule correlates multiple event types to detect [description of pattern being detected].
  
  [Additional context about why this correlation is important]"""
        },
        
        "detection": {
            "query": """# Detection Section
type: query
frequency: 15m
depth: 1h
timestamp_override: 'event.ingested'
integration: [windows|linux|fortinet|etc]
indices:
  - [index-pattern-1]
  - [index-pattern-2]
query: '[Lucene query to identify suspicious activity]'

# Optional Exclusions
exclusions:
  exclusion_1:
    query: '[Lucene query to exclude false positives]'
    date: YYYY/MM/DD
    note: '[Explanation for this exclusion]'
    author: [Your Name]

# Fields to group matches for deduplication
group_match:
  - [field1]
  - [field2]
lifetime: 1h""",
            
            "advanced_threshold": """# Detection Section
type: advanced_threshold
frequency: 15m
depth: 15m
timestamp_override: 'event.ingested'
integration: [windows|linux|fortinet|etc]
indices:
  - [index-pattern-1]
  - [index-pattern-2]
query: '[Base Lucene query to filter relevant events]'

# Aggregation Configuration
aggregation:
  terms:
    field: [primary_grouping_field]
    cardinality:
      field: [field_to_count_unique_values]
      threshold: [numeric_threshold]

# Optional for Nested Terms
#    terms:
#      field: [secondary_grouping_field]
#      cardinality:
#        field: [field_to_count_unique_values]
#        threshold: [numeric_threshold]

# Optional Exclusions
exclusions:
  exclusion_1:
    query: '[Lucene query to exclude false positives]'
    date: YYYY/MM/DD
    note: '[Explanation for this exclusion]'
    author: [Your Name]

lifetime: 4h""",
            
            "source_monitor": """# Detection Section
type: source_monitor
integration: [windows|linux|fortinet|etc]
frequency: 1h
depth: 1h
timestamp_override: 'event.ingested'
indices:
  - [index-pattern]
query: '[Base query to identify relevant events]'
source_file: '[Path to file listing expected sources]'
match_field: '[Field to match against sources list]'
lifetime: 12h""",
            
            "threat_match": """# Rule Configuration
type: threat_match
rule_type: threat_match
frequency: 60m
lifetime: 2h
threat_timestamp_override: ingest_timestamp

# Threat Intelligence Configuration
threat_indicator_indices: 
  - [threat-intel-index-pattern]
threat_indicator_query: "observable_type:[type] AND NOT observable_value:[exclusion-pattern]"
threat_indicator_depth: 14d
threat_indicator_group_match:
  - [threat_field_name]

# Event Source Configuration
indices:
  - [log-index-pattern]
query: "[field]:*"
group_match:
  - '[field]'
  - '[context_field]'
depth: 6d

# Field Mapping
threat_mapping_entries:
  - field: [threat_field_name]
    value: [event_field_name]

# Optional Exclusions
exclusions:
  exclusion_1:
    query: '[exclusion query]'
    date: YYYY/MM/DD
    note: '[reason for exclusion]'
    author: [author name]""",
            
            "code": """# Rule Configuration
type: code
frequency: 15m
# Optional: Use cron syntax for scheduled execution
# cron: '0 */6 * * *'
lifetime: 30m

# Script Configuration
image: default_python
file: code/[script_filename].py
program: python
sha256: [script_hash]
data_sharing_method: shared_file

# Optional: Deduplication configuration
group_match:
  - [field1]
  - [field2]

# Optional: Parameters passed to the script
params:
  - name: threshold
    value: 5
  - name: time_window
    value: 300

# Data queries for the script
queries:
  auth_events:
    language: lucene
    description: 'Authentication events for analysis'
    query: event.category:authentication AND (event.outcome:success OR event.outcome:failure)
    depth: 1d
    indices:
      - [index-pattern]
    group_match:
      - user.name
      - host.name
  network_events:
    language: lucene
    description: 'Network connection events'
    query: event.category:network AND event.type:connection
    depth: 1d
    indices:
      - [index-pattern]
    group_match:
      - source.ip
      - destination.ip""",
            
            "lucene_spark": """# Rule Configuration
type: lucene_spark
frequency: 30m
lifetime: 5m

# Source Data Queries
source_queries:
  primary_events:
    query: [lucene query for first event type]
    depth: 24h
    indices:
      - [index-pattern]
  secondary_events:
    query: [lucene query for second event type]
    depth: 24h
    indices:
      - [index-pattern]
  # Add additional queries as needed
  tertiary_events:
    query: [lucene query for third event type]
    depth: 24h
    indices:
      - [index-pattern]

# Correlation Logic
spark_query: |
  WITH primary_data AS (
      SELECT 
          [fields],
          [calculated_fields]
      FROM primary_events_view
      WHERE [conditions]
      GROUP BY [grouping_fields]
  ),
  secondary_data AS (
      SELECT 
          [fields],
          [calculated_fields]
      FROM secondary_events_view
      WHERE [conditions]
  ),
  tertiary_data AS (
      SELECT 
          [fields],
          [calculated_fields]
      FROM tertiary_events_view
      WHERE [conditions]
  )
  SELECT 
      p.[field1] AS correlation_key,
      p.[field2] AS primary_value,
      s.[field3] AS secondary_value,
      t.[field4] AS tertiary_value,
      [calculated_fields]
  FROM primary_data p
  JOIN secondary_data s ON p.[join_field] = s.[join_field]
  JOIN tertiary_data t ON p.[join_field] = t.[join_field]
  WHERE [correlation_conditions]
      AND [time_window_conditions]
  GROUP BY [grouping_fields]
  ORDER BY [ordering_field];"""
        },
        
        "investigation": {
            "query": """# Investigation Section
investigations:
  [investigation_name]:
    type: query
    query: '[Investigation query with {{ hit_context["field"] }}]'
    description: "[Description of what this investigation provides]"
    per_hit_description: "[Template for each result with {{ investigation['hit']['field'] }}]"
    fallback: "[Message when no results are found]"
    depth: 1h
    indices:
      - [index-pattern]
    group_match:
      - [field1]
      - [field2]""",
            
            "advanced_threshold": """# Investigation Section
investigations:
  [investigation_name]:
    type: query
    query: '[Investigation query with {{ hit_context["field"] }}]'
    description: "[Description of what this investigation provides]"
    per_hit_description: "[Template for each result with {{ investigation['hit']['field'] }}]"
    fallback: "[Message when no results are found]"
    depth: 1h
    indices:
      - [index-pattern]
    group_match:
      - [field1]
      - [field2]""",
            
            "source_monitor": """# Note: Source monitor rules typically don't have investigations section
# as they focus on data source availability rather than threat investigation""",
            
            "threat_match": """# Investigations
investigations:
  additional_context:
    type: query
    query: [field]:{{hit_context['threat_context']['threat_field_name']}} AND [context_field]:{{hit_context['data_context']['context_field']}}
    description: "Additional context:"
    per_hit_description: "- {{ investigation['hit']['field'] }} from {{ investigation['hit']['context_field'] }}"
    fallback: "No additional context found."
    depth: 7d
    indices:
      - [log-index-pattern]
    group_match:
      - [field]""",
            
            "code": """# Investigations for additional context
investigations:
  user_context:
    type: query
    query: user.name:{{hit_context['user.name']}} AND event.category:authentication
    description: "Recent authentication activity for the user:"
    per_hit_description: "- {{ investigation['hit']['@timestamp'] }}: {{ investigation['hit']['event.action'] }} from {{ investigation['hit']['source.ip'] }}"
    fallback: "No recent authentication activity found."
    depth: 7d
    indices:
      - [index-pattern]
    group_match:
      - user.name""",
            
            "lucene_spark": """# Investigations for additional context
investigations:
  primary_context:
    type: query
    query: [field]:{{hit_context['correlation_key']}} AND [additional_conditions]
    description: "Primary event details:"
    per_hit_description: "- {{ investigation['hit']['@timestamp'] }}: {{ investigation['hit']['event.action'] }}"
    fallback: "No additional details found."
    depth: 24h
    indices:
      - [index-pattern]
    group_match:
      - [field]
  
  secondary_context:
    type: query
    query: [field]:{{hit_context['correlation_key']}} AND [additional_conditions]
    description: "Secondary event details:"
    per_hit_description: "- {{ investigation['hit']['@timestamp'] }}: {{ investigation['hit']['event.action'] }}"
    fallback: "No additional details found."
    depth: 24h
    indices:
      - [index-pattern]
    group_match:
      - [field]"""
        },
        
        "playbook": {
            "query": """# Playbook Section
playbook:
  - name: [action_name]
    type: [thehive_soc|processor|email_html|signal]
    params:
      title: "[Alert title with {{ hit_context['field'] }}]"
      description: |
        [Detailed description with {{ hit_context['field'] }} 
        and {{ investigations['investigation_name']['report'] }}]
      [additional_params]: [values]
    mode: single""",
            
            "advanced_threshold": """# Playbook Section
playbook:
  - name: count_of_hits
    type: processor
    params:
      type: count
    mode: group

  - name: [action_name]
    type: [thehive_soc|processor|email_html|signal]
    params:
      title: "[Alert title with {{ hit_context['field'] }}]"
      description: |
        [Detailed description with {{ hit_context['field'] }} 
        and {{ investigations['investigation_name']['report'] }}]
      [additional_params]: [values]
    mode: [single|group]
    if: "[Optional condition for execution]" """,
            
            "source_monitor": """# Playbook Section
playbook:
  - name: count_of_hits
    type: processor
    params:
      type: count
    mode: group

  - name: notify_single_source
    type: [thehive_soc|email_html]
    params:
      title: "[Data source outage alert for {{ hit_context['match_field'] }}]"
      description: |
        [Detailed description of the outage with {{ hit_context['match_field'] }}]
      [additional_params]: [values]
    mode: single
    if: "{{g_playbook['count_of_hits']['value'] }} == 1"

  - name: notify_multiple_sources
    type: [thehive_soc|email_html]
    params:
      title: "[Multiple data source outages alert]"
      description: |
        [Description of multiple outages with
        {% for item in grouped_hits_context %}
          - {{ item.hit_context['match_field'] }}
        {% endfor %}]
      [additional_params]: [values]
    mode: group
    if: "{{g_playbook['count_of_hits']['value'] }} > 1" """,
            
            "threat_match": """# Response Actions
playbook:
  - name: create_ticket
    type: thehive_soc
    params:
      title: "Threat Intelligence Match - {{hit_context['data_context']['context_field']}} to {{hit_context['threat_context']['threat_field_name']}}"
      description: |
        A potential threat has been detected where {{hit_context['data_context']['context_field']}} has communicated with {{hit_context['threat_context']['threat_field_name']}}, which is identified as malicious in our threat intelligence feeds.
        
        {{investigations['additional_context']['report']}}
        
        Recommended actions:
        1. Investigate the affected system
        2. Check for additional indicators of compromise
        3. Block communication with the malicious indicator if verified
      tlp: 3
      pap: 3
      severity: 2
      flag: False
      tags:
       - "XDR"
       - "CTI"
       - "[Source name]"
    mode: single""",
            
            "code": """# Response Actions
playbook:
  - name: create_ticket
    type: thehive_soc
    params:
      title: "Custom Detection - {{hit_context['detection_name']}}"
      description: |
        A security event was detected by custom detection logic:
        
        {{hit_context['description']}}
        
        Details:
        - User: {{hit_context['user.name']}}
        - Host: {{hit_context['host.name']}}
        - Severity: {{hit_context['severity']}}
        
        Additional context:
        {{investigations['user_context']['report']}}
        
        Recommended actions:
        {{hit_context['recommendations']}}
      tlp: 3
      pap: 3
      severity: 2
      flag: False
      tags:
       - "XDR"
       - "Custom Detection"
    mode: single""",
            
            "lucene_spark": """# Response Actions
playbook:
  - name: create_ticket
    type: thehive_soc
    params:
      title: "Correlated Activity - {{hit_context['correlation_key']}}"
      description: |
        A complex pattern of activity has been detected through event correlation:
        
        Key entity: {{hit_context['correlation_key']}}
        Primary indicator: {{hit_context['primary_value']}}
        Secondary indicator: {{hit_context['secondary_value']}}
        Tertiary indicator: {{hit_context['tertiary_value']}}
        
        This pattern may indicate [description of the security implication].
        
        Additional context:
        
        {{investigations['primary_context']['report']}}
        
        {{investigations['secondary_context']['report']}}
        
        Recommended actions:
        1. Investigate the activity related to {{hit_context['correlation_key']}}
        2. Determine if this is a legitimate pattern or potentially malicious
        3. [Additional recommendations]
      tlp: 3
      pap: 3
      severity: 2
      flag: False
      tags:
       - "XDR"
       - "Correlation"
       - "[Specific technique or tactic]"
    mode: single"""
        }
    }
}

  


STAGE_LLM_CONFIG = {
    "metadata": "models/gemini-2.5-flash-preview-05-20",
    "detection": "models/gemini-2.5-flash-preview-05-20",
    "investigation": "models/gemini-2.5-flash-preview-05-20",
    "playbook": "models/gemini-2.5-flash-preview-05-20"
}

# Import the prompt loader functions
from app.engine.agents.prompt_loader import (
    format_metadata_prompt,
    format_detection_prompt,
    format_investigation_prompt,
    format_playbook_prompt
)

def build_metadata_prompt(user_prompt: str) -> str:
    """
    Build the metadata prompt using the prompt loader.
    
    Args:
        user_prompt: User's request for rule generation
        
    Returns:
        Formatted metadata prompt
    """
    return format_metadata_prompt(user_prompt)


def build_detection_prompt(user_prompt: str, rule_type: str, metadata_yaml: str = None, include_metadata: bool = True) -> str:
    """
    Build the detection prompt using the prompt loader.
    
    Args:
        user_prompt: User's request for rule generation
        rule_type: Type of detection rule
        metadata_yaml: Generated metadata YAML (optional)
        include_metadata: Whether to include metadata in the context
        
    Returns:
        Formatted detection prompt
    """
    # Get the detection template for the specific rule type
    detection_template = RULE_TEMPLATES["sections"]["detection"].get(rule_type, "")
    
    # Only include metadata if requested
    metadata_yaml_to_use = metadata_yaml if include_metadata else None
    
    return format_detection_prompt(
        user_prompt=user_prompt,
        rule_type=rule_type,
        metadata_yaml=metadata_yaml_to_use,
        detection_template=detection_template
    )


def build_investigation_prompt(user_prompt: str, rule_type: str, metadata_yaml: str = None, detection_yaml: str = None, include_metadata: bool = True, include_detection: bool = True) -> str:
    """
    Build the investigation prompt using the prompt loader.
    
    Args:
        user_prompt: User's request for rule generation
        rule_type: Type of detection rule
        metadata_yaml: Generated metadata YAML (optional)
        detection_yaml: Generated detection YAML (optional)
        include_metadata: Whether to include metadata in the context
        include_detection: Whether to include detection in the context
        
    Returns:
        Formatted investigation prompt
    """
    # Get the investigation template for the specific rule type
    investigation_template = RULE_TEMPLATES["sections"]["investigation"].get(rule_type, "")
    
    # Only include metadata/detection if requested
    metadata_yaml_to_use = metadata_yaml if include_metadata else None
    detection_yaml_to_use = detection_yaml if include_detection else None
    
    return format_investigation_prompt(
        user_prompt=user_prompt,
        rule_type=rule_type,
        metadata_yaml=metadata_yaml_to_use,
        detection_yaml=detection_yaml_to_use,
        investigation_template=investigation_template
    )


def build_playbook_prompt(user_prompt: str, rule_type: str, metadata_yaml: str = None, detection_yaml: str = None, investigation_yaml: str = None, include_metadata: bool = True, include_detection: bool = True, include_investigation: bool = True) -> str:
    """
    Build the playbook prompt using the prompt loader.
    
    Args:
        user_prompt: User's request for rule generation
        rule_type: Type of detection rule
        metadata_yaml: Generated metadata YAML (optional)
        detection_yaml: Generated detection YAML (optional)
        investigation_yaml: Generated investigation YAML (optional)
        include_metadata: Whether to include metadata in the context
        include_detection: Whether to include detection in the context
        include_investigation: Whether to include investigation in the context
        
    Returns:
        Formatted playbook prompt
    """
    # Get the playbook template for the specific rule type
    playbook_template = RULE_TEMPLATES["sections"]["playbook"].get(rule_type, "")
    
    # Only include metadata/detection/investigation if requested
    metadata_yaml_to_use = metadata_yaml if include_metadata else None
    detection_yaml_to_use = detection_yaml if include_detection else None
    investigation_yaml_to_use = investigation_yaml if include_investigation else None
    
    return format_playbook_prompt(
        user_prompt=user_prompt,
        rule_type=rule_type,
        metadata_yaml=metadata_yaml_to_use,
        detection_yaml=detection_yaml_to_use,
        investigation_yaml=investigation_yaml_to_use,
        playbook_template=playbook_template
    )


