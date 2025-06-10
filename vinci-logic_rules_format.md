# Vinci Logic Rules Documentation

## Quick Reference Table

| Topic | Description | Section Link |
|-------|-------------|--------------|
| Introduction | Overview of Vinci Logic and D&R as Code | [Introduction](#introduction) |
| Rule Structure | Common format for all rule types | [Common Rule Structure](#common-rule-structure) |
| Metadata | Information about the rule itself | [Metadata Section](#metadata-section) |
| Detection Types | Different rule types for detection | |
| - Query Type | Pattern-based detection using Lucene queries | [Query Type Rules](#query-type-rules) |
| - Advanced Threshold | Behavior-based detection using aggregations | [Advanced Threshold Type Rules](#advanced-threshold-type-rules) |
| - Source Monitor | Monitoring the absence of expected data | [Source Monitor Type Rules](#source-monitor-type-rules) |
| Exclusions | Filtering out false positives | [Exclusions Section](#exclusions-section) |
| Investigations | Enriching alerts with context | [Investigation Sections](#investigation-sections) |
| Playbooks | Actions to execute upon detection | [Playbook Section](#playbook-section) |
| - Action Types | Types of actions available in playbooks | [Available Action Types and Parameters](#available-action-types-and-parameters) |
| - Execution Modes | How actions are executed | [Execution Modes](#execution-modes) |
| - Conditional Execution | Running actions based on conditions | [Conditional Execution](#conditional-execution) |
| Rule Examples | Complete examples of different rule types | [Complete Rule Examples](#complete-rule-examples) |
| Best Practices | Guidelines for effective rule development | [Best Practices](#best-practices) |

## Introduction

Vinci Logic is a detection engine that implements Detection and Response (D&R) as Code. The engine uses YAML-formatted rules to detect, investigate, and respond to security incidents. This documentation covers the structure, components, and best practices for writing effective Vinci Logic rules.

The Vinci Logic detection engine represents a modern approach to security monitoring, enabling security teams to define, manage, and deploy detection rules as code. This approach provides several benefits:

1. **Version Control**: Rules can be stored in source control systems, allowing for history tracking, rollbacks, and collaborative development.
2. **CI/CD Integration**: Rules can be automatically tested and deployed through continuous integration pipelines.
3. **Standardization**: All rules follow a consistent format, making them easier to read, review, and maintain.
4. **Automation**: The entire detection and response workflow can be automated, from initial alert to investigation and remediation actions.

Rules in Vinci Logic follow a structured format that includes:
- **Metadata** - Information about the rule itself
- **Detection** - Logic to identify potential threats
- **Investigations** - Methods to enrich and analyze detected alerts
- **Playbook** - Actions to be executed when a threat is detected

The engine uses Jinja2 as a templating engine for investigations and playbook actions, allowing for dynamic content generation. All rules are executed against an OpenSearch instance, using Lucene query syntax.

## Common Rule Structure

All Vinci Logic rules follow this common structure, regardless of their specific type. The structure is organized into four main sections: Metadata, Detection, Investigations, and Playbook. Each section serves a specific purpose in the detection and response workflow.

```yaml
# Metadata Section
title: Rule Title
uuid: unique-identifier-string
severity: low|medium|high|critical
version: 1.0
effort_level: elementary|intermediate|advanced
confidence: low|medium|high
maturity: production|experimental|development
enabled: true|false
learning_mode: true|false
capabilities:
  - Capability1
  - Capability2
author: Author Name
creation_date: 'YYYY/MM/DD'
updated_date: 'YYYY/MM/DD'
description: Detailed description of the rule
references:
  - https://reference-url-1
  - https://reference-url-2
tags:
  - tag1
  - tag2

# Detection Section (varies by rule type)
type: query|advanced_threshold|source_monitor
frequency: 15m
depth: 15m
timestamp_override: 'event.ingested'
integration: windows|linux|fortinet|generic
indices:
  - index-pattern-1
  - index-pattern-2
query: 'Lucene query syntax'

# Optional Exclusions Section
exclusions:
  exclusion_name:
    query: 'Exclusion query'
    date: YYYY/MM/DD
    note: 'Exclusion note'
    author: Author Name

# Optional group_match for deduplication
group_match:
  - field1
  - field2

# Lifetime for deduplication
lifetime: 1h

# Investigations Section
investigations:
  investigation_name:
    type: query
    query: 'Investigation query with {{ hit_context['field'] }}'
    description: "Description text"
    per_hit_description: "Per hit description with {{ investigation['hit']['field'] }}"
    fallback: "Fallback message if no hits"
    depth: 10m
    indices:
      - index-pattern
    group_match:
      - field1
      - field2

# Playbook Section
playbook:
  - name: action_name
    type: action_type
    params:
      param1: value1
      param2: value2
    mode: single|group
    if: "{{conditional_expression}}"
```

## Metadata Section

The metadata section provides information about the rule itself. This section is required for all rule types and includes:

| Field | Description | Required | Example Values |
|-------|-------------|----------|---------------|
| `title` | Human-readable name of the rule | Yes | `"Windows Multiple Users Failed To Authenticate Using Kerberos"` |
| `uuid` | Unique identifier for the rule | Yes | `"b84e0131-dc9e-4873-be3a-4557f25e12a1i"` |
| `tdr` | Optional identifier for tracking detection rules | No | `"TDR-1095"` |
| `severity` | Impact level of the detected activity | Yes | `low`, `medium`, `high`, `critical` |
| `version` | Rule version number | Yes | `1.0`, `0.1` |
| `effort_level` | Complexity level of implementation | Yes | `elementary`, `intermediate`, `advanced` |
| `confidence` | Level of certainty in rule effectiveness | Yes | `low`, `medium`, `high` |
| `maturity` | Development stage of the rule | Yes | `production`, `experimental`, `development` |
| `enabled` | Whether the rule is active | Yes | `true`, `false` |
| `learning_mode` | Whether the rule is in learning mode | Yes | `true`, `false` |
| `capabilities` | MITRE ATT&CK techniques or other categorization | No | List of strings |
| `author` | Rule creator | Yes | `"wbouhali"`, `"SEKERA SERVICES"` |
| `creation_date` | Date when rule was created | Yes | `'07/03/2024'`, `'2023/07/10'` |
| `updated_date` | Date when rule was last updated | Yes | `'07/03/2024'`, `'2023/07/25'` |
| `description` | Detailed explanation of what the rule detects | Yes | Text description |
| `references` | External documentation or resources | No | List of URLs |
| `tags` | Categorization tags | No | List of strings |
| `note` | Additional notes about the rule | No | `'Note here'` |
| `false_positives` | Known false positive scenarios | No | Text description |
| `risk_score` | Numerical risk score | No | `80` |
| `status` | Status of the rule | No | `experimental`, `stable` |

Example:

```yaml
title: Windows Multiple Users Failed To Authenticate Using Kerberos 
uuid: b84e0131-dc9e-4873-be3a-4557f25e12a1i
tdr: TDR-1095
description: The following analytic identifies one source endpoint failing to authenticate with 30 unique users using the Kerberos protocol. Event 4771 is generated when the Key Distribution Center fails to issue a Kerberos Ticket Granting Ticket (TGT). Failure code 0x18 stands for wrong password provided (the attempted user is a legitimate domain user).
author: wbouhali
severity: medium
effort_level: elementary
maturity: production
enabled: true
learning_mode: false
creation_date: '07/03/2024'
updated_date: '07/03/2024'
```

## Detection Section

The detection section defines how potential threats are identified. This section varies depending on the rule type.

### Common Detection Fields

| Field | Description | Required | Example Values |
|-------|-------------|----------|---------------|
| `type` | The type of detection rule | Yes | `query`, `advanced_threshold`, `source_monitor` |
| `frequency` | How often the rule should run | Yes | `9m`, `15m`, `30m`, `1h` |
| `depth` | Timeframe to look back for matching events | Yes | `9m`, `15m`, `24h` |
| `timestamp_override` | Field to use for event timestamp | Yes | `'event.ingested'`, `'@timestamp'` |
| `integration` | Source system type | Yes | `windows`, `linux`, `fortinet` |
| `indices` | Elasticsearch/OpenSearch index patterns | Yes | List of index patterns |
| `lifetime` | Deduplication time window | Yes | `1h`, `2h`, `4h`, `12h` |

### Query Type Rules

Query type rules search for specific patterns or events using a Lucene query.

Additional fields for Query Type rules:

| Field | Description | Required | Example Values |
|-------|-------------|----------|---------------|
| `query` | Lucene query to identify matching events | Yes | `'event.code:4624 AND winlog.event_data.LogonType:3 AND source.ip:*'` |
| `group_match` | Fields to group matches for deduplication | No | List of field names |

Example:

```yaml
type: query
frequency: 9m
depth: 1h
integration:
- windows
timestamp_override: event.ingested
indices:
- winlogbeat-*
query: 'event.code:4624 AND winlog.event_data.LogonType:3 AND source.ip:* AND NOT user.name:*$'
group_match:
  - host.name
  - source.ip
  - user.name
lifetime: 2h
```

### Advanced Threshold Type Rules

Advanced threshold rules identify patterns that exceed specific thresholds, often used for detecting behavior-based anomalies.

Additional fields for Advanced Threshold Type rules:

| Field | Description | Required | Example Values |
|-------|-------------|----------|---------------|
| `query` | Base query to filter events | Yes | Lucene query string |
| `aggregation` | Aggregation configuration | Yes | Object |
| `aggregation.terms` | Terms aggregation configuration | Yes | Object |
| `aggregation.terms.field` | Field to perform primary grouping on | Yes | `source.ip` |
| `aggregation.terms.cardinality` | Cardinality aggregation configuration | Yes | Object |
| `aggregation.terms.cardinality.field` | Field to calculate cardinality on | Yes | `destination.port`, `user.name` |
| `aggregation.terms.cardinality.threshold` | Threshold value to trigger an alert | Yes | `15`, `50` |
| `aggregation.terms.terms` | Optional nested terms aggregation | No | Object |

Example:

```yaml
type: advanced_threshold
frequency: 15m
depth: 15m
timestamp_override: 'event.ingested'
indices:
  - syslog-fortinet-fw*
query: 'event.category:network AND event.type:allowed AND event.action:accept AND destination.port:* AND NOT source.ip:(172.16.8.150 OR 172.16.8.50)'
aggregation:
  terms:
    field: source.ip
    cardinality:
      field: destination.port
      threshold: 50
lifetime: 6h
```

Example with nested terms:

```yaml
type: advanced_threshold
aggregation:
  terms:
    field: host.name
    terms:
      field: source.ip
      cardinality:
        field: _id
        threshold: 10
```

### Source Monitor Type Rules

Source monitor rules detect when expected data sources stop sending events, which could indicate service disruption or logging issues.

Additional fields for Source Monitor Type rules:

| Field | Description | Required | Example Values |
|-------|-------------|----------|---------------|
| `query` | Base query to filter events | Yes | Lucene query string |
| `source_file` | Path to file listing expected sources | Yes | `'/engine/inventory/auditbeat_supervised_assets.csv'` |
| `match_field` | Field to match against sources list | Yes | `'host.name'` |

Example:

```yaml
type: source_monitor
integration: linux
frequency: 1h
depth: 1h
timestamp_override: 'event.ingested'
indices:
  - auditbeat-*
query: '_exists_:host.name'
source_file: '/engine/inventory/auditbeat_supervised_assets.csv'
match_field: 'host.name'
lifetime: 12h
```

## Exclusions Section

The exclusions section allows defining conditions to filter out false positives. This is an optional section.

| Field | Description | Required | Example Values |
|-------|-------------|----------|---------------|
| `exclusion_name` | Unique name for the exclusion | Yes | `exclusion_1`, `exclusion_2` |
| `query` | Lucene query defining what to exclude | Yes | `'source.ip:172.16.8.150'` |
| `date` | Date when exclusion was added | Yes | `2024/05/10` |
| `note` | Explanation for the exclusion | Yes | `'Exclude DC IPs'` |
| `author` | Person who added the exclusion | Yes | `tradah` |

Example:

```yaml
exclusions:
  exclusion_1:
    query: 'source.ip:172.16.8.150'
    date: 2024/07/15
    note: 'Exclude DC IPs'
    author: tradah
  exclusion_2:
    query: 'source.ip:10.255.2.1 AND destination.ip:10.255.2.0\/24 AND destination.port:443'
    date: 2024/06/16
    note: 'Exclusions based on client validation'
    author: tradah
```

## Investigation Sections

The investigations section defines how to enrich and analyze alerts through additional queries. This allows gathering context around detected events.

| Field | Description | Required | Example Values |
|-------|-------------|----------|---------------|
| `investigation_name` | Unique name for the investigation | Yes | `computer_account_source`, `users_involved_in_incident` |
| `type` | Type of investigation | Yes | `query` |
| `query` | Query to retrieve context data | Yes | Lucene query with Jinja2 templating |
| `description` | Introduction text for investigation results | Yes | `"Les utilisateurs impliqués dans cet indcidents sont:\n"` |
| `per_hit_description` | Template for formatting each result | Yes | Jinja2 template string |
| `fallback` | Message displayed when no results found | Yes | `"Aucune authentification reussie n'a été observé depuis cette source"` |
| `depth` | Timeframe to look back for investigation data | Yes | `10m`, `12h` |
| `indices` | Index patterns to query for investigation | Yes | List of index patterns |
| `group_match` | Fields to group investigation results | No | List of field names |

Example:

```yaml
investigations:
  computer_account_source:
    type: query
    query: source.ip:{{ hit_context['source.ip'] }} AND event.code:4624 AND user.name:*$
    description: "Selon les logs Windows Active Directory: "
    per_hit_description: " - L'adresse IP {{ hit_context['source.ip'] }} est associé à la machine {{ investigation['hit']['user.name'] }}."
    fallback: "Selon les logs Windows Active Directory l'adresse IP {{hit_context['source.ip']}} n'est associé à aucune machine Windows"
    depth: 12h
    indices:
      - winlogbeat-*
    group_match:
      - user.name
```

### Context Variables in Investigations

Investigations can reference:

- `hit_context` - Fields from the original detection event
- `investigation['hit']` - Fields from each investigation result
- `rule_context` - Metadata from the rule definition

## Playbook Section

The playbook section defines automated actions to execute when a rule detects a threat. Actions can create tickets, send notifications, or perform other response activities.

### Common Playbook Fields

| Field | Description | Required | Example Values |
|-------|-------------|----------|---------------|
| `name` | Unique name for the action | Yes | `create_a_grouped_thehive_ticket`, `count_of_hits` |
| `type` | Type of action to perform | Yes | `thehive_soc_atlantasanad`, `processor`, `email_html`, etc. |
| `params` | Parameters for the action | Yes | Object with action-specific parameters |
| `mode` | Execution mode for the action | Yes | `single`, `group` |
| `if` | Conditional expression for execution | No | Jinja2 condition |
| `description` | Description of the action | No | Text description |

### Available Action Types and Parameters

#### Processor Type

Used for internal processing and value manipulation.

| Parameter | Description | Required | Example Values |
|-----------|-------------|----------|---------------|
| `type` | Processor operation | Yes | `count`, `message`, `set` |
| `scope` | Variable scope to operate on | No | `hit_context` |
| `field` | Field to modify | No | `risk_score` |
| `value` | Value to set | No | `2`, `4` |
| `description` | Message template | No | Jinja2 template string |

Example:

```yaml
- name: set_default_risk_score
  type: processor
  params:
    type: set
    scope: 'hit_context'
    field: 'risk_score'
    value: 2
  mode: single
```

#### TheHive SOC Types

Used to create tickets in TheHive incident management system.

| Parameter | Description | Required | Example Values |
|-----------|-------------|----------|---------------|
| `title` | Ticket title | Yes | Jinja2 template string |
| `description` | Ticket description | Yes | Jinja2 template string |
| `tlp` | Traffic Light Protocol level | Yes | `3` |
| `pap` | Permissible Actions Protocol level | Yes | `3` |
| `severity` | Incident severity level | Yes | `1`, `2`, `3`, `4` or `"{{hit_context['risk_score']}}"` |
| `flag` | Flag for additional attention | Yes | `True`, `False` |
| `tags` | Tags for categorization | Yes | List of strings |

Example:

```yaml
- name: create_single_thehive_ticket
  type: thehive_soc_atlantasanad
  params:
    title: "{{rule_context['title']}}"
    description: "Bonjour,\n\n
     \nDes tentatives d'authentification avec {{ hit_context['count'] }} comptes inexistants ont été détectées à partir de l'adresse IP {{ hit_context['source.ip'] }}.\
     \nCela pourrait indiquer une tentative d'énumération des utilisateurs existant dans l'Active Directory..."
    tlp: 3
    pap: 3
    severity: "{{hit_context['risk_score']}}"
    flag: False
    tags:
     - "XDR"
     - "{{rule_context['tdr']}}"
     - "windows"
  mode: single
```

#### Email HTML Type

Used to send HTML email notifications.

| Parameter | Description | Required | Example Values |
|-----------|-------------|----------|---------------|
| `subject` | Email subject | Yes | Jinja2 template string |
| `title` | Email title | Yes | Jinja2 template string |
| `to_email` | Recipient email address | Yes | `"wbouhali@sekera-group.com"` |
| `to_name` | Recipient name | Yes | `"client"` |
| `incident_id` | Reference to incident ID | Yes | `"{{playbook['create_a_grouped_thehive_ticket']['caseId']}}"` |
| `risk_level` | Human-readable risk level | Yes | Jinja2 conditional expression |
| `description` | Email content | Yes | HTML content with Jinja2 templates |
| `affected_hosts` | Hosts affected by incident | Yes | `"{{ hit_context['host.name'] }}"` |
| `affected_accounts` | Accounts affected by incident | Yes | `"{{ hit_context['winlog.event_data.SubjectUserName'] }}"` |
| `tdr_id` | Reference ID | Yes | `"{{rule_context['tdr']}}"` |
| `detection_date` | Date of detection | Yes | `"{{ hit_context['@timestamp'] }}"` |
| `event_date` | Date of original event | Yes | `"{{ hit_context['original_timestamp'] }}"` |
| `impact` | Impact description | Yes | `"Evasion de la défense"` |

Example:

```yaml
- name: create_default_email_notification
  type: email_html
  params:
    subject: "[SOC-SEKERA-ALERT][{{playbook['create_a_grouped_thehive_ticket']['caseId']}}][{{ 'Faible' if playbook['create_a_grouped_thehive_ticket']['severity'] == 1 else 'Moyenne' if playbook['create_a_grouped_thehive_ticket']['severity'] == 2 else 'Elevée' if playbook['create_a_grouped_thehive_ticket']['severity'] == 3 else 'Critique' if playbook['create_a_grouped_thehive_ticket']['severity'] == 4 else 'Moyenne' }}] {{playbook['create_a_grouped_thehive_ticket']['title']}}"
    title: "{{playbook['create_a_grouped_thehive_ticket']['title']}}"
    to_email: "wbouhali@sekera-group.com"
    to_name: "client"
    incident_id: "{{playbook['create_a_grouped_thehive_ticket']['caseId']}}"
    risk_level: "{{ 'Faible' if playbook['create_a_grouped_thehive_ticket']['severity'] == 1 else 'Moyen' if playbook['create_a_grouped_thehive_ticket']['severity'] == 2 else 'Elevé' if playbook['create_a_grouped_thehive_ticket']['severity'] == 3 else 'Critique' if playbook['create_a_grouped_thehive_ticket']['severity'] == 4 else 'Moyen' }}"
    description: |
        <p>Nous avons détecté une activité de désactivation des politiques d'audit du système sur l'hôte <strong>{{ hit_context['host.name'] }}</strong> par l'utilisateur <strong>{{ hit_context['winlog.event_data.SubjectUserName'] }}</strong>.</p>
        <p>Le timestamp d'origine de cette activité est: <strong>{{ hit_context['original_timestamp'] }}</strong>.</p>
                  </p>
              <p>Pour les détails complets de l'incident, veuillez consulter le ticket 
                  <a href="https://scsrv-nginx/index.html#!/case/~{{playbook['create_a_grouped_thehive_ticket']['_id']}}/details" target="_blank">
                  TheHive.
                  </a> 
          </p>
    affected_hosts: "{{ hit_context['host.name'] }}"
    affected_accounts: "{{ hit_context['winlog.event_data.SubjectUserName'] }}"
    tdr_id: "{{rule_context['tdr']}}"
    detection_date: "{{ hit_context['@timestamp'] }}"
    event_date: "{{ hit_context['original_timestamp'] }}"
    impact: "Evasion de la défense"
  mode: single
```

#### Signal Type

Used to create weak signals or other reference signals in the system.

| Parameter | Description | Required | Example Values |
|-----------|-------------|----------|---------------|
| `index` | Index to store the signal | Yes | `"test-weak-signals"` |
| `fields` | Fields to include in the signal | Yes | List of key-value pairs |

Example:

```yaml
- name: create_a_weak_signal
  type: signal
  params:
    index: "test-weak-signals"
    fields:
      - signal.title: "Network login of user {{ hit_context['user.name'] }} from {{ hit_context['source.ip'] }} to {{ hit_context['host.name'] }}"
      - signal.match_hash: "{{hit_context['match_hash']}}"
      - signal.rule.uuid: "{{rule_context['uuid']}}"
      - logon.id: "{{hit_context['winlog.event_data.TargetLogonId']}}"
      - source.ip: "{{hit_context['source.ip']}}"
      - user.name: "{{hit_context['user.name']}}"
      - timestamp: "{{hit_context['@timestamp']}}"
  mode: single
```

### Execution Modes

Playbook actions support different execution modes:

| Mode | Description |
|------|-------------|
| `single` | Execute once per detection event |
| `group` | Execute once for a group of detection events |

### Conditional Execution

Actions can be conditionally executed using the `if` parameter with Jinja2 expressions.

Example:

```yaml
- name: create_single_thehive_ticket
  type: thehive_soc_atlantasanad
  params:
    title: "{{rule_context['title']}}"
    description: "Alert description..."
  mode: single
  if: "{{g_playbook['count_of_hits']['value'] }} == 1"
```

### Context Variables in Playbooks

Playbooks can reference:

- `hit_context` - Fields from the original detection event
- `investigations` - Results from investigation queries
- `rule_context` - Metadata from the rule definition
- `playbook` - Results from previous playbook actions
- `g_playbook` - Global playbook context (for group mode)
- `grouped_hits_context` - All detection events in a group (for group mode)
- `tenant_context` - Tenant-specific settings

## Rule Type-Specific Documentation

### Query Type Rules

Query type rules search for patterns in logs using a Lucene query. They are ideal for identifying specific event patterns that directly indicate a security concern.

Key components specific to Query type rules:

1. The `query` field using Lucene syntax to match events
2. Optional `group_match` fields for deduplication
3. `lifetime` field for deduplication window

Example:

```yaml
title: Weak Signal
uuid: weak-signal-network-login-556dc790-b045-4568-8f12-c6cd1a5c1cfafsbdid
type: query
frequency: 9m
depth: 1h
integration:
- windows
timestamp_override: event.ingested
indices:
- winlogbeat-*
query: 'event.code:4624 AND winlog.event_data.LogonType:3 AND source.ip:* AND NOT user.name:*$'
group_match:
  - host.name
  - source.ip
  - user.name
lifetime: 2h
```

### Advanced Threshold Rules

Advanced threshold rules detect anomalous behavior by tracking when specific activity exceeds defined thresholds. They are useful for identifying behavior-based threats like port scanning, brute force attacks, and unusual network activity.

Key components specific to Advanced Threshold type rules:

1. The base `query` field to filter relevant events
2. The `aggregation` section with nested configuration:
   - Primary grouping field
   - Cardinality field to count unique values
   - Threshold value that triggers an alert
3. Optional nested aggregations for more complex scenarios

Example - Simple Cardinality:

```yaml
title: Windows Multiple Invalid Users Fail To Authenticate Using Kerberos
type: advanced_threshold
frequency: 15m
depth: 15m
timestamp_override: 'event.ingested'
integration: windows
indices:
- winlogbeat-*
query: 'event.code:4768 AND source.ip:* AND winlog.event_data.Status:0x6 AND NOT winlog.event_data.TargetUserName:*$'
aggregation:
  terms:
    field: source.ip
    cardinality:
      field: user.name
      threshold: 15
lifetime: 4h
```

Example - Nested Terms:

```yaml
title: Bruteforce On Windows Openssh Server With Valid Users
type: advanced_threshold
frequency: 9m
depth: 9m
integration:
- windows
indices:
- winlogbeat-*
query: 'event.code:4625 AND winlog.event_data.SubStatus:0xc000006a AND process.name:(ssh.exe OR sshd.exe)'
aggregation:
  terms:
    field: host.name
    terms:
      field: source.ip
      cardinality:
        field: _id
        threshold: 10
lifetime: 2h
```

### Source Monitor Rules

Source monitor rules detect the absence of expected data. They are primarily used to monitor the health of logging sources and alert when a system stops sending events.

Key components specific to Source Monitor type rules:

1. The base `query` field to identify relevant events
2. The `source_file` pointing to a list of expected sources
3. The `match_field` that identifies which field to match against the source list

Example:

```yaml
title: Lost of a critical event source
type: source_monitor
integration: linux
frequency: 1h
depth: 1h
timestamp_override: 'event.ingested'
indices:
  - auditbeat-*
query: '_exists_:host.name'
source_file: '/engine/inventory/auditbeat_supervised_assets.csv'
match_field: 'host.name'
lifetime: 12h
```

## Complete Rule Examples

### Source Monitor Rule Example

```yaml
title: Lost of a critical event source
uuid: 939aa10-fac6-c4df-auditbeat-15-lost-3
severity: low
risk_score: 80
version: 1.0
effort_level: elementary
confidence: high
maturity: production
enabled: True
learning_mode: False
capabilities:
  - Attack pattern
  - Threat
  - Weakness introduction
  - Attacker Tool
author: Sekera
creation_date: 2023/07/10
updated_date: 2023/07/25
description: An alert was raised by Microsoft M365 Defender console.
references:
  - https://url
  - https://url2
type: source_monitor
integration: linux
tags:
  - attack.persistence
  - attack.t1098
frequency: 1h
depth: 1h
timestamp_override: 'event.ingested'
false_positives: Administrators adding legitimate accounts to DA group
note: Verify if this logon event is legitimate
indices:
  - auditbeat-*
query: '_exists_:host.name'
source_file: '/engine/inventory/auditbeat_supervised_assets.csv'
match_field: 'host.name'
lifetime: 12h
playbook:
  - name: count_of_hits
    description: "Get the count of hits"
    type: processor
    params:
      type: count
    mode: group

  - name: create_thehive_ticket_single_machine
    type: thehive_soc_atlantasanad
    params:
      title: "[{{tenant_context['client_name']}}] Interruption de l'envoi de logs linux auditbeat de la machine {{ hit_context['host.name'] }}"
      description: "
      La machine **{{ hit_context['host.name'] }}** a cessé d'envoyer les logs linux auditbeat vers le SIEM.\n\
      Durant les 2 dernières heures, seuls **{{hit_context['count']}}** événements ont été reçus depuis la machine **{{ hit_context['host.name'] }}**.\n\
      Nous vous prions de prendre les mesures nécessaires pour diagnostiquer la source du problème et rétablir l'envoi des logs linux auditbeat de la machine **{{ hit_context['host.name'] }}**.\n\
      "
      tlp: 3
      pap: 3
      severity: 1
      flag: False
      tags:
       - "XDR"
       - "source_monitor"
       - "mco"
    mode: single
    if: "{{g_playbook['count_of_hits']['value'] }} == 1"

  - name: create_thehive_ticket_multiple_machines
    type: thehive_soc_atlantasanad
    params:
      title: "[{{tenant_context['client_name']}}] Interruption de l'envoi de logs linux auditbeat de plusieurs machines"
      description: "
      Plusieurs machines linux auditbeat ont cessé d'envoyer leurs logs vers le SIEM.\n\
      Durant les 2 dernières heures:\n\
      {% for item in grouped_hits_context %}\
        - La machine **{{ item.hit_context['host.name'] }}** a envoyé seulement **{{ item.hit_context['count'] }}** événements.\n\
      {% endfor %}\
      \nNous vous prions de prendre les mesures nécessaires pour diagnostiquer la source du problème et rétablir l'envoi des logs de ces machines linux auditbeat.\n\
      "
      tlp: 3
      pap: 3
      severity: 2
      flag: False
      tags:
       - "XDR"
       - "source_monitor"
       - "mco"
    mode: group
    if: "{{g_playbook['count_of_hits']['value'] }} > 1 and {{g_playbook['count_of_hits']['value'] }} < 65"
```

### Query Type Rule Example

```yaml
title: Weak Signal
uuid: weak-signal-network-login-556dc790-b045-4568-8f12-c6cd1a5c1cfafsbdid
tdr: TDR-1000001
severity: medium
version: 1.0
effort_level: elementary
confidence: high
maturity: production
enabled: false
learning_mode: false
capabilities:
  - initial_access
  - intrusion_detection
author: SEKERA SERVICES
creation_date: '07/03/2024'
updated_date: '07/03/2024'
note: 'Note here'
description: Detects successful logon from public IP address via RDP. This can indicate a publicly-exposed RDP port.
references:
- https://www.inversecos.com/2020/04/successful-4624-anonymous-logons-to.html
- https://twitter.com/Purp1eW0lf/status/1616144561965002752
type: query
tags:
  - initial_access
  - valid_account
  - windows
frequency: 9m
depth: 1h
integration:
- windows
timestamp_override: event.ingested
false_positives:
- Legitimate or intentional inbound connections from public IP addresses on the RDP port.
note: Notes here
indices:
- winlogbeat-*
query: 'event.code:4624 AND winlog.event_data.LogonType:3 AND source.ip:* AND NOT user.name:*$'
group_match:
  - host.name
  - source.ip
  - user.name
lifetime: 2h
playbook:
  - name: create_a_weak_signal
    type: signal
    params:
      index: "test-weak-signals"
      fields:
        - signal.title: "Network login of user {{ hit_context['user.name'] }} from {{ hit_context['source.ip'] }} to {{ hit_context['host.name'] }}"
        - signal.match_hash: "{{hit_context['match_hash']}}"
        - signal.rule.uuid: "{{rule_context['uuid']}}"
        - logon.id: "{{hit_context['winlog.event_data.TargetLogonId']}}"
        - source.ip: "{{hit_context['source.ip']}}"
        - user.name: "{{hit_context['user.name']}}"
        - timestamp:  "{{hit_context['@timestamp']}}"
    mode: single
```

### Advanced Threshold Rule Example

```yaml
title: Windows Multiple Users Failed To Authenticate Using Kerberos 
uuid: b84e0131-dc9e-4873-be3a-4557f25e12a1i
tdr: TDR-1095
description: The following analytic identifies one source endpoint failing to authenticate with 30 unique users using the Kerberos protocol. Event 4771 is generated when the Key Distribution Center fails to issue a Kerberos Ticket Granting Ticket (TGT). Failure code 0x18 stands for wrong password provided (the attempted user is a legitimate domain user).
author: wbouhali
severity: medium
effort_level: elementary
maturity: production
enabled: true
learning_mode: false
creation_date: '07/03/2024'
updated_date: '07/03/2024'
timestamp_override: 'event.ingested'
integration: windows
note: 'Note here'
status: experimental
capabilities:
  - initial_access
  - intrusion_detection
indices: winlogbeat-*
tags:
    - T1110.003
    - Password Spraying
    - Brute Force
    - Credential Access
    - Exploitation
    - NIST.DE.CM
    - CIS20.CIS 10
references:
    - https://research.splunk.com/endpoint/3a91a212-98a9-11eb-b86a-acde48001122/
type: advanced_threshold
frequency: 9m
depth: 9m
false_positives: A host failing to authenticate with multiple valid domain users is not a common behavior for legitimate systems. Possible false positive scenarios include but are not limited to vulnerability scanners, missconfigured systems and multi-user systems like Citrix farms.
query: 'event.code:4771 AND source.ip:* AND winlog.event_data.Status:0x18 AND NOT winlog.event_data.TargetUserName:*
exclusions:
  exclusion_1:
    query: 'source.ip:172.16.8.150'
    date: 2024/07/15
    note: 'Exclude DC IPs'
    author: tradah
aggregation:
  terms:
    field: source.ip
    cardinality:
      field: user.name
      threshold: 15
lifetime: 4h
investigations:
  computer_account_source:
    type: query
    query: source.ip:{{ hit_context['source.ip'] }} AND event.code:4624 AND user.name:*$
    description: "Selon les logs Windows Active Directory: "
    per_hit_description: " - L'adresse IP {{ hit_context['source.ip'] }} est associé à la machine {{ investigation['hit']['user.name'] }}."
    fallback: "Selon les logs Windows Active Directory l'adresse IP {{hit_context['source.ip']}} n'est associé à aucune machine Windows"
    depth: 12h
    indices:
      - winlogbeat-*
    group_match:
      - user.name
  users_involved_in_incident:
    type: query
    query: event.code:4768 AND winlog.event_data.Status:0x18 AND source.ip:{{ hit_context['source.ip'] }} AND NOT winlog.event_data.TargetUserName:*$
    description: "Les utilisateurs impliqués dans cet indcidents sont:\n"
    per_hit_description: "- Utilisateur: {{ investigation['hit']['user.name'] }}\n"
    fallback: "Cet incident n'est associé à aucun utilisateur."
    depth: 12h
    indices:
      - winlogbeat-*
    group_match:
      - user.name
  valid_users_valid_pass:
    type: query
    query: event.code:4768 AND winlog.event_data.Status:0x0 AND source.ip:{{ hit_context['source.ip'] }} AND NOT winlog.event_data.TargetUserName:*$
    description: "La source {{ hit_context['source.ip'] }} a parenue à s'authentifié avec les utilisateurs:"
    per_hit_description: "- Utilisateur: {{ investigation['hit']['user.name'] }}\n"
    fallback: "Aucune authentification reussie n'a été observé depuis cette source dans les 12 dernières heures."
    depth: 12h
    indices:
      - winlogbeat-*
    group_match:
      - user.name
playbook:
  - name: count_of_hits
    description: "Get the count of hits"
    type: processor
    params:
      type: count
    mode: group

  - name: create_a_grouped_thehive_ticket
    type: thehive_soc_atlantasanad
    params:
      title: "{{grouped_hits_context[0].rule_context['title']}}"
      description: "Bonjour,\n
       \nPlusieurs tentatives d'authentification avec des comptes inexistant ont été effectué a partir de plusieurs adresses IP:
       \n{% for item in grouped_hits_context %}\
       \nFrom {{ item.hit_context['source.ip'] }} on {{ item.hit_context['host.name']}}, {{ item.hit_context['threshold_value'] }}\
       \n{{ item.investigations['users_involved_in_incident']['report'] }}\
       \n{{ item.investigations['valid_users_wrong_pass']['report'] }}\
       \n{{ item.investigations['valid_users_valid_pass']['report'] }}\
       {% endfor %}"
      tlp: 3
      pap: 3
      severity: 2
      flag: False
      tags:
       - "XDR"
    mode: group
    if: "{{g_playbook['count_of_hits']['value'] }} > 1"

  - name: set_default_risk_score
    type: processor
    params:
      type: set
      scope: 'hit_context'
      field: 'risk_score'
      value: 2
    mode: single

  - name: create_single_thehive_ticket
    type: thehive_soc_atlantasanad
    params:
      title: "{{rule_context['title']}}"
      description: "Bonjour,\n\n
       \nDes tentatives d'authentification avec {{ hit_context['count'] }} comptes AD ont été détectées à partir de l'adresse IP {{ hit_context['source.ip'] }}.\
       \nCela pourrait indiquer une tentative d'énumération des utilisateurs existant dans l'Active Directory..."
      tlp: 3
      pap: 3
      severity: "{{hit_context['risk_score']}}"
      flag: False
      tags:
       - "XDR"
       - "{{rule_context['tdr']}}"
       - "windows"
       - "initial_access"
       - "intrusion_detection"
    mode: single
    if: "{{g_playbook['count_of_hits']['value'] }} == 1"
```

## Best Practices

When developing Vinci Logic rules, following these best practices will help ensure your rules are effective, maintainable, and efficient:

### Rule Development

1. **Start with a Clear Use Case**: Define exactly what security scenario you're trying to detect before writing the rule.
2. **Use Descriptive Titles and Descriptions**: Rule titles should be clear and descriptive. Descriptions should explain what the rule detects, why it's important, and any potential limitations.
3. **Include References**: When possible, include external references like ATT&CK techniques, blog posts, or research papers that support your detection methodology.
4. **Document Known False Positives**: Always include known false positive scenarios in the `false_positives` field to help analysts during investigation.

### Query Development

1. **Start Simple, Then Refine**: Begin with a simple query that captures the core behavior, then add conditions to reduce false positives.
2. **Test Thoroughly**: Test queries against historical data to validate effectiveness and understand potential alert volume.
3. **Use Exclusions Instead of Complex Queries**: When dealing with known false positives, use the exclusions section rather than making the main query overly complex.
4. **Optimize for Performance**: Be mindful of query performance, especially for rules that run frequently or against high-volume indices.

### Threshold Tuning

1. **Start Conservative**: Begin with thresholds that will generate alerts, then adjust based on actual alert quality.
2. **Consider Normal Behavior**: Understand what normal behavior looks like in your environment before setting thresholds.
3. **Adjust by Environment**: Threshold values often need to be customized to specific environments - what works in one environment may generate too many or too few alerts in another.

### Playbook Design

1. **Begin with Enrichment**: Initial playbook actions should focus on gathering context before taking more significant actions.
2. **Implement Progressive Response**: Design playbooks with escalating response actions based on confidence and severity.
3. **Include Clear Descriptions**: Ensure descriptions in tickets and notifications provide clear guidance on what was detected and recommended next steps.
4. **Use Conditional Execution**: Leverage conditional execution to adapt the response based on the specific context of each alert.

### Maintenance

1. **Review and Update Regularly**: Review rule effectiveness periodically and update as threats evolve.
2. **Document Changes**: Keep track of rule modifications, especially threshold adjustments, to understand how the rule has evolved.
3. **Monitor Alert Volume**: Watch for sudden changes in alert volume that might indicate either a security event or a need to adjust the rule.
4. **Version Control**: Use a version control system to track changes to rules over time.

### Templating

1. **Use Consistent Formatting**: Maintain consistent formatting in your Jinja2 templates for readability.
2. **Handle Missing Values**: Always include fallback options for when expected fields are missing.
3. **Test Template Rendering**: Verify that templates render as expected with different input data.

By following these best practices, you'll create more effective, maintainable, and reliable detection rules that generate high-quality alerts with appropriate response actions.

# Vinci Logic Advanced Rule Templates

## Additional Rule Types

This section covers three advanced rule types in the Vinci Logic framework that enable more sophisticated detection capabilities:

1. **Threat Match** - For matching events against threat intelligence indicators
2. **Code-Based Detection** - For using custom Python scripts to implement complex detection logic
3. **Lucene Spark** - For SQL-based correlation of events across multiple data sources

These rule types extend the Vinci Logic framework's capabilities beyond simple pattern matching and statistical analysis, allowing for more advanced threat detection scenarios.

## 1. Threat Match Rule Type

Threat Match rules enable correlation between events in your environment and threat intelligence indicators. They are designed to detect communication with or usage of known malicious IPs, domains, hashes, or other indicators.

### Threat Match Rule Template

```yaml
title: [Threat Intelligence Source] [Indicator Type] Detection
uuid: [unique-identifier]
version_uuid: [version-unique-identifier]
severity: [low|medium|high|critical]
version: 1.0
effort_level: elementary
confidence: [low|medium|high]
maturity: [production|experimental|development]
enabled: true
learning_mode: false
capabilities:
  - Threat Detection
  - [Additional capability]
author: [Your Name]
creation_date: '[YYYY/MM/DD]'
updated_date: '[YYYY/MM/DD]'
description: [Description of what this rule detects, e.g., "Detect communication with known malicious IPs"]
integration: 'TI'
threat_timestamp_override: event.ingested
note: '[Additional notes]'
false_positives: '[Known false positive scenarios]'
references:
  - [URL to threat intelligence source]
tags:
  - CTI
  - [Threat Intelligence Source]
  - [Additional tags]

# Rule Type and Settings
type: threat_match
rule_type: threat_match
frequency: 60m
lifetime: 2h
threat_timestamp_override: ingest_timestamp

# Threat Intelligence Source Configuration
threat_indicator_indices: 
  - [threat-intelligence-index-pattern]
threat_indicator_query: "observable_type:[indicator_type] AND NOT observable_value:[exclusion_pattern]"
threat_indicator_depth: 14d
threat_indicator_group_match:
  - [threat_field]

# Event Source Configuration
indices:
  - [event-index-pattern]
query: "[field_to_match]:*"
group_match:
  - '[field_to_match_with_indicator]'
  - '[additional_field_for_context]'
depth: 6d

# Optional Exclusions
exclusions:
  exclusion_1:
    query: '[Exclusion query]'
    date: YYYY/MM/DD
    note: '[Explanation for exclusion]'
    author: [Author name]

# Mapping between events and threat indicators
threat_mapping_entries:
  - field: [threat_field]
    value: [event_field]

# Investigations for additional context
investigations:
  investigation1:
    type: query
    query: [field_to_match_with_indicator]:{{hit_context['threat_context']['threat_field']}} AND [additional_field]:{{hit_context['data_context']['additional_field']}}
    description: "[Description of investigation]"
    per_hit_description: "[Template for each hit with {{ investigation['hit']['field'] }}]"
    fallback: "[Message when no results found]"
    depth: 4d
    indices:
      - [event-index-pattern]
    group_match:
      - [field_to_match_with_indicator]

# Response actions
playbook:
  - name: create_ticket
    type: [thehive_soc|jira_soc]
    params:
      title: "[Ticket title with {{hit_context['data_context']['field']}} and {{hit_context['threat_context']['threat_field']}}]"
      description: |
        [Detailed description of the threat match with context from hit_context and investigations]
      tlp: 3
      pap: 3
      severity: 2
      flag: False
      tags:
       - "XDR"
       - "CTI"
    mode: single
```

### Key Components Specific to Threat Match Rules

- **threat_indicator_indices**: Index patterns where threat intelligence is stored
- **threat_indicator_query**: Query to filter relevant threat indicators
- **threat_indicator_depth**: How far back to look for threat indicators
- **threat_indicator_group_match**: Fields to group threat indicators
- **threat_mapping_entries**: Maps fields in threat intelligence to fields in event data
- **hit_context** structure includes two distinct contexts:
  - **threat_context**: Fields from the matching threat indicator
  - **data_context**: Fields from the event that matched the indicator

## 2. Code-Based Detection Rules

Code-based detection rules allow you to implement complex detection logic using custom Python scripts. This provides maximum flexibility for detection scenarios that can't be expressed using query languages or statistical approaches.

### Code-Based Detection Rule Template

```yaml
title: [Descriptive name for your code-based rule]
uuid: [unique-identifier]
version_uuid: [version-unique-identifier]
severity: [low|medium|high|critical]
enabled: [true|false]
learning_mode: [true|false]
description: [Description of what this rule detects]

# Detection Configuration
type: code
frequency: 5m
# Optional: Cron-based schedule instead of frequency
# cron: '0 */4 * * *'
lifetime: 30m

# Script Configuration
image: [container_image_name]
file: [path_to_python_script]
program: python
sha256: [script_file_hash]
data_sharing_method: shared_file

# Optional: Group matching for deduplication
group_match:
  - [field1]
  - [field2]

# Optional: Parameters to pass to the script
params:
  - name: [param_name]
    value: [param_value]
  - name: [another_param]
    value: [another_value]

# Data Queries for the Script
queries:
  [query_name]:
    language: lucene
    description: '[Description of the query purpose]'
    query: [Lucene query to retrieve data]
    depth: [time_range]
    indices:
      - [index_pattern]
    group_match:
      - [field1]
      - [field2]

# Optional: Investigations for additional context
investigations:
  [investigation_name]:
    type: query
    query: [Investigation query with template variables]
    description: "[Description text]"
    per_hit_description: "[Per hit description with {{ investigation['hit']['field'] }}]"
    fallback: "[Message when no results found]"
    depth: [time_range]
    indices:
      - [index_pattern]
    group_match:
      - [field1]

# Response actions
playbook:
  - name: [action_name]
    type: [action_type]
    params:
      [param1]: [value1]
      [param2]: [value2]
    mode: [single|group]
    if: [condition]
```

### Simplified Code-Based Rule Template

A minimal version is also possible for simpler cases:

```yaml
title: [Descriptive name]
uuid: [unique-identifier]
version_uuid: [version-unique-identifier]
severity: [low|medium|high|critical]
enabled: [true|false]
learning_mode: [true|false]
description: [Description of rule function]
type: code
frequency: 9m
image: [container_image_name]
file: [path_to_script]
sha256: [script_file_hash]
data_sharing_method: shared_file
playbook: null
```

### Key Components Specific to Code-Based Rules

- **image**: Container image name for script execution environment
- **file**: Path to the Python script that implements the detection logic
- **program**: Interpreter to use (typically "python")
- **sha256**: Hash of the script file for integrity verification
- **data_sharing_method**: Method for sharing data between the rule engine and script
- **params**: Key-value pairs to pass as parameters to the script
- **queries**: Named queries that provide data for the script to analyze

The Python script needs to follow specific conventions to interact with the Vinci Logic engine, including how it:
- Reads query results
- Reports detected events
- Handles parameters
- Returns results

## 3. Lucene Spark Rule Type

Lucene Spark rules allow using SQL queries via Apache Spark to correlate across multiple data sources or perform complex analytical processing. This is particularly useful for detecting multi-stage attacks or behavior patterns that span across different event types.

### Lucene Spark Rule Template

```yaml
title: [Descriptive name for your correlation detection]
uuid: [unique-identifier]
version_uuid: [version-unique-identifier]
severity: [low|medium|high|critical]
enabled: [true|false]
learning_mode: [true|false]
description: [Description of the complex pattern being detected]

# Rule Type and Settings
type: lucene_spark
frequency: 30m
lifetime: 5m

# Data Source Queries
source_queries:
  [query_name_1]:
    query: [Lucene query for first data source]
    depth: [time_range]
    indices:
      - [index_pattern]
  [query_name_2]:
    query: [Lucene query for second data source]
    depth: [time_range]
    indices:
      - [index_pattern]

# Spark SQL Query for Correlation Logic
spark_query: |
  WITH [temp_table_1] AS (
      SELECT [fields]
      FROM [query_name_1]_view
      WHERE [conditions]
      GROUP BY [fields]
  ),
  [temp_table_2] AS (
      SELECT [fields]
      FROM [query_name_2]_view
      WHERE [conditions]
  )
  SELECT [fields]
  FROM [temp_table_1] t1
  JOIN [temp_table_2] t2 ON t1.[join_field] = t2.[join_field]
  WHERE [correlation_conditions]
  GROUP BY [fields]
  ORDER BY [sort_field];

# Optional: Investigations for additional context
investigations:
  [investigation_name]:
    type: query
    query: [Investigation query with {{hit_context['field']}}]
    description: "[Description text]"
    per_hit_description: "[Per hit description with {{ investigation['hit']['field'] }}]"
    fallback: "[Message when no results found]"
    depth: [time_range]
    indices:
      - [index_pattern]
    group_match:
      - [field1]

# Response actions
playbook:
  - name: [action_name]
    type: [action_type]
    params:
      title: "[Ticket title with {{hit_context['field']}}]"
      description: |
        [Detailed description incorporating results from the Spark query
        and investigations]
      [additional_params]: [values]
    mode: [single|group]
```

### Key Components Specific to Lucene Spark Rules

- **source_queries**: Named Lucene queries that provide data sources for the Spark query
- **spark_query**: SQL query using Spark SQL syntax for correlating and analyzing data
  - Each query defined in source_queries is available as a view named `[query_name]_view`
  - Results of the Spark query become available in `hit_context`
- **Joins, window functions, and aggregations** in the SQL query enable complex correlation patterns

## Example Rules

### Threat Match Example: AbuseCH ThreatFox IP Detection

```yaml
title: AbuseCH Threatfox IP Live Check
uuid: abusech-threatfox-ip-live-check
version_uuid: v-cfe5c7e8-e8c5-404e-b90c-62c34a4e36d7udiixxxdiabdrdde
severity: medium
version: 1.0
effort_level: elementary
confidence: high
maturity: production
enabled: false
learning_mode: false
capabilities:
  - Threat Detection
author: tradah
creation_date: '09/07/2024'
updated_date: '09/07/2024'
description: Detect communication with malicious IPs
integration: 'TI'
threat_timestamp_override: event.ingested
note: '...'
false_positives: 'None'
references:
- https://threatfox.abuse.ch/
tags:
  - CTI
  - AbuseCH
type: threat_match
rule_type: threat_match
frequency: 60m
lifetime: 2h
threat_timestamp_override: ingest_timestamp
threat_indicator_indices: 
  - abusech-threatfox-*
threat_indicator_query: "observable_type:ip AND NOT observable_value:%domain_controllers_ips%"
threat_indicator_depth: 14d
threat_indicator_group_match:
  - threat_ip
indices:
  - filebeat-cloudflare*
query: "destination.ip:*"
group_match:
  - 'destination.ip'
  - 'host.name'
exclusions:
  exclusion_1:
    query: 'source.ip: 8.8.8.1'
    date: 2023/07/31
    note: 'An example of exclusion'
    author: tradah
threat_mapping_entries:
  - field: threat_ip
    value: destination.ip
depth: 6d
investigations:
  investigation1:
    type: query
    query: destination.ip:{{hit_context['threat_context']['threat_ip']}} AND host.name:{{hit_context['data_context']['host.name']}}
    description: ""
    per_hit_description: "**{{ investigation['hit']['destination.ip'] }} from {{investigation['hit']['host.name']}}**"
    fallback: "-"
    depth: 4d
    indices:
      - filebeat-cloudflare*
    group_match:
      - destination.ip
playbook:
  - name: create_a_grouped_thehive_ticket
    type: thehive_soc_sekera
    params:
      title: "AbuseCH Threatfox IP Live Check - from {{hit_context['data_context']['host.name']}} to {{hit_context['threat_context']['threat_ip']}}"
      description:  "Malicious connection from {{hit_context['data_context']['host.name']}} to {{hit_context['threat_context']['threat_ip']}}\
      \n\n\n\n{{investigations['investigation1']['report']}}.\n\n"
      tlp: 3
      pap: 3
      severity: 2
      flag: False
      tags:
       - "XDR"
       - "CTI"
    mode: single
```

### Code-Based Detection Example: Custom Python Script

```yaml
title: Code based detection rule
uuid: cfe5c7e8_code_based_detection_rule
version_uuid: v-cfe5imersddsql
severity: medium
enabled: false
learning_mode: false
description: Example of a code based detection rule
type: code
frequency: 5m
lifetime: 30m
image: default_python
file: code/code_test.py
program: python
sha256: cf22fd49471cb3fb9cf28dae70eb0e6a57875e7416800a0ded6d7700c4a70569
data_sharing_method: shared_file
group_match:
  - source.ip
  - user.name
  - host.name
params:
  - name: param1
    value: value1
  - name: param2
    value: value2
queries:
  query_1:
    language: lucene
    description: 'Get Network logins'
    query: event.code:4624 AND source.ip:* AND NOT source.ip:%non_existing_variable%
    depth: 9d
    indices:
      - winlogbeat-*
    group_match:
      - host.name
      - user.name
      - source.ip
  query_2:
    language: lucene
    description: 'Get created services'
    query: event.code:7045
    depth: 10m
    indices:
      - winlogbeat-*
    group_match:
      - service.name
      - host.name
playbook:
  - name: create_a_grouped_thehive_ticket
    type: thehive_soc_sekera
    params:
      title: "SQLITE TEST - {{rule_context['title']}}"
      description:  "{{rule_context['description']}}.\n timenow is {{ 'Europe/Paris' | timenow}} ."
      tlp: 3
      pap: 3
      severity: 2
      tags:
        - 'vincilogic'
    mode: single
    if: True
```

### Lucene Spark Example: Login Correlation

```yaml
title: Multiple failed logins followed by success for the same user
uuid: my-lucene-spark-rule-0-0-1-2-3-6-yrrddi
version_uuid: belisarious
severity: medium
enabled: false
learning_mode: false
description: Example of a lucene spark-based rule
type: lucene_spark
frequency: 30m
lifetime: 5m
source_queries:
  get_success_logins:
    query: event.code:4624
    depth: 148h
    indices:
      - "winlogbeat-*"
  get_failed_logins:
    query: event.code:4625
    depth: 148h
    indices:
      - "winlogbeat-*"
spark_query: |
  WITH failed_logons AS (
      SELECT winlog.event_data.TargetUserName AS TargetUserName,
             COUNT(CASE WHEN event.code = '4625' THEN 1 ELSE NULL END) AS failed_logon_count,
             MAX(CASE WHEN event.code = '4625' THEN `@timestamp` END) AS last_failed_logon
      FROM get_failed_logins_view
      WHERE event.code = '4625'
      GROUP BY winlog.event_data.TargetUserName
  ),
  successful_logons AS (
      SELECT winlog.event_data.TargetUserName AS TargetUserName,
             `@timestamp` AS successful_logon_time,
             winlog.event_data.IpAddress AS successful_ip
      FROM get_success_logins_view
      WHERE event.code = '4624'
  )
  SELECT f.TargetUserName,
         f.failed_logon_count,
         f.last_failed_logon,
         MIN(s.successful_logon_time) AS first_successful_logon,
         ANY_VALUE(s.successful_ip) AS first_successful_ip
  FROM failed_logons f
  JOIN successful_logons s ON f.TargetUserName = s.TargetUserName
  WHERE f.failed_logon_count > 3
    AND s.successful_logon_time > f.last_failed_logon
    AND s.successful_logon_time <= TIMESTAMPADD(SECOND, 300, f.last_failed_logon)
  GROUP BY f.TargetUserName, f.failed_logon_count, f.last_failed_logon
  ORDER BY first_successful_logon DESC;
investigations:
  failed_logins:
    type: query
    query: event.code:4625 AND user.name:{{hit_context['TargetUserName']}} AND source.ip:*
    description: "Failed logins summary: "
    per_hit_description: "\n - Failed login from **{{ investigation['hit']['source.ip'] }}** on **{{ investigation['hit']['host.name'] }}**."
    fallback: "No failed logins."
    depth: 148h
    indices:
      - winlogbeat-*
    group_match:
      - user.name
      - host.name
      - source.ip
playbook:
  - name: create_a_grouped_thehive_ticket
    type: thehive_soc_sekera
    params:
      title: "{{rule_context['title']}}"
      description: "\
        {{rule_context['description']}}.\n\n\n\
        The user {{hit_context['TargetUserName']}} failed to login {{hit_context['failed_logon_count']}} times \
        before successfully logging in at {{hit_context['first_successful_logon']}} \
        from IP address {{hit_context['first_successful_ip']}}.\n\n\
        {{ investigations['failed_logins']['report'] }}"
      tlp: 3
      pap: 3
      severity: 2
      flag: False
      tags:
        - 'vincilogic'
        - 'delete_me'
    mode: single
```

## Additional Tips for Advanced Rule Types

### For Threat Match Rules:
1. **Indicator Quality**: Ensure your threat intelligence sources are high-quality and regularly updated
2. **Context Preservation**: Use investigations to gather additional context about matched events
3. **False Positive Management**: Implement exclusions for known benign matches
4. **Indicator Freshness**: Set appropriate `threat_indicator_depth` to focus on recent indicators

### For Code-Based Rules:
1. **Environment Consistency**: Ensure the execution environment (`image`) has all necessary dependencies
2. **Error Handling**: Implement robust error handling in your Python scripts
3. **Query Optimization**: Keep data queries focused to minimize data transfer
4. **Parameter Flexibility**: Use parameters to make your scripts adaptable without code changes
5. **Version Control**: Maintain scripts in a version control system alongside rule definitions

### For Lucene Spark Rules:
1. **Query Performance**: Optimize SQL queries by limiting selected fields and using efficient joins
2. **Time Boundaries**: Set appropriate time boundaries to balance detection capability with performance
3. **Data Volume**: Be mindful of data volume in source queries to avoid performance issues
4. **SQL Complexity**: Start with simpler queries and incrementally add complexity
5. **Testing**: Test queries on historical data to validate results before deployment

These advanced rule types significantly extend the detection capabilities of the Vinci Logic framework, enabling sophisticated threat detection scenarios that would be difficult or impossible to implement using basic rule types.