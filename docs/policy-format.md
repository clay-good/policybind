# PolicyBind Policy Format

This document describes the YAML format for PolicyBind policy files.

## Overview

PolicyBind policies are written in YAML and define rules for controlling AI API access. Each policy file contains a set of rules that are evaluated against incoming requests.

## Basic Structure

```yaml
name: my-policy
version: "1.0.0"
description: Description of what this policy does

variables:
  max_cost: 10.0
  allowed_departments:
    - engineering
    - research

rules:
  - name: rule-name
    description: What this rule does
    match:
      # conditions to match
    action: DENY
    action_params:
      # action-specific parameters
    priority: 100
    enabled: true
    tags:
      - production
```

## Policy Metadata

### Required Fields

- `name`: Unique identifier for the policy (string)
- `version`: Version string for tracking changes (string)

### Optional Fields

- `description`: Human-readable description (string)
- `variables`: Key-value pairs for variable substitution (mapping)
- `metadata`: Additional custom metadata (mapping)
- `include`: List of other policy files to include (list)

## Rules

Each rule defines a condition-action pair. When a request matches the conditions, the specified action is taken.

### Rule Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | Yes | - | Unique identifier for the rule |
| `description` | string | No | "" | Human-readable description |
| `match` | mapping | No | {} | Conditions to match (alias: `match_conditions`) |
| `action` | string | Yes | - | Action to take when matched |
| `action_params` | mapping | No | {} | Parameters for the action |
| `priority` | integer | No | 0 | Higher priority rules are evaluated first |
| `enabled` | boolean | No | true | Whether the rule is active |
| `tags` | list | No | [] | Tags for categorization |

## Match Conditions

Match conditions specify when a rule should apply. Conditions can be simple values or use operators for complex matching.

### Simple Matching

```yaml
match:
  provider: openai
  department: engineering
```

### Operator-Based Matching

```yaml
match:
  cost:
    gt: 1.0
  data_classification:
    contains: pii
```

### Available Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `eq` | Equals | `model: { eq: "gpt-4" }` |
| `ne` | Not equals | `provider: { ne: "openai" }` |
| `gt` | Greater than | `cost: { gt: 10.0 }` |
| `gte` | Greater than or equal | `tokens: { gte: 1000 }` |
| `lt` | Less than | `cost: { lt: 5.0 }` |
| `lte` | Less than or equal | `tokens: { lte: 500 }` |
| `in` | In list | `department: { in: ["eng", "research"] }` |
| `not_in` | Not in list | `user: { not_in: ["bot1", "bot2"] }` |
| `contains` | Contains value | `data_classification: { contains: "pii" }` |
| `not_contains` | Does not contain | `tags: { not_contains: "test" }` |
| `matches` | Regex match | `model: { matches: "gpt-4.*" }` |
| `exists` | Field exists | `metadata.project: { exists: true }` |
| `not_exists` | Field does not exist | `approval_ticket: { not_exists: true }` |

### Condition Fields

| Field | Description |
|-------|-------------|
| `provider` | AI provider name (openai, anthropic, etc.) |
| `model` | Model name (gpt-4, claude-3, etc.) |
| `department` | Requesting department |
| `user` / `user_id` | User identifier |
| `data_classification` | Data types in request (pii, financial, etc.) |
| `use_case` / `intended_use_case` | Purpose of the request |
| `cost` / `estimated_cost` | Estimated cost in USD |
| `tokens` / `estimated_tokens` | Estimated token count |
| `source` / `source_application` | Application making the request |
| `time` | Time-based conditions |
| `day_of_week` | Day of week (0-6, Monday=0) |
| `hour_of_day` | Hour of day (0-23) |
| `metadata` | Custom metadata fields |

### Logical Operators

Combine conditions with logical operators:

```yaml
# AND - all conditions must match
match:
  and:
    - provider: openai
    - department: engineering

# OR - any condition must match
match:
  or:
    - department: engineering
    - department: research

# NOT - negate a condition
match:
  not:
    data_classification:
      contains: pii

# Complex combinations
match:
  and:
    - provider: openai
    - or:
        - department: engineering
        - user:
            in: ["admin1", "admin2"]
    - not:
        cost:
          gt: 100.0
```

## Actions

Actions define what happens when a rule matches.

### ALLOW

Permit the request to proceed unchanged.

```yaml
action: ALLOW
```

### DENY

Block the request entirely.

```yaml
action: DENY
action_params:
  reason: "Request denied due to policy violation"
```

### MODIFY

Transform the request before allowing it.

```yaml
action: MODIFY
action_params:
  modifications:
    redact_pii: true
    max_tokens: 1000
  reason: "Request modified for compliance"
```

### REQUIRE_APPROVAL

Queue the request for human approval.

```yaml
action: REQUIRE_APPROVAL
action_params:
  approvers:
    - security-team
    - manager
  timeout_hours: 24
  reason: "High-risk request requires approval"
```

### RATE_LIMIT

Apply rate limiting to the request.

```yaml
action: RATE_LIMIT
action_params:
  requests_per_minute: 10
  burst_size: 5
  key: user  # Rate limit by user, department, or source
```

### AUDIT

Allow but flag the request for review.

```yaml
action: AUDIT
action_params:
  audit_level: high
  tags:
    - suspicious
    - review-needed
  reason: "Unusual pattern detected"
```

### REDIRECT

Route to a different model or endpoint.

```yaml
action: REDIRECT
action_params:
  target_provider: openai
  target_model: gpt-3.5-turbo
  reason: "Redirected to cost-effective model"
```

## Variables

Define variables for reuse throughout the policy:

```yaml
variables:
  max_cost: 10.0
  allowed_models:
    - gpt-4
    - claude-3

rules:
  - name: enforce-cost-limit
    match:
      cost:
        gt: ${max_cost}
    action: DENY

  - name: allow-approved-models
    match:
      model:
        in: ${allowed_models}
    action: ALLOW
```

## Includes

Include other policy files:

```yaml
include:
  - common/base-rules.yaml
  - department/engineering.yaml

# Additional rules specific to this file
rules:
  - name: local-rule
    # ...
```

Included files are processed in order, and their rules are merged into the main policy.

## Priority

Rules are evaluated in priority order (highest first). When multiple rules match, the highest priority rule's action is taken.

```yaml
rules:
  # This rule is checked first
  - name: emergency-block
    priority: 1000
    match:
      metadata.emergency: true
    action: DENY

  # This rule is checked second
  - name: allow-engineering
    priority: 100
    match:
      department: engineering
    action: ALLOW

  # Default rule (lowest priority)
  - name: default-deny
    priority: 0
    match: {}  # Matches everything
    action: DENY
```

## Examples

### Basic Cost Control

```yaml
name: cost-control
version: "1.0.0"
description: Control AI spending by department

variables:
  engineering_limit: 100.0
  marketing_limit: 50.0

rules:
  - name: engineering-cost-limit
    description: Limit engineering department spending
    match:
      and:
        - department: engineering
        - cost:
            gt: ${engineering_limit}
    action: DENY
    action_params:
      reason: "Request exceeds department cost limit"
    priority: 100

  - name: marketing-cost-limit
    match:
      and:
        - department: marketing
        - cost:
            gt: ${marketing_limit}
    action: DENY
    priority: 100

  - name: allow-all
    match: {}
    action: ALLOW
    priority: 0
```

### Data Classification Policy

```yaml
name: data-classification
version: "1.0.0"
description: Enforce data handling rules

rules:
  - name: block-pii-to-external
    description: Block PII data from going to external models
    match:
      and:
        - data_classification:
            contains: pii
        - provider:
            not_in: ["internal", "on-premise"]
    action: DENY
    priority: 500

  - name: audit-financial-data
    description: Audit all requests with financial data
    match:
      data_classification:
        contains: financial
    action: AUDIT
    action_params:
      audit_level: high
      tags:
        - financial
        - compliance
    priority: 400

  - name: default-allow
    match: {}
    action: ALLOW
    priority: 0
```

### Model Access Control

```yaml
name: model-access
version: "1.0.0"
description: Control access to AI models

variables:
  premium_models:
    - gpt-4
    - claude-3-opus

rules:
  - name: premium-model-approval
    description: Require approval for premium models
    match:
      model:
        in: ${premium_models}
    action: REQUIRE_APPROVAL
    action_params:
      approvers:
        - ai-governance
      timeout_hours: 4
    priority: 200

  - name: redirect-to-efficient
    description: Redirect simple queries to efficient models
    match:
      and:
        - use_case: simple_query
        - model:
            in: ${premium_models}
    action: REDIRECT
    action_params:
      target_model: gpt-3.5-turbo
      reason: "Redirected for cost efficiency"
    priority: 300

  - name: allow-standard
    match: {}
    action: ALLOW
    priority: 0
```

## Best Practices

1. **Use meaningful names**: Rule names should describe what the rule does.

2. **Add descriptions**: Always add descriptions to explain the purpose of rules.

3. **Set explicit priorities**: Don't rely on default priorities; be explicit about rule ordering.

4. **Use variables**: Extract common values into variables for maintainability.

5. **Include a default rule**: Always include a catch-all rule at the lowest priority.

6. **Tag rules**: Use tags to categorize rules for filtering and reporting.

7. **Test policies**: Validate policies before deploying to production.

8. **Version policies**: Use semantic versioning to track policy changes.

9. **Document exceptions**: When rules have exceptions, document why.

10. **Review regularly**: Schedule regular reviews of policy effectiveness.
