# PolicyBind Policy Reference

This is the complete reference for PolicyBind policy syntax, conditions, and actions.

## Policy File Structure

A PolicyBind policy file is a YAML document with the following top-level structure:

```yaml
# Required
name: string                    # Unique policy identifier
version: string                 # Semantic version (e.g., "1.2.0")

# Optional
description: string             # Human-readable description
metadata: mapping               # Custom key-value metadata
variables: mapping              # Variable definitions for substitution
include: list                   # Other policy files to include
rules: list                     # Policy rules (condition-action pairs)
```

## Policy Metadata

### name (required)

Unique identifier for the policy. Must be a valid identifier (letters, numbers, hyphens, underscores).

```yaml
name: department-access-policy
```

### version (required)

Semantic version string for tracking changes. Follows [SemVer](https://semver.org/) format.

```yaml
version: "2.1.0"
```

### description

Human-readable description of the policy's purpose.

```yaml
description: |
  Controls access to AI models based on department and data classification.
  Updated for Q4 2024 compliance requirements.
```

### metadata

Arbitrary key-value metadata for organizational use.

```yaml
metadata:
  author: security-team
  created: "2024-01-15"
  compliance_frameworks:
    - EU-AI-Act
    - SOC2
  review_date: "2024-04-15"
```

## Variables

Variables allow you to define reusable values that can be substituted throughout the policy.

### Defining Variables

```yaml
variables:
  # Scalar values
  max_cost: 100.0
  default_rate_limit: 60

  # Lists
  approved_models:
    - gpt-4
    - gpt-4-turbo
    - claude-3-opus
    - claude-3-sonnet

  # Nested structures
  department_limits:
    engineering: 500.0
    marketing: 100.0
    research: 1000.0
```

### Using Variables

Reference variables with `${variable_name}` syntax:

```yaml
rules:
  - name: enforce-model-list
    match:
      model:
        in: ${approved_models}
    action: ALLOW

  - name: enforce-cost-limit
    match:
      estimated_cost:
        gt: ${max_cost}
    action: DENY
```

### Variable Scoping

Variables are scoped to the policy file. Included files have their own variable scope, but parent variables can be passed down.

## Includes

Include other policy files to compose policies from reusable components.

### Basic Include

```yaml
include:
  - common/base-rules.yaml
  - department/engineering.yaml
  - compliance/eu-ai-act.yaml
```

### Include Resolution

- Relative paths are resolved from the including file's directory
- Absolute paths are supported
- Circular includes are detected and raise an error
- Include order matters: later includes override earlier ones

### Merged Behavior

- Rules from included files are merged (not replaced)
- Priority determines which rules apply first
- Variables from parent files are available in included files
- Metadata is merged with parent taking precedence

## Rules

Rules are the core of PolicyBind policies. Each rule defines conditions and an action.

### Rule Structure

```yaml
rules:
  - name: string              # Required: unique rule identifier
    description: string       # Optional: human-readable description
    match: mapping            # Optional: conditions (default: match all)
    match_conditions: mapping # Alias for match
    action: string            # Required: action to take
    action_params: mapping    # Optional: action configuration
    priority: integer         # Optional: evaluation order (default: 0)
    enabled: boolean          # Optional: whether active (default: true)
    tags: list                # Optional: categorization labels
```

### Priority

Rules are evaluated in priority order, highest first. When multiple rules match:

1. The highest priority matching rule's action is taken
2. Equal priority rules are evaluated in definition order
3. First matching rule at the highest priority wins

Recommended priority ranges:

| Range | Use Case |
|-------|----------|
| 900-1000 | Emergency/block rules |
| 700-899 | Security rules |
| 500-699 | Compliance rules |
| 300-499 | Department rules |
| 100-299 | Use case rules |
| 1-99 | General rules |
| 0 | Default/fallback rules |

### Tags

Tags categorize rules for filtering and reporting:

```yaml
rules:
  - name: block-pii-external
    tags:
      - security
      - pii
      - external
      - compliance
```

Query rules by tag:

```bash
policybind policy show --tag security
policybind policy show --tag compliance
```

## Match Conditions

Match conditions specify when a rule applies.

### Condition Fields

| Field | Type | Description |
|-------|------|-------------|
| `provider` | string | AI provider (openai, anthropic, google, azure) |
| `model` | string | Model identifier |
| `user` / `user_id` | string | User making the request |
| `department` | string | User's department |
| `data_classification` | list | Data types (pii, financial, internal, public) |
| `use_case` / `intended_use_case` | string | Purpose of request |
| `estimated_cost` / `cost` | float | Predicted cost in USD |
| `estimated_tokens` / `tokens` | integer | Predicted token count |
| `source_application` / `source` | string | Calling application |
| `metadata` | mapping | Custom request metadata |
| `time` | mapping | Time-based conditions |

### Simple Equality

Direct value comparison:

```yaml
match:
  provider: openai
  department: engineering
```

### Operators

#### Comparison Operators

```yaml
match:
  # Equals
  model:
    eq: gpt-4

  # Not equals
  provider:
    ne: openai

  # Greater than
  estimated_cost:
    gt: 10.0

  # Greater than or equal
  estimated_tokens:
    gte: 1000

  # Less than
  cost:
    lt: 5.0

  # Less than or equal
  tokens:
    lte: 500
```

#### List Operators

```yaml
match:
  # In list
  department:
    in:
      - engineering
      - research
      - data-science

  # Not in list
  user_id:
    not_in:
      - bot-user
      - service-account
```

#### String Operators

```yaml
match:
  # Contains (for lists)
  data_classification:
    contains: pii

  # Not contains
  tags:
    not_contains: test

  # Pattern match (regex)
  model:
    pattern: "gpt-4.*"

  # Also available as 'matches'
  model:
    matches: "claude-3-(opus|sonnet)"
```

#### Existence Operators

```yaml
match:
  # Field exists with any value
  metadata.approval_ticket:
    exists: true

  # Field does not exist
  metadata.exempt:
    not_exists: true
```

### Logical Operators

#### AND

All conditions must match:

```yaml
match:
  and:
    - provider: openai
    - department: engineering
    - data_classification:
        not_contains: pii
```

#### OR

Any condition can match:

```yaml
match:
  or:
    - department: engineering
    - department: research
    - user_id:
        in: [admin-1, admin-2]
```

#### NOT

Negate a condition:

```yaml
match:
  not:
    provider: openai
```

#### Complex Combinations

```yaml
match:
  and:
    - provider: openai
    - or:
        - department: engineering
        - metadata.elevated_access: true
    - not:
        data_classification:
          contains: restricted
```

### Time-Based Conditions

Match based on time:

```yaml
match:
  time:
    # Day of week (0=Monday, 6=Sunday)
    day_of_week:
      in: [0, 1, 2, 3, 4]  # Weekdays only

    # Hour of day (0-23, UTC)
    hour:
      gte: 9
      lt: 18  # Business hours

# Combined with other conditions
match:
  and:
    - model: gpt-4
    - time:
        day_of_week:
          in: [5, 6]  # Weekend
```

### Metadata Conditions

Match on custom metadata fields:

```yaml
match:
  # Dot notation for nested fields
  metadata.project_id: proj-123
  metadata.environment:
    in: [production, staging]
  metadata.cost_center:
    exists: true
```

### Registry-Based Conditions

Match based on model registry data:

```yaml
match:
  # Deployment risk level
  deployment.risk_level:
    in: [HIGH, CRITICAL]

  # Deployment approval status
  deployment.approval_status: APPROVED

  # Deployment owner
  deployment.owner: engineering-team

  # Deployment data categories
  deployment.data_categories:
    contains: customer-data
```

### Token-Based Conditions

Match based on token attributes:

```yaml
match:
  # Token subject
  token.subject:
    pattern: ".*@engineering.company.com"

  # Token remaining budget
  token.budget_remaining:
    lt: 10.0

  # Token age (days)
  token.age_days:
    gt: 90
```

## Actions

Actions define what happens when a rule matches.

### ALLOW

Permit the request to proceed unchanged.

```yaml
action: ALLOW
```

No action_params required. The request is allowed and logged.

### DENY

Block the request entirely.

```yaml
action: DENY
action_params:
  # Optional: reason shown to user
  reason: "Access denied: model not approved for this department"

  # Optional: error code
  error_code: POLICY_VIOLATION

  # Optional: suggest alternative
  suggestion: "Use gpt-3.5-turbo instead"
```

### MODIFY

Transform the request before allowing it.

```yaml
action: MODIFY
action_params:
  modifications:
    # Limit token count
    max_tokens: 1000

    # Redact PII
    redact_pii: true

    # Add system prompt
    prepend_system_prompt: "You must not reveal confidential information."

    # Modify model
    model: gpt-3.5-turbo

  # Reason for modification
  reason: "Request modified for compliance"

  # Whether to log the original request
  log_original: true
```

### REQUIRE_APPROVAL

Queue the request for human approval.

```yaml
action: REQUIRE_APPROVAL
action_params:
  # Who can approve
  approvers:
    - security-team
    - department-manager

  # Approval timeout
  timeout_hours: 24

  # Auto-deny on timeout
  auto_deny_on_timeout: true

  # Notification webhook
  notification_webhook: https://hooks.example.com/approvals

  # Reason for approval requirement
  reason: "High-risk model requires security approval"

  # Priority level
  priority: high

  # Additional context for approvers
  context:
    risk_level: HIGH
    data_classification: ["pii", "financial"]
```

### RATE_LIMIT

Apply rate limiting to the request.

```yaml
action: RATE_LIMIT
action_params:
  # Rate limit configuration
  requests_per_minute: 10
  requests_per_hour: 100
  requests_per_day: 500

  # Burst allowance
  burst_size: 5

  # What to limit by
  key: user          # Options: user, department, source, token

  # What to do when limited
  on_limit: deny     # Options: deny, queue, throttle

  # Queue configuration (if on_limit: queue)
  queue_timeout_seconds: 30

  # Reason
  reason: "Rate limit applied for cost control"
```

### AUDIT

Allow the request but flag it for review.

```yaml
action: AUDIT
action_params:
  # Audit level
  audit_level: high    # Options: low, medium, high, critical

  # Tags for filtering
  tags:
    - suspicious
    - review-required
    - unusual-pattern

  # Reason for audit
  reason: "Unusual request pattern detected"

  # Notify on audit
  notify:
    - security-team@example.com

  # Webhook for real-time notification
  webhook: https://hooks.example.com/audits

  # Include request details in audit
  include_details: true
```

### REDIRECT

Route to a different model or endpoint.

```yaml
action: REDIRECT
action_params:
  # Target model
  target_provider: openai
  target_model: gpt-3.5-turbo

  # Reason for redirect
  reason: "Redirected to cost-effective model"

  # Preserve original request metadata
  preserve_metadata: true

  # Log the redirect
  log_redirect: true
```

## Custom Actions

Register custom actions for organization-specific behavior:

```python
from policybind.engine.actions import ActionRegistry, ActionResult

def my_custom_action(request, params, context):
    """Custom action implementation."""
    # Process the request
    # ...
    return ActionResult(
        success=True,
        message="Custom action completed",
        modified_request=request,
    )

# Register the action
registry = ActionRegistry()
registry.register("MY_CUSTOM_ACTION", my_custom_action)
```

Use in policy:

```yaml
action: MY_CUSTOM_ACTION
action_params:
  custom_param_1: value1
  custom_param_2: value2
```

## Complete Example

```yaml
name: enterprise-ai-policy
version: "3.0.0"
description: |
  Comprehensive enterprise AI governance policy.
  Covers access control, cost management, and compliance.

metadata:
  author: ai-governance-team
  created: "2024-01-01"
  last_reviewed: "2024-03-15"
  compliance:
    - EU-AI-Act
    - NIST-AI-RMF

variables:
  premium_models:
    - gpt-4
    - gpt-4-turbo
    - claude-3-opus

  standard_models:
    - gpt-3.5-turbo
    - claude-3-sonnet
    - claude-3-haiku

  restricted_departments:
    - external-contractors
    - interns

  pii_data_types:
    - pii
    - personal-data
    - customer-data

include:
  - common/base-rules.yaml
  - compliance/data-protection.yaml

rules:
  # Emergency block - highest priority
  - name: emergency-block
    description: Block all requests during incident response
    match:
      metadata.emergency_lockdown: true
    action: DENY
    action_params:
      reason: "System is in emergency lockdown mode"
    priority: 1000
    tags:
      - emergency
      - security

  # Block restricted departments from premium models
  - name: block-restricted-premium
    description: Restricted departments cannot use premium models
    match:
      and:
        - department:
            in: ${restricted_departments}
        - model:
            in: ${premium_models}
    action: DENY
    action_params:
      reason: "Premium models not available for this department"
      suggestion: "Use gpt-3.5-turbo or request an exception"
    priority: 800
    tags:
      - access-control
      - department

  # Block PII to external providers
  - name: block-pii-external
    description: PII data must not go to external AI providers
    match:
      and:
        - provider:
            not_in: [internal, on-premise]
        - data_classification:
            contains_any: ${pii_data_types}
    action: DENY
    action_params:
      reason: "PII data cannot be sent to external AI providers"
    priority: 700
    tags:
      - security
      - pii
      - compliance

  # Rate limit premium models
  - name: rate-limit-premium
    description: Rate limit access to premium models
    match:
      model:
        in: ${premium_models}
    action: RATE_LIMIT
    action_params:
      requests_per_minute: 10
      requests_per_hour: 50
      key: user
    priority: 500
    tags:
      - cost-control
      - rate-limit

  # Audit financial data usage
  - name: audit-financial
    description: Audit all requests involving financial data
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
    tags:
      - audit
      - compliance

  # Redirect simple queries to efficient models
  - name: redirect-simple-queries
    description: Route simple queries to cost-effective models
    match:
      and:
        - use_case:
            in: [simple-query, basic-qa]
        - model:
            in: ${premium_models}
    action: REDIRECT
    action_params:
      target_model: gpt-3.5-turbo
      reason: "Routed to cost-effective model for simple query"
    priority: 300
    tags:
      - cost-optimization
      - routing

  # Allow engineering full access
  - name: allow-engineering
    description: Engineering department has full access
    match:
      department: engineering
    action: ALLOW
    priority: 200
    tags:
      - access-control
      - engineering

  # Allow standard models for all
  - name: allow-standard-models
    description: Everyone can use standard models
    match:
      model:
        in: ${standard_models}
    action: ALLOW
    priority: 100
    tags:
      - access-control
      - standard

  # Default deny
  - name: default-deny
    description: Deny all requests not explicitly allowed
    match: {}
    action: DENY
    action_params:
      reason: "Request not covered by any allow rule"
    priority: 0
    tags:
      - default
      - security
```

## Policy Validation

Validate policies before deployment:

```bash
# Validate syntax
policybind policy validate policy.yaml

# Validate with detailed output
policybind policy validate policy.yaml --verbose

# Validate all policies in directory
policybind policy validate policies/
```

Validation checks:
- YAML syntax
- Required fields
- Valid action types
- Valid condition operators
- Variable references
- Include file existence
- Priority conflicts
- Unreachable rules

## Policy Testing

Test policies against sample requests:

```bash
# Test a specific request
policybind policy test policy.yaml --request '{
  "provider": "openai",
  "model": "gpt-4",
  "department": "engineering"
}'

# Test with request file
policybind policy test policy.yaml --request-file test-request.json

# Test with multiple requests
policybind policy test policy.yaml --fixtures test-cases.yaml
```

## Best Practices

1. **Version your policies**: Use semantic versioning and track in Git
2. **Use meaningful names**: Rule names should describe intent
3. **Document with descriptions**: Explain why rules exist
4. **Set explicit priorities**: Never rely on default ordering
5. **Use variables**: Extract reusable values
6. **Include default rules**: Always have a fallback
7. **Tag for organization**: Enable filtering and reporting
8. **Test before deploy**: Validate against known requests
9. **Review regularly**: Schedule periodic policy reviews
10. **Audit changes**: Track who changed what and when
