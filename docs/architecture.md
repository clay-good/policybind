# PolicyBind Architecture

This document describes the internal architecture of PolicyBind, including component responsibilities, data flow, and extension points.

## System Overview

PolicyBind is designed as a modular, extensible platform for AI governance. It can run as:

- **Library**: Embedded directly in Python applications
- **Server**: Standalone HTTP service for centralized enforcement
- **CLI**: Command-line tool for operations and management

```
                                    +------------------+
                                    |   Applications   |
                                    +--------+---------+
                                             |
                    +------------------------+------------------------+
                    |                        |                        |
            +-------v-------+        +-------v-------+        +-------v-------+
            |  Python SDK   |        |   HTTP API    |        |     CLI       |
            +-------+-------+        +-------+-------+        +-------+-------+
                    |                        |                        |
                    +------------------------+------------------------+
                                             |
                                    +--------v---------+
                                    |                  |
                                    |   PolicyBind     |
                                    |     Core         |
                                    |                  |
                                    +--------+---------+
                                             |
              +------------+-----------+-----+-----+-----------+------------+
              |            |           |           |           |            |
      +-------v---+ +------v----+ +----v-----+ +---v----+ +----v----+ +-----v-----+
      |  Policy   | |  Model    | |  Token   | |Incident| | Audit   | |  Reports  |
      |  Engine   | | Registry  | | Manager  | |Manager | | Logger  | | Generator |
      +-----------+ +-----------+ +----------+ +--------+ +---------+ +-----------+
              |            |           |           |           |            |
              +------------+-----------+-----+-----+-----------+------------+
                                             |
                                    +--------v---------+
                                    |                  |
                                    |    Database      |
                                    |    (SQLite)      |
                                    |                  |
                                    +------------------+
```

## Core Components

### Policy Engine

The Policy Engine is the heart of PolicyBind, responsible for loading, validating, and evaluating policies.

```
+------------------------------------------------------------------+
|                         Policy Engine                             |
|                                                                   |
|  +----------------+    +----------------+    +-----------------+  |
|  |    Parser      |    |   Validator    |    |    Matcher      |  |
|  |                |    |                |    |                 |  |
|  | - YAML parsing | -> | - Syntax check | -> | - Condition     |  |
|  | - Includes     |    | - Semantic     |    |   evaluation    |  |
|  | - Variables    |    |   validation   |    | - Priority      |  |
|  +----------------+    +----------------+    |   ordering      |  |
|                                              +-----------------+  |
|                                                      |            |
|                                              +-------v---------+  |
|                                              |    Pipeline     |  |
|                                              |                 |  |
|                                              | - Middleware    |  |
|                                              | - Action exec   |  |
|                                              | - Logging       |  |
|                                              +-----------------+  |
+------------------------------------------------------------------+
```

#### Parser (`policybind.engine.parser`)

- Parses YAML policy files
- Resolves includes and variable substitutions
- Produces PolicySet objects

#### Validator (`policybind.engine.validator`)

- Validates policy syntax and semantics
- Detects conflicts and unreachable rules
- Returns detailed validation results

#### Matcher (`policybind.engine.matcher`)

- Evaluates requests against policies
- Implements condition logic (AND, OR, NOT)
- Returns matching rules sorted by priority

#### Pipeline (`policybind.engine.pipeline`)

- Orchestrates the enforcement flow
- Manages middleware chain
- Executes actions and handles results

### Enforcement Pipeline

The pipeline processes each request through multiple stages:

```
Request
   |
   v
+------------------+
| Request Logging  |  Log incoming request
+------------------+
   |
   v
+------------------+
| Authentication   |  Validate token/API key
+------------------+
   |
   v
+------------------+
| Enrichment       |  Add registry/token data
+------------------+
   |
   v
+------------------+
| Validation       |  Check required fields
+------------------+
   |
   v
+------------------+
| Classification   |  Verify data classification
+------------------+
   |
   v
+------------------+
| Policy Matching  |  Find applicable rules
+------------------+
   |
   v
+------------------+
| Action Execution |  Run matched action
+------------------+
   |
   v
+------------------+
| Response Logging |  Log decision
+------------------+
   |
   v
Response
```

Each stage is implemented as middleware that can:
- Modify the request context
- Short-circuit processing (return early)
- Add metadata for later stages
- Generate audit events

### Model Registry

The Model Registry tracks all AI deployments in the organization.

```
+------------------------------------------------------------------+
|                        Model Registry                             |
|                                                                   |
|  +----------------+    +----------------+    +-----------------+  |
|  |    Manager     |    | Risk Assessor  |    |   Compliance    |  |
|  |                |    |                |    |    Checker      |  |
|  | - CRUD ops     |    | - Risk scoring |    |                 |  |
|  | - Lifecycle    |    | - Factors      |    | - Framework     |  |
|  | - Events       |    | - Mitigations  |    |   mapping       |  |
|  +----------------+    +----------------+    | - Gap analysis  |  |
|                                              +-----------------+  |
|                                                                   |
|  +----------------+    +----------------+                         |
|  |   Workflows    |    | Notifications  |                         |
|  |                |    |                |                         |
|  | - Approval     |    | - Email        |                         |
|  | - Review       |    | - Webhook      |                         |
|  | - Suspension   |    | - Templates    |                         |
|  +----------------+    +----------------+                         |
+------------------------------------------------------------------+
```

#### Manager (`policybind.registry.manager`)

- Manages deployment lifecycle
- Enforces business rules
- Emits events for integrations

#### Risk Assessor (`policybind.registry.risk`)

- Computes risk levels from deployment attributes
- Considers data categories, model capabilities, exposure
- Suggests mitigations

#### Compliance Checker (`policybind.registry.compliance`)

- Maps deployments to compliance frameworks
- Identifies gaps and required documentation
- Generates compliance reports

### Token Manager

The Token Manager handles scoped access tokens.

```
+------------------------------------------------------------------+
|                        Token Manager                              |
|                                                                   |
|  +----------------+    +----------------+    +-----------------+  |
|  |    Manager     |    |   Validator    |    |     Budget      |  |
|  |                |    |                |    |    Tracker      |  |
|  | - Issue tokens |    | - Verify token |    |                 |  |
|  | - Revocation   |    | - Check perms  |    | - Usage track   |  |
|  | - Lifecycle    |    | - Validate req |    | - Period reset  |  |
|  +----------------+    +----------------+    +-----------------+  |
|                                                                   |
|  +----------------+    +----------------+                         |
|  |  NL Parser     |    |   Templates    |                         |
|  |                |    |                |                         |
|  | - Parse text   |    | - Predefined   |                         |
|  | - Extract      |    |   permissions  |                         |
|  |   permissions  |    | - Extensible   |                         |
|  +----------------+    +----------------+                         |
+------------------------------------------------------------------+
```

#### Natural Language Parser (`policybind.tokens.natural_language`)

- Parses permission descriptions in plain English
- Extracts structured TokenPermissions
- Returns confidence scores

### Incident Manager

The Incident Manager tracks policy violations and AI safety events.

```
+------------------------------------------------------------------+
|                       Incident Manager                            |
|                                                                   |
|  +----------------+    +----------------+    +-----------------+  |
|  |    Manager     |    |   Detector     |    |   Workflows     |  |
|  |                |    |                |    |                 |  |
|  | - CRUD ops     |    | - Pattern      |    | - Triage        |  |
|  | - Lifecycle    |    |   detection    |    | - Investigation |  |
|  | - Linking      |    | - Anomaly      |    | - Remediation   |  |
|  +----------------+    +----------------+    +-----------------+  |
|                                                                   |
|  +----------------+                                               |
|  |   Reporter     |                                               |
|  |                |                                               |
|  | - Individual   |                                               |
|  |   reports      |                                               |
|  | - Summary      |                                               |
|  | - Metrics      |                                               |
|  +----------------+                                               |
+------------------------------------------------------------------+
```

### Storage Layer

The storage layer provides persistence using SQLite.

```
+------------------------------------------------------------------+
|                         Storage Layer                             |
|                                                                   |
|  +----------------+    +----------------+    +-----------------+  |
|  |   Database     |    |   Migrations   |    |  Repositories   |  |
|  |                |    |                |    |                 |  |
|  | - Connection   |    | - Version      |    | - Policy        |  |
|  |   pooling      |    |   tracking     |    | - Registry      |  |
|  | - WAL mode     |    | - Schema       |    | - Token         |  |
|  | - Transactions |    |   upgrades     |    | - Audit         |  |
|  +----------------+    +----------------+    | - Incident      |  |
|                                              +-----------------+  |
+------------------------------------------------------------------+
```

#### Database (`policybind.storage.database`)

- SQLite connection management
- Connection pooling for thread safety
- WAL mode for concurrent reads

#### Repositories (`policybind.storage.repositories`)

- Repository pattern for each entity type
- Parameterized queries (SQL injection prevention)
- Common query patterns

## Data Flow

### Enforcement Request Flow

```
1. Request arrives (HTTP/Library)
         |
         v
2. Authentication check
   - API key validation
   - Token validation
         |
         v
3. Context enrichment
   - Load deployment info
   - Load token permissions
   - Add request metadata
         |
         v
4. Policy evaluation
   - Match conditions
   - Sort by priority
   - Select winning rule
         |
         v
5. Action execution
   - ALLOW: pass through
   - DENY: return error
   - MODIFY: transform
   - etc.
         |
         v
6. Response generation
   - Decision
   - Applied rules
   - Reason
         |
         v
7. Audit logging
   - Request details
   - Decision details
   - Timing metrics
         |
         v
8. Response returned
```

### Policy Reload Flow

```
1. Change detected
   - File watcher
   - Manual trigger
   - API call
         |
         v
2. Parse new policies
   - YAML parsing
   - Include resolution
   - Variable substitution
         |
         v
3. Validate policies
   - Syntax check
   - Semantic validation
   - Conflict detection
         |
         v
4. Compare versions
   - Diff old vs new
   - Log changes
         |
         v
5. Atomic swap
   - Create new PolicySet
   - Swap reference
   - Old set available for rollback
         |
         v
6. Notify listeners
   - Emit reload event
   - Log success
```

## Extension Points

### Custom Actions

Register custom actions for organization-specific behavior:

```python
from policybind.engine.actions import ActionRegistry, ActionResult

def custom_notify_action(request, params, context):
    """Send custom notification."""
    webhook_url = params.get("webhook")
    # Send notification...
    return ActionResult(success=True)

registry = ActionRegistry()
registry.register("CUSTOM_NOTIFY", custom_notify_action)
```

### Custom Conditions

Add custom condition evaluators:

```python
from policybind.engine.conditions import ConditionRegistry, Condition

class CustomCondition(Condition):
    """Check custom business logic."""

    def evaluate(self, request, context):
        # Custom evaluation logic
        return True

registry = ConditionRegistry()
registry.register("custom_check", CustomCondition)
```

### Middleware

Add custom middleware to the pipeline:

```python
from policybind.engine.middleware import Middleware

class CustomMiddleware(Middleware):
    """Custom processing stage."""

    async def process(self, context, next_middleware):
        # Pre-processing
        context.metadata["custom_data"] = compute_something()

        # Call next middleware
        response = await next_middleware(context)

        # Post-processing
        log_custom_metrics(context, response)

        return response
```

### Event Handlers

Subscribe to system events:

```python
from policybind.events import EventBus

def on_policy_reload(event):
    """Handle policy reload event."""
    print(f"Policies reloaded: {event.version}")

bus = EventBus()
bus.subscribe("policy.reloaded", on_policy_reload)
bus.subscribe("token.created", on_token_created)
bus.subscribe("incident.created", on_incident_created)
```

### Custom Reporters

Add custom report generators:

```python
from policybind.reports.generator import ReportGenerator

class CustomReportGenerator(ReportGenerator):
    """Generate custom report format."""

    def generate(self, data, params):
        # Custom report generation
        return formatted_report
```

## Database Schema

### Core Tables

```
+------------------+       +------------------+
|     policies     |       |  policy_audit    |
+------------------+       +------------------+
| id               |       | id               |
| name             |       | policy_id        |
| version          |       | action           |
| content (JSON)   |       | old_value        |
| active           |       | new_value        |
| created_at       |       | changed_by       |
| updated_at       |       | changed_at       |
+------------------+       +------------------+

+------------------+       +------------------+
|  model_registry  |       |  model_usage     |
+------------------+       +------------------+
| deployment_id    |       | id               |
| name             |       | deployment_id    |
| model_provider   |       | period_start     |
| model_name       |       | period_end       |
| owner            |       | request_count    |
| risk_level       |       | token_count      |
| approval_status  |       | cost             |
| created_at       |       | violations       |
+------------------+       +------------------+

+------------------+       +------------------+
|     tokens       |       |  enforcement_log |
+------------------+       +------------------+
| token_id         |       | id               |
| token_hash       |       | request_id       |
| subject          |       | timestamp        |
| permissions      |       | request (JSON)   |
| issued_at        |       | response (JSON)  |
| expires_at       |       | decision         |
| revoked_at       |       | latency_ms       |
| usage_count      |       | applied_rules    |
| budget_used      |       +------------------+
+------------------+

+------------------+       +------------------+
|    incidents     |       | incident_events  |
+------------------+       +------------------+
| incident_id      |       | id               |
| severity         |       | incident_id      |
| status           |       | event_type       |
| incident_type    |       | old_value        |
| title            |       | new_value        |
| description      |       | actor            |
| assignee         |       | timestamp        |
| created_at       |       +------------------+
| resolved_at      |
+------------------+
```

## Performance Considerations

### Policy Matching

- Policies are compiled to optimized matching structures
- Common conditions are indexed for fast lookup
- Regex patterns are pre-compiled
- Target: < 1ms for typical policy sets (< 100 rules)

### Database

- SQLite WAL mode for concurrent reads
- Connection pooling for thread safety
- Indexes on common query patterns
- Prepared statements for repeated queries

### Caching

- Policy sets cached in memory
- Token validation cached with TTL
- Deployment data cached per request
- Cache invalidation on updates

### Async Support

- Pipeline supports async execution
- Database operations can be async
- HTTP server uses async I/O
- Background tasks for notifications

## Security Architecture

See [Security Guide](security.md) for detailed security information.

Key security features:
- Token hashing (never store plaintext)
- Parameterized SQL queries
- Input validation at all boundaries
- Audit logging of all operations
- Role-based access control for API
