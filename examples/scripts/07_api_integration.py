#!/usr/bin/env python3
"""
PolicyBind Example: API Integration

This script demonstrates how to integrate with the PolicyBind HTTP API,
including:

1. Starting the PolicyBind server
2. Making enforcement requests
3. Managing policies via API
4. Working with the model registry API
5. Token management via API
6. Incident reporting via API
7. Audit log queries
8. Health checks and metrics

This example uses both the internal client and raw HTTP requests to
demonstrate different integration patterns.

Prerequisites:
    - PolicyBind installed: pip install policybind
    - aiohttp installed: pip install aiohttp

Usage:
    python 07_api_integration.py
"""

import asyncio
import json
import sys
from typing import Any

# Check for aiohttp availability
try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


def main() -> int:
    """
    Main function demonstrating API integration.

    Returns:
        Exit code (0 for success, 1 for errors).
    """
    print("=" * 60)
    print("PolicyBind Example: API Integration")
    print("=" * 60)
    print()

    if not HAS_AIOHTTP:
        print("This example requires aiohttp. Install it with:")
        print("  pip install aiohttp")
        print()
        print("Continuing with documentation of API patterns...")
        return demonstrate_api_patterns()

    # Run async main
    return asyncio.run(async_main())


async def async_main() -> int:
    """Async main function for API demonstration."""

    # -------------------------------------------------------------------------
    # Step 1: API Overview
    # -------------------------------------------------------------------------
    print("Step 1: PolicyBind API Overview...")
    print("-" * 60)

    api_endpoints = {
        "System": [
            ("GET", "/v1/health", "Health check"),
            ("GET", "/v1/ready", "Readiness check"),
            ("GET", "/v1/metrics", "Prometheus metrics"),
        ],
        "Enforcement": [
            ("POST", "/v1/enforce", "Evaluate request against policies"),
        ],
        "Policies": [
            ("GET", "/v1/policies", "List all policies"),
            ("GET", "/v1/policies/version", "Get current policy version"),
            ("GET", "/v1/policies/history", "Get policy change history"),
            ("POST", "/v1/policies/reload", "Reload policies from source"),
            ("POST", "/v1/policies/test", "Test a request against policies"),
        ],
        "Registry": [
            ("GET", "/v1/registry", "List all deployments"),
            ("POST", "/v1/registry", "Register new deployment"),
            ("GET", "/v1/registry/{id}", "Get deployment details"),
            ("PUT", "/v1/registry/{id}", "Update deployment"),
            ("DELETE", "/v1/registry/{id}", "Delete deployment"),
            ("POST", "/v1/registry/{id}/approve", "Approve deployment"),
            ("POST", "/v1/registry/{id}/suspend", "Suspend deployment"),
        ],
        "Tokens": [
            ("GET", "/v1/tokens", "List all tokens"),
            ("POST", "/v1/tokens", "Create new token"),
            ("GET", "/v1/tokens/{id}", "Get token details"),
            ("DELETE", "/v1/tokens/{id}", "Revoke token"),
            ("POST", "/v1/tokens/from-natural-language", "Create from natural language"),
        ],
        "Incidents": [
            ("GET", "/v1/incidents", "List incidents"),
            ("POST", "/v1/incidents", "Create incident"),
            ("GET", "/v1/incidents/{id}", "Get incident details"),
            ("POST", "/v1/incidents/{id}/assign", "Assign incident"),
            ("POST", "/v1/incidents/{id}/resolve", "Resolve incident"),
        ],
        "Audit": [
            ("GET", "/v1/audit/logs", "Query audit logs"),
            ("GET", "/v1/audit/stats", "Get enforcement statistics"),
        ],
    }

    print("\nAPI Endpoints by Category:")
    for category, endpoints in api_endpoints.items():
        print(f"\n  {category}:")
        for method, path, description in endpoints:
            print(f"    {method:6} {path:40} - {description}")

    print()

    # -------------------------------------------------------------------------
    # Step 2: Demonstrate HTTP Client Pattern
    # -------------------------------------------------------------------------
    print("Step 2: HTTP Client Pattern...")
    print("-" * 60)

    print("\nPolicyBind API Client Example:")
    print("""
    class PolicyBindClient:
        def __init__(self, base_url: str, api_key: str):
            self.base_url = base_url
            self.api_key = api_key
            self.session = None

        async def __aenter__(self):
            self.session = aiohttp.ClientSession(
                headers={
                    "X-API-Key": self.api_key,
                    "Content-Type": "application/json",
                }
            )
            return self

        async def __aexit__(self, *args):
            await self.session.close()

        async def enforce(self, request: dict) -> dict:
            async with self.session.post(
                f"{self.base_url}/v1/enforce",
                json=request,
            ) as response:
                return await response.json()
    """)

    print()

    # -------------------------------------------------------------------------
    # Step 3: Enforcement Request Format
    # -------------------------------------------------------------------------
    print("Step 3: Enforcement Request Format...")
    print("-" * 60)

    enforce_request = {
        "provider": "openai",
        "model": "gpt-4",
        "user_id": "user-123",
        "department": "engineering",
        "use_case": "code-review",
        "data_classification": "internal",
        "metadata": {
            "source_application": "code-assistant",
            "session_id": "sess-abc123",
        },
    }

    print("\nEnforcement Request:")
    print(json.dumps(enforce_request, indent=2))

    enforce_response = {
        "decision": "ALLOW",
        "request_id": "req-xyz789",
        "applied_rules": [
            {
                "name": "allow-engineering-gpt4",
                "action": "ALLOW",
                "matched": True,
            }
        ],
        "warnings": [],
        "metadata": {
            "processing_time_ms": 5.2,
            "policy_version": "1.2.3",
        },
    }

    print("\nEnforcement Response:")
    print(json.dumps(enforce_response, indent=2))

    print()

    # -------------------------------------------------------------------------
    # Step 4: Token Creation via API
    # -------------------------------------------------------------------------
    print("Step 4: Token Creation via API...")
    print("-" * 60)

    token_create_request = {
        "name": "engineering-team-token",
        "subject": "engineering@company.com",
        "permissions": {
            "allowed_models": ["gpt-4", "gpt-3.5-turbo", "claude-3-*"],
            "denied_models": ["dall-e-*"],
            "budget_limit": 100.0,
            "budget_period": "monthly",
            "rate_limit": {
                "requests_per_minute": 60,
                "burst_size": 20,
            },
        },
        "expires_in_days": 90,
        "tags": ["engineering", "development"],
    }

    print("\nToken Creation Request:")
    print(json.dumps(token_create_request, indent=2))

    token_response = {
        "token_id": "tok-abc123",
        "plaintext_token": "pb_live_xxxxxxxxxxxxxxxx",
        "name": "engineering-team-token",
        "subject": "engineering@company.com",
        "expires_at": "2024-04-01T00:00:00Z",
        "created_at": "2024-01-01T00:00:00Z",
        "status": "ACTIVE",
    }

    print("\nToken Creation Response:")
    print(json.dumps(token_response, indent=2))
    print("\n  IMPORTANT: Save the plaintext_token - it won't be shown again!")

    print()

    # -------------------------------------------------------------------------
    # Step 5: Natural Language Token Creation
    # -------------------------------------------------------------------------
    print("Step 5: Natural Language Token Creation...")
    print("-" * 60)

    nl_request = {
        "description": "Allow only GPT-4 with $50 monthly budget and 30 requests per minute",
        "subject": "data-science@company.com",
        "name": "data-science-token",
    }

    print("\nNatural Language Request:")
    print(json.dumps(nl_request, indent=2))

    nl_response = {
        "token_id": "tok-def456",
        "plaintext_token": "pb_live_yyyyyyyyyyyyyyyy",
        "permissions": {
            "allowed_models": ["gpt-4"],
            "budget_limit": 50.0,
            "budget_period": "monthly",
            "rate_limit": {
                "requests_per_minute": 30,
            },
        },
        "parsing": {
            "confidence": 0.95,
            "warnings": [],
        },
    }

    print("\nParsed Token Response:")
    print(json.dumps(nl_response, indent=2))

    print()

    # -------------------------------------------------------------------------
    # Step 6: Registry Deployment Management
    # -------------------------------------------------------------------------
    print("Step 6: Registry Deployment Management...")
    print("-" * 60)

    deployment_create = {
        "name": "Customer Support Chatbot",
        "model_provider": "openai",
        "model_name": "gpt-4-turbo",
        "owner": "customer-success-team",
        "owner_contact": "cs-team@company.com",
        "description": "AI-powered customer support for product inquiries",
        "data_categories": ["internal", "customer-data"],
        "metadata": {
            "environment": "production",
            "cost_center": "CS-001",
            "compliance": ["SOC2", "GDPR"],
        },
    }

    print("\nDeployment Registration Request:")
    print(json.dumps(deployment_create, indent=2))

    deployment_response = {
        "deployment_id": "dep-xyz789",
        "name": "Customer Support Chatbot",
        "model_provider": "openai",
        "model_name": "gpt-4-turbo",
        "owner": "customer-success-team",
        "risk_level": "MEDIUM",
        "approval_status": "PENDING",
        "created_at": "2024-01-01T00:00:00Z",
    }

    print("\nDeployment Registration Response:")
    print(json.dumps(deployment_response, indent=2))

    # Approval request
    approval_request = {
        "approved_by": "security-team@company.com",
        "approval_notes": "Reviewed and approved for production use",
        "approval_ticket": "SEC-2024-001",
    }

    print("\nDeployment Approval Request (POST /v1/registry/{id}/approve):")
    print(json.dumps(approval_request, indent=2))

    print()

    # -------------------------------------------------------------------------
    # Step 7: Incident Reporting via API
    # -------------------------------------------------------------------------
    print("Step 7: Incident Reporting via API...")
    print("-" * 60)

    incident_create = {
        "title": "Potential Data Leak Detected",
        "incident_type": "DATA_LEAK",
        "severity": "HIGH",
        "description": "AI response contained potential PII that was not in the prompt",
        "source_request_id": "req-abc123",
        "deployment_id": "dep-xyz789",
        "evidence": {
            "pii_types": ["email", "phone"],
            "confidence_score": 0.92,
            "response_hash": "sha256:abcd...",
        },
        "tags": ["pii", "data-leak", "auto-detected"],
    }

    print("\nIncident Creation Request:")
    print(json.dumps(incident_create, indent=2))

    incident_response = {
        "incident_id": "inc-123abc",
        "title": "Potential Data Leak Detected",
        "severity": "HIGH",
        "status": "OPEN",
        "created_at": "2024-01-15T10:30:00Z",
    }

    print("\nIncident Creation Response:")
    print(json.dumps(incident_response, indent=2))

    # Assignment
    assign_request = {
        "assignee": "security-analyst-1",
        "actor": "security-manager",
    }

    print("\nIncident Assignment Request (POST /v1/incidents/{id}/assign):")
    print(json.dumps(assign_request, indent=2))

    print()

    # -------------------------------------------------------------------------
    # Step 8: Audit Log Queries
    # -------------------------------------------------------------------------
    print("Step 8: Audit Log Queries...")
    print("-" * 60)

    audit_query_params = {
        "start_date": "2024-01-01T00:00:00Z",
        "end_date": "2024-01-31T23:59:59Z",
        "decision": "DENY",
        "department": "marketing",
        "limit": 100,
        "offset": 0,
    }

    print("\nAudit Log Query Parameters:")
    print("  GET /v1/audit/logs")
    for param, value in audit_query_params.items():
        print(f"    ?{param}={value}")

    audit_response = {
        "total_count": 42,
        "page_size": 100,
        "offset": 0,
        "entries": [
            {
                "request_id": "req-001",
                "timestamp": "2024-01-15T10:30:00Z",
                "decision": "DENY",
                "applied_rule": "deny-marketing-gpt4",
                "user_id": "user-marketing-001",
                "department": "marketing",
                "model": "gpt-4",
            },
        ],
    }

    print("\nAudit Log Response:")
    print(json.dumps(audit_response, indent=2))

    # Statistics endpoint
    stats_response = {
        "period": {
            "start": "2024-01-01T00:00:00Z",
            "end": "2024-01-31T23:59:59Z",
        },
        "total_requests": 15234,
        "by_decision": {
            "ALLOW": 14892,
            "DENY": 312,
            "AUDIT": 30,
        },
        "by_department": {
            "engineering": 8500,
            "data-science": 4200,
            "marketing": 1200,
            "hr": 534,
            "other": 800,
        },
        "by_model": {
            "gpt-4": 5000,
            "gpt-3.5-turbo": 8500,
            "claude-3-sonnet": 1734,
        },
    }

    print("\nEnforcement Statistics Response (GET /v1/audit/stats):")
    print(json.dumps(stats_response, indent=2))

    print()

    # -------------------------------------------------------------------------
    # Step 9: Health Checks and Metrics
    # -------------------------------------------------------------------------
    print("Step 9: Health Checks and Metrics...")
    print("-" * 60)

    health_response = {
        "status": "healthy",
        "version": "1.0.0",
        "components": {
            "database": "healthy",
            "policy_engine": "healthy",
            "token_service": "healthy",
        },
    }

    print("\nHealth Check Response (GET /v1/health):")
    print(json.dumps(health_response, indent=2))

    ready_response = {
        "ready": True,
        "policies_loaded": True,
        "database_connected": True,
    }

    print("\nReadiness Check Response (GET /v1/ready):")
    print(json.dumps(ready_response, indent=2))

    metrics_sample = """
# Metrics Response (GET /v1/metrics) - Prometheus format:

# HELP policybind_requests_total Total number of enforcement requests
# TYPE policybind_requests_total counter
policybind_requests_total{decision="ALLOW"} 14892
policybind_requests_total{decision="DENY"} 312
policybind_requests_total{decision="AUDIT"} 30

# HELP policybind_request_duration_seconds Request processing time
# TYPE policybind_request_duration_seconds histogram
policybind_request_duration_seconds_bucket{le="0.001"} 8000
policybind_request_duration_seconds_bucket{le="0.005"} 14000
policybind_request_duration_seconds_bucket{le="0.01"} 15000

# HELP policybind_active_tokens Number of active tokens
# TYPE policybind_active_tokens gauge
policybind_active_tokens 42

# HELP policybind_registered_deployments Number of registered deployments
# TYPE policybind_registered_deployments gauge
policybind_registered_deployments 15
"""

    print(metrics_sample)

    print()

    # -------------------------------------------------------------------------
    # Step 10: Error Handling
    # -------------------------------------------------------------------------
    print("Step 10: API Error Handling...")
    print("-" * 60)

    error_responses = [
        {
            "status": 400,
            "name": "Bad Request",
            "response": {
                "error": "validation_error",
                "message": "Invalid request body",
                "details": {
                    "field": "model",
                    "issue": "Model name is required",
                },
            },
        },
        {
            "status": 401,
            "name": "Unauthorized",
            "response": {
                "error": "unauthorized",
                "message": "Invalid or missing API key",
            },
        },
        {
            "status": 403,
            "name": "Forbidden",
            "response": {
                "error": "forbidden",
                "message": "Insufficient permissions for this operation",
                "required_role": "admin",
            },
        },
        {
            "status": 404,
            "name": "Not Found",
            "response": {
                "error": "not_found",
                "message": "Deployment not found",
                "resource_type": "deployment",
                "resource_id": "dep-xyz789",
            },
        },
        {
            "status": 429,
            "name": "Rate Limited",
            "response": {
                "error": "rate_limited",
                "message": "Rate limit exceeded",
                "retry_after_seconds": 60,
            },
        },
    ]

    print("\nCommon Error Responses:")
    for error in error_responses:
        print(f"\n  HTTP {error['status']} - {error['name']}:")
        print(f"  {json.dumps(error['response'], indent=4)}")

    print()

    # -------------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------------
    print("=" * 60)
    print("Example completed successfully!")
    print("=" * 60)
    print()
    print("Key Takeaways:")
    print("  1. PolicyBind provides a RESTful API for all operations")
    print("  2. Authentication via API key (X-API-Key header) or token")
    print("  3. All requests and responses use JSON format")
    print("  4. Prometheus-compatible metrics endpoint for monitoring")
    print("  5. Comprehensive error responses with details")
    print()
    print("Integration Patterns:")
    print("  - Direct HTTP integration with any language/framework")
    print("  - Async Python client with aiohttp")
    print("  - Sync Python client with requests library")
    print("  - SDK wrappers for language-specific ergonomics")
    print()
    print("Authentication Options:")
    print("  - API Key: For server-to-server communication")
    print("  - Token: For end-user/application authentication")
    print()
    print("Best Practices:")
    print("  - Use health/ready endpoints for load balancer checks")
    print("  - Implement retry logic with exponential backoff")
    print("  - Handle rate limiting gracefully")
    print("  - Log request_id for debugging")

    return 0


def demonstrate_api_patterns() -> int:
    """Demonstrate API patterns without requiring aiohttp."""

    print("\n" + "=" * 60)
    print("API Integration Patterns (Documentation Mode)")
    print("=" * 60)
    print()

    # Show code samples
    print("Python HTTP Client Example (using requests):")
    print("-" * 60)
    print('''
import requests

class PolicyBindClient:
    """Synchronous PolicyBind API client."""

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "X-API-Key": api_key,
            "Content-Type": "application/json",
        })

    def enforce(self, request: dict) -> dict:
        """Enforce a request against policies."""
        response = self.session.post(
            f"{self.base_url}/v1/enforce",
            json=request,
        )
        response.raise_for_status()
        return response.json()

    def create_token(self, name: str, subject: str, permissions: dict) -> dict:
        """Create a new token."""
        response = self.session.post(
            f"{self.base_url}/v1/tokens",
            json={
                "name": name,
                "subject": subject,
                "permissions": permissions,
            },
        )
        response.raise_for_status()
        return response.json()

    def health_check(self) -> dict:
        """Check API health."""
        response = self.session.get(f"{self.base_url}/v1/health")
        response.raise_for_status()
        return response.json()


# Usage:
client = PolicyBindClient(
    base_url="http://localhost:8080",
    api_key="your-api-key",
)

# Check health
health = client.health_check()
print(f"Status: {health['status']}")

# Enforce a request
result = client.enforce({
    "provider": "openai",
    "model": "gpt-4",
    "user_id": "user-123",
    "department": "engineering",
})
print(f"Decision: {result['decision']}")
''')

    print()
    print("Async Python Client Example (using aiohttp):")
    print("-" * 60)
    print('''
import aiohttp
import asyncio

class AsyncPolicyBindClient:
    """Asynchronous PolicyBind API client."""

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._session = None

    async def __aenter__(self):
        self._session = aiohttp.ClientSession(
            headers={
                "X-API-Key": self.api_key,
                "Content-Type": "application/json",
            }
        )
        return self

    async def __aexit__(self, *args):
        await self._session.close()

    async def enforce(self, request: dict) -> dict:
        """Enforce a request against policies."""
        async with self._session.post(
            f"{self.base_url}/v1/enforce",
            json=request,
        ) as response:
            response.raise_for_status()
            return await response.json()


# Usage:
async def main():
    async with AsyncPolicyBindClient(
        base_url="http://localhost:8080",
        api_key="your-api-key",
    ) as client:
        result = await client.enforce({
            "provider": "openai",
            "model": "gpt-4",
            "user_id": "user-123",
        })
        print(f"Decision: {result['decision']}")

asyncio.run(main())
''')

    print()
    print("cURL Examples:")
    print("-" * 60)
    print('''
# Health check
curl http://localhost:8080/v1/health

# Enforce a request
curl -X POST http://localhost:8080/v1/enforce \\
  -H "X-API-Key: your-api-key" \\
  -H "Content-Type: application/json" \\
  -d '{
    "provider": "openai",
    "model": "gpt-4",
    "user_id": "user-123",
    "department": "engineering"
  }'

# Create a token
curl -X POST http://localhost:8080/v1/tokens \\
  -H "X-API-Key: your-api-key" \\
  -H "Content-Type: application/json" \\
  -d '{
    "name": "my-token",
    "subject": "user@example.com",
    "permissions": {
      "allowed_models": ["gpt-4"],
      "budget_limit": 100.0,
      "budget_period": "monthly"
    }
  }'

# List deployments
curl http://localhost:8080/v1/registry \\
  -H "X-API-Key: your-api-key"

# Get metrics (Prometheus format)
curl http://localhost:8080/v1/metrics
''')

    print()
    print("=" * 60)
    print("Documentation complete!")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
