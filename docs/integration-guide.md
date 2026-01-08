# PolicyBind Integration Guide

This guide provides comprehensive examples for integrating PolicyBind into your AI/ML applications.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Python Integration](#python-integration)
3. [JavaScript/TypeScript Integration](#javascripttypescript-integration)
4. [LangChain Integration](#langchain-integration)
5. [OpenAI Integration](#openai-integration)
6. [FastAPI Middleware](#fastapi-middleware)
7. [Error Handling](#error-handling)
8. [Best Practices](#best-practices)

---

## Quick Start

### 1. Register Your Deployment

Before making enforcement requests, register your AI deployment:

```bash
curl -X POST http://localhost:8080/v1/registry \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-admin-key" \
  -d '{
    "name": "My AI Application",
    "model": "gpt-4",
    "department": "engineering",
    "owner": "team@example.com",
    "use_case": "customer_support"
  }'
```

Response:
```json
{
  "deployment_id": "dep_abc123",
  "status": "pending"
}
```

### 2. Get Deployment Approved

Have an admin approve your deployment:

```bash
curl -X POST http://localhost:8080/v1/registry/dep_abc123/approve \
  -H "X-API-Key: admin-key"
```

### 3. Create an Access Token

```bash
curl -X POST http://localhost:8080/v1/tokens \
  -H "Content-Type: application/json" \
  -H "X-API-Key: admin-key" \
  -d '{
    "name": "My App Token",
    "deployment_id": "dep_abc123",
    "expires_in_days": 90
  }'
```

Response:
```json
{
  "token_id": "tok_xyz789",
  "token": "pb_live_xxxxxxxxxxxx",
  "expires_at": "2024-04-15T10:30:00Z"
}
```

### 4. Enforce Requests

```bash
curl -X POST http://localhost:8080/v1/enforce \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer pb_live_xxxxxxxxxxxx" \
  -d '{
    "deployment_id": "dep_abc123",
    "user_id": "user@example.com",
    "prompt": "Summarize this document"
  }'
```

---

## Python Integration

### Basic Client

```python
"""PolicyBind Python client for AI policy enforcement."""

import requests
from typing import Any, Optional
from dataclasses import dataclass
from enum import Enum


class Decision(Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    MODIFY = "MODIFY"


@dataclass
class EnforcementResult:
    """Result of an enforcement request."""
    decision: Decision
    request_id: str
    modified_prompt: Optional[str] = None
    reason: Optional[str] = None
    violations: Optional[list[dict]] = None
    warnings: Optional[list[str]] = None
    data_classification: Optional[list[str]] = None


class PolicyBindClient:
    """Client for interacting with PolicyBind API."""

    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        api_key: Optional[str] = None,
        token: Optional[str] = None,
        timeout: int = 30
    ):
        """
        Initialize the client.

        Args:
            base_url: PolicyBind server URL
            api_key: API key for authentication
            token: Bearer token for authentication
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

        self.headers = {"Content-Type": "application/json"}
        if api_key:
            self.headers["X-API-Key"] = api_key
        elif token:
            self.headers["Authorization"] = f"Bearer {token}"

    def enforce(
        self,
        deployment_id: str,
        user_id: str,
        prompt: str,
        department: Optional[str] = None,
        model: Optional[str] = None,
        metadata: Optional[dict] = None
    ) -> EnforcementResult:
        """
        Submit a request for policy enforcement.

        Args:
            deployment_id: Registered deployment ID
            user_id: User making the request
            prompt: The prompt to check
            department: User's department
            model: Target model name
            metadata: Additional context

        Returns:
            EnforcementResult with decision and details

        Raises:
            PolicyBindError: If enforcement fails
        """
        payload = {
            "deployment_id": deployment_id,
            "user_id": user_id,
            "prompt": prompt,
        }
        if department:
            payload["department"] = department
        if model:
            payload["model"] = model
        if metadata:
            payload["metadata"] = metadata

        response = requests.post(
            f"{self.base_url}/v1/enforce",
            headers=self.headers,
            json=payload,
            timeout=self.timeout
        )

        if response.status_code != 200:
            self._handle_error(response)

        data = response.json()
        return EnforcementResult(
            decision=Decision(data["decision"]),
            request_id=data.get("request_id", ""),
            modified_prompt=data.get("modified_prompt"),
            reason=data.get("reason"),
            violations=data.get("violations"),
            warnings=data.get("warnings"),
            data_classification=data.get("data_classification")
        )

    def enforce_or_fail(
        self,
        deployment_id: str,
        user_id: str,
        prompt: str,
        **kwargs
    ) -> str:
        """
        Enforce and return the prompt to use, or raise an error.

        Returns the original prompt if ALLOW, modified prompt if MODIFY,
        raises PolicyDenied if DENY.
        """
        result = self.enforce(deployment_id, user_id, prompt, **kwargs)

        if result.decision == Decision.DENY:
            raise PolicyDenied(result.reason, result.violations)

        if result.decision == Decision.MODIFY:
            return result.modified_prompt

        return prompt

    def health_check(self) -> bool:
        """Check if the server is healthy."""
        try:
            response = requests.get(
                f"{self.base_url}/v1/health",
                timeout=5
            )
            return response.status_code == 200
        except requests.RequestException:
            return False

    def _handle_error(self, response: requests.Response):
        """Handle error responses."""
        try:
            data = response.json()
            error = data.get("error", {})
            error_type = error.get("type", "UnknownError")
            message = error.get("message", "Unknown error")
        except:
            error_type = "HTTPError"
            message = response.text

        if response.status_code == 401:
            raise AuthenticationError(message)
        elif response.status_code == 403:
            if error_type == "PolicyViolation":
                raise PolicyDenied(message)
            raise AuthorizationError(message)
        elif response.status_code == 404:
            raise NotFoundError(message)
        elif response.status_code == 429:
            raise RateLimitError(message)
        else:
            raise PolicyBindError(message, error_type)


class PolicyBindError(Exception):
    """Base exception for PolicyBind errors."""
    def __init__(self, message: str, error_type: str = "Error"):
        self.message = message
        self.error_type = error_type
        super().__init__(f"{error_type}: {message}")


class PolicyDenied(PolicyBindError):
    """Request was denied by policy."""
    def __init__(self, reason: str, violations: Optional[list] = None):
        self.reason = reason
        self.violations = violations or []
        super().__init__(reason, "PolicyDenied")


class AuthenticationError(PolicyBindError):
    """Authentication failed."""
    def __init__(self, message: str):
        super().__init__(message, "AuthenticationError")


class AuthorizationError(PolicyBindError):
    """Authorization failed."""
    def __init__(self, message: str):
        super().__init__(message, "AuthorizationError")


class NotFoundError(PolicyBindError):
    """Resource not found."""
    def __init__(self, message: str):
        super().__init__(message, "NotFound")


class RateLimitError(PolicyBindError):
    """Rate limit exceeded."""
    def __init__(self, message: str):
        super().__init__(message, "RateLimitExceeded")


# Usage example
if __name__ == "__main__":
    client = PolicyBindClient(
        base_url="http://localhost:8080",
        token="pb_live_xxxxxxxxxxxx"
    )

    try:
        prompt = client.enforce_or_fail(
            deployment_id="dep_abc123",
            user_id="user@example.com",
            prompt="Analyze customer feedback"
        )
        print(f"Using prompt: {prompt}")
    except PolicyDenied as e:
        print(f"Request denied: {e.reason}")
```

### Async Client

```python
"""Async PolicyBind client using aiohttp."""

import aiohttp
from typing import Optional


class AsyncPolicyBindClient:
    """Async client for PolicyBind API."""

    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        api_key: Optional[str] = None,
        token: Optional[str] = None
    ):
        self.base_url = base_url.rstrip("/")
        self.headers = {"Content-Type": "application/json"}
        if api_key:
            self.headers["X-API-Key"] = api_key
        elif token:
            self.headers["Authorization"] = f"Bearer {token}"
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        self._session = aiohttp.ClientSession(headers=self.headers)
        return self

    async def __aexit__(self, *args):
        if self._session:
            await self._session.close()

    async def enforce(
        self,
        deployment_id: str,
        user_id: str,
        prompt: str,
        **kwargs
    ) -> dict:
        """Submit request for enforcement."""
        if not self._session:
            raise RuntimeError("Use 'async with' context manager")

        payload = {
            "deployment_id": deployment_id,
            "user_id": user_id,
            "prompt": prompt,
            **kwargs
        }

        async with self._session.post(
            f"{self.base_url}/v1/enforce",
            json=payload
        ) as response:
            data = await response.json()
            if response.status != 200:
                raise PolicyBindError(
                    data.get("error", {}).get("message", "Unknown error")
                )
            return data


# Usage
async def main():
    async with AsyncPolicyBindClient(token="pb_live_xxx") as client:
        result = await client.enforce(
            deployment_id="dep_abc123",
            user_id="user@example.com",
            prompt="Hello, world!"
        )
        print(result["decision"])


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
```

---

## JavaScript/TypeScript Integration

### TypeScript Client

```typescript
/**
 * PolicyBind TypeScript client for AI policy enforcement.
 */

export enum Decision {
  ALLOW = 'ALLOW',
  DENY = 'DENY',
  MODIFY = 'MODIFY',
}

export interface EnforcementRequest {
  deployment_id: string;
  user_id: string;
  prompt: string;
  department?: string;
  model?: string;
  metadata?: Record<string, unknown>;
}

export interface EnforcementResult {
  decision: Decision;
  request_id: string;
  modified_prompt?: string;
  reason?: string;
  violations?: Array<{ rule: string; message: string }>;
  warnings?: string[];
  data_classification?: string[];
}

export interface PolicyBindError {
  type: string;
  message: string;
}

export class PolicyBindClient {
  private baseUrl: string;
  private headers: HeadersInit;

  constructor(options: {
    baseUrl?: string;
    apiKey?: string;
    token?: string;
  }) {
    this.baseUrl = (options.baseUrl || 'http://localhost:8080').replace(/\/$/, '');
    this.headers = {
      'Content-Type': 'application/json',
    };

    if (options.apiKey) {
      this.headers['X-API-Key'] = options.apiKey;
    } else if (options.token) {
      this.headers['Authorization'] = `Bearer ${options.token}`;
    }
  }

  async enforce(request: EnforcementRequest): Promise<EnforcementResult> {
    const response = await fetch(`${this.baseUrl}/v1/enforce`, {
      method: 'POST',
      headers: this.headers,
      body: JSON.stringify(request),
    });

    const data = await response.json();

    if (!response.ok) {
      const error = data.error as PolicyBindError;
      throw new PolicyBindApiError(error.type, error.message, response.status);
    }

    return {
      decision: data.decision as Decision,
      request_id: data.request_id,
      modified_prompt: data.modified_prompt,
      reason: data.reason,
      violations: data.violations,
      warnings: data.warnings,
      data_classification: data.data_classification,
    };
  }

  /**
   * Enforce and return the prompt to use.
   * Throws PolicyDeniedError if request is denied.
   */
  async enforceOrFail(request: EnforcementRequest): Promise<string> {
    const result = await this.enforce(request);

    if (result.decision === Decision.DENY) {
      throw new PolicyDeniedError(result.reason || 'Request denied', result.violations);
    }

    if (result.decision === Decision.MODIFY && result.modified_prompt) {
      return result.modified_prompt;
    }

    return request.prompt;
  }

  async healthCheck(): Promise<boolean> {
    try {
      const response = await fetch(`${this.baseUrl}/v1/health`);
      return response.ok;
    } catch {
      return false;
    }
  }
}

export class PolicyBindApiError extends Error {
  constructor(
    public readonly errorType: string,
    message: string,
    public readonly statusCode: number
  ) {
    super(`${errorType}: ${message}`);
    this.name = 'PolicyBindApiError';
  }
}

export class PolicyDeniedError extends Error {
  constructor(
    public readonly reason: string,
    public readonly violations?: Array<{ rule: string; message: string }>
  ) {
    super(`Policy denied: ${reason}`);
    this.name = 'PolicyDeniedError';
  }
}

// Usage example
async function example() {
  const client = new PolicyBindClient({
    baseUrl: 'http://localhost:8080',
    token: 'pb_live_xxxxxxxxxxxx',
  });

  try {
    const prompt = await client.enforceOrFail({
      deployment_id: 'dep_abc123',
      user_id: 'user@example.com',
      prompt: 'Analyze this data',
    });
    console.log('Using prompt:', prompt);
  } catch (error) {
    if (error instanceof PolicyDeniedError) {
      console.log('Request denied:', error.reason);
    } else {
      throw error;
    }
  }
}
```

### React Hook

```typescript
import { useState, useCallback } from 'react';
import { PolicyBindClient, EnforcementResult, Decision } from './policybind-client';

const client = new PolicyBindClient({
  baseUrl: process.env.REACT_APP_POLICYBIND_URL,
  token: process.env.REACT_APP_POLICYBIND_TOKEN,
});

interface UseEnforcementOptions {
  deploymentId: string;
  userId: string;
  department?: string;
}

export function useEnforcement(options: UseEnforcementOptions) {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<EnforcementResult | null>(null);

  const enforce = useCallback(
    async (prompt: string): Promise<string | null> => {
      setIsLoading(true);
      setError(null);

      try {
        const result = await client.enforce({
          deployment_id: options.deploymentId,
          user_id: options.userId,
          department: options.department,
          prompt,
        });

        setLastResult(result);

        if (result.decision === Decision.DENY) {
          setError(result.reason || 'Request denied by policy');
          return null;
        }

        return result.decision === Decision.MODIFY
          ? result.modified_prompt!
          : prompt;
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Unknown error');
        return null;
      } finally {
        setIsLoading(false);
      }
    },
    [options.deploymentId, options.userId, options.department]
  );

  return { enforce, isLoading, error, lastResult };
}

// Usage in component
function ChatInput() {
  const { enforce, isLoading, error } = useEnforcement({
    deploymentId: 'dep_abc123',
    userId: 'user@example.com',
  });

  const handleSubmit = async (prompt: string) => {
    const enforcedPrompt = await enforce(prompt);
    if (enforcedPrompt) {
      // Send to AI model
      await sendToAI(enforcedPrompt);
    }
  };

  return (
    <div>
      {error && <div className="error">{error}</div>}
      <input disabled={isLoading} />
    </div>
  );
}
```

---

## LangChain Integration

### Custom LangChain Callback

```python
"""LangChain integration for PolicyBind enforcement."""

from typing import Any, Dict, List, Optional, Union
from langchain.callbacks.base import BaseCallbackHandler
from langchain.schema import LLMResult, AgentAction, AgentFinish


class PolicyBindCallbackHandler(BaseCallbackHandler):
    """LangChain callback that enforces policies on LLM inputs."""

    def __init__(
        self,
        client: "PolicyBindClient",
        deployment_id: str,
        user_id: str,
        department: Optional[str] = None,
        fail_on_deny: bool = True
    ):
        self.client = client
        self.deployment_id = deployment_id
        self.user_id = user_id
        self.department = department
        self.fail_on_deny = fail_on_deny
        self.last_result = None

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        **kwargs: Any
    ) -> None:
        """Enforce policy before LLM call."""
        for i, prompt in enumerate(prompts):
            result = self.client.enforce(
                deployment_id=self.deployment_id,
                user_id=self.user_id,
                prompt=prompt,
                department=self.department,
                model=serialized.get("name", "unknown")
            )

            self.last_result = result

            if result.decision.value == "DENY":
                if self.fail_on_deny:
                    raise PolicyDenied(result.reason, result.violations)
                # Log but continue
                print(f"Warning: Request would be denied: {result.reason}")

            elif result.decision.value == "MODIFY":
                # Replace the prompt with the modified version
                prompts[i] = result.modified_prompt

    def on_llm_end(self, response: LLMResult, **kwargs: Any) -> None:
        """Called after LLM completes."""
        pass


# Usage with LangChain
from langchain.llms import OpenAI
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate

# Create PolicyBind client
pb_client = PolicyBindClient(
    base_url="http://localhost:8080",
    token="pb_live_xxxxxxxxxxxx"
)

# Create callback handler
policy_callback = PolicyBindCallbackHandler(
    client=pb_client,
    deployment_id="dep_abc123",
    user_id="user@example.com",
    department="engineering"
)

# Use with LangChain
llm = OpenAI(temperature=0.7, callbacks=[policy_callback])

prompt = PromptTemplate(
    input_variables=["topic"],
    template="Tell me about {topic}"
)

chain = LLMChain(llm=llm, prompt=prompt)

try:
    result = chain.run("machine learning")
    print(result)
except PolicyDenied as e:
    print(f"Request blocked: {e.reason}")
```

### LangChain Wrapper

```python
"""LangChain wrapper that enforces PolicyBind policies."""

from langchain.llms.base import LLM
from typing import Any, List, Optional, Mapping


class PolicyBindLLM(LLM):
    """LLM wrapper that enforces PolicyBind policies."""

    inner_llm: Any
    pb_client: Any
    deployment_id: str
    user_id: str
    department: Optional[str] = None

    @property
    def _llm_type(self) -> str:
        return f"policybind-{self.inner_llm._llm_type}"

    def _call(
        self,
        prompt: str,
        stop: Optional[List[str]] = None,
        **kwargs: Any
    ) -> str:
        # Enforce policy
        result = self.pb_client.enforce(
            deployment_id=self.deployment_id,
            user_id=self.user_id,
            prompt=prompt,
            department=self.department
        )

        if result.decision.value == "DENY":
            raise PolicyDenied(result.reason, result.violations)

        # Use modified prompt if applicable
        enforced_prompt = (
            result.modified_prompt
            if result.decision.value == "MODIFY"
            else prompt
        )

        # Call inner LLM
        return self.inner_llm._call(enforced_prompt, stop=stop, **kwargs)

    @property
    def _identifying_params(self) -> Mapping[str, Any]:
        return {
            "inner_llm": self.inner_llm._identifying_params,
            "deployment_id": self.deployment_id
        }


# Usage
from langchain.llms import OpenAI

inner_llm = OpenAI(temperature=0.7)

llm = PolicyBindLLM(
    inner_llm=inner_llm,
    pb_client=PolicyBindClient(token="pb_live_xxx"),
    deployment_id="dep_abc123",
    user_id="user@example.com"
)

response = llm("What is machine learning?")
```

---

## OpenAI Integration

### Direct Integration

```python
"""OpenAI integration with PolicyBind enforcement."""

import openai
from typing import Optional, List, Dict, Any


class PolicyBindOpenAI:
    """OpenAI client wrapper with PolicyBind enforcement."""

    def __init__(
        self,
        pb_client: "PolicyBindClient",
        deployment_id: str,
        openai_api_key: str
    ):
        self.pb_client = pb_client
        self.deployment_id = deployment_id
        openai.api_key = openai_api_key

    def chat_completion(
        self,
        messages: List[Dict[str, str]],
        user_id: str,
        model: str = "gpt-4",
        department: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create a chat completion with policy enforcement.

        Enforces policy on the last user message.
        """
        # Find the last user message
        user_messages = [m for m in messages if m["role"] == "user"]
        if not user_messages:
            raise ValueError("No user message found")

        last_user_message = user_messages[-1]["content"]

        # Enforce policy
        result = self.pb_client.enforce(
            deployment_id=self.deployment_id,
            user_id=user_id,
            prompt=last_user_message,
            department=department,
            model=model
        )

        if result.decision.value == "DENY":
            raise PolicyDenied(result.reason, result.violations)

        # Apply modifications if needed
        if result.decision.value == "MODIFY":
            # Replace the content of the last user message
            for i in range(len(messages) - 1, -1, -1):
                if messages[i]["role"] == "user":
                    messages[i]["content"] = result.modified_prompt
                    break

        # Call OpenAI
        response = openai.ChatCompletion.create(
            model=model,
            messages=messages,
            **kwargs
        )

        return response

    def completion(
        self,
        prompt: str,
        user_id: str,
        model: str = "gpt-3.5-turbo-instruct",
        department: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Create a completion with policy enforcement."""
        # Enforce policy
        result = self.pb_client.enforce(
            deployment_id=self.deployment_id,
            user_id=user_id,
            prompt=prompt,
            department=department,
            model=model
        )

        if result.decision.value == "DENY":
            raise PolicyDenied(result.reason, result.violations)

        enforced_prompt = (
            result.modified_prompt
            if result.decision.value == "MODIFY"
            else prompt
        )

        # Call OpenAI
        response = openai.Completion.create(
            model=model,
            prompt=enforced_prompt,
            **kwargs
        )

        return response


# Usage
client = PolicyBindOpenAI(
    pb_client=PolicyBindClient(token="pb_live_xxx"),
    deployment_id="dep_abc123",
    openai_api_key="sk-xxx"
)

try:
    response = client.chat_completion(
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Analyze this customer data: ..."}
        ],
        user_id="user@example.com",
        department="support"
    )
    print(response.choices[0].message.content)
except PolicyDenied as e:
    print(f"Request blocked: {e.reason}")
```

### Async OpenAI Integration

```python
"""Async OpenAI integration with PolicyBind."""

import asyncio
from openai import AsyncOpenAI


class AsyncPolicyBindOpenAI:
    """Async OpenAI client with PolicyBind enforcement."""

    def __init__(
        self,
        pb_client: "AsyncPolicyBindClient",
        deployment_id: str,
        openai_api_key: str
    ):
        self.pb_client = pb_client
        self.deployment_id = deployment_id
        self.openai = AsyncOpenAI(api_key=openai_api_key)

    async def chat_completion(
        self,
        messages: list,
        user_id: str,
        model: str = "gpt-4",
        **kwargs
    ):
        # Enforce policy on last user message
        user_messages = [m for m in messages if m["role"] == "user"]
        if user_messages:
            last_message = user_messages[-1]["content"]

            result = await self.pb_client.enforce(
                deployment_id=self.deployment_id,
                user_id=user_id,
                prompt=last_message
            )

            if result["decision"] == "DENY":
                raise PolicyDenied(result.get("reason", "Denied"))

            if result["decision"] == "MODIFY":
                # Update the message
                for i in range(len(messages) - 1, -1, -1):
                    if messages[i]["role"] == "user":
                        messages[i]["content"] = result["modified_prompt"]
                        break

        # Call OpenAI
        return await self.openai.chat.completions.create(
            model=model,
            messages=messages,
            **kwargs
        )


# Usage
async def main():
    async with AsyncPolicyBindClient(token="pb_live_xxx") as pb_client:
        client = AsyncPolicyBindOpenAI(
            pb_client=pb_client,
            deployment_id="dep_abc123",
            openai_api_key="sk-xxx"
        )

        response = await client.chat_completion(
            messages=[{"role": "user", "content": "Hello!"}],
            user_id="user@example.com"
        )
        print(response.choices[0].message.content)


asyncio.run(main())
```

---

## FastAPI Middleware

### Enforcement Middleware

```python
"""FastAPI middleware for PolicyBind enforcement."""

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
import json


class PolicyBindMiddleware(BaseHTTPMiddleware):
    """Middleware that enforces PolicyBind policies on AI requests."""

    def __init__(
        self,
        app: FastAPI,
        pb_client: "PolicyBindClient",
        deployment_id: str,
        enforce_paths: list[str] = None
    ):
        super().__init__(app)
        self.pb_client = pb_client
        self.deployment_id = deployment_id
        self.enforce_paths = enforce_paths or ["/api/ai/", "/api/chat/"]

    async def dispatch(self, request: Request, call_next):
        # Check if this path should be enforced
        should_enforce = any(
            request.url.path.startswith(path)
            for path in self.enforce_paths
        )

        if not should_enforce:
            return await call_next(request)

        # Get user from request (customize based on your auth)
        user_id = request.headers.get("X-User-ID", "anonymous")
        department = request.headers.get("X-Department")

        # Read and parse request body
        body = await request.body()
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return await call_next(request)

        # Extract prompt from request
        prompt = self._extract_prompt(data)
        if not prompt:
            return await call_next(request)

        # Enforce policy
        try:
            result = self.pb_client.enforce(
                deployment_id=self.deployment_id,
                user_id=user_id,
                prompt=prompt,
                department=department
            )
        except Exception as e:
            return JSONResponse(
                status_code=503,
                content={"error": f"Policy enforcement unavailable: {str(e)}"}
            )

        if result.decision.value == "DENY":
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Request blocked by policy",
                    "reason": result.reason,
                    "violations": result.violations
                }
            )

        if result.decision.value == "MODIFY":
            # Modify the request body
            data = self._apply_modification(data, result.modified_prompt)

            # Create new request with modified body
            request._body = json.dumps(data).encode()

        return await call_next(request)

    def _extract_prompt(self, data: dict) -> str | None:
        """Extract prompt from request data."""
        # Handle different formats
        if "prompt" in data:
            return data["prompt"]
        if "messages" in data:
            # OpenAI format
            for msg in reversed(data["messages"]):
                if msg.get("role") == "user":
                    return msg.get("content")
        if "input" in data:
            return data["input"]
        return None

    def _apply_modification(self, data: dict, modified_prompt: str) -> dict:
        """Apply modified prompt to request data."""
        if "prompt" in data:
            data["prompt"] = modified_prompt
        elif "messages" in data:
            for i in range(len(data["messages"]) - 1, -1, -1):
                if data["messages"][i].get("role") == "user":
                    data["messages"][i]["content"] = modified_prompt
                    break
        elif "input" in data:
            data["input"] = modified_prompt
        return data


# Usage
from fastapi import FastAPI

app = FastAPI()

# Add middleware
pb_client = PolicyBindClient(
    base_url="http://localhost:8080",
    token="pb_live_xxx"
)

app.add_middleware(
    PolicyBindMiddleware,
    pb_client=pb_client,
    deployment_id="dep_abc123",
    enforce_paths=["/api/ai/", "/api/chat/"]
)


@app.post("/api/ai/completion")
async def completion(request: Request):
    data = await request.json()
    # Process with AI (prompt already enforced by middleware)
    return {"response": "..."}
```

### Dependency Injection

```python
"""FastAPI dependency injection for PolicyBind."""

from fastapi import FastAPI, Depends, HTTPException, Header
from typing import Optional


app = FastAPI()

# Global client
pb_client = PolicyBindClient(
    base_url="http://localhost:8080",
    token="pb_live_xxx"
)


async def get_enforced_prompt(
    prompt: str,
    x_user_id: str = Header(...),
    x_department: Optional[str] = Header(None)
) -> str:
    """Dependency that enforces policy and returns usable prompt."""
    result = pb_client.enforce(
        deployment_id="dep_abc123",
        user_id=x_user_id,
        prompt=prompt,
        department=x_department
    )

    if result.decision.value == "DENY":
        raise HTTPException(
            status_code=403,
            detail={
                "error": "Policy violation",
                "reason": result.reason
            }
        )

    if result.decision.value == "MODIFY":
        return result.modified_prompt

    return prompt


@app.post("/api/chat")
async def chat(
    prompt: str = Depends(get_enforced_prompt)
):
    """Chat endpoint with automatic policy enforcement."""
    # prompt is already enforced
    response = call_ai_model(prompt)
    return {"response": response}
```

---

## Error Handling

### Comprehensive Error Handling

```python
"""Comprehensive error handling for PolicyBind integration."""

import logging
from enum import Enum
from typing import Callable, TypeVar, Optional
from functools import wraps
import time

logger = logging.getLogger(__name__)

T = TypeVar('T')


class RetryStrategy(Enum):
    NONE = "none"
    EXPONENTIAL = "exponential"
    LINEAR = "linear"


def with_retry(
    max_retries: int = 3,
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL,
    base_delay: float = 1.0,
    retryable_errors: tuple = (RateLimitError, ConnectionError)
) -> Callable:
    """Decorator for retrying failed PolicyBind calls."""

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            last_exception = None

            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except retryable_errors as e:
                    last_exception = e

                    if attempt < max_retries:
                        if strategy == RetryStrategy.EXPONENTIAL:
                            delay = base_delay * (2 ** attempt)
                        elif strategy == RetryStrategy.LINEAR:
                            delay = base_delay * (attempt + 1)
                        else:
                            raise

                        logger.warning(
                            f"Retry {attempt + 1}/{max_retries} after {delay}s: {e}"
                        )
                        time.sleep(delay)
                    else:
                        logger.error(f"Max retries exceeded: {e}")
                        raise

            raise last_exception

        return wrapper
    return decorator


class PolicyBindErrorHandler:
    """Centralized error handler for PolicyBind operations."""

    def __init__(
        self,
        on_deny: Optional[Callable] = None,
        on_error: Optional[Callable] = None,
        fallback_allow: bool = False
    ):
        self.on_deny = on_deny
        self.on_error = on_error
        self.fallback_allow = fallback_allow

    def handle_enforcement(
        self,
        client: "PolicyBindClient",
        deployment_id: str,
        user_id: str,
        prompt: str,
        **kwargs
    ) -> tuple[bool, str]:
        """
        Handle enforcement with error handling.

        Returns:
            Tuple of (allowed, prompt_to_use)
        """
        try:
            result = client.enforce(
                deployment_id=deployment_id,
                user_id=user_id,
                prompt=prompt,
                **kwargs
            )

            if result.decision.value == "DENY":
                if self.on_deny:
                    self.on_deny(result)
                return (False, prompt)

            if result.decision.value == "MODIFY":
                return (True, result.modified_prompt)

            return (True, prompt)

        except PolicyDenied as e:
            if self.on_deny:
                self.on_deny(e)
            return (False, prompt)

        except (ConnectionError, TimeoutError) as e:
            logger.error(f"PolicyBind connection error: {e}")
            if self.on_error:
                self.on_error(e)

            if self.fallback_allow:
                logger.warning("Falling back to ALLOW due to connection error")
                return (True, prompt)

            raise

        except Exception as e:
            logger.exception(f"Unexpected error in PolicyBind: {e}")
            if self.on_error:
                self.on_error(e)
            raise


# Usage with retry and error handling
@with_retry(max_retries=3, strategy=RetryStrategy.EXPONENTIAL)
def safe_enforce(client, deployment_id, user_id, prompt):
    return client.enforce(
        deployment_id=deployment_id,
        user_id=user_id,
        prompt=prompt
    )


# Usage with error handler
handler = PolicyBindErrorHandler(
    on_deny=lambda r: logger.warning(f"Request denied: {r.reason}"),
    on_error=lambda e: alert_ops_team(e),
    fallback_allow=False  # Fail closed
)

allowed, prompt = handler.handle_enforcement(
    client=pb_client,
    deployment_id="dep_abc123",
    user_id="user@example.com",
    prompt="Hello"
)

if allowed:
    response = call_ai(prompt)
```

---

## Best Practices

### 1. Connection Management

```python
# Bad: Creating client for each request
def handle_request(prompt):
    client = PolicyBindClient(token="...")  # Creates connection each time
    return client.enforce(...)

# Good: Reuse client instance
class AIService:
    def __init__(self):
        self.pb_client = PolicyBindClient(
            base_url="http://localhost:8080",
            token="pb_live_xxx"
        )

    def handle_request(self, prompt):
        return self.pb_client.enforce(...)
```

### 2. Graceful Degradation

```python
def enforce_with_fallback(client, prompt, user_id, deployment_id):
    """Enforce with graceful fallback."""
    try:
        result = client.enforce(
            deployment_id=deployment_id,
            user_id=user_id,
            prompt=prompt
        )
        return result
    except (ConnectionError, TimeoutError):
        # Log and decide on fallback behavior
        logger.error("PolicyBind unavailable")

        # Option 1: Fail closed (more secure)
        raise ServiceUnavailableError("Policy enforcement unavailable")

        # Option 2: Fail open (more available, less secure)
        # return EnforcementResult(decision=Decision.ALLOW, ...)
```

### 3. Caching for Performance

```python
from functools import lru_cache
import hashlib


class CachedPolicyBindClient(PolicyBindClient):
    """Client with caching for identical requests."""

    def __init__(self, *args, cache_ttl_seconds: int = 60, **kwargs):
        super().__init__(*args, **kwargs)
        self.cache_ttl = cache_ttl_seconds
        self._cache = {}

    def enforce(self, deployment_id, user_id, prompt, **kwargs):
        # Create cache key
        cache_key = hashlib.sha256(
            f"{deployment_id}:{user_id}:{prompt}".encode()
        ).hexdigest()

        # Check cache
        if cache_key in self._cache:
            result, timestamp = self._cache[cache_key]
            if time.time() - timestamp < self.cache_ttl:
                return result

        # Call API
        result = super().enforce(deployment_id, user_id, prompt, **kwargs)

        # Cache result
        self._cache[cache_key] = (result, time.time())

        return result
```

### 4. Logging and Monitoring

```python
import logging
import time
from dataclasses import dataclass


@dataclass
class EnforcementMetrics:
    total_requests: int = 0
    allowed_requests: int = 0
    denied_requests: int = 0
    modified_requests: int = 0
    total_latency_ms: float = 0
    errors: int = 0


class MonitoredPolicyBindClient(PolicyBindClient):
    """Client with built-in monitoring."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.metrics = EnforcementMetrics()
        self.logger = logging.getLogger("policybind.client")

    def enforce(self, *args, **kwargs):
        start_time = time.time()

        try:
            result = super().enforce(*args, **kwargs)

            # Update metrics
            self.metrics.total_requests += 1
            latency = (time.time() - start_time) * 1000
            self.metrics.total_latency_ms += latency

            if result.decision.value == "ALLOW":
                self.metrics.allowed_requests += 1
            elif result.decision.value == "DENY":
                self.metrics.denied_requests += 1
            elif result.decision.value == "MODIFY":
                self.metrics.modified_requests += 1

            # Log
            self.logger.info(
                f"Enforcement: decision={result.decision.value}, "
                f"latency={latency:.2f}ms, user={kwargs.get('user_id')}"
            )

            return result

        except Exception as e:
            self.metrics.errors += 1
            self.logger.error(f"Enforcement error: {e}")
            raise

    def get_metrics(self) -> dict:
        """Get current metrics."""
        avg_latency = (
            self.metrics.total_latency_ms / self.metrics.total_requests
            if self.metrics.total_requests > 0
            else 0
        )

        return {
            "total_requests": self.metrics.total_requests,
            "allowed_requests": self.metrics.allowed_requests,
            "denied_requests": self.metrics.denied_requests,
            "modified_requests": self.metrics.modified_requests,
            "errors": self.metrics.errors,
            "average_latency_ms": avg_latency,
            "deny_rate": (
                self.metrics.denied_requests / self.metrics.total_requests
                if self.metrics.total_requests > 0
                else 0
            )
        }
```

### 5. Testing

```python
"""Testing utilities for PolicyBind integration."""

from unittest.mock import Mock, patch


class MockPolicyBindClient:
    """Mock client for testing."""

    def __init__(self, default_decision: Decision = Decision.ALLOW):
        self.default_decision = default_decision
        self.enforce_calls = []

    def enforce(self, **kwargs) -> EnforcementResult:
        self.enforce_calls.append(kwargs)
        return EnforcementResult(
            decision=self.default_decision,
            request_id="test_req_123"
        )

    def set_response(
        self,
        decision: Decision,
        modified_prompt: str = None,
        reason: str = None
    ):
        """Configure mock response."""
        self.default_decision = decision
        self._modified_prompt = modified_prompt
        self._reason = reason


# Usage in tests
def test_ai_service_handles_deny():
    mock_client = MockPolicyBindClient(default_decision=Decision.DENY)
    mock_client._reason = "PII detected"

    service = AIService(pb_client=mock_client)

    with pytest.raises(PolicyDenied):
        service.process_prompt("Hello")

    assert len(mock_client.enforce_calls) == 1
```
