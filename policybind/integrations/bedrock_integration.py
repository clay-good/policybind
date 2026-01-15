"""
AWS Bedrock SDK integration for PolicyBind.

This module provides middleware and wrapper classes for integrating
PolicyBind policy enforcement with the AWS Bedrock Runtime SDK.

The integration works by wrapping the Bedrock Runtime client and intercepting
API calls before they are made. This allows PolicyBind to:
- Enforce policies before requests are sent
- Block denied requests from reaching the API
- Track usage and costs
- Log all requests for audit purposes

Example:
    Basic usage::

        import boto3
        from policybind.integrations.bedrock_integration import (
            create_policy_client,
            PolicyBindBedrock,
        )

        # Method 1: Create a wrapped client
        client = create_policy_client(
            policy_set=policy_set,
            user_id="user@example.com",
            department="engineering",
        )

        # Method 2: Wrap an existing client
        bedrock_client = boto3.client("bedrock-runtime")
        wrapped_client = PolicyBindBedrock(
            client=bedrock_client,
            policy_set=policy_set,
            user_id="user@example.com",
        )

        # Use as normal - invoke model
        response = client.invoke_model(
            modelId="anthropic.claude-3-sonnet-20240229-v1:0",
            body=json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 1024,
                "messages": [{"role": "user", "content": "Hello!"}]
            }),
        )

    With enforcement callback::

        def on_decision(request, response):
            print(f"Decision: {response.decision}")
            if response.is_denied():
                print(f"Blocked: {response.reason}")

        client = create_policy_client(
            policy_set=policy_set,
            on_enforcement=on_decision,
        )

    Using Converse API::

        response = client.converse(
            modelId="anthropic.claude-3-sonnet-20240229-v1:0",
            messages=[{"role": "user", "content": [{"text": "Hello!"}]}],
        )
"""

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

from policybind.engine.pipeline import EnforcementPipeline, PipelineConfig
from policybind.exceptions import PolicyBindError
from policybind.models.policy import PolicySet
from policybind.models.request import AIRequest, AIResponse, Decision

if TYPE_CHECKING:
    pass

logger = logging.getLogger("policybind.integrations.bedrock")


# Token cost estimates per model (per 1K tokens, input/output)
# AWS Bedrock pricing as of 2024 (On-Demand pricing, US regions)
MODEL_COSTS = {
    # Anthropic Claude 3.5
    "anthropic.claude-3-5-sonnet-20241022-v2:0": (3.00, 15.00),
    "anthropic.claude-3-5-sonnet-20240620-v1:0": (3.00, 15.00),
    "anthropic.claude-3-5-haiku-20241022-v1:0": (0.80, 4.00),
    # Anthropic Claude 3
    "anthropic.claude-3-opus-20240229-v1:0": (15.00, 75.00),
    "anthropic.claude-3-sonnet-20240229-v1:0": (3.00, 15.00),
    "anthropic.claude-3-haiku-20240307-v1:0": (0.25, 1.25),
    # Anthropic Claude 2
    "anthropic.claude-v2:1": (8.00, 24.00),
    "anthropic.claude-v2": (8.00, 24.00),
    "anthropic.claude-instant-v1": (0.80, 2.40),
    # Amazon Titan Text
    "amazon.titan-text-premier-v1:0": (0.50, 1.50),
    "amazon.titan-text-express-v1": (0.20, 0.60),
    "amazon.titan-text-lite-v1": (0.15, 0.20),
    # Amazon Titan Embeddings
    "amazon.titan-embed-text-v2:0": (0.02, 0.00),
    "amazon.titan-embed-text-v1": (0.10, 0.00),
    "amazon.titan-embed-image-v1": (0.80, 0.00),
    # Amazon Nova
    "amazon.nova-pro-v1:0": (0.80, 3.20),
    "amazon.nova-lite-v1:0": (0.06, 0.24),
    "amazon.nova-micro-v1:0": (0.035, 0.14),
    # Meta Llama 3.2
    "meta.llama3-2-90b-instruct-v1:0": (2.00, 2.00),
    "meta.llama3-2-11b-instruct-v1:0": (0.35, 0.35),
    "meta.llama3-2-3b-instruct-v1:0": (0.15, 0.15),
    "meta.llama3-2-1b-instruct-v1:0": (0.10, 0.10),
    # Meta Llama 3.1
    "meta.llama3-1-405b-instruct-v1:0": (5.32, 16.00),
    "meta.llama3-1-70b-instruct-v1:0": (0.99, 0.99),
    "meta.llama3-1-8b-instruct-v1:0": (0.22, 0.22),
    # Meta Llama 3
    "meta.llama3-70b-instruct-v1:0": (2.65, 3.50),
    "meta.llama3-8b-instruct-v1:0": (0.30, 0.60),
    # Mistral AI
    "mistral.mistral-large-2407-v1:0": (4.00, 12.00),
    "mistral.mistral-large-2402-v1:0": (4.00, 12.00),
    "mistral.mistral-small-2402-v1:0": (1.00, 3.00),
    "mistral.mixtral-8x7b-instruct-v0:1": (0.45, 0.70),
    "mistral.mistral-7b-instruct-v0:2": (0.15, 0.20),
    # Cohere
    "cohere.command-r-plus-v1:0": (3.00, 15.00),
    "cohere.command-r-v1:0": (0.50, 1.50),
    "cohere.command-text-v14": (1.50, 2.00),
    "cohere.command-light-text-v14": (0.30, 0.60),
    "cohere.embed-english-v3": (0.10, 0.00),
    "cohere.embed-multilingual-v3": (0.10, 0.00),
    # AI21 Labs Jamba
    "ai21.jamba-1-5-large-v1:0": (2.00, 8.00),
    "ai21.jamba-1-5-mini-v1:0": (0.20, 0.40),
    "ai21.jamba-instruct-v1:0": (0.50, 0.70),
    # AI21 Labs Jurassic
    "ai21.j2-ultra-v1": (18.80, 18.80),
    "ai21.j2-mid-v1": (12.50, 12.50),
    # Stability AI
    "stability.stable-diffusion-xl-v1": (0.04, 0.00),  # Per image
    "stability.sd3-large-v1:0": (0.08, 0.00),  # Per image
}

# Average tokens per word for estimation
TOKENS_PER_WORD = 1.3


class PolicyDeniedError(PolicyBindError):
    """Raised when a request is denied by policy."""

    def __init__(
        self,
        message: str,
        response: AIResponse,
        request: AIRequest | None = None,
    ) -> None:
        """
        Initialize the error.

        Args:
            message: Error message.
            response: The enforcement response.
            request: The original request.
        """
        super().__init__(message)
        self.response = response
        self.request = request
        self.decision = response.decision
        self.reason = response.reason
        self.applied_rules = response.applied_rules


class PolicyApprovalRequiredError(PolicyBindError):
    """Raised when a request requires approval."""

    def __init__(
        self,
        message: str,
        response: AIResponse,
        request: AIRequest | None = None,
    ) -> None:
        """
        Initialize the error.

        Args:
            message: Error message.
            response: The enforcement response.
            request: The original request.
        """
        super().__init__(message)
        self.response = response
        self.request = request
        self.reason = response.reason


@dataclass
class EnforcementContext:
    """
    Context for tracking enforcement during a request.

    Attributes:
        user_id: User making the request.
        department: User's department.
        source_application: Application identifier.
        data_classification: Data classification tags.
        intended_use_case: Use case description.
        metadata: Additional metadata.
    """

    user_id: str = ""
    department: str = ""
    source_application: str = ""
    data_classification: tuple[str, ...] = field(default_factory=tuple)
    intended_use_case: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class EnforcementResult:
    """
    Result of policy enforcement.

    Attributes:
        allowed: Whether the request was allowed.
        request: The AIRequest that was evaluated.
        response: The enforcement response.
        enforcement_time_ms: Time taken for enforcement.
        modified: Whether the request was modified.
        modifications: Any modifications applied.
    """

    allowed: bool
    request: AIRequest
    response: AIResponse
    enforcement_time_ms: float = 0.0
    modified: bool = False
    modifications: dict[str, Any] = field(default_factory=dict)


EnforcementCallback = Callable[[AIRequest, AIResponse], None]


def estimate_tokens(text: str) -> int:
    """
    Estimate the number of tokens in a text string.

    This is a rough estimate based on word count. For accurate
    token counting, use a proper tokenizer.

    Args:
        text: The text to estimate tokens for.

    Returns:
        Estimated token count.
    """
    if not text:
        return 0
    words = len(text.split())
    return int(words * TOKENS_PER_WORD)


def estimate_message_tokens(messages: list[dict[str, Any]]) -> int:
    """
    Estimate tokens for a list of chat messages.

    Args:
        messages: List of message dictionaries.

    Returns:
        Estimated token count.
    """
    total = 0
    for message in messages:
        # Role token overhead
        total += 4  # Approximate overhead per message
        content = message.get("content", "")
        if isinstance(content, str):
            total += estimate_tokens(content)
        elif isinstance(content, list):
            # Multi-modal content (Converse API format)
            for part in content:
                if isinstance(part, dict):
                    if "text" in part:
                        total += estimate_tokens(part.get("text", ""))
                    elif "image" in part:
                        total += 85  # Base image tokens
    return total


def estimate_cost(model_id: str, input_tokens: int, output_tokens: int = 0) -> float:
    """
    Estimate the cost for a request.

    Args:
        model_id: Model ID.
        input_tokens: Number of input tokens.
        output_tokens: Number of output tokens.

    Returns:
        Estimated cost in USD.
    """
    # Normalize model ID
    model_lower = model_id.lower()

    # Find matching model costs
    costs = MODEL_COSTS.get(model_lower)
    if not costs:
        # Try prefix matching
        for model_prefix, model_costs in MODEL_COSTS.items():
            if model_lower.startswith(model_prefix.split("-v")[0]):
                costs = model_costs
                break
        if not costs:
            # Default to Claude 3 Haiku pricing as fallback
            costs = MODEL_COSTS["anthropic.claude-3-haiku-20240307-v1:0"]

    # Bedrock prices are per 1K tokens (not 1M like some other providers)
    input_cost = (input_tokens / 1_000) * costs[0]
    output_cost = (output_tokens / 1_000) * costs[1] if output_tokens > 0 else 0

    return input_cost + output_cost


def hash_content(content: str) -> str:
    """
    Create a SHA-256 hash of content.

    Args:
        content: Content to hash.

    Returns:
        Hex digest of the hash.
    """
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def extract_content_from_body(body: bytes | str | dict) -> str:
    """
    Extract text content from various Bedrock request body formats.

    Args:
        body: Request body (bytes, string, or dict).

    Returns:
        Content string for hashing.
    """
    parts = []

    # Parse body if needed
    if isinstance(body, bytes):
        try:
            body = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return ""
    elif isinstance(body, str):
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            return body

    if not isinstance(body, dict):
        return str(body)

    # Anthropic Claude format (messages API)
    if "messages" in body:
        for msg in body["messages"]:
            content = msg.get("content", "")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and "text" in part:
                        parts.append(part["text"])

    # Anthropic Claude format (legacy prompt)
    if "prompt" in body:
        parts.append(body["prompt"])

    # Amazon Titan format
    if "inputText" in body:
        parts.append(body["inputText"])

    # Meta Llama format
    if "prompt" in body and not parts:
        parts.append(body["prompt"])

    # Cohere format
    if "message" in body:
        parts.append(body["message"])

    # AI21 format
    if "text" in body:
        parts.append(body["text"])

    # System prompt
    if "system" in body:
        if isinstance(body["system"], str):
            parts.append(body["system"])
        elif isinstance(body["system"], list):
            for s in body["system"]:
                if isinstance(s, dict) and "text" in s:
                    parts.append(s["text"])

    return "\n".join(parts)


def extract_content_from_converse(messages: list[dict[str, Any]]) -> str:
    """
    Extract text content from Converse API messages.

    Args:
        messages: List of Converse API message dictionaries.

    Returns:
        Content string for hashing.
    """
    parts = []
    for msg in messages:
        content = msg.get("content", [])
        if isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and "text" in part:
                    parts.append(part["text"])
    return "\n".join(parts)


def get_provider_from_model_id(model_id: str) -> str:
    """
    Extract the provider name from a Bedrock model ID.

    Args:
        model_id: The model ID (e.g., "anthropic.claude-3-sonnet-20240229-v1:0").

    Returns:
        Provider name (e.g., "anthropic").
    """
    if "." in model_id:
        return model_id.split(".")[0]
    return "unknown"


class PolicyEnforcer:
    """
    Handles policy enforcement for Bedrock requests.

    This class manages the enforcement pipeline and tracks statistics
    for all requests processed.
    """

    def __init__(
        self,
        policy_set: PolicySet,
        context: EnforcementContext | None = None,
        pipeline_config: PipelineConfig | None = None,
        on_enforcement: EnforcementCallback | None = None,
        raise_on_deny: bool = True,
        raise_on_approval_required: bool = True,
    ) -> None:
        """
        Initialize the enforcer.

        Args:
            policy_set: The policy set to enforce.
            context: Default enforcement context.
            pipeline_config: Pipeline configuration.
            on_enforcement: Callback for enforcement decisions.
            raise_on_deny: Whether to raise on denied requests.
            raise_on_approval_required: Whether to raise on approval required.
        """
        self.policy_set = policy_set
        self.context = context or EnforcementContext()
        self.on_enforcement = on_enforcement
        self.raise_on_deny = raise_on_deny
        self.raise_on_approval_required = raise_on_approval_required

        # Create enforcement pipeline
        self.pipeline = EnforcementPipeline(policy_set, pipeline_config)

        # Statistics
        self._total_requests = 0
        self._allowed_requests = 0
        self._denied_requests = 0
        self._modified_requests = 0

    @property
    def stats(self) -> dict[str, int]:
        """Get enforcement statistics."""
        return {
            "total_requests": self._total_requests,
            "allowed_requests": self._allowed_requests,
            "denied_requests": self._denied_requests,
            "modified_requests": self._modified_requests,
        }

    def enforce(
        self,
        model_id: str,
        content: str,
        request_type: str = "invoke_model",
        context_override: EnforcementContext | None = None,
        **kwargs: Any,
    ) -> EnforcementResult:
        """
        Enforce policies for a Bedrock request.

        Args:
            model_id: Model ID.
            content: Request content.
            request_type: Type of request (invoke_model, converse, etc.).
            context_override: Override the default context.
            **kwargs: Additional parameters.

        Returns:
            EnforcementResult with the decision.

        Raises:
            PolicyDeniedError: If request is denied and raise_on_deny is True.
            PolicyApprovalRequiredError: If approval required.
        """
        start_time = time.time()
        ctx = context_override or self.context

        # Hash content for privacy
        prompt_hash = hash_content(content)

        # Estimate tokens and cost
        estimated_tokens = estimate_tokens(content)
        estimated_cost = estimate_cost(model_id, estimated_tokens, estimated_tokens)

        # Extract provider from model ID
        provider = get_provider_from_model_id(model_id)

        # Build AI request
        ai_request = AIRequest(
            provider=f"bedrock-{provider}",
            model=model_id,
            prompt_hash=prompt_hash,
            estimated_tokens=estimated_tokens,
            estimated_cost=estimated_cost,
            source_application=ctx.source_application,
            user_id=ctx.user_id,
            department=ctx.department,
            data_classification=list(ctx.data_classification),
            intended_use_case=ctx.intended_use_case,
            metadata={
                **ctx.metadata,
                "bedrock": True,
                "bedrock_provider": provider,
                "request_type": request_type,
                **{k: v for k, v in kwargs.items() if k not in ("body", "messages")},
            },
        )

        # Run enforcement through pipeline
        ai_response = self.pipeline.process(ai_request)
        enforcement_time = (time.time() - start_time) * 1000

        # Update statistics
        self._total_requests += 1
        if ai_response.decision == Decision.ALLOW:
            self._allowed_requests += 1
        elif ai_response.decision == Decision.DENY:
            self._denied_requests += 1
        elif ai_response.decision == Decision.MODIFY:
            self._modified_requests += 1

        # Call callback if provided
        if self.on_enforcement:
            try:
                self.on_enforcement(ai_request, ai_response)
            except Exception as e:
                logger.warning(f"Enforcement callback error: {e}")

        result = EnforcementResult(
            allowed=ai_response.is_allowed(),
            request=ai_request,
            response=ai_response,
            enforcement_time_ms=enforcement_time,
            modified=ai_response.decision == Decision.MODIFY,
            modifications=ai_response.modifications,
        )

        # Handle deny
        if ai_response.decision == Decision.DENY and self.raise_on_deny:
            raise PolicyDeniedError(
                f"Request denied by policy: {ai_response.reason}",
                ai_response,
                ai_request,
            )

        # Handle approval required
        if ai_response.decision == Decision.REQUIRE_APPROVAL and self.raise_on_approval_required:
            raise PolicyApprovalRequiredError(
                f"Request requires approval: {ai_response.reason}",
                ai_response,
                ai_request,
            )

        return result


class InvokeModelWrapper:
    """Wrapper for Bedrock client invoke_model method."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The Bedrock Runtime client.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        modelId: str,
        body: bytes | str,
        contentType: str = "application/json",
        accept: str = "application/json",
        **kwargs: Any,
    ) -> Any:
        """
        Invoke a model with policy enforcement.

        Args:
            modelId: Model ID to invoke.
            body: Request body.
            contentType: Content type.
            accept: Accept header.
            **kwargs: Additional arguments.

        Returns:
            Model invocation response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        # Extract content from body
        content = extract_content_from_body(body)

        # Enforce policies
        result = self._enforcer.enforce(
            model_id=modelId,
            content=content,
            request_type="invoke_model",
            contentType=contentType,
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._client.invoke_model(
            modelId=modelId,
            body=body,
            contentType=contentType,
            accept=accept,
            **kwargs,
        )


class InvokeModelWithResponseStreamWrapper:
    """Wrapper for Bedrock client invoke_model_with_response_stream method."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The Bedrock Runtime client.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        modelId: str,
        body: bytes | str,
        contentType: str = "application/json",
        accept: str = "application/json",
        **kwargs: Any,
    ) -> Any:
        """
        Invoke a model with streaming response and policy enforcement.

        Args:
            modelId: Model ID to invoke.
            body: Request body.
            contentType: Content type.
            accept: Accept header.
            **kwargs: Additional arguments.

        Returns:
            Streaming model invocation response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        # Extract content from body
        content = extract_content_from_body(body)

        # Enforce policies
        result = self._enforcer.enforce(
            model_id=modelId,
            content=content,
            request_type="invoke_model_stream",
            contentType=contentType,
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._client.invoke_model_with_response_stream(
            modelId=modelId,
            body=body,
            contentType=contentType,
            accept=accept,
            **kwargs,
        )


class ConverseWrapper:
    """Wrapper for Bedrock client converse method."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The Bedrock Runtime client.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        modelId: str,
        messages: list[dict[str, Any]],
        system: list[dict[str, Any]] | None = None,
        inferenceConfig: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        """
        Converse with a model using policy enforcement.

        Args:
            modelId: Model ID to use.
            messages: Conversation messages.
            system: System prompts.
            inferenceConfig: Inference configuration.
            **kwargs: Additional arguments.

        Returns:
            Converse response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        # Extract content from messages
        content = extract_content_from_converse(messages)
        if system:
            system_content = extract_content_from_converse([{"content": system}])
            content = f"{system_content}\n{content}"

        # Enforce policies
        result = self._enforcer.enforce(
            model_id=modelId,
            content=content,
            request_type="converse",
            inferenceConfig=inferenceConfig,
        )

        if not result.allowed:
            return None

        # Build kwargs for the actual call
        call_kwargs: dict[str, Any] = {"modelId": modelId, "messages": messages}
        if system:
            call_kwargs["system"] = system
        if inferenceConfig:
            call_kwargs["inferenceConfig"] = inferenceConfig
        call_kwargs.update(kwargs)

        # Call the actual method
        return self._client.converse(**call_kwargs)


class ConverseStreamWrapper:
    """Wrapper for Bedrock client converse_stream method."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The Bedrock Runtime client.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        modelId: str,
        messages: list[dict[str, Any]],
        system: list[dict[str, Any]] | None = None,
        inferenceConfig: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        """
        Converse with streaming using policy enforcement.

        Args:
            modelId: Model ID to use.
            messages: Conversation messages.
            system: System prompts.
            inferenceConfig: Inference configuration.
            **kwargs: Additional arguments.

        Returns:
            Streaming converse response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        # Extract content from messages
        content = extract_content_from_converse(messages)
        if system:
            system_content = extract_content_from_converse([{"content": system}])
            content = f"{system_content}\n{content}"

        # Enforce policies
        result = self._enforcer.enforce(
            model_id=modelId,
            content=content,
            request_type="converse_stream",
            inferenceConfig=inferenceConfig,
        )

        if not result.allowed:
            return None

        # Build kwargs for the actual call
        call_kwargs: dict[str, Any] = {"modelId": modelId, "messages": messages}
        if system:
            call_kwargs["system"] = system
        if inferenceConfig:
            call_kwargs["inferenceConfig"] = inferenceConfig
        call_kwargs.update(kwargs)

        # Call the actual method
        return self._client.converse_stream(**call_kwargs)


class ApplyGuardrailWrapper:
    """Wrapper for Bedrock client apply_guardrail method."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The Bedrock Runtime client.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        guardrailIdentifier: str,
        guardrailVersion: str,
        source: str,
        content: list[dict[str, Any]],
        **kwargs: Any,
    ) -> Any:
        """
        Apply guardrail with policy enforcement.

        Args:
            guardrailIdentifier: Guardrail identifier.
            guardrailVersion: Guardrail version.
            source: Source type (INPUT or OUTPUT).
            content: Content to evaluate.
            **kwargs: Additional arguments.

        Returns:
            Guardrail evaluation response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        # Extract text content
        text_content = ""
        for item in content:
            if "text" in item:
                text_content += item["text"]["text"] + "\n"

        # Enforce policies
        result = self._enforcer.enforce(
            model_id=f"guardrail:{guardrailIdentifier}",
            content=text_content,
            request_type="apply_guardrail",
            guardrailVersion=guardrailVersion,
            source=source,
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._client.apply_guardrail(
            guardrailIdentifier=guardrailIdentifier,
            guardrailVersion=guardrailVersion,
            source=source,
            content=content,
            **kwargs,
        )


class PolicyBindBedrock:
    """
    Policy-enforcing wrapper for AWS Bedrock Runtime client.

    This class wraps a Bedrock Runtime client and enforces PolicyBind policies
    on all API requests.
    """

    def __init__(
        self,
        client: Any,
        policy_set: PolicySet,
        user_id: str = "",
        department: str = "",
        source_application: str = "",
        data_classification: tuple[str, ...] | list[str] = (),
        intended_use_case: str = "",
        metadata: dict[str, Any] | None = None,
        on_enforcement: EnforcementCallback | None = None,
        raise_on_deny: bool = True,
        raise_on_approval_required: bool = True,
    ) -> None:
        """
        Initialize the policy-enforcing client wrapper.

        Args:
            client: The Bedrock Runtime client to wrap.
            policy_set: The policy set to enforce.
            user_id: User making requests.
            department: User's department.
            source_application: Application identifier.
            data_classification: Data classification tags.
            intended_use_case: Use case description.
            metadata: Additional metadata.
            on_enforcement: Callback for enforcement decisions.
            raise_on_deny: Whether to raise on denied requests.
            raise_on_approval_required: Whether to raise on approval required.
        """
        self._client = client

        # Create enforcement context
        context = EnforcementContext(
            user_id=user_id,
            department=department,
            source_application=source_application,
            data_classification=tuple(data_classification),
            intended_use_case=intended_use_case,
            metadata=metadata or {},
        )

        # Create enforcer
        self._enforcer = PolicyEnforcer(
            policy_set=policy_set,
            context=context,
            on_enforcement=on_enforcement,
            raise_on_deny=raise_on_deny,
            raise_on_approval_required=raise_on_approval_required,
        )

        # Wrap methods
        self.invoke_model = InvokeModelWrapper(client, self._enforcer)
        self.invoke_model_with_response_stream = InvokeModelWithResponseStreamWrapper(
            client, self._enforcer
        )
        self.converse = ConverseWrapper(client, self._enforcer)
        self.converse_stream = ConverseStreamWrapper(client, self._enforcer)
        self.apply_guardrail = ApplyGuardrailWrapper(client, self._enforcer)

    @property
    def stats(self) -> dict[str, int]:
        """Get enforcement statistics."""
        return self._enforcer.stats

    def __getattr__(self, name: str) -> Any:
        """Forward attribute access to the wrapped client."""
        return getattr(self._client, name)


def create_policy_client(
    policy_set: PolicySet,
    region_name: str | None = None,
    user_id: str = "",
    department: str = "",
    source_application: str = "",
    data_classification: tuple[str, ...] | list[str] = (),
    intended_use_case: str = "",
    metadata: dict[str, Any] | None = None,
    on_enforcement: EnforcementCallback | None = None,
    raise_on_deny: bool = True,
    raise_on_approval_required: bool = True,
    **client_kwargs: Any,
) -> PolicyBindBedrock:
    """
    Create a policy-enforced Bedrock Runtime client.

    This is the recommended way to create a policy-enforced Bedrock client.

    Args:
        policy_set: The policy set to enforce.
        region_name: AWS region name (or use AWS_DEFAULT_REGION env var).
        user_id: User making requests.
        department: User's department.
        source_application: Application identifier.
        data_classification: Data classification tags.
        intended_use_case: Use case description.
        metadata: Additional metadata.
        on_enforcement: Callback for enforcement decisions.
        raise_on_deny: Whether to raise on denied requests.
        raise_on_approval_required: Whether to raise on approval required.
        **client_kwargs: Additional arguments for boto3 client.

    Returns:
        PolicyBindBedrock wrapping a new Bedrock Runtime client.

    Example:
        >>> client = create_policy_client(
        ...     policy_set=policy_set,
        ...     region_name="us-east-1",
        ...     user_id="user@example.com",
        ...     department="engineering",
        ... )
        >>> response = client.converse(
        ...     modelId="anthropic.claude-3-sonnet-20240229-v1:0",
        ...     messages=[{"role": "user", "content": [{"text": "Hello!"}]}],
        ... )
    """
    try:
        import boto3

        # Create the base client
        if region_name:
            client = boto3.client("bedrock-runtime", region_name=region_name, **client_kwargs)
        else:
            client = boto3.client("bedrock-runtime", **client_kwargs)

        return PolicyBindBedrock(
            client=client,
            policy_set=policy_set,
            user_id=user_id,
            department=department,
            source_application=source_application,
            data_classification=data_classification,
            intended_use_case=intended_use_case,
            metadata=metadata,
            on_enforcement=on_enforcement,
            raise_on_deny=raise_on_deny,
            raise_on_approval_required=raise_on_approval_required,
        )
    except ImportError as err:
        raise ImportError(
            "boto3 is not installed. Install with: pip install boto3"
        ) from err


def wrap_client(
    client: Any,
    policy_set: PolicySet,
    user_id: str = "",
    department: str = "",
    source_application: str = "",
    data_classification: tuple[str, ...] | list[str] = (),
    intended_use_case: str = "",
    metadata: dict[str, Any] | None = None,
    on_enforcement: EnforcementCallback | None = None,
    raise_on_deny: bool = True,
    raise_on_approval_required: bool = True,
) -> PolicyBindBedrock:
    """
    Wrap an existing Bedrock Runtime client with policy enforcement.

    Use this when you already have a configured Bedrock client instance.

    Args:
        client: The Bedrock Runtime client to wrap.
        policy_set: The policy set to enforce.
        user_id: User making requests.
        department: User's department.
        source_application: Application identifier.
        data_classification: Data classification tags.
        intended_use_case: Use case description.
        metadata: Additional metadata.
        on_enforcement: Callback for enforcement decisions.
        raise_on_deny: Whether to raise on denied requests.
        raise_on_approval_required: Whether to raise on approval required.

    Returns:
        PolicyBindBedrock wrapping the provided client.

    Example:
        >>> import boto3
        >>> client = boto3.client("bedrock-runtime", region_name="us-east-1")
        >>> wrapped = wrap_client(client, policy_set=policy_set)
        >>> response = wrapped.invoke_model(
        ...     modelId="anthropic.claude-3-sonnet-20240229-v1:0",
        ...     body=json.dumps({"messages": [...]}),
        ... )
    """
    return PolicyBindBedrock(
        client=client,
        policy_set=policy_set,
        user_id=user_id,
        department=department,
        source_application=source_application,
        data_classification=data_classification,
        intended_use_case=intended_use_case,
        metadata=metadata,
        on_enforcement=on_enforcement,
        raise_on_deny=raise_on_deny,
        raise_on_approval_required=raise_on_approval_required,
    )
