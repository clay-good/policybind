"""
OpenAI SDK integration for PolicyBind.

This module provides middleware and wrapper classes for integrating
PolicyBind policy enforcement with the OpenAI Python SDK (>=1.0).

The integration works by wrapping the OpenAI client and intercepting
API calls before they are made. This allows PolicyBind to:
- Enforce policies before requests are sent
- Block denied requests from reaching the API
- Track usage and costs
- Log all requests for audit purposes

Example:
    Basic usage::

        from openai import OpenAI
        from policybind.integrations.openai_integration import (
            create_policy_client,
            PolicyBindOpenAI,
        )

        # Method 1: Create a wrapped client
        client = create_policy_client(
            policy_set=policy_set,
            user_id="user@example.com",
            department="engineering",
        )

        # Method 2: Wrap an existing client
        original_client = OpenAI()
        wrapped_client = PolicyBindOpenAI(
            client=original_client,
            policy_set=policy_set,
            user_id="user@example.com",
        )

        # Use as normal
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Hello!"}]
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
"""

import hashlib
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Callable

from policybind.engine.pipeline import EnforcementPipeline, PipelineConfig
from policybind.exceptions import EnforcementError, PolicyBindError
from policybind.models.policy import PolicySet
from policybind.models.request import AIRequest, AIResponse, Decision

if TYPE_CHECKING:
    pass

logger = logging.getLogger("policybind.integrations.openai")


# Token cost estimates per model (per 1K tokens, input/output)
MODEL_COSTS = {
    # GPT-4 Turbo
    "gpt-4-turbo": (0.01, 0.03),
    "gpt-4-turbo-preview": (0.01, 0.03),
    "gpt-4-0125-preview": (0.01, 0.03),
    "gpt-4-1106-preview": (0.01, 0.03),
    # GPT-4
    "gpt-4": (0.03, 0.06),
    "gpt-4-0613": (0.03, 0.06),
    "gpt-4-32k": (0.06, 0.12),
    "gpt-4-32k-0613": (0.06, 0.12),
    # GPT-4o
    "gpt-4o": (0.005, 0.015),
    "gpt-4o-2024-05-13": (0.005, 0.015),
    "gpt-4o-mini": (0.00015, 0.0006),
    "gpt-4o-mini-2024-07-18": (0.00015, 0.0006),
    # GPT-3.5
    "gpt-3.5-turbo": (0.0005, 0.0015),
    "gpt-3.5-turbo-0125": (0.0005, 0.0015),
    "gpt-3.5-turbo-1106": (0.001, 0.002),
    "gpt-3.5-turbo-instruct": (0.0015, 0.002),
    # o1 reasoning models
    "o1": (0.015, 0.06),
    "o1-preview": (0.015, 0.06),
    "o1-mini": (0.003, 0.012),
    # Embeddings
    "text-embedding-3-small": (0.00002, 0.0),
    "text-embedding-3-large": (0.00013, 0.0),
    "text-embedding-ada-002": (0.0001, 0.0),
    # DALL-E (per image, not tokens)
    "dall-e-3": (0.04, 0.0),
    "dall-e-2": (0.02, 0.0),
    # TTS
    "tts-1": (0.015, 0.0),
    "tts-1-hd": (0.03, 0.0),
    # Whisper
    "whisper-1": (0.006, 0.0),  # per minute
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
    token counting, use the tiktoken library.

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
        # Role token
        total += 4  # Approximate overhead per message
        content = message.get("content", "")
        if isinstance(content, str):
            total += estimate_tokens(content)
        elif isinstance(content, list):
            # Multi-modal content
            for part in content:
                if isinstance(part, dict):
                    if part.get("type") == "text":
                        total += estimate_tokens(part.get("text", ""))
                    elif part.get("type") == "image_url":
                        total += 85  # Base image tokens
    return total


def estimate_cost(model: str, input_tokens: int, output_tokens: int = 0) -> float:
    """
    Estimate the cost for a request.

    Args:
        model: Model name.
        input_tokens: Number of input tokens.
        output_tokens: Number of output tokens (for estimation).

    Returns:
        Estimated cost in USD.
    """
    # Find matching model costs
    costs = MODEL_COSTS.get(model)
    if not costs:
        # Try prefix matching
        for model_prefix, model_costs in MODEL_COSTS.items():
            if model.startswith(model_prefix):
                costs = model_costs
                break
        if not costs:
            # Default to GPT-3.5 pricing as fallback
            costs = MODEL_COSTS["gpt-3.5-turbo"]

    input_cost = (input_tokens / 1000) * costs[0]
    output_cost = (output_tokens / 1000) * costs[1] if output_tokens > 0 else 0

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


def extract_content_for_hash(messages: list[dict[str, Any]] | None = None, **kwargs: Any) -> str:
    """
    Extract content from various request types for hashing.

    Args:
        messages: Chat messages (for chat completions).
        **kwargs: Other request parameters.

    Returns:
        Content string for hashing.
    """
    parts = []

    if messages:
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        parts.append(part.get("text", ""))

    # For completions API
    if "prompt" in kwargs:
        prompt = kwargs["prompt"]
        if isinstance(prompt, str):
            parts.append(prompt)
        elif isinstance(prompt, list):
            parts.extend(str(p) for p in prompt)

    # For embeddings
    if "input" in kwargs:
        input_data = kwargs["input"]
        if isinstance(input_data, str):
            parts.append(input_data)
        elif isinstance(input_data, list):
            parts.extend(str(i) for i in input_data)

    return "\n".join(parts)


class PolicyEnforcer:
    """
    Handles policy enforcement for OpenAI requests.

    This class encapsulates the logic for creating AIRequest objects,
    running them through the enforcement pipeline, and handling the
    results.
    """

    def __init__(
        self,
        policy_set: PolicySet,
        pipeline_config: PipelineConfig | None = None,
        default_context: EnforcementContext | None = None,
        on_enforcement: EnforcementCallback | None = None,
        raise_on_deny: bool = True,
        raise_on_approval_required: bool = True,
    ) -> None:
        """
        Initialize the policy enforcer.

        Args:
            policy_set: PolicySet to enforce.
            pipeline_config: Pipeline configuration.
            default_context: Default context for requests.
            on_enforcement: Callback for enforcement decisions.
            raise_on_deny: Whether to raise exception on deny.
            raise_on_approval_required: Whether to raise on approval required.
        """
        self._policy_set = policy_set
        self._pipeline = EnforcementPipeline(policy_set, pipeline_config)
        self._default_context = default_context or EnforcementContext()
        self._on_enforcement = on_enforcement
        self._raise_on_deny = raise_on_deny
        self._raise_on_approval_required = raise_on_approval_required

        # Statistics
        self._total_requests = 0
        self._allowed_requests = 0
        self._denied_requests = 0
        self._modified_requests = 0
        self._approval_required_requests = 0

    def enforce(
        self,
        model: str,
        messages: list[dict[str, Any]] | None = None,
        context: EnforcementContext | None = None,
        **kwargs: Any,
    ) -> EnforcementResult:
        """
        Enforce policies for a request.

        Args:
            model: Model being requested.
            messages: Chat messages (for chat completions).
            context: Request context override.
            **kwargs: Additional request parameters.

        Returns:
            EnforcementResult with the decision.

        Raises:
            PolicyDeniedError: If request is denied and raise_on_deny is True.
            PolicyApprovalRequiredError: If approval is required and raise_on_approval_required is True.
        """
        ctx = context or self._default_context
        start_time = time.perf_counter()

        # Estimate tokens
        if messages:
            estimated_tokens = estimate_message_tokens(messages)
        else:
            content = extract_content_for_hash(messages, **kwargs)
            estimated_tokens = estimate_tokens(content)

        # Estimate cost
        estimated_cost = estimate_cost(model, estimated_tokens)

        # Create content hash
        content_for_hash = extract_content_for_hash(messages, **kwargs)
        prompt_hash = hash_content(content_for_hash) if content_for_hash else ""

        # Build AIRequest
        ai_request = AIRequest(
            provider="openai",
            model=model,
            prompt_hash=prompt_hash,
            estimated_tokens=estimated_tokens,
            estimated_cost=estimated_cost,
            source_application=ctx.source_application,
            user_id=ctx.user_id,
            department=ctx.department,
            data_classification=ctx.data_classification,
            intended_use_case=ctx.intended_use_case,
            metadata={
                **ctx.metadata,
                "has_messages": messages is not None,
                "message_count": len(messages) if messages else 0,
            },
        )

        # Run through pipeline
        ai_response = self._pipeline.process(ai_request)
        enforcement_time = (time.perf_counter() - start_time) * 1000

        # Update statistics
        self._total_requests += 1
        if ai_response.decision == Decision.ALLOW:
            self._allowed_requests += 1
        elif ai_response.decision == Decision.DENY:
            self._denied_requests += 1
        elif ai_response.decision == Decision.MODIFY:
            self._modified_requests += 1
        elif ai_response.decision == Decision.REQUIRE_APPROVAL:
            self._approval_required_requests += 1

        # Call callback if set
        if self._on_enforcement:
            try:
                self._on_enforcement(ai_request, ai_response)
            except Exception as e:
                logger.warning(f"Enforcement callback failed: {e}")

        # Build result
        result = EnforcementResult(
            allowed=ai_response.is_allowed(),
            request=ai_request,
            response=ai_response,
            enforcement_time_ms=enforcement_time,
            modified=ai_response.decision == Decision.MODIFY,
            modifications=ai_response.modifications,
        )

        # Handle decisions
        if ai_response.is_denied() and self._raise_on_deny:
            raise PolicyDeniedError(
                f"Request denied by policy: {ai_response.reason}",
                response=ai_response,
                request=ai_request,
            )

        if ai_response.requires_approval() and self._raise_on_approval_required:
            raise PolicyApprovalRequiredError(
                f"Request requires approval: {ai_response.reason}",
                response=ai_response,
                request=ai_request,
            )

        return result

    def reload_policies(self, policy_set: PolicySet) -> None:
        """
        Reload with a new policy set.

        Args:
            policy_set: New PolicySet to use.
        """
        self._policy_set = policy_set
        self._pipeline.reload_policies(policy_set)

    def get_stats(self) -> dict[str, Any]:
        """
        Get enforcement statistics.

        Returns:
            Dictionary of statistics.
        """
        return {
            "total_requests": self._total_requests,
            "allowed_requests": self._allowed_requests,
            "denied_requests": self._denied_requests,
            "modified_requests": self._modified_requests,
            "approval_required_requests": self._approval_required_requests,
            "allow_rate": (
                self._allowed_requests / self._total_requests * 100
                if self._total_requests > 0
                else 0.0
            ),
            "deny_rate": (
                self._denied_requests / self._total_requests * 100
                if self._total_requests > 0
                else 0.0
            ),
        }

    def reset_stats(self) -> None:
        """Reset enforcement statistics."""
        self._total_requests = 0
        self._allowed_requests = 0
        self._denied_requests = 0
        self._modified_requests = 0
        self._approval_required_requests = 0


class ChatCompletionsWrapper:
    """
    Wrapper for OpenAI chat.completions API with policy enforcement.

    This wrapper intercepts calls to the chat completions API and
    runs them through PolicyBind enforcement before allowing them
    to proceed.
    """

    def __init__(
        self,
        original_completions: Any,
        enforcer: PolicyEnforcer,
        context: EnforcementContext,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            original_completions: Original completions object.
            enforcer: Policy enforcer.
            context: Enforcement context.
        """
        self._original = original_completions
        self._enforcer = enforcer
        self._context = context

    def create(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        **kwargs: Any,
    ) -> Any:
        """
        Create a chat completion with policy enforcement.

        Args:
            model: Model to use.
            messages: Chat messages.
            **kwargs: Additional parameters.

        Returns:
            Chat completion response.

        Raises:
            PolicyDeniedError: If request is denied.
            PolicyApprovalRequiredError: If approval is required.
        """
        # Enforce policies
        result = self._enforcer.enforce(
            model=model,
            messages=messages,
            context=self._context,
            **kwargs,
        )

        logger.debug(
            f"Enforcement result: allowed={result.allowed}, "
            f"decision={result.response.decision.value}, "
            f"time={result.enforcement_time_ms:.2f}ms"
        )

        # If allowed, proceed with the request
        return self._original.create(model=model, messages=messages, **kwargs)


class ChatWrapper:
    """Wrapper for OpenAI chat API."""

    def __init__(
        self,
        original_chat: Any,
        enforcer: PolicyEnforcer,
        context: EnforcementContext,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            original_chat: Original chat object.
            enforcer: Policy enforcer.
            context: Enforcement context.
        """
        self._original = original_chat
        self._enforcer = enforcer
        self._context = context

    @property
    def completions(self) -> ChatCompletionsWrapper:
        """Get wrapped completions object."""
        return ChatCompletionsWrapper(
            self._original.completions,
            self._enforcer,
            self._context,
        )


class EmbeddingsWrapper:
    """Wrapper for OpenAI embeddings API with policy enforcement."""

    def __init__(
        self,
        original_embeddings: Any,
        enforcer: PolicyEnforcer,
        context: EnforcementContext,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            original_embeddings: Original embeddings object.
            enforcer: Policy enforcer.
            context: Enforcement context.
        """
        self._original = original_embeddings
        self._enforcer = enforcer
        self._context = context

    def create(
        self,
        *,
        model: str,
        input: str | list[str],
        **kwargs: Any,
    ) -> Any:
        """
        Create embeddings with policy enforcement.

        Args:
            model: Model to use.
            input: Text to embed.
            **kwargs: Additional parameters.

        Returns:
            Embeddings response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        # Enforce policies
        self._enforcer.enforce(
            model=model,
            context=self._context,
            input=input,
            **kwargs,
        )

        return self._original.create(model=model, input=input, **kwargs)


class CompletionsWrapper:
    """Wrapper for OpenAI completions API with policy enforcement."""

    def __init__(
        self,
        original_completions: Any,
        enforcer: PolicyEnforcer,
        context: EnforcementContext,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            original_completions: Original completions object.
            enforcer: Policy enforcer.
            context: Enforcement context.
        """
        self._original = original_completions
        self._enforcer = enforcer
        self._context = context

    def create(
        self,
        *,
        model: str,
        prompt: str | list[str],
        **kwargs: Any,
    ) -> Any:
        """
        Create a completion with policy enforcement.

        Args:
            model: Model to use.
            prompt: Prompt text.
            **kwargs: Additional parameters.

        Returns:
            Completion response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        # Enforce policies
        self._enforcer.enforce(
            model=model,
            context=self._context,
            prompt=prompt,
            **kwargs,
        )

        return self._original.create(model=model, prompt=prompt, **kwargs)


class PolicyBindOpenAI:
    """
    OpenAI client wrapper with PolicyBind enforcement.

    This class wraps an OpenAI client and intercepts API calls to
    enforce policies before requests are made.

    Example:
        Basic usage::

            from openai import OpenAI
            from policybind.integrations.openai_integration import PolicyBindOpenAI

            client = PolicyBindOpenAI(
                client=OpenAI(),
                policy_set=policy_set,
                user_id="user@example.com",
                department="engineering",
            )

            # Use as normal
            response = client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": "Hello!"}]
            )
    """

    def __init__(
        self,
        client: Any,
        policy_set: PolicySet,
        user_id: str = "",
        department: str = "",
        source_application: str = "",
        data_classification: tuple[str, ...] = (),
        intended_use_case: str = "",
        metadata: dict[str, Any] | None = None,
        pipeline_config: PipelineConfig | None = None,
        on_enforcement: EnforcementCallback | None = None,
        raise_on_deny: bool = True,
        raise_on_approval_required: bool = True,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: OpenAI client instance.
            policy_set: PolicySet to enforce.
            user_id: User identifier.
            department: User's department.
            source_application: Application identifier.
            data_classification: Data classification tags.
            intended_use_case: Use case description.
            metadata: Additional metadata.
            pipeline_config: Pipeline configuration.
            on_enforcement: Callback for enforcement decisions.
            raise_on_deny: Whether to raise on deny.
            raise_on_approval_required: Whether to raise on approval required.
        """
        self._client = client
        self._policy_set = policy_set

        self._context = EnforcementContext(
            user_id=user_id,
            department=department,
            source_application=source_application,
            data_classification=data_classification,
            intended_use_case=intended_use_case,
            metadata=metadata or {},
        )

        self._enforcer = PolicyEnforcer(
            policy_set=policy_set,
            pipeline_config=pipeline_config,
            default_context=self._context,
            on_enforcement=on_enforcement,
            raise_on_deny=raise_on_deny,
            raise_on_approval_required=raise_on_approval_required,
        )

    @property
    def chat(self) -> ChatWrapper:
        """Get wrapped chat object."""
        return ChatWrapper(self._client.chat, self._enforcer, self._context)

    @property
    def embeddings(self) -> EmbeddingsWrapper:
        """Get wrapped embeddings object."""
        return EmbeddingsWrapper(
            self._client.embeddings, self._enforcer, self._context
        )

    @property
    def completions(self) -> CompletionsWrapper:
        """Get wrapped completions object."""
        return CompletionsWrapper(
            self._client.completions, self._enforcer, self._context
        )

    @property
    def enforcer(self) -> PolicyEnforcer:
        """Get the policy enforcer."""
        return self._enforcer

    def get_enforcement_stats(self) -> dict[str, Any]:
        """
        Get enforcement statistics.

        Returns:
            Dictionary of statistics.
        """
        return self._enforcer.get_stats()

    def reload_policies(self, policy_set: PolicySet) -> None:
        """
        Reload with a new policy set.

        Args:
            policy_set: New PolicySet to use.
        """
        self._policy_set = policy_set
        self._enforcer.reload_policies(policy_set)

    def update_context(
        self,
        user_id: str | None = None,
        department: str | None = None,
        source_application: str | None = None,
        data_classification: tuple[str, ...] | None = None,
        intended_use_case: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """
        Update the enforcement context.

        Args:
            user_id: New user ID.
            department: New department.
            source_application: New application ID.
            data_classification: New data classification.
            intended_use_case: New use case.
            metadata: Additional metadata to merge.
        """
        if user_id is not None:
            self._context.user_id = user_id
        if department is not None:
            self._context.department = department
        if source_application is not None:
            self._context.source_application = source_application
        if data_classification is not None:
            self._context.data_classification = data_classification
        if intended_use_case is not None:
            self._context.intended_use_case = intended_use_case
        if metadata is not None:
            self._context.metadata.update(metadata)

    def __getattr__(self, name: str) -> Any:
        """
        Forward attribute access to wrapped client.

        This allows access to other OpenAI client attributes and
        methods that are not explicitly wrapped.

        Args:
            name: Attribute name.

        Returns:
            Attribute from wrapped client.
        """
        return getattr(self._client, name)


def create_policy_client(
    policy_set: PolicySet,
    api_key: str | None = None,
    user_id: str = "",
    department: str = "",
    source_application: str = "",
    data_classification: tuple[str, ...] = (),
    intended_use_case: str = "",
    metadata: dict[str, Any] | None = None,
    pipeline_config: PipelineConfig | None = None,
    on_enforcement: EnforcementCallback | None = None,
    raise_on_deny: bool = True,
    raise_on_approval_required: bool = True,
    **openai_kwargs: Any,
) -> PolicyBindOpenAI:
    """
    Create a policy-enforced OpenAI client.

    This is a convenience function that creates an OpenAI client and
    wraps it with PolicyBind enforcement in one step.

    Args:
        policy_set: PolicySet to enforce.
        api_key: OpenAI API key (optional, uses env var if not provided).
        user_id: User identifier.
        department: User's department.
        source_application: Application identifier.
        data_classification: Data classification tags.
        intended_use_case: Use case description.
        metadata: Additional metadata.
        pipeline_config: Pipeline configuration.
        on_enforcement: Callback for enforcement decisions.
        raise_on_deny: Whether to raise on deny.
        raise_on_approval_required: Whether to raise on approval required.
        **openai_kwargs: Additional arguments for OpenAI client.

    Returns:
        PolicyBindOpenAI wrapper instance.

    Raises:
        ImportError: If openai package is not installed.

    Example:
        Basic usage::

            client = create_policy_client(
                policy_set=policy_set,
                user_id="user@example.com",
                department="engineering",
            )

            response = client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": "Hello!"}]
            )
    """
    try:
        from openai import OpenAI
    except ImportError as e:
        raise ImportError(
            "The openai package is required for OpenAI integration. "
            "Install it with: pip install openai"
        ) from e

    # Create OpenAI client
    if api_key:
        openai_kwargs["api_key"] = api_key

    client = OpenAI(**openai_kwargs)

    # Wrap with PolicyBind
    return PolicyBindOpenAI(
        client=client,
        policy_set=policy_set,
        user_id=user_id,
        department=department,
        source_application=source_application,
        data_classification=data_classification,
        intended_use_case=intended_use_case,
        metadata=metadata,
        pipeline_config=pipeline_config,
        on_enforcement=on_enforcement,
        raise_on_deny=raise_on_deny,
        raise_on_approval_required=raise_on_approval_required,
    )


def create_async_policy_client(
    policy_set: PolicySet,
    api_key: str | None = None,
    user_id: str = "",
    department: str = "",
    source_application: str = "",
    data_classification: tuple[str, ...] = (),
    intended_use_case: str = "",
    metadata: dict[str, Any] | None = None,
    pipeline_config: PipelineConfig | None = None,
    on_enforcement: EnforcementCallback | None = None,
    raise_on_deny: bool = True,
    raise_on_approval_required: bool = True,
    **openai_kwargs: Any,
) -> PolicyBindOpenAI:
    """
    Create an async policy-enforced OpenAI client.

    Similar to create_policy_client but uses AsyncOpenAI.

    Args:
        policy_set: PolicySet to enforce.
        api_key: OpenAI API key (optional, uses env var if not provided).
        user_id: User identifier.
        department: User's department.
        source_application: Application identifier.
        data_classification: Data classification tags.
        intended_use_case: Use case description.
        metadata: Additional metadata.
        pipeline_config: Pipeline configuration.
        on_enforcement: Callback for enforcement decisions.
        raise_on_deny: Whether to raise on deny.
        raise_on_approval_required: Whether to raise on approval required.
        **openai_kwargs: Additional arguments for OpenAI client.

    Returns:
        PolicyBindOpenAI wrapper instance (wrapping AsyncOpenAI).

    Raises:
        ImportError: If openai package is not installed.
    """
    try:
        from openai import AsyncOpenAI
    except ImportError as e:
        raise ImportError(
            "The openai package is required for OpenAI integration. "
            "Install it with: pip install openai"
        ) from e

    # Create AsyncOpenAI client
    if api_key:
        openai_kwargs["api_key"] = api_key

    client = AsyncOpenAI(**openai_kwargs)

    # Wrap with PolicyBind
    return PolicyBindOpenAI(
        client=client,
        policy_set=policy_set,
        user_id=user_id,
        department=department,
        source_application=source_application,
        data_classification=data_classification,
        intended_use_case=intended_use_case,
        metadata=metadata,
        pipeline_config=pipeline_config,
        on_enforcement=on_enforcement,
        raise_on_deny=raise_on_deny,
        raise_on_approval_required=raise_on_approval_required,
    )
