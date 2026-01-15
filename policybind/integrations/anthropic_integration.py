"""
Anthropic SDK integration for PolicyBind.

This module provides middleware and wrapper classes for integrating
PolicyBind policy enforcement with the Anthropic Python SDK.

The integration works by wrapping the Anthropic client and intercepting
API calls before they are made. This allows PolicyBind to:
- Enforce policies before requests are sent
- Block denied requests from reaching the API
- Track usage and costs
- Log all requests for audit purposes

Example:
    Basic usage::

        from anthropic import Anthropic
        from policybind.integrations.anthropic_integration import (
            create_policy_client,
            PolicyBindAnthropic,
        )

        # Method 1: Create a wrapped client
        client = create_policy_client(
            policy_set=policy_set,
            user_id="user@example.com",
            department="engineering",
        )

        # Method 2: Wrap an existing client
        original_client = Anthropic()
        wrapped_client = PolicyBindAnthropic(
            client=original_client,
            policy_set=policy_set,
            user_id="user@example.com",
        )

        # Use as normal
        response = client.messages.create(
            model="claude-3-opus-20240229",
            max_tokens=1024,
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
from typing import TYPE_CHECKING, Any, Callable

from policybind.engine.pipeline import EnforcementPipeline, PipelineConfig
from policybind.exceptions import PolicyBindError
from policybind.models.policy import PolicySet
from policybind.models.request import AIRequest, AIResponse, Decision

if TYPE_CHECKING:
    pass

logger = logging.getLogger("policybind.integrations.anthropic")


# Token cost estimates per model (per 1M tokens, input/output)
# Anthropic pricing as of 2024
MODEL_COSTS = {
    # Claude 3.5 family
    "claude-3-5-sonnet-20241022": (3.00, 15.00),
    "claude-3-5-sonnet-20240620": (3.00, 15.00),
    "claude-3-5-haiku-20241022": (0.80, 4.00),
    # Claude 3 family
    "claude-3-opus-20240229": (15.00, 75.00),
    "claude-3-sonnet-20240229": (3.00, 15.00),
    "claude-3-haiku-20240307": (0.25, 1.25),
    # Claude 2 family (legacy)
    "claude-2.1": (8.00, 24.00),
    "claude-2.0": (8.00, 24.00),
    # Claude Instant (legacy)
    "claude-instant-1.2": (0.80, 2.40),
}

# Average tokens per word for estimation
TOKENS_PER_WORD = 1.3

# Default max tokens if not specified
DEFAULT_MAX_TOKENS = 1024


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
    token counting, use the anthropic tokenizer.

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
    Estimate tokens for a list of Anthropic messages.

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
            # Content blocks (text, image, etc.)
            for block in content:
                if isinstance(block, dict):
                    block_type = block.get("type", "")
                    if block_type == "text":
                        total += estimate_tokens(block.get("text", ""))
                    elif block_type == "image":
                        # Base64 images contribute to token count
                        # Rough estimate based on image size
                        total += 1000  # Base image tokens
                    elif block_type == "tool_use":
                        # Tool use blocks
                        total += estimate_tokens(str(block.get("input", {})))
                    elif block_type == "tool_result":
                        total += estimate_tokens(str(block.get("content", "")))
    return total


def estimate_system_tokens(system: str | list[dict[str, Any]] | None) -> int:
    """
    Estimate tokens for the system prompt.

    Args:
        system: System prompt string or list of content blocks.

    Returns:
        Estimated token count.
    """
    if not system:
        return 0
    if isinstance(system, str):
        return estimate_tokens(system)
    if isinstance(system, list):
        total = 0
        for block in system:
            if isinstance(block, dict) and block.get("type") == "text":
                total += estimate_tokens(block.get("text", ""))
        return total
    return 0


def estimate_cost(
    model: str, input_tokens: int, output_tokens: int = 0
) -> float:
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
        # Try prefix matching for versioned models
        for model_name, model_costs in MODEL_COSTS.items():
            if model.startswith(model_name.rsplit("-", 1)[0]):
                costs = model_costs
                break
        if not costs:
            # Default to Claude 3 Haiku pricing as fallback
            costs = MODEL_COSTS["claude-3-haiku-20240307"]

    # Anthropic pricing is per 1M tokens
    input_cost = (input_tokens / 1_000_000) * costs[0]
    output_cost = (output_tokens / 1_000_000) * costs[1] if output_tokens > 0 else 0

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


def extract_content_for_hash(
    messages: list[dict[str, Any]] | None = None,
    system: str | list[dict[str, Any]] | None = None,
    **kwargs: Any,
) -> str:
    """
    Extract content from various request types for hashing.

    Args:
        messages: Chat messages.
        system: System prompt.
        **kwargs: Other request parameters.

    Returns:
        Content string for hashing.
    """
    parts = []

    # Add system prompt
    if system:
        if isinstance(system, str):
            parts.append(system)
        elif isinstance(system, list):
            for block in system:
                if isinstance(block, dict) and block.get("type") == "text":
                    parts.append(block.get("text", ""))

    # Add messages
    if messages:
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict):
                        if block.get("type") == "text":
                            parts.append(block.get("text", ""))
                        elif block.get("type") == "tool_result":
                            parts.append(str(block.get("content", "")))

    # For completions API (legacy)
    if "prompt" in kwargs:
        prompt = kwargs["prompt"]
        if isinstance(prompt, str):
            parts.append(prompt)

    return "\n".join(parts)


class PolicyEnforcer:
    """
    Handles policy enforcement for Anthropic requests.

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
        system: str | list[dict[str, Any]] | None = None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        context: EnforcementContext | None = None,
        **kwargs: Any,
    ) -> EnforcementResult:
        """
        Enforce policies for a request.

        Args:
            model: Model being requested.
            messages: Chat messages.
            system: System prompt.
            max_tokens: Maximum tokens for response.
            context: Request context override.
            **kwargs: Additional request parameters.

        Returns:
            EnforcementResult with the decision.

        Raises:
            PolicyDeniedError: If request is denied and raise_on_deny is True.
            PolicyApprovalRequiredError: If approval required and raise_on_approval_required is True.
        """
        ctx = context or self._default_context
        start_time = time.perf_counter()

        # Estimate input tokens
        input_tokens = 0
        if messages:
            input_tokens += estimate_message_tokens(messages)
        if system:
            input_tokens += estimate_system_tokens(system)

        # Estimate cost (include estimated output)
        estimated_cost = estimate_cost(model, input_tokens, max_tokens)

        # Create content hash
        content_for_hash = extract_content_for_hash(messages, system, **kwargs)
        prompt_hash = hash_content(content_for_hash) if content_for_hash else ""

        # Build AIRequest
        ai_request = AIRequest(
            provider="anthropic",
            model=model,
            prompt_hash=prompt_hash,
            estimated_tokens=input_tokens,
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
                "has_system": system is not None,
                "max_tokens": max_tokens,
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


class MessagesWrapper:
    """
    Wrapper for Anthropic messages API with policy enforcement.

    This wrapper intercepts calls to the messages API and
    runs them through PolicyBind enforcement before allowing them
    to proceed.
    """

    def __init__(
        self,
        original_messages: Any,
        enforcer: PolicyEnforcer,
        context: EnforcementContext,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            original_messages: Original messages object.
            enforcer: Policy enforcer.
            context: Enforcement context.
        """
        self._original = original_messages
        self._enforcer = enforcer
        self._context = context

    def create(
        self,
        *,
        model: str,
        max_tokens: int,
        messages: list[dict[str, Any]],
        system: str | list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> Any:
        """
        Create a message with policy enforcement.

        Args:
            model: Model to use.
            max_tokens: Maximum tokens in response.
            messages: Chat messages.
            system: System prompt.
            **kwargs: Additional parameters.

        Returns:
            Message response.

        Raises:
            PolicyDeniedError: If request is denied.
            PolicyApprovalRequiredError: If approval is required.
        """
        # Enforce policies
        result = self._enforcer.enforce(
            model=model,
            messages=messages,
            system=system,
            max_tokens=max_tokens,
            context=self._context,
            **kwargs,
        )

        logger.debug(
            f"Enforcement result: allowed={result.allowed}, "
            f"decision={result.response.decision.value}, "
            f"time={result.enforcement_time_ms:.2f}ms"
        )

        # If allowed, proceed with the request
        return self._original.create(
            model=model,
            max_tokens=max_tokens,
            messages=messages,
            system=system,
            **kwargs,
        )

    def stream(
        self,
        *,
        model: str,
        max_tokens: int,
        messages: list[dict[str, Any]],
        system: str | list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> Any:
        """
        Create a streaming message with policy enforcement.

        Args:
            model: Model to use.
            max_tokens: Maximum tokens in response.
            messages: Chat messages.
            system: System prompt.
            **kwargs: Additional parameters.

        Returns:
            Streaming message response.

        Raises:
            PolicyDeniedError: If request is denied.
            PolicyApprovalRequiredError: If approval is required.
        """
        # Enforce policies (same as create)
        result = self._enforcer.enforce(
            model=model,
            messages=messages,
            system=system,
            max_tokens=max_tokens,
            context=self._context,
            **kwargs,
        )

        logger.debug(
            f"Enforcement result (stream): allowed={result.allowed}, "
            f"decision={result.response.decision.value}, "
            f"time={result.enforcement_time_ms:.2f}ms"
        )

        # If allowed, proceed with the stream
        return self._original.stream(
            model=model,
            max_tokens=max_tokens,
            messages=messages,
            system=system,
            **kwargs,
        )

    def __getattr__(self, name: str) -> Any:
        """Forward attribute access to original messages object."""
        return getattr(self._original, name)


class CompletionsWrapper:
    """
    Wrapper for Anthropic completions API (legacy) with policy enforcement.

    Note: The completions API is deprecated in favor of the messages API.
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
        prompt: str,
        max_tokens_to_sample: int,
        **kwargs: Any,
    ) -> Any:
        """
        Create a completion with policy enforcement.

        Args:
            model: Model to use.
            prompt: Prompt text.
            max_tokens_to_sample: Maximum tokens in response.
            **kwargs: Additional parameters.

        Returns:
            Completion response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        # Enforce policies
        self._enforcer.enforce(
            model=model,
            max_tokens=max_tokens_to_sample,
            context=self._context,
            prompt=prompt,
            **kwargs,
        )

        return self._original.create(
            model=model,
            prompt=prompt,
            max_tokens_to_sample=max_tokens_to_sample,
            **kwargs,
        )

    def __getattr__(self, name: str) -> Any:
        """Forward attribute access to original completions object."""
        return getattr(self._original, name)


class BetaWrapper:
    """
    Wrapper for Anthropic beta API with policy enforcement.

    This wraps beta features like prompt caching, tool use, etc.
    """

    def __init__(
        self,
        original_beta: Any,
        enforcer: PolicyEnforcer,
        context: EnforcementContext,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            original_beta: Original beta object.
            enforcer: Policy enforcer.
            context: Enforcement context.
        """
        self._original = original_beta
        self._enforcer = enforcer
        self._context = context

    @property
    def messages(self) -> MessagesWrapper:
        """Get wrapped beta messages object."""
        return MessagesWrapper(
            self._original.messages,
            self._enforcer,
            self._context,
        )

    def __getattr__(self, name: str) -> Any:
        """Forward attribute access to original beta object."""
        return getattr(self._original, name)


class PolicyBindAnthropic:
    """
    Anthropic client wrapper with PolicyBind enforcement.

    This class wraps an Anthropic client and intercepts API calls to
    enforce policies before requests are made.

    Example:
        Basic usage::

            from anthropic import Anthropic
            from policybind.integrations.anthropic_integration import PolicyBindAnthropic

            client = PolicyBindAnthropic(
                client=Anthropic(),
                policy_set=policy_set,
                user_id="user@example.com",
                department="engineering",
            )

            # Use as normal
            response = client.messages.create(
                model="claude-3-opus-20240229",
                max_tokens=1024,
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
            client: Anthropic client instance.
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
    def messages(self) -> MessagesWrapper:
        """Get wrapped messages object."""
        return MessagesWrapper(self._client.messages, self._enforcer, self._context)

    @property
    def completions(self) -> CompletionsWrapper:
        """Get wrapped completions object (legacy API)."""
        return CompletionsWrapper(
            self._client.completions, self._enforcer, self._context
        )

    @property
    def beta(self) -> BetaWrapper:
        """Get wrapped beta object."""
        return BetaWrapper(self._client.beta, self._enforcer, self._context)

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

    def count_tokens(self, text: str) -> int:
        """
        Estimate token count for text.

        This is a convenience method that uses the estimation function.
        For accurate counts, use the Anthropic tokenizer directly.

        Args:
            text: Text to count tokens for.

        Returns:
            Estimated token count.
        """
        return estimate_tokens(text)

    def __getattr__(self, name: str) -> Any:
        """
        Forward attribute access to wrapped client.

        This allows access to other Anthropic client attributes and
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
    **anthropic_kwargs: Any,
) -> PolicyBindAnthropic:
    """
    Create a policy-enforced Anthropic client.

    This is a convenience function that creates an Anthropic client and
    wraps it with PolicyBind enforcement in one step.

    Args:
        policy_set: PolicySet to enforce.
        api_key: Anthropic API key (optional, uses env var if not provided).
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
        **anthropic_kwargs: Additional arguments for Anthropic client.

    Returns:
        PolicyBindAnthropic wrapper instance.

    Raises:
        ImportError: If anthropic package is not installed.

    Example:
        Basic usage::

            client = create_policy_client(
                policy_set=policy_set,
                user_id="user@example.com",
                department="engineering",
            )

            response = client.messages.create(
                model="claude-3-opus-20240229",
                max_tokens=1024,
                messages=[{"role": "user", "content": "Hello!"}]
            )
    """
    try:
        from anthropic import Anthropic
    except ImportError as e:
        raise ImportError(
            "The anthropic package is required for Anthropic integration. "
            "Install it with: pip install anthropic"
        ) from e

    # Create Anthropic client
    if api_key:
        anthropic_kwargs["api_key"] = api_key

    client = Anthropic(**anthropic_kwargs)

    # Wrap with PolicyBind
    return PolicyBindAnthropic(
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
    **anthropic_kwargs: Any,
) -> PolicyBindAnthropic:
    """
    Create an async policy-enforced Anthropic client.

    Similar to create_policy_client but uses AsyncAnthropic.

    Args:
        policy_set: PolicySet to enforce.
        api_key: Anthropic API key (optional, uses env var if not provided).
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
        **anthropic_kwargs: Additional arguments for Anthropic client.

    Returns:
        PolicyBindAnthropic wrapper instance (wrapping AsyncAnthropic).

    Raises:
        ImportError: If anthropic package is not installed.
    """
    try:
        from anthropic import AsyncAnthropic
    except ImportError as e:
        raise ImportError(
            "The anthropic package is required for Anthropic integration. "
            "Install it with: pip install anthropic"
        ) from e

    # Create AsyncAnthropic client
    if api_key:
        anthropic_kwargs["api_key"] = api_key

    client = AsyncAnthropic(**anthropic_kwargs)

    # Wrap with PolicyBind
    return PolicyBindAnthropic(
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
