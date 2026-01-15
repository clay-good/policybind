"""
Mistral AI SDK integration for PolicyBind.

This module provides middleware and wrapper classes for integrating
PolicyBind policy enforcement with the Mistral AI Python SDK.

The integration works by wrapping the Mistral client and intercepting
API calls before they are made. This allows PolicyBind to:
- Enforce policies before requests are sent
- Block denied requests from reaching the API
- Track usage and costs
- Log all requests for audit purposes

Example:
    Basic usage::

        from mistralai import Mistral
        from policybind.integrations.mistral_integration import (
            create_policy_client,
            PolicyBindMistral,
        )

        # Method 1: Create a wrapped client
        client = create_policy_client(
            policy_set=policy_set,
            user_id="user@example.com",
            department="engineering",
        )

        # Method 2: Wrap an existing client
        original_client = Mistral(api_key="...")
        wrapped_client = PolicyBindMistral(
            client=original_client,
            policy_set=policy_set,
            user_id="user@example.com",
        )

        # Use as normal - chat
        response = client.chat.complete(
            model="mistral-large-latest",
            messages=[{"role": "user", "content": "Hello!"}],
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

logger = logging.getLogger("policybind.integrations.mistral")


# Token cost estimates per model (per 1M tokens, input/output)
# Mistral pricing as of 2024
MODEL_COSTS = {
    # Mistral Large (flagship)
    "mistral-large-latest": (2.00, 6.00),
    "mistral-large-2411": (2.00, 6.00),
    "mistral-large-2407": (2.00, 6.00),
    # Mistral Small (efficient)
    "mistral-small-latest": (0.20, 0.60),
    "mistral-small-2409": (0.20, 0.60),
    "mistral-small-2402": (0.20, 0.60),
    # Codestral (code-specialized)
    "codestral-latest": (0.20, 0.60),
    "codestral-2405": (0.20, 0.60),
    # Ministral (lightweight)
    "ministral-8b-latest": (0.10, 0.10),
    "ministral-8b-2410": (0.10, 0.10),
    "ministral-3b-latest": (0.04, 0.04),
    "ministral-3b-2410": (0.04, 0.04),
    # Pixtral (multimodal)
    "pixtral-large-latest": (2.00, 6.00),
    "pixtral-large-2411": (2.00, 6.00),
    "pixtral-12b-2409": (0.15, 0.15),
    # Mistral NeMo
    "open-mistral-nemo": (0.15, 0.15),
    "open-mistral-nemo-2407": (0.15, 0.15),
    # Mistral 7B (open)
    "open-mistral-7b": (0.25, 0.25),
    "mistral-tiny": (0.25, 0.25),  # Alias
    "mistral-tiny-2312": (0.25, 0.25),
    # Mixtral 8x7B
    "open-mixtral-8x7b": (0.70, 0.70),
    "mistral-small": (0.70, 0.70),  # Alias
    # Mixtral 8x22B
    "open-mixtral-8x22b": (2.00, 6.00),
    # Embedding models
    "mistral-embed": (0.10, 0.00),
    # Moderation model
    "mistral-moderation-latest": (0.10, 0.10),
    "mistral-moderation-2411": (0.10, 0.10),
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
    token counting, use the Mistral tokenizer.

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
        output_tokens: Number of output tokens.

    Returns:
        Estimated cost in USD.
    """
    # Normalize model name
    model_lower = model.lower()

    # Find matching model costs
    costs = MODEL_COSTS.get(model_lower)
    if not costs:
        # Try prefix matching
        for model_prefix, model_costs in MODEL_COSTS.items():
            if model_lower.startswith(model_prefix):
                costs = model_costs
                break
        if not costs:
            # Default to mistral-small pricing as fallback
            costs = MODEL_COSTS["mistral-small-latest"]

    # Mistral prices are per 1M tokens
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
    inputs: list[str] | None = None,
    **kwargs: Any,
) -> str:
    """
    Extract content from various Mistral request types for hashing.

    Args:
        messages: Chat messages.
        inputs: Embed inputs.
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

    if inputs:
        parts.extend(inputs)

    # For other inputs
    if "input" in kwargs:
        input_data = kwargs["input"]
        if isinstance(input_data, str):
            parts.append(input_data)
        elif isinstance(input_data, list):
            parts.extend(str(i) for i in input_data)

    return "\n".join(parts)


class PolicyEnforcer:
    """
    Handles policy enforcement for Mistral requests.

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
        model: str,
        content: str,
        request_type: str = "chat",
        context_override: EnforcementContext | None = None,
        **kwargs: Any,
    ) -> EnforcementResult:
        """
        Enforce policies for a Mistral request.

        Args:
            model: Model name.
            content: Request content.
            request_type: Type of request (chat, embed, fim, moderation).
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
        estimated_cost = estimate_cost(model, estimated_tokens, estimated_tokens)

        # Build AI request
        ai_request = AIRequest(
            provider="mistral",
            model=model,
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
                "mistral": True,
                "request_type": request_type,
                **{k: v for k, v in kwargs.items() if k not in ("messages", "inputs")},
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


class ChatCompleteWrapper:
    """Wrapper for Mistral client.chat.complete method."""

    def __init__(
        self,
        chat_resource: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            chat_resource: The chat resource from Mistral client.
            enforcer: The policy enforcer.
        """
        self._chat = chat_resource
        self._enforcer = enforcer

    def __call__(
        self,
        model: str,
        messages: list[dict[str, Any]],
        temperature: float | None = None,
        max_tokens: int | None = None,
        stream: bool = False,
        **kwargs: Any,
    ) -> Any:
        """
        Complete a chat with policy enforcement.

        Args:
            model: Model to use.
            messages: Chat messages.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens to generate.
            stream: Whether to stream the response.
            **kwargs: Additional arguments.

        Returns:
            Chat completion response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        # Build content for hashing
        content = extract_content_for_hash(messages=messages)

        # Enforce policies
        result = self._enforcer.enforce(
            model=model,
            content=content,
            request_type="chat",
            temperature=temperature,
            max_tokens=max_tokens,
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._chat.complete(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=stream,
            **kwargs,
        )


class ChatStreamWrapper:
    """Wrapper for Mistral client.chat.stream method."""

    def __init__(
        self,
        chat_resource: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            chat_resource: The chat resource from Mistral client.
            enforcer: The policy enforcer.
        """
        self._chat = chat_resource
        self._enforcer = enforcer

    def __call__(
        self,
        model: str,
        messages: list[dict[str, Any]],
        temperature: float | None = None,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> Any:
        """
        Stream a chat with policy enforcement.

        Args:
            model: Model to use.
            messages: Chat messages.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens to generate.
            **kwargs: Additional arguments.

        Returns:
            Chat stream.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        # Build content for hashing
        content = extract_content_for_hash(messages=messages)

        # Enforce policies
        result = self._enforcer.enforce(
            model=model,
            content=content,
            request_type="chat_stream",
            temperature=temperature,
            max_tokens=max_tokens,
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._chat.stream(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs,
        )


class ChatResourceWrapper:
    """Wrapper for Mistral client.chat resource."""

    def __init__(
        self,
        chat_resource: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            chat_resource: The chat resource from Mistral client.
            enforcer: The policy enforcer.
        """
        self._chat = chat_resource
        self._enforcer = enforcer
        self.complete = ChatCompleteWrapper(chat_resource, enforcer)
        self.stream = ChatStreamWrapper(chat_resource, enforcer)

    def __getattr__(self, name: str) -> Any:
        """Forward attribute access to the wrapped resource."""
        return getattr(self._chat, name)


class EmbeddingsCreateWrapper:
    """Wrapper for Mistral client.embeddings.create method."""

    def __init__(
        self,
        embeddings_resource: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            embeddings_resource: The embeddings resource from Mistral client.
            enforcer: The policy enforcer.
        """
        self._embeddings = embeddings_resource
        self._enforcer = enforcer

    def __call__(
        self,
        model: str,
        inputs: list[str],
        **kwargs: Any,
    ) -> Any:
        """
        Create embeddings with policy enforcement.

        Args:
            model: Model to use.
            inputs: Texts to embed.
            **kwargs: Additional arguments.

        Returns:
            Embedding response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        # Build content for hashing
        content = "\n".join(inputs)

        # Enforce policies
        result = self._enforcer.enforce(
            model=model,
            content=content,
            request_type="embed",
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._embeddings.create(
            model=model,
            inputs=inputs,
            **kwargs,
        )


class EmbeddingsResourceWrapper:
    """Wrapper for Mistral client.embeddings resource."""

    def __init__(
        self,
        embeddings_resource: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            embeddings_resource: The embeddings resource from Mistral client.
            enforcer: The policy enforcer.
        """
        self._embeddings = embeddings_resource
        self._enforcer = enforcer
        self.create = EmbeddingsCreateWrapper(embeddings_resource, enforcer)

    def __getattr__(self, name: str) -> Any:
        """Forward attribute access to the wrapped resource."""
        return getattr(self._embeddings, name)


class FIMCompleteWrapper:
    """Wrapper for Mistral client.fim.complete method (Fill-in-the-Middle)."""

    def __init__(
        self,
        fim_resource: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            fim_resource: The FIM resource from Mistral client.
            enforcer: The policy enforcer.
        """
        self._fim = fim_resource
        self._enforcer = enforcer

    def __call__(
        self,
        model: str,
        prompt: str,
        suffix: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> Any:
        """
        Complete fill-in-the-middle with policy enforcement.

        Args:
            model: Model to use.
            prompt: The prompt (prefix).
            suffix: The suffix to complete towards.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens to generate.
            **kwargs: Additional arguments.

        Returns:
            FIM completion response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        # Build content for hashing
        content = prompt + (suffix or "")

        # Enforce policies
        result = self._enforcer.enforce(
            model=model,
            content=content,
            request_type="fim",
            temperature=temperature,
            max_tokens=max_tokens,
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._fim.complete(
            model=model,
            prompt=prompt,
            suffix=suffix,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs,
        )


class FIMResourceWrapper:
    """Wrapper for Mistral client.fim resource."""

    def __init__(
        self,
        fim_resource: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            fim_resource: The FIM resource from Mistral client.
            enforcer: The policy enforcer.
        """
        self._fim = fim_resource
        self._enforcer = enforcer
        self.complete = FIMCompleteWrapper(fim_resource, enforcer)

    def __getattr__(self, name: str) -> Any:
        """Forward attribute access to the wrapped resource."""
        return getattr(self._fim, name)


class ClassifiersModerateWrapper:
    """Wrapper for Mistral client.classifiers.moderate method."""

    def __init__(
        self,
        classifiers_resource: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            classifiers_resource: The classifiers resource from Mistral client.
            enforcer: The policy enforcer.
        """
        self._classifiers = classifiers_resource
        self._enforcer = enforcer

    def __call__(
        self,
        model: str,
        inputs: list[str],
        **kwargs: Any,
    ) -> Any:
        """
        Moderate content with policy enforcement.

        Args:
            model: Model to use.
            inputs: Texts to moderate.
            **kwargs: Additional arguments.

        Returns:
            Moderation response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        # Build content for hashing
        content = "\n".join(inputs)

        # Enforce policies
        result = self._enforcer.enforce(
            model=model,
            content=content,
            request_type="moderation",
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._classifiers.moderate(
            model=model,
            inputs=inputs,
            **kwargs,
        )


class ClassifiersResourceWrapper:
    """Wrapper for Mistral client.classifiers resource."""

    def __init__(
        self,
        classifiers_resource: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            classifiers_resource: The classifiers resource from Mistral client.
            enforcer: The policy enforcer.
        """
        self._classifiers = classifiers_resource
        self._enforcer = enforcer
        self.moderate = ClassifiersModerateWrapper(classifiers_resource, enforcer)

    def __getattr__(self, name: str) -> Any:
        """Forward attribute access to the wrapped resource."""
        return getattr(self._classifiers, name)


class PolicyBindMistral:
    """
    Policy-enforcing wrapper for Mistral client.

    This class wraps a Mistral client and enforces PolicyBind policies
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
            client: The Mistral client to wrap.
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

        # Wrap resources
        if hasattr(client, "chat"):
            self.chat = ChatResourceWrapper(client.chat, self._enforcer)
        if hasattr(client, "embeddings"):
            self.embeddings = EmbeddingsResourceWrapper(client.embeddings, self._enforcer)
        if hasattr(client, "fim"):
            self.fim = FIMResourceWrapper(client.fim, self._enforcer)
        if hasattr(client, "classifiers"):
            self.classifiers = ClassifiersResourceWrapper(client.classifiers, self._enforcer)

    @property
    def stats(self) -> dict[str, int]:
        """Get enforcement statistics."""
        return self._enforcer.stats

    def __getattr__(self, name: str) -> Any:
        """Forward attribute access to the wrapped client."""
        return getattr(self._client, name)


def create_policy_client(
    policy_set: PolicySet,
    api_key: str | None = None,
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
) -> PolicyBindMistral:
    """
    Create a policy-enforced Mistral client.

    This is the recommended way to create a policy-enforced Mistral client.

    Args:
        policy_set: The policy set to enforce.
        api_key: Mistral API key (or use MISTRAL_API_KEY env var).
        user_id: User making requests.
        department: User's department.
        source_application: Application identifier.
        data_classification: Data classification tags.
        intended_use_case: Use case description.
        metadata: Additional metadata.
        on_enforcement: Callback for enforcement decisions.
        raise_on_deny: Whether to raise on denied requests.
        raise_on_approval_required: Whether to raise on approval required.
        **client_kwargs: Additional arguments for Mistral client.

    Returns:
        PolicyBindMistral wrapping a new Mistral client.

    Example:
        >>> client = create_policy_client(
        ...     policy_set=policy_set,
        ...     user_id="user@example.com",
        ...     department="engineering",
        ... )
        >>> response = client.chat.complete(
        ...     model="mistral-large-latest",
        ...     messages=[{"role": "user", "content": "Hello!"}],
        ... )
    """
    try:
        from mistralai import Mistral

        # Create the base client
        if api_key:
            client = Mistral(api_key=api_key, **client_kwargs)
        else:
            client = Mistral(**client_kwargs)

        return PolicyBindMistral(
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
            "Mistral AI SDK not installed. " "Install with: pip install mistralai"
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
) -> PolicyBindMistral:
    """
    Wrap an existing Mistral client with policy enforcement.

    Use this when you already have a configured Mistral client instance.

    Args:
        client: The Mistral client to wrap.
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
        PolicyBindMistral wrapping the provided client.

    Example:
        >>> from mistralai import Mistral
        >>> client = Mistral(api_key="...")
        >>> wrapped = wrap_client(client, policy_set=policy_set)
        >>> response = wrapped.chat.complete(
        ...     model="mistral-large-latest",
        ...     messages=[{"role": "user", "content": "Hello!"}],
        ... )
    """
    return PolicyBindMistral(
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
