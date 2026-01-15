"""
Cohere SDK integration for PolicyBind.

This module provides middleware and wrapper classes for integrating
PolicyBind policy enforcement with the Cohere Python SDK.

The integration works by wrapping the Cohere client and intercepting
API calls before they are made. This allows PolicyBind to:
- Enforce policies before requests are sent
- Block denied requests from reaching the API
- Track usage and costs
- Log all requests for audit purposes

Example:
    Basic usage::

        import cohere
        from policybind.integrations.cohere_integration import (
            create_policy_client,
            PolicyBindCohere,
        )

        # Method 1: Create a wrapped client
        client = create_policy_client(
            policy_set=policy_set,
            user_id="user@example.com",
            department="engineering",
        )

        # Method 2: Wrap an existing client
        original_client = cohere.Client()
        wrapped_client = PolicyBindCohere(
            client=original_client,
            policy_set=policy_set,
            user_id="user@example.com",
        )

        # Use as normal - chat
        response = client.chat(
            model="command-r-plus",
            message="Hello!",
        )

        # Or generate
        response = client.generate(
            model="command",
            prompt="Write a story about",
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

logger = logging.getLogger("policybind.integrations.cohere")


# Token cost estimates per model (per 1M tokens, input/output)
# Cohere pricing as of 2024
MODEL_COSTS = {
    # Command R+ (latest flagship)
    "command-r-plus": (2.50, 10.00),
    "command-r-plus-04-2024": (2.50, 10.00),
    "command-r-plus-08-2024": (2.50, 10.00),
    # Command R (balanced)
    "command-r": (0.50, 1.50),
    "command-r-03-2024": (0.50, 1.50),
    "command-r-08-2024": (0.50, 1.50),
    # Command (legacy)
    "command": (1.00, 2.00),
    "command-light": (0.30, 0.60),
    "command-nightly": (1.00, 2.00),
    "command-light-nightly": (0.30, 0.60),
    # Embed models (input only)
    "embed-english-v3.0": (0.10, 0.00),
    "embed-multilingual-v3.0": (0.10, 0.00),
    "embed-english-light-v3.0": (0.10, 0.00),
    "embed-multilingual-light-v3.0": (0.10, 0.00),
    "embed-english-v2.0": (0.10, 0.00),
    "embed-multilingual-v2.0": (0.10, 0.00),
    # Rerank models (per search)
    "rerank-english-v3.0": (2.00, 0.00),  # per 1K searches
    "rerank-multilingual-v3.0": (2.00, 0.00),
    "rerank-english-v2.0": (2.00, 0.00),
    "rerank-multilingual-v2.0": (2.00, 0.00),
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
    token counting, use the Cohere tokenize API.

    Args:
        text: The text to estimate tokens for.

    Returns:
        Estimated token count.
    """
    if not text:
        return 0
    words = len(text.split())
    return int(words * TOKENS_PER_WORD)


def estimate_chat_tokens(
    message: str,
    chat_history: list[dict[str, str]] | None = None,
    preamble: str | None = None,
) -> int:
    """
    Estimate tokens for a chat request.

    Args:
        message: The current message.
        chat_history: Previous chat messages.
        preamble: System preamble.

    Returns:
        Estimated token count.
    """
    total = 0

    # Current message
    total += estimate_tokens(message)

    # Preamble/system prompt
    if preamble:
        total += estimate_tokens(preamble)

    # Chat history
    if chat_history:
        for msg in chat_history:
            if isinstance(msg, dict):
                content = msg.get("message", "") or msg.get("text", "")
                total += estimate_tokens(content)
                total += 4  # Overhead per message

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
            # Default to command pricing as fallback
            costs = MODEL_COSTS["command"]

    # Cohere prices are per 1M tokens
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
    message: str | None = None,
    prompt: str | None = None,
    texts: list[str] | None = None,
    chat_history: list[dict[str, str]] | None = None,
) -> str:
    """
    Extract content from various Cohere request types for hashing.

    Args:
        message: Chat message.
        prompt: Generate prompt.
        texts: Embed texts.
        chat_history: Chat history.

    Returns:
        Content string for hashing.
    """
    parts = []

    if message:
        parts.append(message)

    if prompt:
        parts.append(prompt)

    if texts:
        parts.extend(texts)

    if chat_history:
        for msg in chat_history:
            if isinstance(msg, dict):
                content = msg.get("message", "") or msg.get("text", "")
                if content:
                    parts.append(content)

    return "\n".join(parts)


class PolicyEnforcer:
    """
    Handles policy enforcement for Cohere requests.

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
        Enforce policies for a Cohere request.

        Args:
            model: Model name.
            content: Request content (message, prompt, or texts).
            request_type: Type of request (chat, generate, embed, rerank).
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
            provider="cohere",
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
                "cohere": True,
                "request_type": request_type,
                **{k: v for k, v in kwargs.items() if k not in ("message", "prompt", "texts")},
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


class ChatWrapper:
    """Wrapper for Cohere client.chat method."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The Cohere client.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        message: str,
        model: str = "command-r-plus",
        preamble: str | None = None,
        chat_history: list[dict[str, str]] | None = None,
        stream: bool = False,
        **kwargs: Any,
    ) -> Any:
        """
        Send a chat message with policy enforcement.

        Args:
            message: The message to send.
            model: Model to use.
            preamble: System preamble.
            chat_history: Previous chat messages.
            stream: Whether to stream the response.
            **kwargs: Additional arguments.

        Returns:
            Chat response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        # Build content for hashing
        content = extract_content_for_hash(
            message=message,
            chat_history=chat_history,
        )

        # Enforce policies
        result = self._enforcer.enforce(
            model=model,
            content=content,
            request_type="chat",
            preamble=preamble,
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._client.chat(
            message=message,
            model=model,
            preamble=preamble,
            chat_history=chat_history,
            stream=stream,
            **kwargs,
        )


class GenerateWrapper:
    """Wrapper for Cohere client.generate method."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The Cohere client.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        prompt: str,
        model: str = "command",
        max_tokens: int | None = None,
        temperature: float | None = None,
        stream: bool = False,
        **kwargs: Any,
    ) -> Any:
        """
        Generate text with policy enforcement.

        Args:
            prompt: The prompt to generate from.
            model: Model to use.
            max_tokens: Maximum tokens to generate.
            temperature: Sampling temperature.
            stream: Whether to stream the response.
            **kwargs: Additional arguments.

        Returns:
            Generation response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        # Enforce policies
        result = self._enforcer.enforce(
            model=model,
            content=prompt,
            request_type="generate",
            max_tokens=max_tokens,
            temperature=temperature,
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._client.generate(
            prompt=prompt,
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            stream=stream,
            **kwargs,
        )


class EmbedWrapper:
    """Wrapper for Cohere client.embed method."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The Cohere client.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        texts: list[str],
        model: str = "embed-english-v3.0",
        input_type: str = "search_document",
        **kwargs: Any,
    ) -> Any:
        """
        Generate embeddings with policy enforcement.

        Args:
            texts: Texts to embed.
            model: Model to use.
            input_type: Type of input (search_document, search_query, etc.).
            **kwargs: Additional arguments.

        Returns:
            Embedding response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        # Build content for hashing
        content = "\n".join(texts)

        # Enforce policies
        result = self._enforcer.enforce(
            model=model,
            content=content,
            request_type="embed",
            input_type=input_type,
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._client.embed(
            texts=texts,
            model=model,
            input_type=input_type,
            **kwargs,
        )


class RerankWrapper:
    """Wrapper for Cohere client.rerank method."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The Cohere client.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        query: str,
        documents: list[str] | list[dict[str, str]],
        model: str = "rerank-english-v3.0",
        top_n: int | None = None,
        **kwargs: Any,
    ) -> Any:
        """
        Rerank documents with policy enforcement.

        Args:
            query: The search query.
            documents: Documents to rerank.
            model: Model to use.
            top_n: Number of top results to return.
            **kwargs: Additional arguments.

        Returns:
            Rerank response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        # Build content for hashing
        doc_texts = []
        for doc in documents:
            if isinstance(doc, str):
                doc_texts.append(doc)
            elif isinstance(doc, dict):
                doc_texts.append(doc.get("text", ""))

        content = query + "\n" + "\n".join(doc_texts)

        # Enforce policies
        result = self._enforcer.enforce(
            model=model,
            content=content,
            request_type="rerank",
            top_n=top_n,
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._client.rerank(
            query=query,
            documents=documents,
            model=model,
            top_n=top_n,
            **kwargs,
        )


class ClassifyWrapper:
    """Wrapper for Cohere client.classify method."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The Cohere client.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        inputs: list[str],
        model: str = "embed-english-v3.0",
        examples: list[dict[str, str]] | None = None,
        **kwargs: Any,
    ) -> Any:
        """
        Classify text with policy enforcement.

        Args:
            inputs: Texts to classify.
            model: Model to use.
            examples: Classification examples.
            **kwargs: Additional arguments.

        Returns:
            Classification response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        # Build content for hashing
        content = "\n".join(inputs)

        # Enforce policies
        result = self._enforcer.enforce(
            model=model,
            content=content,
            request_type="classify",
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._client.classify(
            inputs=inputs,
            model=model,
            examples=examples,
            **kwargs,
        )


class PolicyBindCohere:
    """
    Policy-enforcing wrapper for Cohere client.

    This class wraps a Cohere client and enforces PolicyBind policies
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
            client: The Cohere client to wrap.
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
        self.chat = ChatWrapper(client, self._enforcer)
        self.generate = GenerateWrapper(client, self._enforcer)
        self.embed = EmbedWrapper(client, self._enforcer)
        self.rerank = RerankWrapper(client, self._enforcer)
        self.classify = ClassifyWrapper(client, self._enforcer)

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
) -> PolicyBindCohere:
    """
    Create a policy-enforced Cohere client.

    This is the recommended way to create a policy-enforced Cohere client.

    Args:
        policy_set: The policy set to enforce.
        api_key: Cohere API key (or use CO_API_KEY env var).
        user_id: User making requests.
        department: User's department.
        source_application: Application identifier.
        data_classification: Data classification tags.
        intended_use_case: Use case description.
        metadata: Additional metadata.
        on_enforcement: Callback for enforcement decisions.
        raise_on_deny: Whether to raise on denied requests.
        raise_on_approval_required: Whether to raise on approval required.
        **client_kwargs: Additional arguments for Cohere client.

    Returns:
        PolicyBindCohere wrapping a new Cohere client.

    Example:
        >>> client = create_policy_client(
        ...     policy_set=policy_set,
        ...     user_id="user@example.com",
        ...     department="engineering",
        ... )
        >>> response = client.chat(message="Hello!")
    """
    try:
        import cohere

        # Create the base client
        if api_key:
            client = cohere.Client(api_key=api_key, **client_kwargs)
        else:
            client = cohere.Client(**client_kwargs)

        return PolicyBindCohere(
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
            "Cohere SDK not installed. " "Install with: pip install cohere"
        ) from err


def create_async_policy_client(
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
) -> PolicyBindCohere:
    """
    Create a policy-enforced async Cohere client.

    Args:
        policy_set: The policy set to enforce.
        api_key: Cohere API key (or use CO_API_KEY env var).
        user_id: User making requests.
        department: User's department.
        source_application: Application identifier.
        data_classification: Data classification tags.
        intended_use_case: Use case description.
        metadata: Additional metadata.
        on_enforcement: Callback for enforcement decisions.
        raise_on_deny: Whether to raise on denied requests.
        raise_on_approval_required: Whether to raise on approval required.
        **client_kwargs: Additional arguments for Cohere client.

    Returns:
        PolicyBindCohere wrapping a new async Cohere client.

    Example:
        >>> client = create_async_policy_client(
        ...     policy_set=policy_set,
        ...     user_id="user@example.com",
        ... )
        >>> response = await client.chat(message="Hello!")
    """
    try:
        import cohere

        # Create the base async client
        if api_key:
            client = cohere.AsyncClient(api_key=api_key, **client_kwargs)
        else:
            client = cohere.AsyncClient(**client_kwargs)

        return PolicyBindCohere(
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
            "Cohere SDK not installed. " "Install with: pip install cohere"
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
) -> PolicyBindCohere:
    """
    Wrap an existing Cohere client with policy enforcement.

    Use this when you already have a configured Cohere client instance.

    Args:
        client: The Cohere client to wrap.
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
        PolicyBindCohere wrapping the provided client.

    Example:
        >>> import cohere
        >>> client = cohere.Client(api_key="...")
        >>> wrapped = wrap_client(client, policy_set=policy_set)
        >>> response = wrapped.chat(message="Hello!")
    """
    return PolicyBindCohere(
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
