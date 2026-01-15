"""
Ollama integration for PolicyBind.

This module provides middleware and wrapper classes for integrating
PolicyBind policy enforcement with Ollama for local LLM inference.

Ollama is a tool for running large language models locally. This integration
supports both the native Ollama Python library and the REST API.

The integration works by wrapping the Ollama client and intercepting
API calls before they are made. This allows PolicyBind to:
- Enforce policies before requests are sent
- Block denied requests from reaching the model
- Track usage (tokens estimated, no cost for local models)
- Log all requests for audit purposes

Example:
    Basic usage with ollama library::

        import ollama
        from policybind.integrations.ollama_integration import (
            create_policy_client,
            PolicyBindOllama,
        )

        # Method 1: Create a wrapped client
        client = create_policy_client(
            policy_set=policy_set,
            user_id="user@example.com",
            department="engineering",
        )

        # Method 2: Wrap an existing client
        original_client = ollama.Client()
        wrapped_client = PolicyBindOllama(
            client=original_client,
            policy_set=policy_set,
            user_id="user@example.com",
        )

        # Use as normal - chat
        response = client.chat(
            model="llama3.2",
            messages=[{"role": "user", "content": "Hello!"}],
        )

        # Generate text
        response = client.generate(
            model="llama3.2",
            prompt="Once upon a time",
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

    Using with custom host::

        client = create_policy_client(
            policy_set=policy_set,
            host="http://localhost:11434",
            user_id="user@example.com",
        )
"""

import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Iterator

from policybind.engine.pipeline import EnforcementPipeline, PipelineConfig
from policybind.exceptions import PolicyBindError
from policybind.models.policy import PolicySet
from policybind.models.request import AIRequest, AIResponse, Decision

if TYPE_CHECKING:
    pass

logger = logging.getLogger("policybind.integrations.ollama")


# Model families and their approximate sizes (for tracking purposes)
# Ollama runs locally so there's no cost, but we track token estimates
MODEL_FAMILIES = {
    # Llama 3.2
    "llama3.2": {"size": "3b", "context": 131072},
    "llama3.2:1b": {"size": "1b", "context": 131072},
    "llama3.2:3b": {"size": "3b", "context": 131072},
    # Llama 3.1
    "llama3.1": {"size": "8b", "context": 131072},
    "llama3.1:8b": {"size": "8b", "context": 131072},
    "llama3.1:70b": {"size": "70b", "context": 131072},
    "llama3.1:405b": {"size": "405b", "context": 131072},
    # Llama 3
    "llama3": {"size": "8b", "context": 8192},
    "llama3:8b": {"size": "8b", "context": 8192},
    "llama3:70b": {"size": "70b", "context": 8192},
    # Llama 2
    "llama2": {"size": "7b", "context": 4096},
    "llama2:7b": {"size": "7b", "context": 4096},
    "llama2:13b": {"size": "13b", "context": 4096},
    "llama2:70b": {"size": "70b", "context": 4096},
    # Mistral
    "mistral": {"size": "7b", "context": 32768},
    "mistral:7b": {"size": "7b", "context": 32768},
    "mistral-nemo": {"size": "12b", "context": 131072},
    # Mixtral
    "mixtral": {"size": "47b", "context": 32768},
    "mixtral:8x7b": {"size": "47b", "context": 32768},
    "mixtral:8x22b": {"size": "141b", "context": 65536},
    # Phi
    "phi3": {"size": "3.8b", "context": 131072},
    "phi3:mini": {"size": "3.8b", "context": 131072},
    "phi3:medium": {"size": "14b", "context": 131072},
    # Gemma
    "gemma": {"size": "7b", "context": 8192},
    "gemma:2b": {"size": "2b", "context": 8192},
    "gemma:7b": {"size": "7b", "context": 8192},
    "gemma2": {"size": "9b", "context": 8192},
    "gemma2:2b": {"size": "2b", "context": 8192},
    "gemma2:9b": {"size": "9b", "context": 8192},
    "gemma2:27b": {"size": "27b", "context": 8192},
    # Qwen
    "qwen": {"size": "7b", "context": 32768},
    "qwen:7b": {"size": "7b", "context": 32768},
    "qwen:14b": {"size": "14b", "context": 32768},
    "qwen:72b": {"size": "72b", "context": 32768},
    "qwen2": {"size": "7b", "context": 131072},
    "qwen2:0.5b": {"size": "0.5b", "context": 131072},
    "qwen2:1.5b": {"size": "1.5b", "context": 131072},
    "qwen2:7b": {"size": "7b", "context": 131072},
    "qwen2:72b": {"size": "72b", "context": 131072},
    "qwen2.5": {"size": "7b", "context": 131072},
    "qwen2.5-coder": {"size": "7b", "context": 131072},
    # CodeLlama
    "codellama": {"size": "7b", "context": 16384},
    "codellama:7b": {"size": "7b", "context": 16384},
    "codellama:13b": {"size": "13b", "context": 16384},
    "codellama:34b": {"size": "34b", "context": 16384},
    # DeepSeek
    "deepseek-coder": {"size": "6.7b", "context": 16384},
    "deepseek-coder:6.7b": {"size": "6.7b", "context": 16384},
    "deepseek-coder:33b": {"size": "33b", "context": 16384},
    "deepseek-coder-v2": {"size": "16b", "context": 131072},
    # Starcoder
    "starcoder": {"size": "15b", "context": 8192},
    "starcoder2": {"size": "15b", "context": 16384},
    # Vicuna
    "vicuna": {"size": "7b", "context": 2048},
    "vicuna:7b": {"size": "7b", "context": 2048},
    "vicuna:13b": {"size": "13b", "context": 2048},
    # Neural Chat
    "neural-chat": {"size": "7b", "context": 8192},
    # Orca
    "orca-mini": {"size": "3b", "context": 2048},
    "orca2": {"size": "7b", "context": 4096},
    # Embedding models
    "nomic-embed-text": {"size": "137m", "context": 8192, "embedding": True},
    "mxbai-embed-large": {"size": "335m", "context": 512, "embedding": True},
    "all-minilm": {"size": "33m", "context": 256, "embedding": True},
    # Vision models
    "llava": {"size": "7b", "context": 4096, "vision": True},
    "llava:13b": {"size": "13b", "context": 4096, "vision": True},
    "llava:34b": {"size": "34b", "context": 4096, "vision": True},
    "bakllava": {"size": "7b", "context": 4096, "vision": True},
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
    token counting, use the model's tokenizer.

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
                    elif part.get("type") == "image":
                        total += 85  # Base image tokens
    return total


def get_model_info(model: str) -> dict[str, Any]:
    """
    Get information about a model.

    Args:
        model: Model name.

    Returns:
        Dict with model information (size, context, etc.).
    """
    # Normalize model name (remove tags like :latest)
    base_model = model.split(":")[0].lower() if ":" in model else model.lower()
    full_model = model.lower()

    # Try exact match first
    if full_model in MODEL_FAMILIES:
        return MODEL_FAMILIES[full_model]

    # Try base model
    if base_model in MODEL_FAMILIES:
        return MODEL_FAMILIES[base_model]

    # Default for unknown models
    return {"size": "unknown", "context": 4096}


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
    prompt: str | None = None,
    **kwargs: Any,
) -> str:
    """
    Extract content from various Ollama request types for hashing.

    Args:
        messages: Chat messages.
        prompt: Generate prompt.
        **kwargs: Other request parameters.

    Returns:
        Content string for hashing.
    """
    parts = []

    if prompt:
        parts.append(prompt)

    if messages:
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        parts.append(part.get("text", ""))

    # System prompt
    if "system" in kwargs:
        parts.append(kwargs["system"])

    return "\n".join(parts)


class PolicyEnforcer:
    """
    Handles policy enforcement for Ollama requests.

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
        Enforce policies for an Ollama request.

        Args:
            model: Model name.
            content: Request content.
            request_type: Type of request (chat, generate, embed).
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

        # Estimate tokens (no cost for local models)
        estimated_tokens = estimate_tokens(content)

        # Get model info
        model_info = get_model_info(model)

        # Build AI request
        ai_request = AIRequest(
            provider="ollama",
            model=model,
            prompt_hash=prompt_hash,
            estimated_tokens=estimated_tokens,
            estimated_cost=0.0,  # Local models have no API cost
            source_application=ctx.source_application,
            user_id=ctx.user_id,
            department=ctx.department,
            data_classification=list(ctx.data_classification),
            intended_use_case=ctx.intended_use_case,
            metadata={
                **ctx.metadata,
                "ollama": True,
                "local_model": True,
                "request_type": request_type,
                "model_size": model_info.get("size", "unknown"),
                "context_length": model_info.get("context", 4096),
                "is_embedding": model_info.get("embedding", False),
                "is_vision": model_info.get("vision", False),
                **{k: v for k, v in kwargs.items() if k not in ("messages", "prompt")},
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
    """Wrapper for Ollama client chat method."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The Ollama client.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        model: str,
        messages: list[dict[str, Any]],
        stream: bool = False,
        **kwargs: Any,
    ) -> Any:
        """
        Chat with a model with policy enforcement.

        Args:
            model: Model to use.
            messages: Chat messages.
            stream: Whether to stream the response.
            **kwargs: Additional arguments.

        Returns:
            Chat response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        # Build content for hashing
        content = extract_content_for_hash(messages=messages, **kwargs)

        # Enforce policies
        result = self._enforcer.enforce(
            model=model,
            content=content,
            request_type="chat",
            stream=stream,
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._client.chat(
            model=model,
            messages=messages,
            stream=stream,
            **kwargs,
        )


class GenerateWrapper:
    """Wrapper for Ollama client generate method."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The Ollama client.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        model: str,
        prompt: str,
        stream: bool = False,
        **kwargs: Any,
    ) -> Any:
        """
        Generate text with policy enforcement.

        Args:
            model: Model to use.
            prompt: The prompt.
            stream: Whether to stream the response.
            **kwargs: Additional arguments.

        Returns:
            Generate response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        # Build content for hashing
        content = extract_content_for_hash(prompt=prompt, **kwargs)

        # Enforce policies
        result = self._enforcer.enforce(
            model=model,
            content=content,
            request_type="generate",
            stream=stream,
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._client.generate(
            model=model,
            prompt=prompt,
            stream=stream,
            **kwargs,
        )


class EmbeddingsWrapper:
    """Wrapper for Ollama client embeddings method."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The Ollama client.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        model: str,
        prompt: str | list[str],
        **kwargs: Any,
    ) -> Any:
        """
        Create embeddings with policy enforcement.

        Args:
            model: Model to use.
            prompt: Text(s) to embed.
            **kwargs: Additional arguments.

        Returns:
            Embeddings response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        # Build content for hashing
        if isinstance(prompt, list):
            content = "\n".join(prompt)
        else:
            content = prompt

        # Enforce policies
        result = self._enforcer.enforce(
            model=model,
            content=content,
            request_type="embeddings",
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._client.embeddings(
            model=model,
            prompt=prompt,
            **kwargs,
        )


class EmbedWrapper:
    """Wrapper for Ollama client embed method (newer API)."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The Ollama client.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        model: str,
        input: str | list[str],
        **kwargs: Any,
    ) -> Any:
        """
        Create embeddings with policy enforcement.

        Args:
            model: Model to use.
            input: Text(s) to embed.
            **kwargs: Additional arguments.

        Returns:
            Embeddings response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        # Build content for hashing
        if isinstance(input, list):
            content = "\n".join(input)
        else:
            content = input

        # Enforce policies
        result = self._enforcer.enforce(
            model=model,
            content=content,
            request_type="embed",
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._client.embed(
            model=model,
            input=input,
            **kwargs,
        )


class PullWrapper:
    """Wrapper for Ollama client pull method."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The Ollama client.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        model: str,
        **kwargs: Any,
    ) -> Any:
        """
        Pull a model with policy enforcement.

        Args:
            model: Model to pull.
            **kwargs: Additional arguments.

        Returns:
            Pull progress/response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        # Enforce policies for model pull
        result = self._enforcer.enforce(
            model=model,
            content=f"pull:{model}",
            request_type="pull",
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._client.pull(model=model, **kwargs)


class PolicyBindOllama:
    """
    Policy-enforcing wrapper for Ollama client.

    This class wraps an Ollama client and enforces PolicyBind policies
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
            client: The Ollama client to wrap.
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
        self.embeddings = EmbeddingsWrapper(client, self._enforcer)
        if hasattr(client, "embed"):
            self.embed = EmbedWrapper(client, self._enforcer)
        self.pull = PullWrapper(client, self._enforcer)

    @property
    def stats(self) -> dict[str, int]:
        """Get enforcement statistics."""
        return self._enforcer.stats

    def __getattr__(self, name: str) -> Any:
        """Forward attribute access to the wrapped client."""
        return getattr(self._client, name)


def create_policy_client(
    policy_set: PolicySet,
    host: str | None = None,
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
) -> PolicyBindOllama:
    """
    Create a policy-enforced Ollama client.

    This is the recommended way to create a policy-enforced Ollama client.

    Args:
        policy_set: The policy set to enforce.
        host: Ollama server host (default: http://localhost:11434).
        user_id: User making requests.
        department: User's department.
        source_application: Application identifier.
        data_classification: Data classification tags.
        intended_use_case: Use case description.
        metadata: Additional metadata.
        on_enforcement: Callback for enforcement decisions.
        raise_on_deny: Whether to raise on denied requests.
        raise_on_approval_required: Whether to raise on approval required.
        **client_kwargs: Additional arguments for Ollama client.

    Returns:
        PolicyBindOllama wrapping a new Ollama client.

    Example:
        >>> client = create_policy_client(
        ...     policy_set=policy_set,
        ...     user_id="user@example.com",
        ...     department="engineering",
        ... )
        >>> response = client.chat(
        ...     model="llama3.2",
        ...     messages=[{"role": "user", "content": "Hello!"}],
        ... )
    """
    try:
        import ollama

        # Create the base client
        if host:
            client = ollama.Client(host=host, **client_kwargs)
        else:
            client = ollama.Client(**client_kwargs)

        return PolicyBindOllama(
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
            "ollama package is not installed. Install with: pip install ollama"
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
) -> PolicyBindOllama:
    """
    Wrap an existing Ollama client with policy enforcement.

    Use this when you already have a configured Ollama client instance.

    Args:
        client: The Ollama client to wrap.
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
        PolicyBindOllama wrapping the provided client.

    Example:
        >>> import ollama
        >>> client = ollama.Client(host="http://localhost:11434")
        >>> wrapped = wrap_client(client, policy_set=policy_set)
        >>> response = wrapped.chat(
        ...     model="llama3.2",
        ...     messages=[{"role": "user", "content": "Hello!"}],
        ... )
    """
    return PolicyBindOllama(
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
