"""
Hugging Face Hub integration for PolicyBind.

This module provides middleware and wrapper classes for integrating
PolicyBind policy enforcement with the Hugging Face Hub InferenceClient.

The Hugging Face Hub provides access to thousands of open source models
for text generation, embeddings, image generation, audio processing,
and more. This integration supports both the Inference API and
Inference Endpoints.

The integration works by wrapping the InferenceClient and intercepting
API calls before they are made. This allows PolicyBind to:
- Enforce policies before requests are sent
- Block denied requests from reaching the model
- Track usage (tokens estimated)
- Log all requests for audit purposes

Example:
    Basic usage with huggingface_hub::

        from huggingface_hub import InferenceClient
        from policybind.integrations.huggingface_integration import (
            create_policy_client,
            PolicyBindHuggingFace,
        )

        # Method 1: Create a wrapped client
        client = create_policy_client(
            policy_set=policy_set,
            token="hf_...",
            user_id="user@example.com",
            department="engineering",
        )

        # Method 2: Wrap an existing client
        original_client = InferenceClient(token="hf_...")
        wrapped_client = PolicyBindHuggingFace(
            client=original_client,
            policy_set=policy_set,
            user_id="user@example.com",
        )

        # Use as normal - chat completion
        response = client.chat_completion(
            model="meta-llama/Llama-3.1-8B-Instruct",
            messages=[{"role": "user", "content": "Hello!"}],
        )

        # Text generation
        response = client.text_generation(
            model="mistralai/Mistral-7B-Instruct-v0.3",
            prompt="Once upon a time",
        )

        # Embeddings
        embeddings = client.feature_extraction(
            model="sentence-transformers/all-MiniLM-L6-v2",
            text="Hello, world!",
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

    Using with Inference Endpoints::

        client = create_policy_client(
            policy_set=policy_set,
            model="https://your-endpoint.endpoints.huggingface.cloud",
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

logger = logging.getLogger("policybind.integrations.huggingface")


# Popular Hugging Face models with approximate pricing (per 1M tokens)
# Pricing varies by provider and can change - these are estimates
MODEL_PRICING = {
    # Meta Llama models
    "meta-llama/llama-3.1-8b-instruct": {"input": 0.05, "output": 0.08},
    "meta-llama/llama-3.1-70b-instruct": {"input": 0.35, "output": 0.40},
    "meta-llama/llama-3.1-405b-instruct": {"input": 2.00, "output": 2.00},
    "meta-llama/llama-3.2-1b-instruct": {"input": 0.02, "output": 0.03},
    "meta-llama/llama-3.2-3b-instruct": {"input": 0.03, "output": 0.05},
    "meta-llama/llama-3.2-11b-vision-instruct": {"input": 0.10, "output": 0.15},
    "meta-llama/llama-3.2-90b-vision-instruct": {"input": 0.50, "output": 0.60},
    "meta-llama/llama-3.3-70b-instruct": {"input": 0.35, "output": 0.40},
    # Mistral models
    "mistralai/mistral-7b-instruct-v0.3": {"input": 0.03, "output": 0.05},
    "mistralai/mixtral-8x7b-instruct-v0.1": {"input": 0.15, "output": 0.20},
    "mistralai/mixtral-8x22b-instruct-v0.1": {"input": 0.30, "output": 0.35},
    "mistralai/mistral-nemo-instruct-2407": {"input": 0.10, "output": 0.15},
    "mistralai/mistral-small-instruct-2409": {"input": 0.10, "output": 0.15},
    "mistralai/codestral-22b-v0.1": {"input": 0.20, "output": 0.25},
    # Qwen models
    "qwen/qwen2.5-72b-instruct": {"input": 0.35, "output": 0.40},
    "qwen/qwen2.5-32b-instruct": {"input": 0.20, "output": 0.25},
    "qwen/qwen2.5-7b-instruct": {"input": 0.05, "output": 0.08},
    "qwen/qwen2.5-3b-instruct": {"input": 0.03, "output": 0.05},
    "qwen/qwen2.5-coder-32b-instruct": {"input": 0.20, "output": 0.25},
    "qwen/qwq-32b-preview": {"input": 0.20, "output": 0.25},
    # Google models
    "google/gemma-2-9b-it": {"input": 0.08, "output": 0.12},
    "google/gemma-2-27b-it": {"input": 0.15, "output": 0.20},
    "google/gemma-7b-it": {"input": 0.05, "output": 0.08},
    # Microsoft models
    "microsoft/phi-3.5-mini-instruct": {"input": 0.03, "output": 0.05},
    "microsoft/phi-3-mini-4k-instruct": {"input": 0.03, "output": 0.05},
    "microsoft/phi-3-medium-4k-instruct": {"input": 0.10, "output": 0.15},
    # Cohere models (via providers)
    "cohereforai/c4ai-command-r-plus": {"input": 0.50, "output": 0.60},
    "cohereforai/c4ai-command-r-v01": {"input": 0.25, "output": 0.30},
    # DeepSeek models
    "deepseek-ai/deepseek-coder-33b-instruct": {"input": 0.20, "output": 0.25},
    "deepseek-ai/deepseek-v2.5": {"input": 0.30, "output": 0.35},
    # Embedding models (per 1M tokens)
    "sentence-transformers/all-minilm-l6-v2": {"input": 0.01, "output": 0.0},
    "sentence-transformers/all-mpnet-base-v2": {"input": 0.02, "output": 0.0},
    "baai/bge-large-en-v1.5": {"input": 0.02, "output": 0.0},
    "baai/bge-m3": {"input": 0.02, "output": 0.0},
    "thenlper/gte-large": {"input": 0.02, "output": 0.0},
    "nomic-ai/nomic-embed-text-v1.5": {"input": 0.01, "output": 0.0},
    # Image generation models (per image)
    "black-forest-labs/flux.1-dev": {"input": 0.025, "output": 0.0, "per_image": True},
    "black-forest-labs/flux.1-schnell": {"input": 0.01, "output": 0.0, "per_image": True},
    "stabilityai/stable-diffusion-xl-base-1.0": {"input": 0.015, "output": 0.0, "per_image": True},
    "stabilityai/stable-diffusion-3-medium": {"input": 0.02, "output": 0.0, "per_image": True},
    "runwayml/stable-diffusion-v1-5": {"input": 0.01, "output": 0.0, "per_image": True},
    # Audio models (per second)
    "openai/whisper-large-v3": {"input": 0.0001, "output": 0.0, "per_second": True},
    "openai/whisper-large-v3-turbo": {"input": 0.0001, "output": 0.0, "per_second": True},
    "facebook/musicgen-small": {"input": 0.001, "output": 0.0, "per_second": True},
}

# Model metadata for governance
MODEL_METADATA = {
    # Llama 3.1/3.2/3.3
    "meta-llama/llama-3.1-8b-instruct": {"params": "8b", "context": 131072, "type": "text"},
    "meta-llama/llama-3.1-70b-instruct": {"params": "70b", "context": 131072, "type": "text"},
    "meta-llama/llama-3.1-405b-instruct": {"params": "405b", "context": 131072, "type": "text"},
    "meta-llama/llama-3.2-1b-instruct": {"params": "1b", "context": 131072, "type": "text"},
    "meta-llama/llama-3.2-3b-instruct": {"params": "3b", "context": 131072, "type": "text"},
    "meta-llama/llama-3.2-11b-vision-instruct": {"params": "11b", "context": 131072, "type": "vision"},
    "meta-llama/llama-3.2-90b-vision-instruct": {"params": "90b", "context": 131072, "type": "vision"},
    "meta-llama/llama-3.3-70b-instruct": {"params": "70b", "context": 131072, "type": "text"},
    # Mistral
    "mistralai/mistral-7b-instruct-v0.3": {"params": "7b", "context": 32768, "type": "text"},
    "mistralai/mixtral-8x7b-instruct-v0.1": {"params": "47b", "context": 32768, "type": "text"},
    "mistralai/mixtral-8x22b-instruct-v0.1": {"params": "141b", "context": 65536, "type": "text"},
    "mistralai/mistral-nemo-instruct-2407": {"params": "12b", "context": 131072, "type": "text"},
    "mistralai/mistral-small-instruct-2409": {"params": "22b", "context": 32768, "type": "text"},
    "mistralai/codestral-22b-v0.1": {"params": "22b", "context": 32768, "type": "code"},
    # Qwen
    "qwen/qwen2.5-72b-instruct": {"params": "72b", "context": 131072, "type": "text"},
    "qwen/qwen2.5-32b-instruct": {"params": "32b", "context": 131072, "type": "text"},
    "qwen/qwen2.5-7b-instruct": {"params": "7b", "context": 131072, "type": "text"},
    "qwen/qwen2.5-3b-instruct": {"params": "3b", "context": 131072, "type": "text"},
    "qwen/qwen2.5-coder-32b-instruct": {"params": "32b", "context": 131072, "type": "code"},
    "qwen/qwq-32b-preview": {"params": "32b", "context": 32768, "type": "reasoning"},
    # Google
    "google/gemma-2-9b-it": {"params": "9b", "context": 8192, "type": "text"},
    "google/gemma-2-27b-it": {"params": "27b", "context": 8192, "type": "text"},
    "google/gemma-7b-it": {"params": "7b", "context": 8192, "type": "text"},
    # Microsoft
    "microsoft/phi-3.5-mini-instruct": {"params": "3.8b", "context": 131072, "type": "text"},
    "microsoft/phi-3-mini-4k-instruct": {"params": "3.8b", "context": 4096, "type": "text"},
    "microsoft/phi-3-medium-4k-instruct": {"params": "14b", "context": 4096, "type": "text"},
    # Embedding models
    "sentence-transformers/all-minilm-l6-v2": {"params": "22m", "context": 256, "type": "embedding"},
    "sentence-transformers/all-mpnet-base-v2": {"params": "110m", "context": 384, "type": "embedding"},
    "baai/bge-large-en-v1.5": {"params": "335m", "context": 512, "type": "embedding"},
    "baai/bge-m3": {"params": "568m", "context": 8192, "type": "embedding"},
    "thenlper/gte-large": {"params": "335m", "context": 512, "type": "embedding"},
    "nomic-ai/nomic-embed-text-v1.5": {"params": "137m", "context": 8192, "type": "embedding"},
    # Image generation
    "black-forest-labs/flux.1-dev": {"params": "12b", "context": 0, "type": "image"},
    "black-forest-labs/flux.1-schnell": {"params": "12b", "context": 0, "type": "image"},
    "stabilityai/stable-diffusion-xl-base-1.0": {"params": "6.6b", "context": 0, "type": "image"},
    "stabilityai/stable-diffusion-3-medium": {"params": "2b", "context": 0, "type": "image"},
    "runwayml/stable-diffusion-v1-5": {"params": "860m", "context": 0, "type": "image"},
    # Audio
    "openai/whisper-large-v3": {"params": "1.5b", "context": 0, "type": "audio"},
    "openai/whisper-large-v3-turbo": {"params": "809m", "context": 0, "type": "audio"},
    "facebook/musicgen-small": {"params": "300m", "context": 0, "type": "audio"},
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
                    elif part.get("type") in ("image_url", "image"):
                        total += 85  # Base image tokens
    return total


def get_model_pricing(model: str) -> dict[str, float]:
    """
    Get pricing information for a model.

    Args:
        model: Model name or ID.

    Returns:
        Dict with input/output pricing per 1M tokens.
    """
    # Normalize model name
    model_lower = model.lower()

    # Try exact match
    if model_lower in MODEL_PRICING:
        return MODEL_PRICING[model_lower]

    # Try partial match
    for key, pricing in MODEL_PRICING.items():
        if key in model_lower or model_lower in key:
            return pricing

    # Default pricing for unknown models
    return {"input": 0.10, "output": 0.15}


def get_model_metadata(model: str) -> dict[str, Any]:
    """
    Get metadata for a model.

    Args:
        model: Model name or ID.

    Returns:
        Dict with model metadata.
    """
    # Normalize model name
    model_lower = model.lower()

    # Try exact match
    if model_lower in MODEL_METADATA:
        return MODEL_METADATA[model_lower]

    # Try partial match
    for key, metadata in MODEL_METADATA.items():
        if key in model_lower or model_lower in key:
            return metadata

    # Default metadata
    return {"params": "unknown", "context": 4096, "type": "text"}


def calculate_cost(
    model: str,
    input_tokens: int,
    output_tokens: int = 0,
) -> float:
    """
    Calculate estimated cost for a request.

    Args:
        model: Model name.
        input_tokens: Number of input tokens.
        output_tokens: Number of output tokens.

    Returns:
        Estimated cost in dollars.
    """
    pricing = get_model_pricing(model)

    # Handle per-image pricing
    if pricing.get("per_image"):
        return pricing["input"]

    # Handle per-second pricing
    if pricing.get("per_second"):
        return pricing["input"] * input_tokens  # input_tokens = seconds in this case

    # Standard per-token pricing
    input_cost = (input_tokens / 1_000_000) * pricing["input"]
    output_cost = (output_tokens / 1_000_000) * pricing["output"]

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
    prompt: str | None = None,
    text: str | None = None,
    **kwargs: Any,
) -> str:
    """
    Extract content from various request types for hashing.

    Args:
        messages: Chat messages.
        prompt: Text generation prompt.
        text: Text for classification/embedding.
        **kwargs: Other request parameters.

    Returns:
        Content string for hashing.
    """
    parts = []

    if prompt:
        parts.append(prompt)

    if text:
        if isinstance(text, list):
            parts.extend(text)
        else:
            parts.append(text)

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
    Handles policy enforcement for Hugging Face Hub requests.

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
        self._total_cost = 0.0

    @property
    def stats(self) -> dict[str, Any]:
        """Get enforcement statistics."""
        return {
            "total_requests": self._total_requests,
            "allowed_requests": self._allowed_requests,
            "denied_requests": self._denied_requests,
            "modified_requests": self._modified_requests,
            "total_cost": self._total_cost,
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
        Enforce policies for a Hugging Face Hub request.

        Args:
            model: Model name.
            content: Request content.
            request_type: Type of request (chat, text_generation, embedding, etc.).
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

        # Estimate tokens
        estimated_tokens = estimate_tokens(content)

        # Get model info
        model_metadata = get_model_metadata(model)
        pricing = get_model_pricing(model)

        # Calculate estimated cost
        estimated_cost = calculate_cost(model, estimated_tokens)

        # Build AI request
        ai_request = AIRequest(
            provider="huggingface",
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
                "huggingface": True,
                "request_type": request_type,
                "model_params": model_metadata.get("params", "unknown"),
                "context_length": model_metadata.get("context", 4096),
                "model_type": model_metadata.get("type", "text"),
                "input_price_per_1m": pricing.get("input", 0),
                "output_price_per_1m": pricing.get("output", 0),
                **{k: v for k, v in kwargs.items() if k not in ("messages", "prompt", "text")},
            },
        )

        # Run enforcement through pipeline
        ai_response = self.pipeline.process(ai_request)
        enforcement_time = (time.time() - start_time) * 1000

        # Update statistics
        self._total_requests += 1
        if ai_response.decision == Decision.ALLOW:
            self._allowed_requests += 1
            self._total_cost += estimated_cost
        elif ai_response.decision == Decision.DENY:
            self._denied_requests += 1
        elif ai_response.decision == Decision.MODIFY:
            self._modified_requests += 1
            self._total_cost += estimated_cost

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


class ChatCompletionWrapper:
    """Wrapper for InferenceClient chat_completion method."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The InferenceClient.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        messages: list[dict[str, Any]],
        model: str | None = None,
        stream: bool = False,
        **kwargs: Any,
    ) -> Any:
        """
        Chat completion with policy enforcement.

        Args:
            messages: Chat messages.
            model: Model to use.
            stream: Whether to stream the response.
            **kwargs: Additional arguments.

        Returns:
            Chat completion response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        # Use model from client if not specified
        effective_model = model or getattr(self._client, "model", "unknown")

        # Build content for hashing
        content = extract_content_for_hash(messages=messages, **kwargs)

        # Enforce policies
        result = self._enforcer.enforce(
            model=effective_model,
            content=content,
            request_type="chat_completion",
            stream=stream,
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._client.chat_completion(
            messages=messages,
            model=model,
            stream=stream,
            **kwargs,
        )


class TextGenerationWrapper:
    """Wrapper for InferenceClient text_generation method."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The InferenceClient.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        prompt: str,
        model: str | None = None,
        stream: bool = False,
        **kwargs: Any,
    ) -> Any:
        """
        Text generation with policy enforcement.

        Args:
            prompt: The prompt.
            model: Model to use.
            stream: Whether to stream the response.
            **kwargs: Additional arguments.

        Returns:
            Text generation response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        effective_model = model or getattr(self._client, "model", "unknown")

        # Enforce policies
        result = self._enforcer.enforce(
            model=effective_model,
            content=prompt,
            request_type="text_generation",
            stream=stream,
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._client.text_generation(
            prompt=prompt,
            model=model,
            stream=stream,
            **kwargs,
        )


class FeatureExtractionWrapper:
    """Wrapper for InferenceClient feature_extraction method (embeddings)."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The InferenceClient.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        text: str | list[str],
        model: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """
        Feature extraction (embeddings) with policy enforcement.

        Args:
            text: Text(s) to embed.
            model: Model to use.
            **kwargs: Additional arguments.

        Returns:
            Feature extraction response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        effective_model = model or getattr(self._client, "model", "unknown")

        # Build content for hashing
        if isinstance(text, list):
            content = "\n".join(text)
        else:
            content = text

        # Enforce policies
        result = self._enforcer.enforce(
            model=effective_model,
            content=content,
            request_type="feature_extraction",
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._client.feature_extraction(
            text=text,
            model=model,
            **kwargs,
        )


class SentenceSimilarityWrapper:
    """Wrapper for InferenceClient sentence_similarity method."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The InferenceClient.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        sentence: str,
        other_sentences: list[str],
        model: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """
        Sentence similarity with policy enforcement.

        Args:
            sentence: Reference sentence.
            other_sentences: Sentences to compare.
            model: Model to use.
            **kwargs: Additional arguments.

        Returns:
            Similarity scores.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        effective_model = model or getattr(self._client, "model", "unknown")

        # Build content for hashing
        content = sentence + "\n" + "\n".join(other_sentences)

        # Enforce policies
        result = self._enforcer.enforce(
            model=effective_model,
            content=content,
            request_type="sentence_similarity",
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._client.sentence_similarity(
            sentence=sentence,
            other_sentences=other_sentences,
            model=model,
            **kwargs,
        )


class TextClassificationWrapper:
    """Wrapper for InferenceClient text_classification method."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The InferenceClient.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        text: str,
        model: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """
        Text classification with policy enforcement.

        Args:
            text: Text to classify.
            model: Model to use.
            **kwargs: Additional arguments.

        Returns:
            Classification response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        effective_model = model or getattr(self._client, "model", "unknown")

        # Enforce policies
        result = self._enforcer.enforce(
            model=effective_model,
            content=text,
            request_type="text_classification",
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._client.text_classification(
            text=text,
            model=model,
            **kwargs,
        )


class TokenClassificationWrapper:
    """Wrapper for InferenceClient token_classification method (NER)."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The InferenceClient.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        text: str,
        model: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """
        Token classification (NER) with policy enforcement.

        Args:
            text: Text to classify.
            model: Model to use.
            **kwargs: Additional arguments.

        Returns:
            Token classification response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        effective_model = model or getattr(self._client, "model", "unknown")

        # Enforce policies
        result = self._enforcer.enforce(
            model=effective_model,
            content=text,
            request_type="token_classification",
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._client.token_classification(
            text=text,
            model=model,
            **kwargs,
        )


class FillMaskWrapper:
    """Wrapper for InferenceClient fill_mask method."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The InferenceClient.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        text: str,
        model: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """
        Fill mask with policy enforcement.

        Args:
            text: Text with [MASK] token.
            model: Model to use.
            **kwargs: Additional arguments.

        Returns:
            Fill mask response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        effective_model = model or getattr(self._client, "model", "unknown")

        # Enforce policies
        result = self._enforcer.enforce(
            model=effective_model,
            content=text,
            request_type="fill_mask",
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._client.fill_mask(
            text=text,
            model=model,
            **kwargs,
        )


class ZeroShotClassificationWrapper:
    """Wrapper for InferenceClient zero_shot_classification method."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The InferenceClient.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        text: str,
        candidate_labels: list[str],
        model: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """
        Zero-shot classification with policy enforcement.

        Args:
            text: Text to classify.
            candidate_labels: Possible labels.
            model: Model to use.
            **kwargs: Additional arguments.

        Returns:
            Classification response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        effective_model = model or getattr(self._client, "model", "unknown")

        # Build content for hashing
        content = text + "\n" + "\n".join(candidate_labels)

        # Enforce policies
        result = self._enforcer.enforce(
            model=effective_model,
            content=content,
            request_type="zero_shot_classification",
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._client.zero_shot_classification(
            text=text,
            candidate_labels=candidate_labels,
            model=model,
            **kwargs,
        )


class QuestionAnsweringWrapper:
    """Wrapper for InferenceClient question_answering method."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The InferenceClient.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        question: str,
        context: str,
        model: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """
        Question answering with policy enforcement.

        Args:
            question: The question.
            context: Context to find answer in.
            model: Model to use.
            **kwargs: Additional arguments.

        Returns:
            Question answering response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        effective_model = model or getattr(self._client, "model", "unknown")

        # Build content for hashing
        content = f"Question: {question}\nContext: {context}"

        # Enforce policies
        result = self._enforcer.enforce(
            model=effective_model,
            content=content,
            request_type="question_answering",
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._client.question_answering(
            question=question,
            context=context,
            model=model,
            **kwargs,
        )


class SummarizationWrapper:
    """Wrapper for InferenceClient summarization method."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The InferenceClient.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        text: str,
        model: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """
        Summarization with policy enforcement.

        Args:
            text: Text to summarize.
            model: Model to use.
            **kwargs: Additional arguments.

        Returns:
            Summarization response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        effective_model = model or getattr(self._client, "model", "unknown")

        # Enforce policies
        result = self._enforcer.enforce(
            model=effective_model,
            content=text,
            request_type="summarization",
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._client.summarization(
            text=text,
            model=model,
            **kwargs,
        )


class TranslationWrapper:
    """Wrapper for InferenceClient translation method."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The InferenceClient.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        text: str,
        model: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """
        Translation with policy enforcement.

        Args:
            text: Text to translate.
            model: Model to use.
            **kwargs: Additional arguments.

        Returns:
            Translation response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        effective_model = model or getattr(self._client, "model", "unknown")

        # Enforce policies
        result = self._enforcer.enforce(
            model=effective_model,
            content=text,
            request_type="translation",
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._client.translation(
            text=text,
            model=model,
            **kwargs,
        )


class TextToImageWrapper:
    """Wrapper for InferenceClient text_to_image method."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The InferenceClient.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        prompt: str,
        model: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """
        Text to image with policy enforcement.

        Args:
            prompt: Image generation prompt.
            model: Model to use.
            **kwargs: Additional arguments.

        Returns:
            Generated image.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        effective_model = model or getattr(self._client, "model", "unknown")

        # Build content for hashing (include negative prompt if present)
        content = prompt
        if "negative_prompt" in kwargs and kwargs["negative_prompt"]:
            content += f"\nNegative: {kwargs['negative_prompt']}"

        # Enforce policies
        result = self._enforcer.enforce(
            model=effective_model,
            content=content,
            request_type="text_to_image",
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._client.text_to_image(
            prompt=prompt,
            model=model,
            **kwargs,
        )


class ImageClassificationWrapper:
    """Wrapper for InferenceClient image_classification method."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The InferenceClient.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        image: Any,
        model: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """
        Image classification with policy enforcement.

        Args:
            image: Image to classify.
            model: Model to use.
            **kwargs: Additional arguments.

        Returns:
            Classification response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        effective_model = model or getattr(self._client, "model", "unknown")

        # Enforce policies (content is image hash or placeholder)
        result = self._enforcer.enforce(
            model=effective_model,
            content="[image_classification]",
            request_type="image_classification",
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._client.image_classification(
            image=image,
            model=model,
            **kwargs,
        )


class ImageToTextWrapper:
    """Wrapper for InferenceClient image_to_text method."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The InferenceClient.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        image: Any,
        model: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """
        Image to text with policy enforcement.

        Args:
            image: Image to caption.
            model: Model to use.
            **kwargs: Additional arguments.

        Returns:
            Caption response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        effective_model = model or getattr(self._client, "model", "unknown")

        # Enforce policies
        result = self._enforcer.enforce(
            model=effective_model,
            content="[image_to_text]",
            request_type="image_to_text",
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._client.image_to_text(
            image=image,
            model=model,
            **kwargs,
        )


class ObjectDetectionWrapper:
    """Wrapper for InferenceClient object_detection method."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The InferenceClient.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        image: Any,
        model: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """
        Object detection with policy enforcement.

        Args:
            image: Image to analyze.
            model: Model to use.
            **kwargs: Additional arguments.

        Returns:
            Detection response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        effective_model = model or getattr(self._client, "model", "unknown")

        # Enforce policies
        result = self._enforcer.enforce(
            model=effective_model,
            content="[object_detection]",
            request_type="object_detection",
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._client.object_detection(
            image=image,
            model=model,
            **kwargs,
        )


class ImageSegmentationWrapper:
    """Wrapper for InferenceClient image_segmentation method."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The InferenceClient.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        image: Any,
        model: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """
        Image segmentation with policy enforcement.

        Args:
            image: Image to segment.
            model: Model to use.
            **kwargs: Additional arguments.

        Returns:
            Segmentation response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        effective_model = model or getattr(self._client, "model", "unknown")

        # Enforce policies
        result = self._enforcer.enforce(
            model=effective_model,
            content="[image_segmentation]",
            request_type="image_segmentation",
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._client.image_segmentation(
            image=image,
            model=model,
            **kwargs,
        )


class AutomaticSpeechRecognitionWrapper:
    """Wrapper for InferenceClient automatic_speech_recognition method."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The InferenceClient.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        audio: Any,
        model: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """
        Speech recognition with policy enforcement.

        Args:
            audio: Audio to transcribe.
            model: Model to use.
            **kwargs: Additional arguments.

        Returns:
            Transcription response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        effective_model = model or getattr(self._client, "model", "unknown")

        # Enforce policies
        result = self._enforcer.enforce(
            model=effective_model,
            content="[automatic_speech_recognition]",
            request_type="automatic_speech_recognition",
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._client.automatic_speech_recognition(
            audio=audio,
            model=model,
            **kwargs,
        )


class TextToSpeechWrapper:
    """Wrapper for InferenceClient text_to_speech method."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The InferenceClient.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        text: str,
        model: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """
        Text to speech with policy enforcement.

        Args:
            text: Text to synthesize.
            model: Model to use.
            **kwargs: Additional arguments.

        Returns:
            Audio response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        effective_model = model or getattr(self._client, "model", "unknown")

        # Enforce policies
        result = self._enforcer.enforce(
            model=effective_model,
            content=text,
            request_type="text_to_speech",
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._client.text_to_speech(
            text=text,
            model=model,
            **kwargs,
        )


class AudioClassificationWrapper:
    """Wrapper for InferenceClient audio_classification method."""

    def __init__(
        self,
        client: Any,
        enforcer: PolicyEnforcer,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            client: The InferenceClient.
            enforcer: The policy enforcer.
        """
        self._client = client
        self._enforcer = enforcer

    def __call__(
        self,
        audio: Any,
        model: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """
        Audio classification with policy enforcement.

        Args:
            audio: Audio to classify.
            model: Model to use.
            **kwargs: Additional arguments.

        Returns:
            Classification response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        effective_model = model or getattr(self._client, "model", "unknown")

        # Enforce policies
        result = self._enforcer.enforce(
            model=effective_model,
            content="[audio_classification]",
            request_type="audio_classification",
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._client.audio_classification(
            audio=audio,
            model=model,
            **kwargs,
        )


class PolicyBindHuggingFace:
    """
    Policy-enforcing wrapper for Hugging Face InferenceClient.

    This class wraps an InferenceClient and enforces PolicyBind policies
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
            client: The InferenceClient to wrap.
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
        self._policy_set = policy_set

        # Build context
        classification = (
            tuple(data_classification)
            if isinstance(data_classification, list)
            else data_classification
        )
        context = EnforcementContext(
            user_id=user_id,
            department=department,
            source_application=source_application,
            data_classification=classification,
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
        self.chat_completion = ChatCompletionWrapper(client, self._enforcer)
        self.text_generation = TextGenerationWrapper(client, self._enforcer)
        self.feature_extraction = FeatureExtractionWrapper(client, self._enforcer)
        self.sentence_similarity = SentenceSimilarityWrapper(client, self._enforcer)
        self.text_classification = TextClassificationWrapper(client, self._enforcer)
        self.token_classification = TokenClassificationWrapper(client, self._enforcer)
        self.fill_mask = FillMaskWrapper(client, self._enforcer)
        self.zero_shot_classification = ZeroShotClassificationWrapper(client, self._enforcer)
        self.question_answering = QuestionAnsweringWrapper(client, self._enforcer)
        self.summarization = SummarizationWrapper(client, self._enforcer)
        self.translation = TranslationWrapper(client, self._enforcer)
        self.text_to_image = TextToImageWrapper(client, self._enforcer)
        self.image_classification = ImageClassificationWrapper(client, self._enforcer)
        self.image_to_text = ImageToTextWrapper(client, self._enforcer)
        self.object_detection = ObjectDetectionWrapper(client, self._enforcer)
        self.image_segmentation = ImageSegmentationWrapper(client, self._enforcer)
        self.automatic_speech_recognition = AutomaticSpeechRecognitionWrapper(client, self._enforcer)
        self.text_to_speech = TextToSpeechWrapper(client, self._enforcer)
        self.audio_classification = AudioClassificationWrapper(client, self._enforcer)

    @property
    def model(self) -> str | None:
        """Get the default model."""
        return getattr(self._client, "model", None)

    @property
    def stats(self) -> dict[str, Any]:
        """Get enforcement statistics."""
        return self._enforcer.stats

    def __getattr__(self, name: str) -> Any:
        """Forward attribute access to the underlying client."""
        return getattr(self._client, name)


def create_policy_client(
    policy_set: PolicySet,
    model: str | None = None,
    token: str | None = None,
    timeout: float | None = None,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    provider: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
    bill_to: str | None = None,
    user_id: str = "",
    department: str = "",
    source_application: str = "",
    data_classification: tuple[str, ...] | list[str] = (),
    intended_use_case: str = "",
    metadata: dict[str, Any] | None = None,
    on_enforcement: EnforcementCallback | None = None,
    raise_on_deny: bool = True,
    raise_on_approval_required: bool = True,
) -> PolicyBindHuggingFace:
    """
    Create a policy-enforcing Hugging Face InferenceClient.

    Args:
        policy_set: The policy set to enforce.
        model: Default model ID or endpoint URL.
        token: Hugging Face API token.
        timeout: Request timeout in seconds.
        headers: Custom headers.
        cookies: Custom cookies.
        provider: Third-party provider name.
        base_url: Base URL for custom endpoints.
        api_key: API key (alias for token).
        bill_to: Billing organization.
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
        A policy-enforcing InferenceClient wrapper.

    Raises:
        ImportError: If huggingface_hub is not installed.
    """
    try:
        from huggingface_hub import InferenceClient
    except ImportError as e:
        raise ImportError(
            "huggingface_hub is required for Hugging Face integration. "
            "Install it with: pip install huggingface_hub"
        ) from e

    # Build client kwargs
    client_kwargs: dict[str, Any] = {}
    if model is not None:
        client_kwargs["model"] = model
    if token is not None:
        client_kwargs["token"] = token
    if timeout is not None:
        client_kwargs["timeout"] = timeout
    if headers is not None:
        client_kwargs["headers"] = headers
    if cookies is not None:
        client_kwargs["cookies"] = cookies
    if provider is not None:
        client_kwargs["provider"] = provider
    if base_url is not None:
        client_kwargs["base_url"] = base_url
    if api_key is not None:
        client_kwargs["api_key"] = api_key
    if bill_to is not None:
        client_kwargs["bill_to"] = bill_to

    # Create the client
    client = InferenceClient(**client_kwargs)

    # Wrap with policy enforcement
    return PolicyBindHuggingFace(
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
) -> PolicyBindHuggingFace:
    """
    Wrap an existing InferenceClient with policy enforcement.

    Args:
        client: The InferenceClient to wrap.
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
        A policy-enforcing InferenceClient wrapper.
    """
    return PolicyBindHuggingFace(
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
