"""
Google Gemini/Vertex AI SDK integration for PolicyBind.

This module provides middleware and wrapper classes for integrating
PolicyBind policy enforcement with the Google Generative AI SDK
(google-generativeai) and Vertex AI SDK (google-cloud-aiplatform).

The integration works by wrapping the Google client and intercepting
API calls before they are made. This allows PolicyBind to:
- Enforce policies before requests are sent
- Block denied requests from reaching the API
- Track usage and costs
- Log all requests for audit purposes

Example:
    Using Generative AI SDK::

        import google.generativeai as genai
        from policybind.integrations.google_integration import (
            create_policy_client,
            PolicyBindGenerativeModel,
        )

        # Method 1: Create a wrapped model
        model = create_policy_client(
            model_name="gemini-1.5-pro",
            policy_set=policy_set,
            user_id="user@example.com",
            department="engineering",
        )

        # Method 2: Wrap an existing model
        original_model = genai.GenerativeModel("gemini-1.5-pro")
        wrapped_model = PolicyBindGenerativeModel(
            model=original_model,
            policy_set=policy_set,
            user_id="user@example.com",
        )

        # Use as normal
        response = model.generate_content("Hello!")

    With enforcement callback::

        def on_decision(request, response):
            print(f"Decision: {response.decision}")
            if response.is_denied():
                print(f"Blocked: {response.reason}")

        model = create_policy_client(
            model_name="gemini-1.5-pro",
            policy_set=policy_set,
            on_enforcement=on_decision,
        )

    Using Vertex AI::

        from policybind.integrations.google_integration import (
            create_vertex_policy_client,
        )

        model = create_vertex_policy_client(
            model_name="gemini-1.5-pro",
            policy_set=policy_set,
            project="my-project",
            location="us-central1",
        )
"""

import hashlib
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Callable, Iterator

from policybind.engine.pipeline import EnforcementPipeline, PipelineConfig
from policybind.exceptions import PolicyBindError
from policybind.models.policy import PolicySet
from policybind.models.request import AIRequest, AIResponse, Decision

if TYPE_CHECKING:
    pass

logger = logging.getLogger("policybind.integrations.google")


# Token cost estimates per model (per 1M tokens for input, per 1M tokens for output)
# Gemini uses per-million token pricing
MODEL_COSTS = {
    # Gemini 1.5 Pro
    "gemini-1.5-pro": (1.25, 5.00),
    "gemini-1.5-pro-001": (1.25, 5.00),
    "gemini-1.5-pro-002": (1.25, 5.00),
    "gemini-1.5-pro-latest": (1.25, 5.00),
    # Gemini 1.5 Flash
    "gemini-1.5-flash": (0.075, 0.30),
    "gemini-1.5-flash-001": (0.075, 0.30),
    "gemini-1.5-flash-002": (0.075, 0.30),
    "gemini-1.5-flash-latest": (0.075, 0.30),
    # Gemini 1.5 Flash-8B
    "gemini-1.5-flash-8b": (0.0375, 0.15),
    "gemini-1.5-flash-8b-001": (0.0375, 0.15),
    "gemini-1.5-flash-8b-latest": (0.0375, 0.15),
    # Gemini 1.0 Pro
    "gemini-1.0-pro": (0.50, 1.50),
    "gemini-1.0-pro-001": (0.50, 1.50),
    "gemini-1.0-pro-002": (0.50, 1.50),
    "gemini-1.0-pro-latest": (0.50, 1.50),
    "gemini-pro": (0.50, 1.50),  # Alias
    # Gemini 1.0 Pro Vision
    "gemini-1.0-pro-vision": (0.50, 1.50),
    "gemini-1.0-pro-vision-001": (0.50, 1.50),
    "gemini-pro-vision": (0.50, 1.50),  # Alias
    # Gemini 2.0
    "gemini-2.0-flash-exp": (0.075, 0.30),
    "gemini-2.0-flash": (0.075, 0.30),
    # Embedding models
    "text-embedding-004": (0.00, 0.00),  # Free tier
    "embedding-001": (0.00, 0.00),  # Free tier
    # PaLM 2 (legacy)
    "text-bison": (0.25, 0.50),
    "text-bison-001": (0.25, 0.50),
    "text-bison-32k": (0.25, 0.50),
    "chat-bison": (0.25, 0.50),
    "chat-bison-001": (0.25, 0.50),
    "chat-bison-32k": (0.25, 0.50),
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
    token counting, use the tokenizers provided by Google.

    Args:
        text: The text to estimate tokens for.

    Returns:
        Estimated token count.
    """
    if not text:
        return 0
    words = len(text.split())
    return int(words * TOKENS_PER_WORD)


def estimate_content_tokens(content: Any) -> int:
    """
    Estimate tokens for Gemini content.

    Args:
        content: Content which can be string, list, or Content object.

    Returns:
        Estimated token count.
    """
    total = 0

    if isinstance(content, str):
        total = estimate_tokens(content)
    elif isinstance(content, list):
        for item in content:
            if isinstance(item, str):
                total += estimate_tokens(item)
            elif isinstance(item, dict):
                # Part dictionary
                if "text" in item:
                    total += estimate_tokens(item["text"])
                elif "inline_data" in item:
                    # Image/video content - estimate base tokens
                    total += 258  # Base image tokens for Gemini
            elif hasattr(item, "text"):
                # Part object with text attribute
                total += estimate_tokens(getattr(item, "text", ""))
            elif hasattr(item, "parts"):
                # Content object
                for part in item.parts:
                    if hasattr(part, "text"):
                        total += estimate_tokens(part.text)
    elif hasattr(content, "parts"):
        # Single Content object
        for part in content.parts:
            if hasattr(part, "text"):
                total += estimate_tokens(part.text)

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
            # Default to Gemini 1.5 Flash pricing as fallback
            costs = MODEL_COSTS["gemini-1.5-flash"]

    # Google prices are per 1M tokens
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


def extract_content_for_hash(content: Any) -> str:
    """
    Extract content from various Gemini content types for hashing.

    Args:
        content: Gemini content (string, list, Content object).

    Returns:
        Content string for hashing.
    """
    parts = []

    if isinstance(content, str):
        parts.append(content)
    elif isinstance(content, list):
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                if "text" in item:
                    parts.append(item["text"])
            elif hasattr(item, "text"):
                parts.append(getattr(item, "text", ""))
            elif hasattr(item, "parts"):
                for part in item.parts:
                    if hasattr(part, "text"):
                        parts.append(part.text)
    elif hasattr(content, "parts"):
        for part in content.parts:
            if hasattr(part, "text"):
                parts.append(part.text)

    return "\n".join(parts)


def extract_model_name(model: Any) -> str:
    """
    Extract model name from a model object or string.

    Args:
        model: Model object or string.

    Returns:
        Model name string.
    """
    if isinstance(model, str):
        # Remove models/ prefix if present
        if model.startswith("models/"):
            return model[7:]
        return model

    # Try to get model_name attribute
    if hasattr(model, "model_name"):
        name = model.model_name
        if name.startswith("models/"):
            return name[7:]
        return name

    # Try _model_name
    if hasattr(model, "_model_name"):
        name = model._model_name
        if name.startswith("models/"):
            return name[7:]
        return name

    return "unknown"


class PolicyEnforcer:
    """
    Handles policy enforcement for Google Gemini requests.

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
        content: Any,
        context_override: EnforcementContext | None = None,
        **kwargs: Any,
    ) -> EnforcementResult:
        """
        Enforce policies for a generate_content request.

        Args:
            model: Model name.
            content: Request content.
            context_override: Override the default context.
            **kwargs: Additional parameters.

        Returns:
            EnforcementResult with the decision.

        Raises:
            PolicyDeniedError: If request is denied and raise_on_deny is True.
            PolicyApprovalRequiredError: If approval required and raise_on_approval_required is True.
        """
        start_time = time.time()
        ctx = context_override or self.context

        # Extract content for hashing
        content_str = extract_content_for_hash(content)
        prompt_hash = hash_content(content_str)

        # Estimate tokens and cost
        estimated_tokens = estimate_content_tokens(content)
        estimated_cost = estimate_cost(model, estimated_tokens, estimated_tokens)

        # Build AI request
        ai_request = AIRequest(
            provider="google",
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
                "google_gemini": True,
                "generation_config": kwargs.get("generation_config"),
                "safety_settings": kwargs.get("safety_settings"),
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


class GenerateContentWrapper:
    """Wrapper for GenerativeModel.generate_content method."""

    def __init__(
        self,
        model: Any,
        enforcer: PolicyEnforcer,
        model_name: str,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            model: The GenerativeModel instance.
            enforcer: The policy enforcer.
            model_name: The model name.
        """
        self._model = model
        self._enforcer = enforcer
        self._model_name = model_name

    def __call__(
        self,
        contents: Any,
        *,
        generation_config: Any = None,
        safety_settings: Any = None,
        stream: bool = False,
        tools: Any = None,
        tool_config: Any = None,
        **kwargs: Any,
    ) -> Any:
        """
        Generate content with policy enforcement.

        Args:
            contents: Content to generate from.
            generation_config: Generation configuration.
            safety_settings: Safety settings.
            stream: Whether to stream the response.
            tools: Tools for function calling.
            tool_config: Tool configuration.
            **kwargs: Additional arguments.

        Returns:
            GenerateContentResponse or stream.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        # Enforce policies
        result = self._enforcer.enforce(
            model=self._model_name,
            content=contents,
            generation_config=generation_config,
            safety_settings=safety_settings,
        )

        if not result.allowed:
            return None

        # Apply modifications if any
        if result.modified and result.modifications:
            # Handle content modifications
            if "redact_patterns" in result.modifications:
                contents = self._apply_redactions(
                    contents, result.modifications["redact_patterns"]
                )

        # Call the actual method
        return self._model.generate_content(
            contents,
            generation_config=generation_config,
            safety_settings=safety_settings,
            stream=stream,
            tools=tools,
            tool_config=tool_config,
            **kwargs,
        )

    def _apply_redactions(self, contents: Any, patterns: list[str]) -> Any:
        """Apply redaction patterns to content."""
        import re

        if isinstance(contents, str):
            for pattern in patterns:
                contents = re.sub(pattern, "[REDACTED]", contents)
            return contents
        # For complex content types, return as-is (would need deeper modification)
        return contents


class GenerateContentAsyncWrapper:
    """Async wrapper for GenerativeModel.generate_content_async method."""

    def __init__(
        self,
        model: Any,
        enforcer: PolicyEnforcer,
        model_name: str,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            model: The GenerativeModel instance.
            enforcer: The policy enforcer.
            model_name: The model name.
        """
        self._model = model
        self._enforcer = enforcer
        self._model_name = model_name

    async def __call__(
        self,
        contents: Any,
        *,
        generation_config: Any = None,
        safety_settings: Any = None,
        stream: bool = False,
        tools: Any = None,
        tool_config: Any = None,
        **kwargs: Any,
    ) -> Any:
        """
        Generate content asynchronously with policy enforcement.

        Args:
            contents: Content to generate from.
            generation_config: Generation configuration.
            safety_settings: Safety settings.
            stream: Whether to stream the response.
            tools: Tools for function calling.
            tool_config: Tool configuration.
            **kwargs: Additional arguments.

        Returns:
            GenerateContentResponse or stream.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        # Enforce policies (synchronous - policies should be fast)
        result = self._enforcer.enforce(
            model=self._model_name,
            content=contents,
            generation_config=generation_config,
            safety_settings=safety_settings,
        )

        if not result.allowed:
            return None

        # Call the actual async method
        return await self._model.generate_content_async(
            contents,
            generation_config=generation_config,
            safety_settings=safety_settings,
            stream=stream,
            tools=tools,
            tool_config=tool_config,
            **kwargs,
        )


class CountTokensWrapper:
    """Wrapper for GenerativeModel.count_tokens method."""

    def __init__(self, model: Any) -> None:
        """
        Initialize the wrapper.

        Args:
            model: The GenerativeModel instance.
        """
        self._model = model

    def __call__(self, contents: Any, **kwargs: Any) -> Any:
        """
        Count tokens without policy enforcement.

        Args:
            contents: Content to count tokens for.
            **kwargs: Additional arguments.

        Returns:
            Token count response.
        """
        return self._model.count_tokens(contents, **kwargs)


class EmbedContentWrapper:
    """Wrapper for embedding model methods."""

    def __init__(
        self,
        model: Any,
        enforcer: PolicyEnforcer,
        model_name: str,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            model: The model instance.
            enforcer: The policy enforcer.
            model_name: The model name.
        """
        self._model = model
        self._enforcer = enforcer
        self._model_name = model_name

    def __call__(
        self,
        content: Any,
        *,
        task_type: str | None = None,
        title: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """
        Generate embeddings with policy enforcement.

        Args:
            content: Content to embed.
            task_type: Task type for the embedding.
            title: Title for the content.
            **kwargs: Additional arguments.

        Returns:
            Embedding response.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        # Enforce policies
        result = self._enforcer.enforce(
            model=self._model_name,
            content=content,
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._model.embed_content(
            content,
            task_type=task_type,
            title=title,
            **kwargs,
        )


class PolicyBindGenerativeModel:
    """
    Policy-enforcing wrapper for google.generativeai.GenerativeModel.

    This class wraps a GenerativeModel and enforces PolicyBind policies
    on all generation requests.
    """

    def __init__(
        self,
        model: Any,
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
        Initialize the policy-enforcing model wrapper.

        Args:
            model: The GenerativeModel to wrap.
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
        self._model = model
        self._model_name = extract_model_name(model)

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
        self.generate_content = GenerateContentWrapper(
            model, self._enforcer, self._model_name
        )
        self.generate_content_async = GenerateContentAsyncWrapper(
            model, self._enforcer, self._model_name
        )
        self.count_tokens = CountTokensWrapper(model)

        # Copy model attributes
        self.model_name = self._model_name

    @property
    def stats(self) -> dict[str, int]:
        """Get enforcement statistics."""
        return self._enforcer.stats

    def __getattr__(self, name: str) -> Any:
        """Forward attribute access to the wrapped model."""
        return getattr(self._model, name)


class ChatSessionWrapper:
    """Wrapper for ChatSession to enforce policies on chat messages."""

    def __init__(
        self,
        chat: Any,
        enforcer: PolicyEnforcer,
        model_name: str,
    ) -> None:
        """
        Initialize the wrapper.

        Args:
            chat: The ChatSession instance.
            enforcer: The policy enforcer.
            model_name: The model name.
        """
        self._chat = chat
        self._enforcer = enforcer
        self._model_name = model_name

    def send_message(
        self,
        content: Any,
        *,
        generation_config: Any = None,
        safety_settings: Any = None,
        stream: bool = False,
        **kwargs: Any,
    ) -> Any:
        """
        Send a message with policy enforcement.

        Args:
            content: Message content.
            generation_config: Generation configuration.
            safety_settings: Safety settings.
            stream: Whether to stream the response.
            **kwargs: Additional arguments.

        Returns:
            GenerateContentResponse.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        # Enforce policies
        result = self._enforcer.enforce(
            model=self._model_name,
            content=content,
            generation_config=generation_config,
            safety_settings=safety_settings,
        )

        if not result.allowed:
            return None

        # Call the actual method
        return self._chat.send_message(
            content,
            generation_config=generation_config,
            safety_settings=safety_settings,
            stream=stream,
            **kwargs,
        )

    async def send_message_async(
        self,
        content: Any,
        *,
        generation_config: Any = None,
        safety_settings: Any = None,
        stream: bool = False,
        **kwargs: Any,
    ) -> Any:
        """
        Send a message asynchronously with policy enforcement.

        Args:
            content: Message content.
            generation_config: Generation configuration.
            safety_settings: Safety settings.
            stream: Whether to stream the response.
            **kwargs: Additional arguments.

        Returns:
            GenerateContentResponse.

        Raises:
            PolicyDeniedError: If request is denied.
        """
        # Enforce policies
        result = self._enforcer.enforce(
            model=self._model_name,
            content=content,
            generation_config=generation_config,
            safety_settings=safety_settings,
        )

        if not result.allowed:
            return None

        # Call the actual async method
        return await self._chat.send_message_async(
            content,
            generation_config=generation_config,
            safety_settings=safety_settings,
            stream=stream,
            **kwargs,
        )

    @property
    def history(self) -> list[Any]:
        """Get chat history."""
        return self._chat.history

    def __getattr__(self, name: str) -> Any:
        """Forward attribute access to the wrapped chat."""
        return getattr(self._chat, name)


def create_policy_client(
    model_name: str,
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
    **model_kwargs: Any,
) -> PolicyBindGenerativeModel:
    """
    Create a policy-enforced GenerativeModel.

    This is the recommended way to create a policy-enforced Google
    Generative AI client.

    Args:
        model_name: The model name (e.g., "gemini-1.5-pro").
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
        **model_kwargs: Additional arguments for GenerativeModel.

    Returns:
        PolicyBindGenerativeModel wrapping a new GenerativeModel.

    Example:
        >>> model = create_policy_client(
        ...     model_name="gemini-1.5-pro",
        ...     policy_set=policy_set,
        ...     user_id="user@example.com",
        ...     department="engineering",
        ... )
        >>> response = model.generate_content("Hello!")
    """
    try:
        import google.generativeai as genai

        # Create the base model
        model = genai.GenerativeModel(model_name, **model_kwargs)

        return PolicyBindGenerativeModel(
            model=model,
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
            "Google Generative AI SDK not installed. "
            "Install with: pip install google-generativeai"
        ) from err


def create_vertex_policy_client(
    model_name: str,
    policy_set: PolicySet,
    project: str,
    location: str = "us-central1",
    user_id: str = "",
    department: str = "",
    source_application: str = "",
    data_classification: tuple[str, ...] | list[str] = (),
    intended_use_case: str = "",
    metadata: dict[str, Any] | None = None,
    on_enforcement: EnforcementCallback | None = None,
    raise_on_deny: bool = True,
    raise_on_approval_required: bool = True,
) -> PolicyBindGenerativeModel:
    """
    Create a policy-enforced Vertex AI GenerativeModel.

    This creates a Vertex AI model with policy enforcement.

    Args:
        model_name: The model name (e.g., "gemini-1.5-pro").
        policy_set: The policy set to enforce.
        project: GCP project ID.
        location: GCP region.
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
        PolicyBindGenerativeModel wrapping a Vertex AI model.

    Example:
        >>> model = create_vertex_policy_client(
        ...     model_name="gemini-1.5-pro",
        ...     policy_set=policy_set,
        ...     project="my-project",
        ...     location="us-central1",
        ...     user_id="user@example.com",
        ... )
        >>> response = model.generate_content("Hello!")
    """
    try:
        import vertexai
        from vertexai.generative_models import GenerativeModel

        # Initialize Vertex AI
        vertexai.init(project=project, location=location)

        # Create the base model
        model = GenerativeModel(model_name)

        return PolicyBindGenerativeModel(
            model=model,
            policy_set=policy_set,
            user_id=user_id,
            department=department,
            source_application=source_application,
            data_classification=data_classification,
            intended_use_case=intended_use_case,
            metadata={
                **(metadata or {}),
                "vertex_ai": True,
                "project": project,
                "location": location,
            },
            on_enforcement=on_enforcement,
            raise_on_deny=raise_on_deny,
            raise_on_approval_required=raise_on_approval_required,
        )
    except ImportError as err:
        raise ImportError(
            "Vertex AI SDK not installed. "
            "Install with: pip install google-cloud-aiplatform"
        ) from err


def wrap_model(
    model: Any,
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
) -> PolicyBindGenerativeModel:
    """
    Wrap an existing GenerativeModel with policy enforcement.

    Use this when you already have a configured GenerativeModel instance.

    Args:
        model: The GenerativeModel to wrap.
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
        PolicyBindGenerativeModel wrapping the provided model.

    Example:
        >>> import google.generativeai as genai
        >>> model = genai.GenerativeModel("gemini-1.5-pro")
        >>> wrapped = wrap_model(model, policy_set=policy_set)
        >>> response = wrapped.generate_content("Hello!")
    """
    return PolicyBindGenerativeModel(
        model=model,
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
