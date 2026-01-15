"""
LangChain integration for PolicyBind.

This module provides callback handlers and wrapper classes for integrating
PolicyBind policy enforcement with LangChain applications.

The integration offers multiple approaches:
1. PolicyBindCallback - A callback handler that enforces policies on LLM calls
2. PolicyBindLLM - A wrapper LLM class that enforces policies
3. PolicyBindChatModel - A wrapper ChatModel class that enforces policies

Example:
    Using callback handler::

        from langchain_openai import ChatOpenAI
        from policybind.integrations.langchain_integration import PolicyBindCallback

        # Create callback handler
        callback = PolicyBindCallback(
            policy_set=policy_set,
            user_id="user@example.com",
            department="engineering",
        )

        # Use with any LangChain LLM
        llm = ChatOpenAI(model="gpt-4")
        response = llm.invoke("Hello!", config={"callbacks": [callback]})

    Using wrapper LLM::

        from policybind.integrations.langchain_integration import PolicyBindChatModel

        # Create policy-enforced LLM
        llm = PolicyBindChatModel(
            llm=ChatOpenAI(model="gpt-4"),
            policy_set=policy_set,
            user_id="user@example.com",
        )

        # Use normally - policies automatically enforced
        response = llm.invoke("Hello!")

    Using with chains::

        from langchain.chains import LLMChain
        from langchain.prompts import PromptTemplate

        callback = PolicyBindCallback(policy_set=policy_set)
        chain = LLMChain(llm=llm, prompt=prompt)
        result = chain.invoke({"input": "test"}, config={"callbacks": [callback]})
"""

import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Sequence
from uuid import UUID

from policybind.engine.pipeline import EnforcementPipeline, PipelineConfig
from policybind.exceptions import PolicyBindError
from policybind.models.policy import PolicySet
from policybind.models.request import AIRequest, AIResponse, Decision

if TYPE_CHECKING:
    pass

logger = logging.getLogger("policybind.integrations.langchain")


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

    This is a rough estimate based on word count.

    Args:
        text: The text to estimate tokens for.

    Returns:
        Estimated token count.
    """
    if not text:
        return 0
    words = len(text.split())
    return int(words * TOKENS_PER_WORD)


def hash_content(content: str) -> str:
    """
    Create a SHA-256 hash of content.

    Args:
        content: Content to hash.

    Returns:
        Hex digest of the hash.
    """
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def extract_model_from_llm(llm: Any) -> str:
    """
    Extract the model name from a LangChain LLM object.

    Args:
        llm: LangChain LLM or ChatModel instance.

    Returns:
        Model name string.
    """
    # Try common attribute names
    for attr in ["model_name", "model", "model_id"]:
        if hasattr(llm, attr):
            value = getattr(llm, attr)
            if value:
                return str(value)

    # Check for model in constructor kwargs
    if hasattr(llm, "_lc_kwargs"):
        kwargs = llm._lc_kwargs
        for key in ["model_name", "model", "model_id"]:
            if key in kwargs:
                return str(kwargs[key])

    return "unknown"


def extract_provider_from_llm(llm: Any) -> str:
    """
    Extract the provider name from a LangChain LLM object.

    Args:
        llm: LangChain LLM or ChatModel instance.

    Returns:
        Provider name string.
    """
    # Get class name
    class_name = llm.__class__.__name__.lower()

    # Map common class names to providers
    provider_map = {
        "chatopenai": "openai",
        "openai": "openai",
        "azurechatopenai": "azure",
        "azureopenai": "azure",
        "chatanthropic": "anthropic",
        "anthropic": "anthropic",
        "chatgooglepalm": "google",
        "googlegenerativeai": "google",
        "chatvertexai": "google",
        "vertexai": "google",
        "chatcohere": "cohere",
        "cohere": "cohere",
        "bedrock": "aws",
        "bedrockllm": "aws",
        "chatbedrock": "aws",
        "huggingfacehub": "huggingface",
        "huggingfacepipeline": "huggingface",
        "ollama": "ollama",
        "chatollama": "ollama",
        "mistral": "mistral",
        "chatmistral": "mistral",
    }

    for key, provider in provider_map.items():
        if key in class_name:
            return provider

    return "unknown"


class PolicyEnforcer:
    """
    Handles policy enforcement for LangChain requests.

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
        provider: str,
        model: str,
        prompt: str,
        context: EnforcementContext | None = None,
        **kwargs: Any,
    ) -> EnforcementResult:
        """
        Enforce policies for a request.

        Args:
            provider: AI provider name.
            model: Model being requested.
            prompt: The prompt text.
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

        # Estimate tokens
        estimated_tokens = estimate_tokens(prompt)

        # Create content hash
        prompt_hash = hash_content(prompt) if prompt else ""

        # Build AIRequest
        ai_request = AIRequest(
            provider=provider,
            model=model,
            prompt_hash=prompt_hash,
            estimated_tokens=estimated_tokens,
            estimated_cost=0.0,  # Cost estimation requires provider-specific logic
            source_application=ctx.source_application,
            user_id=ctx.user_id,
            department=ctx.department,
            data_classification=ctx.data_classification,
            intended_use_case=ctx.intended_use_case,
            metadata={
                **ctx.metadata,
                "langchain": True,
                **kwargs,
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


class PolicyBindCallback:
    """
    LangChain callback handler that enforces PolicyBind policies.

    This callback can be used with any LangChain LLM or chain to enforce
    policies before LLM calls are made.

    Note: This class implements the LangChain callback interface but does
    not inherit from BaseCallbackHandler to avoid requiring langchain as
    a dependency. When used, it will be duck-typed as a callback handler.

    Example:
        Using with ChatOpenAI::

            from langchain_openai import ChatOpenAI
            from policybind.integrations.langchain_integration import PolicyBindCallback

            callback = PolicyBindCallback(
                policy_set=policy_set,
                user_id="user@example.com",
            )

            llm = ChatOpenAI(model="gpt-4")
            response = llm.invoke("Hello!", config={"callbacks": [callback]})
    """

    def __init__(
        self,
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
        Initialize the callback handler.

        Args:
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

        # Track current run info
        self._current_model: str = "unknown"
        self._current_provider: str = "unknown"

    # LangChain callback interface methods

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: UUID | None = None,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Called when an LLM starts processing.

        Args:
            serialized: Serialized LLM information.
            prompts: List of prompts being sent.
            run_id: Run ID.
            parent_run_id: Parent run ID.
            tags: Tags for this run.
            metadata: Metadata for this run.
            **kwargs: Additional arguments.

        Raises:
            PolicyDeniedError: If the request is denied by policy.
        """
        # Extract model and provider from serialized data
        self._current_model = serialized.get("kwargs", {}).get(
            "model_name", serialized.get("name", "unknown")
        )
        self._current_provider = self._extract_provider_from_serialized(serialized)

        # Combine all prompts for enforcement
        combined_prompt = "\n".join(prompts)

        logger.debug(
            f"LangChain LLM start: provider={self._current_provider}, "
            f"model={self._current_model}, prompt_length={len(combined_prompt)}"
        )

        # Enforce policies
        self._enforcer.enforce(
            provider=self._current_provider,
            model=self._current_model,
            prompt=combined_prompt,
            context=self._context,
            run_id=str(run_id) if run_id else None,
            tags=tags,
        )

    def on_chat_model_start(
        self,
        serialized: dict[str, Any],
        messages: list[list[Any]],
        *,
        run_id: UUID | None = None,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Called when a chat model starts processing.

        Args:
            serialized: Serialized chat model information.
            messages: List of message lists being sent.
            run_id: Run ID.
            parent_run_id: Parent run ID.
            tags: Tags for this run.
            metadata: Metadata for this run.
            **kwargs: Additional arguments.

        Raises:
            PolicyDeniedError: If the request is denied by policy.
        """
        # Extract model and provider
        self._current_model = serialized.get("kwargs", {}).get(
            "model_name",
            serialized.get("kwargs", {}).get("model", serialized.get("name", "unknown")),
        )
        self._current_provider = self._extract_provider_from_serialized(serialized)

        # Extract text content from messages
        combined_content = self._extract_message_content(messages)

        logger.debug(
            f"LangChain chat model start: provider={self._current_provider}, "
            f"model={self._current_model}, content_length={len(combined_content)}"
        )

        # Enforce policies
        self._enforcer.enforce(
            provider=self._current_provider,
            model=self._current_model,
            prompt=combined_content,
            context=self._context,
            run_id=str(run_id) if run_id else None,
            tags=tags,
            message_count=sum(len(msg_list) for msg_list in messages),
        )

    def on_llm_end(
        self,
        response: Any,
        *,
        run_id: UUID | None = None,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when LLM ends. No-op for policy enforcement."""
        pass

    def on_llm_error(
        self,
        error: BaseException,
        *,
        run_id: UUID | None = None,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Called on LLM error. No-op for policy enforcement."""
        pass

    def on_chain_start(
        self,
        serialized: dict[str, Any],
        inputs: dict[str, Any],
        *,
        run_id: UUID | None = None,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when chain starts. No-op for policy enforcement."""
        pass

    def on_chain_end(
        self,
        outputs: dict[str, Any],
        *,
        run_id: UUID | None = None,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when chain ends. No-op for policy enforcement."""
        pass

    def on_chain_error(
        self,
        error: BaseException,
        *,
        run_id: UUID | None = None,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Called on chain error. No-op for policy enforcement."""
        pass

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID | None = None,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when tool starts. No-op for policy enforcement."""
        pass

    def on_tool_end(
        self,
        output: Any,
        *,
        run_id: UUID | None = None,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when tool ends. No-op for policy enforcement."""
        pass

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: UUID | None = None,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Called on tool error. No-op for policy enforcement."""
        pass

    def on_text(
        self,
        text: str,
        *,
        run_id: UUID | None = None,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Called on text. No-op for policy enforcement."""
        pass

    def on_retry(
        self,
        retry_state: Any,
        *,
        run_id: UUID | None = None,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Called on retry. No-op for policy enforcement."""
        pass

    # Helper methods

    def _extract_provider_from_serialized(self, serialized: dict[str, Any]) -> str:
        """Extract provider from serialized LLM data."""
        # Try to get from id field (e.g., "langchain_openai.ChatOpenAI")
        id_parts = serialized.get("id", [])
        if id_parts:
            class_name = id_parts[-1].lower() if id_parts else ""
            provider_map = {
                "chatopenai": "openai",
                "openai": "openai",
                "azurechatopenai": "azure",
                "chatanthropic": "anthropic",
                "chatgooglepalm": "google",
                "chatvertexai": "google",
                "chatcohere": "cohere",
                "chatbedrock": "aws",
                "chatollama": "ollama",
                "chatmistral": "mistral",
            }
            for key, provider in provider_map.items():
                if key in class_name:
                    return provider

        # Try from name
        name = serialized.get("name", "").lower()
        if "openai" in name:
            return "openai"
        if "anthropic" in name:
            return "anthropic"
        if "google" in name or "palm" in name or "vertex" in name:
            return "google"

        return "unknown"

    def _extract_message_content(self, messages: list[list[Any]]) -> str:
        """Extract text content from message lists."""
        parts = []
        for msg_list in messages:
            for msg in msg_list:
                # Handle different message types
                if hasattr(msg, "content"):
                    content = msg.content
                    if isinstance(content, str):
                        parts.append(content)
                    elif isinstance(content, list):
                        for part in content:
                            if isinstance(part, str):
                                parts.append(part)
                            elif isinstance(part, dict) and "text" in part:
                                parts.append(part["text"])
                elif isinstance(msg, dict):
                    content = msg.get("content", "")
                    if isinstance(content, str):
                        parts.append(content)
                elif isinstance(msg, str):
                    parts.append(msg)
        return "\n".join(parts)

    # Public methods

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


class PolicyBindLLM:
    """
    Wrapper for LangChain LLMs with PolicyBind enforcement.

    This class wraps a LangChain LLM and enforces policies before
    each invocation.

    Note: This class implements the LangChain Runnable interface but
    does not inherit from langchain classes to avoid requiring langchain
    as a dependency. When used with LangChain, it will be duck-typed.

    Example:
        Basic usage::

            from langchain_openai import OpenAI
            from policybind.integrations.langchain_integration import PolicyBindLLM

            llm = PolicyBindLLM(
                llm=OpenAI(),
                policy_set=policy_set,
                user_id="user@example.com",
            )

            response = llm.invoke("Hello!")
    """

    def __init__(
        self,
        llm: Any,
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
            llm: LangChain LLM instance.
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
        self._llm = llm
        self._policy_set = policy_set
        self._model = extract_model_from_llm(llm)
        self._provider = extract_provider_from_llm(llm)

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

    def invoke(self, input: str, config: dict[str, Any] | None = None, **kwargs: Any) -> str:
        """
        Invoke the LLM with policy enforcement.

        Args:
            input: Input prompt string.
            config: LangChain config dictionary.
            **kwargs: Additional arguments.

        Returns:
            LLM response string.

        Raises:
            PolicyDeniedError: If request is denied by policy.
        """
        # Enforce policies
        self._enforcer.enforce(
            provider=self._provider,
            model=self._model,
            prompt=input,
            context=self._context,
        )

        # Call underlying LLM
        return self._llm.invoke(input, config=config, **kwargs)

    def batch(
        self,
        inputs: list[str],
        config: dict[str, Any] | Sequence[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> list[str]:
        """
        Batch invoke the LLM with policy enforcement.

        Args:
            inputs: List of input prompts.
            config: LangChain config dictionary or list of configs.
            **kwargs: Additional arguments.

        Returns:
            List of LLM responses.

        Raises:
            PolicyDeniedError: If any request is denied by policy.
        """
        # Enforce policies for each input
        for input_text in inputs:
            self._enforcer.enforce(
                provider=self._provider,
                model=self._model,
                prompt=input_text,
                context=self._context,
            )

        # Call underlying LLM
        return self._llm.batch(inputs, config=config, **kwargs)

    async def ainvoke(
        self, input: str, config: dict[str, Any] | None = None, **kwargs: Any
    ) -> str:
        """
        Async invoke the LLM with policy enforcement.

        Args:
            input: Input prompt string.
            config: LangChain config dictionary.
            **kwargs: Additional arguments.

        Returns:
            LLM response string.

        Raises:
            PolicyDeniedError: If request is denied by policy.
        """
        # Enforce policies (sync, as pipeline doesn't need async)
        self._enforcer.enforce(
            provider=self._provider,
            model=self._model,
            prompt=input,
            context=self._context,
        )

        # Call underlying LLM
        return await self._llm.ainvoke(input, config=config, **kwargs)

    def get_enforcement_stats(self) -> dict[str, Any]:
        """Get enforcement statistics."""
        return self._enforcer.get_stats()

    def reload_policies(self, policy_set: PolicySet) -> None:
        """Reload with a new policy set."""
        self._policy_set = policy_set
        self._enforcer.reload_policies(policy_set)

    def __getattr__(self, name: str) -> Any:
        """Forward attribute access to wrapped LLM."""
        return getattr(self._llm, name)


class PolicyBindChatModel:
    """
    Wrapper for LangChain ChatModels with PolicyBind enforcement.

    This class wraps a LangChain ChatModel and enforces policies before
    each invocation.

    Note: This class implements the LangChain Runnable interface but
    does not inherit from langchain classes to avoid requiring langchain
    as a dependency.

    Example:
        Basic usage::

            from langchain_openai import ChatOpenAI
            from policybind.integrations.langchain_integration import PolicyBindChatModel

            llm = PolicyBindChatModel(
                llm=ChatOpenAI(model="gpt-4"),
                policy_set=policy_set,
                user_id="user@example.com",
            )

            response = llm.invoke("Hello!")
    """

    def __init__(
        self,
        llm: Any,
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
            llm: LangChain ChatModel instance.
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
        self._llm = llm
        self._policy_set = policy_set
        self._model = extract_model_from_llm(llm)
        self._provider = extract_provider_from_llm(llm)

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

    def _extract_content(self, input: Any) -> str:
        """Extract text content from various input types."""
        if isinstance(input, str):
            return input
        if isinstance(input, list):
            parts = []
            for item in input:
                if isinstance(item, str):
                    parts.append(item)
                elif hasattr(item, "content"):
                    content = item.content
                    if isinstance(content, str):
                        parts.append(content)
                elif isinstance(item, dict):
                    parts.append(item.get("content", str(item)))
            return "\n".join(parts)
        if hasattr(input, "content"):
            return str(input.content)
        return str(input)

    def invoke(self, input: Any, config: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        """
        Invoke the ChatModel with policy enforcement.

        Args:
            input: Input (string, message, or list of messages).
            config: LangChain config dictionary.
            **kwargs: Additional arguments.

        Returns:
            ChatModel response.

        Raises:
            PolicyDeniedError: If request is denied by policy.
        """
        # Extract content for enforcement
        content = self._extract_content(input)

        # Enforce policies
        self._enforcer.enforce(
            provider=self._provider,
            model=self._model,
            prompt=content,
            context=self._context,
        )

        # Call underlying ChatModel
        return self._llm.invoke(input, config=config, **kwargs)

    def batch(
        self,
        inputs: list[Any],
        config: dict[str, Any] | Sequence[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> list[Any]:
        """
        Batch invoke the ChatModel with policy enforcement.

        Args:
            inputs: List of inputs.
            config: LangChain config dictionary or list of configs.
            **kwargs: Additional arguments.

        Returns:
            List of ChatModel responses.

        Raises:
            PolicyDeniedError: If any request is denied by policy.
        """
        # Enforce policies for each input
        for input_item in inputs:
            content = self._extract_content(input_item)
            self._enforcer.enforce(
                provider=self._provider,
                model=self._model,
                prompt=content,
                context=self._context,
            )

        # Call underlying ChatModel
        return self._llm.batch(inputs, config=config, **kwargs)

    async def ainvoke(
        self, input: Any, config: dict[str, Any] | None = None, **kwargs: Any
    ) -> Any:
        """
        Async invoke the ChatModel with policy enforcement.

        Args:
            input: Input (string, message, or list of messages).
            config: LangChain config dictionary.
            **kwargs: Additional arguments.

        Returns:
            ChatModel response.

        Raises:
            PolicyDeniedError: If request is denied by policy.
        """
        # Extract content for enforcement
        content = self._extract_content(input)

        # Enforce policies
        self._enforcer.enforce(
            provider=self._provider,
            model=self._model,
            prompt=content,
            context=self._context,
        )

        # Call underlying ChatModel
        return await self._llm.ainvoke(input, config=config, **kwargs)

    def stream(self, input: Any, config: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        """
        Stream from the ChatModel with policy enforcement.

        Args:
            input: Input (string, message, or list of messages).
            config: LangChain config dictionary.
            **kwargs: Additional arguments.

        Yields:
            ChatModel response chunks.

        Raises:
            PolicyDeniedError: If request is denied by policy.
        """
        # Extract content for enforcement
        content = self._extract_content(input)

        # Enforce policies
        self._enforcer.enforce(
            provider=self._provider,
            model=self._model,
            prompt=content,
            context=self._context,
        )

        # Call underlying ChatModel
        return self._llm.stream(input, config=config, **kwargs)

    def get_enforcement_stats(self) -> dict[str, Any]:
        """Get enforcement statistics."""
        return self._enforcer.get_stats()

    def reload_policies(self, policy_set: PolicySet) -> None:
        """Reload with a new policy set."""
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
        """Update the enforcement context."""
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
        """Forward attribute access to wrapped ChatModel."""
        return getattr(self._llm, name)


def create_policy_callback(
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
) -> PolicyBindCallback:
    """
    Create a PolicyBind callback handler for LangChain.

    This is a convenience function to create a PolicyBindCallback instance.

    Args:
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

    Returns:
        PolicyBindCallback instance.

    Example:
        Basic usage::

            from langchain_openai import ChatOpenAI
            from policybind.integrations.langchain_integration import create_policy_callback

            callback = create_policy_callback(
                policy_set=policy_set,
                user_id="user@example.com",
            )

            llm = ChatOpenAI(model="gpt-4")
            response = llm.invoke("Hello!", config={"callbacks": [callback]})
    """
    return PolicyBindCallback(
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


def wrap_llm(
    llm: Any,
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
) -> PolicyBindLLM | PolicyBindChatModel:
    """
    Wrap a LangChain LLM or ChatModel with PolicyBind enforcement.

    Automatically detects whether the provided LLM is a base LLM or
    ChatModel and returns the appropriate wrapper.

    Args:
        llm: LangChain LLM or ChatModel instance.
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

    Returns:
        PolicyBindLLM or PolicyBindChatModel wrapper instance.

    Example:
        Basic usage::

            from langchain_openai import ChatOpenAI
            from policybind.integrations.langchain_integration import wrap_llm

            llm = wrap_llm(
                llm=ChatOpenAI(model="gpt-4"),
                policy_set=policy_set,
                user_id="user@example.com",
            )

            response = llm.invoke("Hello!")
    """
    # Check if it's a ChatModel by looking for common chat model patterns
    class_name = llm.__class__.__name__.lower()
    is_chat = "chat" in class_name or hasattr(llm, "bind_tools")

    wrapper_class = PolicyBindChatModel if is_chat else PolicyBindLLM

    return wrapper_class(
        llm=llm,
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
