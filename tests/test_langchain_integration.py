"""
Tests for LangChain integration.

This module tests the LangChain integration for PolicyBind,
ensuring policies are correctly enforced on LangChain LLM calls.
"""

from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from policybind.integrations.langchain_integration import (
    TOKENS_PER_WORD,
    EnforcementContext,
    EnforcementResult,
    PolicyApprovalRequiredError,
    PolicyBindCallback,
    PolicyBindChatModel,
    PolicyBindLLM,
    PolicyDeniedError,
    PolicyEnforcer,
    create_policy_callback,
    estimate_tokens,
    extract_model_from_llm,
    extract_provider_from_llm,
    hash_content,
    wrap_llm,
)
from policybind.models.policy import PolicyRule, PolicySet
from policybind.models.request import Decision


class TestTokenEstimation:
    """Tests for token estimation functions."""

    def test_estimate_tokens_empty(self):
        """Test empty string returns 0."""
        assert estimate_tokens("") == 0

    def test_estimate_tokens_single_word(self):
        """Test single word estimation."""
        tokens = estimate_tokens("hello")
        assert tokens == int(1 * TOKENS_PER_WORD)

    def test_estimate_tokens_multiple_words(self):
        """Test multiple word estimation."""
        text = "Hello world this is a test"
        expected = int(6 * TOKENS_PER_WORD)
        assert estimate_tokens(text) == expected


class TestContentHashing:
    """Tests for content hashing functions."""

    def test_hash_content_basic(self):
        """Test basic content hashing."""
        content = "Hello world"
        hash1 = hash_content(content)
        hash2 = hash_content(content)
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 hex digest

    def test_hash_content_different(self):
        """Test different content produces different hashes."""
        hash1 = hash_content("Hello")
        hash2 = hash_content("World")
        assert hash1 != hash2


class TestModelExtraction:
    """Tests for model/provider extraction from LLM objects."""

    def test_extract_model_from_llm_model_name(self):
        """Test extracting model from model_name attribute."""
        llm = MagicMock()
        llm.model_name = "gpt-4"
        assert extract_model_from_llm(llm) == "gpt-4"

    def test_extract_model_from_llm_model(self):
        """Test extracting model from model attribute."""
        llm = MagicMock(spec=[])
        llm.model = "claude-3-opus"
        assert extract_model_from_llm(llm) == "claude-3-opus"

    def test_extract_model_from_llm_unknown(self):
        """Test unknown model returns 'unknown'."""
        llm = MagicMock(spec=[])
        assert extract_model_from_llm(llm) == "unknown"

    def test_extract_provider_openai(self):
        """Test extracting OpenAI provider."""
        llm = MagicMock()
        llm.__class__.__name__ = "ChatOpenAI"
        assert extract_provider_from_llm(llm) == "openai"

    def test_extract_provider_anthropic(self):
        """Test extracting Anthropic provider."""
        llm = MagicMock()
        llm.__class__.__name__ = "ChatAnthropic"
        assert extract_provider_from_llm(llm) == "anthropic"

    def test_extract_provider_google(self):
        """Test extracting Google provider."""
        llm = MagicMock()
        llm.__class__.__name__ = "ChatVertexAI"
        assert extract_provider_from_llm(llm) == "google"

    def test_extract_provider_ollama(self):
        """Test extracting Ollama provider."""
        llm = MagicMock()
        llm.__class__.__name__ = "ChatOllama"
        assert extract_provider_from_llm(llm) == "ollama"

    def test_extract_provider_unknown(self):
        """Test unknown provider returns 'unknown'."""
        llm = MagicMock()
        llm.__class__.__name__ = "CustomLLM"
        assert extract_provider_from_llm(llm) == "unknown"


class TestEnforcementContext:
    """Tests for EnforcementContext."""

    def test_default_context(self):
        """Test default context values."""
        ctx = EnforcementContext()
        assert ctx.user_id == ""
        assert ctx.department == ""
        assert ctx.source_application == ""
        assert ctx.data_classification == ()
        assert ctx.intended_use_case == ""
        assert ctx.metadata == {}

    def test_context_with_values(self):
        """Test context with provided values."""
        ctx = EnforcementContext(
            user_id="user@example.com",
            department="engineering",
            source_application="test-app",
            data_classification=("pii", "confidential"),
            intended_use_case="testing",
            metadata={"key": "value"},
        )
        assert ctx.user_id == "user@example.com"
        assert ctx.department == "engineering"
        assert ctx.data_classification == ("pii", "confidential")


class TestPolicyEnforcer:
    """Tests for PolicyEnforcer class."""

    @pytest.fixture
    def policy_set(self):
        """Create a basic policy set."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(
            PolicyRule(
                name="allow-all",
                match_conditions={},
                action="ALLOW",
                priority=0,
            )
        )
        return policy_set

    @pytest.fixture
    def deny_policy_set(self):
        """Create a policy set that denies requests."""
        policy_set = PolicySet(name="deny", version="1.0.0")
        policy_set.add_rule(
            PolicyRule(
                name="deny-all",
                match_conditions={},
                action="DENY",
                priority=100,
                action_params={"reason": "Denied by policy"},
            )
        )
        return policy_set

    def test_enforce_allowed(self, policy_set):
        """Test enforcement returns allowed result."""
        enforcer = PolicyEnforcer(policy_set, raise_on_deny=False)
        result = enforcer.enforce(
            provider="openai",
            model="gpt-4",
            prompt="Hello world",
        )
        assert result.allowed is True
        assert result.response.decision == Decision.ALLOW

    def test_enforce_denied_raises(self, deny_policy_set):
        """Test enforcement raises on deny."""
        enforcer = PolicyEnforcer(deny_policy_set)
        with pytest.raises(PolicyDeniedError) as exc_info:
            enforcer.enforce(
                provider="openai",
                model="gpt-4",
                prompt="Hello world",
            )
        assert "Denied by policy" in str(exc_info.value)

    def test_enforce_denied_no_raise(self, deny_policy_set):
        """Test enforcement returns denied result without raising."""
        enforcer = PolicyEnforcer(deny_policy_set, raise_on_deny=False)
        result = enforcer.enforce(
            provider="openai",
            model="gpt-4",
            prompt="Hello world",
        )
        assert result.allowed is False
        assert result.response.decision == Decision.DENY

    def test_enforce_with_context(self, policy_set):
        """Test enforcement with custom context."""
        enforcer = PolicyEnforcer(policy_set, raise_on_deny=False)
        ctx = EnforcementContext(
            user_id="user@example.com",
            department="engineering",
        )
        result = enforcer.enforce(
            provider="openai",
            model="gpt-4",
            prompt="Hello",
            context=ctx,
        )
        assert result.request.user_id == "user@example.com"
        assert result.request.department == "engineering"

    def test_get_stats(self, policy_set):
        """Test statistics tracking."""
        enforcer = PolicyEnforcer(policy_set, raise_on_deny=False)
        enforcer.enforce(provider="openai", model="gpt-4", prompt="Hello")
        stats = enforcer.get_stats()
        assert stats["total_requests"] == 1
        assert stats["allowed_requests"] == 1

    def test_reset_stats(self, policy_set):
        """Test statistics reset."""
        enforcer = PolicyEnforcer(policy_set, raise_on_deny=False)
        enforcer.enforce(provider="openai", model="gpt-4", prompt="Hello")
        enforcer.reset_stats()
        stats = enforcer.get_stats()
        assert stats["total_requests"] == 0

    def test_enforcement_callback(self, policy_set):
        """Test enforcement callback is called."""
        callback_called = []

        def callback(request, response):
            callback_called.append((request, response))

        enforcer = PolicyEnforcer(
            policy_set, on_enforcement=callback, raise_on_deny=False
        )
        enforcer.enforce(provider="openai", model="gpt-4", prompt="Hello")
        assert len(callback_called) == 1


class TestPolicyBindCallback:
    """Tests for PolicyBindCallback class."""

    @pytest.fixture
    def policy_set(self):
        """Create a basic policy set."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(
            PolicyRule(
                name="allow-all",
                match_conditions={},
                action="ALLOW",
                priority=0,
            )
        )
        return policy_set

    @pytest.fixture
    def deny_policy_set(self):
        """Create a policy set that denies requests."""
        policy_set = PolicySet(name="deny", version="1.0.0")
        policy_set.add_rule(
            PolicyRule(
                name="deny-all",
                match_conditions={},
                action="DENY",
                priority=100,
                action_params={"reason": "Denied by policy"},
            )
        )
        return policy_set

    def test_callback_creation(self, policy_set):
        """Test callback can be created."""
        callback = PolicyBindCallback(
            policy_set=policy_set,
            user_id="user@example.com",
        )
        assert callback._context.user_id == "user@example.com"

    def test_on_llm_start_allowed(self, policy_set):
        """Test on_llm_start allows request."""
        callback = PolicyBindCallback(policy_set=policy_set)
        serialized = {"name": "ChatOpenAI", "kwargs": {"model_name": "gpt-4"}, "id": []}
        # Should not raise
        callback.on_llm_start(serialized, ["Hello world"], run_id=uuid4())

    def test_on_llm_start_denied(self, deny_policy_set):
        """Test on_llm_start denies request."""
        callback = PolicyBindCallback(policy_set=deny_policy_set)
        serialized = {"name": "ChatOpenAI", "kwargs": {"model_name": "gpt-4"}, "id": []}
        with pytest.raises(PolicyDeniedError):
            callback.on_llm_start(serialized, ["Hello world"], run_id=uuid4())

    def test_on_chat_model_start_allowed(self, policy_set):
        """Test on_chat_model_start allows request."""
        callback = PolicyBindCallback(policy_set=policy_set)
        serialized = {"name": "ChatOpenAI", "kwargs": {"model": "gpt-4"}, "id": []}
        # Create mock messages
        messages = [[MagicMock(content="Hello world")]]
        # Should not raise
        callback.on_chat_model_start(serialized, messages, run_id=uuid4())

    def test_on_chat_model_start_denied(self, deny_policy_set):
        """Test on_chat_model_start denies request."""
        callback = PolicyBindCallback(policy_set=deny_policy_set)
        serialized = {"name": "ChatOpenAI", "kwargs": {"model": "gpt-4"}, "id": []}
        messages = [[MagicMock(content="Hello world")]]
        with pytest.raises(PolicyDeniedError):
            callback.on_chat_model_start(serialized, messages, run_id=uuid4())

    def test_get_enforcement_stats(self, policy_set):
        """Test enforcement stats retrieval."""
        callback = PolicyBindCallback(policy_set=policy_set)
        serialized = {"name": "ChatOpenAI", "kwargs": {"model_name": "gpt-4"}, "id": []}
        callback.on_llm_start(serialized, ["Hello"], run_id=uuid4())
        stats = callback.get_enforcement_stats()
        assert stats["total_requests"] == 1
        assert stats["allowed_requests"] == 1

    def test_update_context(self, policy_set):
        """Test context updating."""
        callback = PolicyBindCallback(policy_set=policy_set)
        callback.update_context(
            user_id="new_user@example.com",
            department="sales",
        )
        assert callback._context.user_id == "new_user@example.com"
        assert callback._context.department == "sales"

    def test_reload_policies(self, policy_set, deny_policy_set):
        """Test policy reloading."""
        callback = PolicyBindCallback(policy_set=policy_set)
        callback.reload_policies(deny_policy_set)
        assert callback._policy_set is deny_policy_set

    def test_extract_provider_from_serialized_openai(self, policy_set):
        """Test provider extraction from serialized data."""
        callback = PolicyBindCallback(policy_set=policy_set)
        serialized = {"id": ["langchain_openai", "ChatOpenAI"], "name": "test"}
        provider = callback._extract_provider_from_serialized(serialized)
        assert provider == "openai"

    def test_extract_provider_from_serialized_anthropic(self, policy_set):
        """Test provider extraction for Anthropic."""
        callback = PolicyBindCallback(policy_set=policy_set)
        serialized = {"id": ["langchain_anthropic", "ChatAnthropic"], "name": "test"}
        provider = callback._extract_provider_from_serialized(serialized)
        assert provider == "anthropic"

    def test_extract_message_content(self, policy_set):
        """Test message content extraction."""
        callback = PolicyBindCallback(policy_set=policy_set)
        # Test with message objects
        msg1 = MagicMock(content="Hello")
        msg2 = MagicMock(content="World")
        messages = [[msg1, msg2]]
        content = callback._extract_message_content(messages)
        assert "Hello" in content
        assert "World" in content

    def test_extract_message_content_dict(self, policy_set):
        """Test message content extraction from dicts."""
        callback = PolicyBindCallback(policy_set=policy_set)
        messages = [[{"content": "Hello"}, {"content": "World"}]]
        content = callback._extract_message_content(messages)
        assert "Hello" in content
        assert "World" in content

    def test_extract_message_content_string(self, policy_set):
        """Test message content extraction from strings."""
        callback = PolicyBindCallback(policy_set=policy_set)
        messages = [["Hello", "World"]]
        content = callback._extract_message_content(messages)
        assert "Hello" in content
        assert "World" in content


class TestPolicyBindLLM:
    """Tests for PolicyBindLLM wrapper class."""

    @pytest.fixture
    def policy_set(self):
        """Create a basic policy set."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(
            PolicyRule(
                name="allow-all",
                match_conditions={},
                action="ALLOW",
                priority=0,
            )
        )
        return policy_set

    @pytest.fixture
    def deny_policy_set(self):
        """Create a policy set that denies requests."""
        policy_set = PolicySet(name="deny", version="1.0.0")
        policy_set.add_rule(
            PolicyRule(
                name="deny-all",
                match_conditions={},
                action="DENY",
                priority=100,
                action_params={"reason": "Denied by policy"},
            )
        )
        return policy_set

    @pytest.fixture
    def mock_llm(self):
        """Create a mock LLM."""
        llm = MagicMock()
        llm.__class__.__name__ = "OpenAI"
        llm.model_name = "gpt-3.5-turbo-instruct"
        llm.invoke = MagicMock(return_value="Response")
        llm.batch = MagicMock(return_value=["Response1", "Response2"])
        return llm

    def test_wrapper_creation(self, mock_llm, policy_set):
        """Test wrapper can be created."""
        wrapper = PolicyBindLLM(
            llm=mock_llm,
            policy_set=policy_set,
            user_id="user@example.com",
        )
        assert wrapper._llm is mock_llm
        assert wrapper._model == "gpt-3.5-turbo-instruct"
        assert wrapper._provider == "openai"

    def test_invoke_allowed(self, mock_llm, policy_set):
        """Test invoke is allowed."""
        wrapper = PolicyBindLLM(llm=mock_llm, policy_set=policy_set)
        result = wrapper.invoke("Hello")
        mock_llm.invoke.assert_called_once()
        assert result == "Response"

    def test_invoke_denied(self, mock_llm, deny_policy_set):
        """Test invoke is denied."""
        wrapper = PolicyBindLLM(llm=mock_llm, policy_set=deny_policy_set)
        with pytest.raises(PolicyDeniedError):
            wrapper.invoke("Hello")
        mock_llm.invoke.assert_not_called()

    def test_batch_allowed(self, mock_llm, policy_set):
        """Test batch is allowed."""
        wrapper = PolicyBindLLM(llm=mock_llm, policy_set=policy_set)
        result = wrapper.batch(["Hello", "World"])
        mock_llm.batch.assert_called_once()
        assert result == ["Response1", "Response2"]

    def test_batch_denied(self, mock_llm, deny_policy_set):
        """Test batch is denied on first input."""
        wrapper = PolicyBindLLM(llm=mock_llm, policy_set=deny_policy_set)
        with pytest.raises(PolicyDeniedError):
            wrapper.batch(["Hello", "World"])
        mock_llm.batch.assert_not_called()

    def test_get_enforcement_stats(self, mock_llm, policy_set):
        """Test enforcement stats retrieval."""
        wrapper = PolicyBindLLM(llm=mock_llm, policy_set=policy_set)
        wrapper.invoke("Hello")
        stats = wrapper.get_enforcement_stats()
        assert stats["total_requests"] == 1
        assert stats["allowed_requests"] == 1

    def test_attribute_forwarding(self, mock_llm, policy_set):
        """Test attribute forwarding to underlying LLM."""
        mock_llm.some_attribute = "test_value"
        wrapper = PolicyBindLLM(llm=mock_llm, policy_set=policy_set)
        assert wrapper.some_attribute == "test_value"


class TestPolicyBindChatModel:
    """Tests for PolicyBindChatModel wrapper class."""

    @pytest.fixture
    def policy_set(self):
        """Create a basic policy set."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(
            PolicyRule(
                name="allow-all",
                match_conditions={},
                action="ALLOW",
                priority=0,
            )
        )
        return policy_set

    @pytest.fixture
    def deny_policy_set(self):
        """Create a policy set that denies requests."""
        policy_set = PolicySet(name="deny", version="1.0.0")
        policy_set.add_rule(
            PolicyRule(
                name="deny-all",
                match_conditions={},
                action="DENY",
                priority=100,
                action_params={"reason": "Denied by policy"},
            )
        )
        return policy_set

    @pytest.fixture
    def mock_chat_model(self):
        """Create a mock ChatModel."""
        llm = MagicMock()
        llm.__class__.__name__ = "ChatOpenAI"
        llm.model_name = "gpt-4"
        llm.invoke = MagicMock(return_value=MagicMock(content="Response"))
        llm.batch = MagicMock(return_value=[MagicMock(content="R1"), MagicMock(content="R2")])
        llm.stream = MagicMock(return_value=iter(["chunk1", "chunk2"]))
        return llm

    def test_wrapper_creation(self, mock_chat_model, policy_set):
        """Test wrapper can be created."""
        wrapper = PolicyBindChatModel(
            llm=mock_chat_model,
            policy_set=policy_set,
            user_id="user@example.com",
        )
        assert wrapper._llm is mock_chat_model
        assert wrapper._model == "gpt-4"
        assert wrapper._provider == "openai"

    def test_invoke_string_allowed(self, mock_chat_model, policy_set):
        """Test invoke with string is allowed."""
        wrapper = PolicyBindChatModel(llm=mock_chat_model, policy_set=policy_set)
        result = wrapper.invoke("Hello")
        mock_chat_model.invoke.assert_called_once()

    def test_invoke_messages_allowed(self, mock_chat_model, policy_set):
        """Test invoke with messages is allowed."""
        wrapper = PolicyBindChatModel(llm=mock_chat_model, policy_set=policy_set)
        messages = [MagicMock(content="Hello")]
        result = wrapper.invoke(messages)
        mock_chat_model.invoke.assert_called_once()

    def test_invoke_denied(self, mock_chat_model, deny_policy_set):
        """Test invoke is denied."""
        wrapper = PolicyBindChatModel(llm=mock_chat_model, policy_set=deny_policy_set)
        with pytest.raises(PolicyDeniedError):
            wrapper.invoke("Hello")
        mock_chat_model.invoke.assert_not_called()

    def test_batch_allowed(self, mock_chat_model, policy_set):
        """Test batch is allowed."""
        wrapper = PolicyBindChatModel(llm=mock_chat_model, policy_set=policy_set)
        result = wrapper.batch(["Hello", "World"])
        mock_chat_model.batch.assert_called_once()

    def test_stream_allowed(self, mock_chat_model, policy_set):
        """Test stream is allowed."""
        wrapper = PolicyBindChatModel(llm=mock_chat_model, policy_set=policy_set)
        result = wrapper.stream("Hello")
        mock_chat_model.stream.assert_called_once()

    def test_stream_denied(self, mock_chat_model, deny_policy_set):
        """Test stream is denied."""
        wrapper = PolicyBindChatModel(llm=mock_chat_model, policy_set=deny_policy_set)
        with pytest.raises(PolicyDeniedError):
            wrapper.stream("Hello")
        mock_chat_model.stream.assert_not_called()

    def test_update_context(self, mock_chat_model, policy_set):
        """Test context updating."""
        wrapper = PolicyBindChatModel(llm=mock_chat_model, policy_set=policy_set)
        wrapper.update_context(
            user_id="new_user@example.com",
            department="sales",
        )
        assert wrapper._context.user_id == "new_user@example.com"
        assert wrapper._context.department == "sales"

    def test_extract_content_string(self, mock_chat_model, policy_set):
        """Test content extraction from string."""
        wrapper = PolicyBindChatModel(llm=mock_chat_model, policy_set=policy_set)
        content = wrapper._extract_content("Hello world")
        assert content == "Hello world"

    def test_extract_content_message(self, mock_chat_model, policy_set):
        """Test content extraction from message object."""
        wrapper = PolicyBindChatModel(llm=mock_chat_model, policy_set=policy_set)
        msg = MagicMock(content="Hello")
        content = wrapper._extract_content(msg)
        assert content == "Hello"

    def test_extract_content_list(self, mock_chat_model, policy_set):
        """Test content extraction from message list."""
        wrapper = PolicyBindChatModel(llm=mock_chat_model, policy_set=policy_set)
        messages = [MagicMock(content="Hello"), MagicMock(content="World")]
        content = wrapper._extract_content(messages)
        assert "Hello" in content
        assert "World" in content


class TestCreatePolicyCallback:
    """Tests for create_policy_callback function."""

    @pytest.fixture
    def policy_set(self):
        """Create a basic policy set."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(
            PolicyRule(
                name="allow-all",
                match_conditions={},
                action="ALLOW",
                priority=0,
            )
        )
        return policy_set

    def test_create_callback(self, policy_set):
        """Test callback creation."""
        callback = create_policy_callback(
            policy_set=policy_set,
            user_id="user@example.com",
            department="engineering",
        )
        assert isinstance(callback, PolicyBindCallback)
        assert callback._context.user_id == "user@example.com"
        assert callback._context.department == "engineering"


class TestWrapLLM:
    """Tests for wrap_llm function."""

    @pytest.fixture
    def policy_set(self):
        """Create a basic policy set."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(
            PolicyRule(
                name="allow-all",
                match_conditions={},
                action="ALLOW",
                priority=0,
            )
        )
        return policy_set

    def test_wrap_chat_model(self, policy_set):
        """Test wrapping a ChatModel returns PolicyBindChatModel."""
        llm = MagicMock()
        llm.__class__.__name__ = "ChatOpenAI"
        llm.model_name = "gpt-4"
        wrapper = wrap_llm(llm=llm, policy_set=policy_set)
        assert isinstance(wrapper, PolicyBindChatModel)

    def test_wrap_base_llm(self, policy_set):
        """Test wrapping a base LLM returns PolicyBindLLM."""
        llm = MagicMock()
        llm.__class__.__name__ = "OpenAI"
        llm.model_name = "gpt-3.5-turbo-instruct"
        # Remove bind_tools to ensure it's not detected as chat model
        llm.bind_tools = None
        del llm.bind_tools
        wrapper = wrap_llm(llm=llm, policy_set=policy_set)
        assert isinstance(wrapper, PolicyBindLLM)


class TestApprovalRequired:
    """Tests for approval required scenarios."""

    @pytest.fixture
    def approval_policy_set(self):
        """Create a policy set that requires approval."""
        policy_set = PolicySet(name="approval", version="1.0.0")
        policy_set.add_rule(
            PolicyRule(
                name="require-approval",
                match_conditions={"model": {"contains": "gpt-4"}},
                action="REQUIRE_APPROVAL",
                priority=100,
                action_params={"reason": "GPT-4 requires approval"},
            )
        )
        return policy_set

    def test_approval_required_raises(self, approval_policy_set):
        """Test that approval required raises exception."""
        enforcer = PolicyEnforcer(approval_policy_set)
        with pytest.raises(PolicyApprovalRequiredError) as exc_info:
            enforcer.enforce(provider="openai", model="gpt-4", prompt="Hello")
        assert "requires approval" in str(exc_info.value)

    def test_approval_required_no_raise(self, approval_policy_set):
        """Test approval required without raising."""
        enforcer = PolicyEnforcer(approval_policy_set, raise_on_approval_required=False)
        result = enforcer.enforce(provider="openai", model="gpt-4", prompt="Hello")
        assert result.response.decision == Decision.REQUIRE_APPROVAL


class TestDepartmentPolicies:
    """Tests for department-based policies."""

    @pytest.fixture
    def department_policy(self):
        """Create a policy with department restrictions."""
        policy_set = PolicySet(name="dept", version="1.0.0")
        policy_set.add_rule(
            PolicyRule(
                name="deny-marketing",
                match_conditions={"department": "marketing"},
                action="DENY",
                priority=100,
                action_params={"reason": "Marketing department not allowed"},
            )
        )
        policy_set.add_rule(
            PolicyRule(
                name="allow-engineering",
                match_conditions={},
                action="ALLOW",
                priority=0,
            )
        )
        return policy_set

    def test_marketing_denied(self, department_policy):
        """Test marketing department is denied."""
        enforcer = PolicyEnforcer(department_policy, raise_on_deny=False)
        ctx = EnforcementContext(department="marketing")
        result = enforcer.enforce(
            provider="openai",
            model="gpt-4",
            prompt="Hello",
            context=ctx,
        )
        assert result.allowed is False

    def test_engineering_allowed(self, department_policy):
        """Test engineering department is allowed."""
        enforcer = PolicyEnforcer(department_policy, raise_on_deny=False)
        ctx = EnforcementContext(department="engineering")
        result = enforcer.enforce(
            provider="openai",
            model="gpt-4",
            prompt="Hello",
            context=ctx,
        )
        assert result.allowed is True


class TestDataClassificationPolicies:
    """Tests for data classification-based policies."""

    @pytest.fixture
    def classification_policy(self):
        """Create a policy based on data classification."""
        policy_set = PolicySet(name="classification", version="1.0.0")
        policy_set.add_rule(
            PolicyRule(
                name="deny-pii",
                match_conditions={"data_classification": {"contains": "pii"}},
                action="DENY",
                priority=100,
                action_params={"reason": "PII data not allowed"},
            )
        )
        policy_set.add_rule(
            PolicyRule(
                name="allow-public",
                match_conditions={},
                action="ALLOW",
                priority=0,
            )
        )
        return policy_set

    def test_pii_denied(self, classification_policy):
        """Test PII data is denied."""
        enforcer = PolicyEnforcer(classification_policy, raise_on_deny=False)
        ctx = EnforcementContext(data_classification=("pii",))
        result = enforcer.enforce(
            provider="openai",
            model="gpt-4",
            prompt="Hello",
            context=ctx,
        )
        assert result.allowed is False

    def test_public_allowed(self, classification_policy):
        """Test public data is allowed."""
        enforcer = PolicyEnforcer(classification_policy, raise_on_deny=False)
        ctx = EnforcementContext(data_classification=("public",))
        result = enforcer.enforce(
            provider="openai",
            model="gpt-4",
            prompt="Hello",
            context=ctx,
        )
        assert result.allowed is True


class TestProviderPolicies:
    """Tests for provider-specific policies."""

    @pytest.fixture
    def provider_policy(self):
        """Create a policy that matches by provider."""
        policy_set = PolicySet(name="provider", version="1.0.0")
        policy_set.add_rule(
            PolicyRule(
                name="deny-anthropic",
                match_conditions={"provider": "anthropic"},
                action="DENY",
                priority=100,
                action_params={"reason": "Anthropic not allowed"},
            )
        )
        policy_set.add_rule(
            PolicyRule(
                name="allow-other",
                match_conditions={},
                action="ALLOW",
                priority=0,
            )
        )
        return policy_set

    def test_anthropic_denied(self, provider_policy):
        """Test Anthropic provider is denied."""
        enforcer = PolicyEnforcer(provider_policy, raise_on_deny=False)
        result = enforcer.enforce(
            provider="anthropic",
            model="claude-3-opus",
            prompt="Hello",
        )
        assert result.allowed is False

    def test_openai_allowed(self, provider_policy):
        """Test OpenAI provider is allowed."""
        enforcer = PolicyEnforcer(provider_policy, raise_on_deny=False)
        result = enforcer.enforce(
            provider="openai",
            model="gpt-4",
            prompt="Hello",
        )
        assert result.allowed is True


class TestModelPolicies:
    """Tests for model-specific policies."""

    @pytest.fixture
    def model_policy(self):
        """Create a policy with model restrictions."""
        policy_set = PolicySet(name="model", version="1.0.0")
        policy_set.add_rule(
            PolicyRule(
                name="deny-gpt4",
                match_conditions={"model": {"contains": "gpt-4"}},
                action="DENY",
                priority=100,
                action_params={"reason": "GPT-4 not allowed"},
            )
        )
        policy_set.add_rule(
            PolicyRule(
                name="allow-other",
                match_conditions={},
                action="ALLOW",
                priority=0,
            )
        )
        return policy_set

    def test_gpt4_denied(self, model_policy):
        """Test GPT-4 is denied."""
        enforcer = PolicyEnforcer(model_policy, raise_on_deny=False)
        result = enforcer.enforce(
            provider="openai",
            model="gpt-4-turbo",
            prompt="Hello",
        )
        assert result.allowed is False

    def test_gpt35_allowed(self, model_policy):
        """Test GPT-3.5 is allowed."""
        enforcer = PolicyEnforcer(model_policy, raise_on_deny=False)
        result = enforcer.enforce(
            provider="openai",
            model="gpt-3.5-turbo",
            prompt="Hello",
        )
        assert result.allowed is True


class TestLangChainMetadata:
    """Tests for LangChain-specific metadata handling."""

    @pytest.fixture
    def policy_set(self):
        """Create a basic policy set."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(
            PolicyRule(
                name="allow-all",
                match_conditions={},
                action="ALLOW",
                priority=0,
            )
        )
        return policy_set

    def test_langchain_metadata_added(self, policy_set):
        """Test that langchain=True is added to metadata."""
        enforcer = PolicyEnforcer(policy_set, raise_on_deny=False)
        result = enforcer.enforce(
            provider="openai",
            model="gpt-4",
            prompt="Hello",
        )
        assert result.request.metadata.get("langchain") is True
