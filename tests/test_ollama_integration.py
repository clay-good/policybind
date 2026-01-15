"""
Tests for the Ollama integration.

Tests the policy enforcement wrapper for Ollama local model inference.
"""

import pytest
from unittest.mock import MagicMock, patch

from policybind.integrations.ollama_integration import (
    ChatWrapper,
    EmbedWrapper,
    EmbeddingsWrapper,
    EnforcementContext,
    EnforcementResult,
    GenerateWrapper,
    PolicyApprovalRequiredError,
    PolicyBindOllama,
    PolicyDeniedError,
    PolicyEnforcer,
    PullWrapper,
    create_policy_client,
    estimate_message_tokens,
    estimate_tokens,
    extract_content_for_hash,
    get_model_info,
    hash_content,
    wrap_client,
)
from policybind.models.policy import PolicyRule, PolicySet
from policybind.models.request import Decision


class TestTokenEstimation:
    """Tests for token estimation functions."""

    def test_estimate_tokens_empty(self):
        """Test estimation with empty string."""
        assert estimate_tokens("") == 0

    def test_estimate_tokens_simple(self):
        """Test estimation with simple text."""
        # 5 words * 1.3 tokens/word = 6.5 -> 6
        result = estimate_tokens("Hello world how are you")
        assert result == 6

    def test_estimate_tokens_longer(self):
        """Test estimation with longer text."""
        text = "This is a longer piece of text with more words to test"
        result = estimate_tokens(text)
        # 12 words * 1.3 = 15.6 -> 15
        assert result == 15

    def test_estimate_message_tokens_simple(self):
        """Test message token estimation with simple message."""
        messages = [{"role": "user", "content": "Hello world"}]
        result = estimate_message_tokens(messages)
        # 4 (overhead) + 2 words * 1.3 = 6.6 -> ~6
        assert result >= 6

    def test_estimate_message_tokens_multiple(self):
        """Test message token estimation with multiple messages."""
        messages = [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi there"},
        ]
        result = estimate_message_tokens(messages)
        # 2 messages * 4 overhead + content tokens
        assert result >= 10


class TestModelInfo:
    """Tests for model info functions."""

    def test_get_model_info_llama3_2(self):
        """Test getting Llama 3.2 model info."""
        info = get_model_info("llama3.2")
        assert info["size"] == "3b"
        assert info["context"] == 131072

    def test_get_model_info_llama3_1_70b(self):
        """Test getting Llama 3.1 70B model info."""
        info = get_model_info("llama3.1:70b")
        assert info["size"] == "70b"
        assert info["context"] == 131072

    def test_get_model_info_mistral(self):
        """Test getting Mistral model info."""
        info = get_model_info("mistral")
        assert info["size"] == "7b"
        assert info["context"] == 32768

    def test_get_model_info_with_tag(self):
        """Test getting model info with tag."""
        info = get_model_info("llama3.2:latest")
        assert info["size"] == "3b"

    def test_get_model_info_embedding(self):
        """Test getting embedding model info."""
        info = get_model_info("nomic-embed-text")
        assert info.get("embedding") is True

    def test_get_model_info_vision(self):
        """Test getting vision model info."""
        info = get_model_info("llava")
        assert info.get("vision") is True

    def test_get_model_info_unknown(self):
        """Test getting unknown model info."""
        info = get_model_info("unknown-model")
        assert info["size"] == "unknown"
        assert info["context"] == 4096


class TestContentHashing:
    """Tests for content hashing functions."""

    def test_hash_content_simple(self):
        """Test hashing simple content."""
        hash1 = hash_content("Hello")
        hash2 = hash_content("Hello")
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 hex

    def test_hash_content_different(self):
        """Test different content produces different hashes."""
        hash1 = hash_content("Hello")
        hash2 = hash_content("World")
        assert hash1 != hash2

    def test_extract_content_for_hash_messages(self):
        """Test extracting message content for hashing."""
        messages = [
            {"role": "user", "content": "Hello world"},
            {"role": "assistant", "content": "Hi there"},
        ]
        result = extract_content_for_hash(messages=messages)
        assert "Hello world" in result
        assert "Hi there" in result

    def test_extract_content_for_hash_prompt(self):
        """Test extracting prompt content for hashing."""
        result = extract_content_for_hash(prompt="Write a story")
        assert result == "Write a story"

    def test_extract_content_for_hash_with_system(self):
        """Test extracting content with system prompt."""
        result = extract_content_for_hash(
            prompt="Hello",
            system="You are a helpful assistant.",
        )
        assert "Hello" in result
        assert "You are a helpful assistant" in result


class TestEnforcementContext:
    """Tests for EnforcementContext dataclass."""

    def test_default_context(self):
        """Test default context values."""
        ctx = EnforcementContext()
        assert ctx.user_id == ""
        assert ctx.department == ""
        assert ctx.data_classification == ()
        assert ctx.metadata == {}

    def test_custom_context(self):
        """Test custom context values."""
        ctx = EnforcementContext(
            user_id="user@example.com",
            department="engineering",
            data_classification=("pii", "confidential"),
            metadata={"key": "value"},
        )
        assert ctx.user_id == "user@example.com"
        assert ctx.department == "engineering"
        assert "pii" in ctx.data_classification
        assert ctx.metadata["key"] == "value"


class TestPolicyEnforcer:
    """Tests for PolicyEnforcer class."""

    @pytest.fixture
    def allow_policy_set(self):
        """Create a policy set that allows all requests."""
        rule = PolicyRule(
            name="allow-all",
            description="Allow all requests",
            match_conditions={},
            action="ALLOW",
            priority=0,
        )
        return PolicySet(name="test-policies", rules=[rule])

    @pytest.fixture
    def deny_policy_set(self):
        """Create a policy set that denies Ollama requests."""
        rule = PolicyRule(
            name="deny-ollama",
            description="Deny Ollama provider",
            match_conditions={"provider": {"eq": "ollama"}},
            action="DENY",
            action_params={"reason": "Ollama not allowed"},
            priority=100,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_enforcer_creation(self, allow_policy_set):
        """Test creating a policy enforcer."""
        enforcer = PolicyEnforcer(
            policy_set=allow_policy_set,
            context=EnforcementContext(user_id="test"),
        )
        assert enforcer.policy_set == allow_policy_set
        assert enforcer.context.user_id == "test"

    def test_enforcer_allow(self, allow_policy_set):
        """Test enforcer allows requests."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model="llama3.2",
            content="Hello",
        )
        assert result.allowed is True
        assert result.response.decision == Decision.ALLOW

    def test_enforcer_deny(self, deny_policy_set):
        """Test enforcer denies requests."""
        enforcer = PolicyEnforcer(
            policy_set=deny_policy_set,
            raise_on_deny=False,
        )
        result = enforcer.enforce(
            model="llama3.2",
            content="Hello",
        )
        assert result.allowed is False
        assert result.response.decision == Decision.DENY

    def test_enforcer_deny_raises(self, deny_policy_set):
        """Test enforcer raises on deny when configured."""
        enforcer = PolicyEnforcer(
            policy_set=deny_policy_set,
            raise_on_deny=True,
        )
        with pytest.raises(PolicyDeniedError) as exc_info:
            enforcer.enforce(model="llama3.2", content="Hello")
        assert exc_info.value.decision == Decision.DENY

    def test_enforcer_stats(self, allow_policy_set):
        """Test enforcer tracks statistics."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        enforcer.enforce(model="llama3.2", content="Hello")
        enforcer.enforce(model="mistral", content="World")

        stats = enforcer.stats
        assert stats["total_requests"] == 2
        assert stats["allowed_requests"] == 2
        assert stats["denied_requests"] == 0

    def test_enforcer_callback(self, allow_policy_set):
        """Test enforcer calls callback."""
        callback_called = []

        def callback(request, response):
            callback_called.append((request, response))

        enforcer = PolicyEnforcer(
            policy_set=allow_policy_set,
            on_enforcement=callback,
        )
        enforcer.enforce(model="llama3.2", content="Hello")

        assert len(callback_called) == 1
        assert callback_called[0][0].provider == "ollama"

    def test_enforcer_request_type(self, allow_policy_set):
        """Test enforcer tracks request type."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model="llama3.2",
            content="Hello",
            request_type="chat",
        )
        assert result.request.metadata.get("request_type") == "chat"

    def test_enforcer_zero_cost(self, allow_policy_set):
        """Test enforcer sets zero cost for local models."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model="llama3.2",
            content="Hello",
        )
        assert result.request.estimated_cost == 0.0

    def test_enforcer_local_model_metadata(self, allow_policy_set):
        """Test enforcer sets local model metadata."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model="llama3.2",
            content="Hello",
        )
        assert result.request.metadata.get("ollama") is True
        assert result.request.metadata.get("local_model") is True
        assert result.request.metadata.get("model_size") == "3b"


class TestChatWrapper:
    """Tests for ChatWrapper."""

    @pytest.fixture
    def allow_policy_set(self):
        """Create a policy set that allows all requests."""
        rule = PolicyRule(
            name="allow-all",
            description="Allow all requests",
            match_conditions={},
            action="ALLOW",
            priority=0,
        )
        return PolicySet(name="test-policies", rules=[rule])

    @pytest.fixture
    def mock_client(self):
        """Create a mock Ollama client."""
        client = MagicMock()
        client.chat = MagicMock(return_value={"message": {"content": "Hi"}})
        return client

    def test_chat_wrapper(self, mock_client, allow_policy_set):
        """Test ChatWrapper."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = ChatWrapper(mock_client, enforcer)

        result = wrapper(
            model="llama3.2",
            messages=[{"role": "user", "content": "Hello"}],
        )
        assert result is not None
        mock_client.chat.assert_called_once()

    def test_chat_wrapper_with_stream(self, mock_client, allow_policy_set):
        """Test ChatWrapper with streaming."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = ChatWrapper(mock_client, enforcer)

        wrapper(
            model="llama3.2",
            messages=[{"role": "user", "content": "Hello"}],
            stream=True,
        )
        mock_client.chat.assert_called_once()


class TestGenerateWrapper:
    """Tests for GenerateWrapper."""

    @pytest.fixture
    def allow_policy_set(self):
        """Create a policy set that allows all requests."""
        rule = PolicyRule(
            name="allow-all",
            description="Allow all requests",
            match_conditions={},
            action="ALLOW",
            priority=0,
        )
        return PolicySet(name="test-policies", rules=[rule])

    @pytest.fixture
    def mock_client(self):
        """Create a mock Ollama client."""
        client = MagicMock()
        client.generate = MagicMock(return_value={"response": "Story..."})
        return client

    def test_generate_wrapper(self, mock_client, allow_policy_set):
        """Test GenerateWrapper."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = GenerateWrapper(mock_client, enforcer)

        result = wrapper(
            model="llama3.2",
            prompt="Once upon a time",
        )
        assert result is not None
        mock_client.generate.assert_called_once()


class TestEmbeddingsWrapper:
    """Tests for EmbeddingsWrapper."""

    @pytest.fixture
    def allow_policy_set(self):
        """Create a policy set that allows all requests."""
        rule = PolicyRule(
            name="allow-all",
            description="Allow all requests",
            match_conditions={},
            action="ALLOW",
            priority=0,
        )
        return PolicySet(name="test-policies", rules=[rule])

    @pytest.fixture
    def mock_client(self):
        """Create a mock Ollama client."""
        client = MagicMock()
        client.embeddings = MagicMock(return_value={"embedding": [0.1, 0.2, 0.3]})
        return client

    def test_embeddings_wrapper_string(self, mock_client, allow_policy_set):
        """Test EmbeddingsWrapper with string input."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = EmbeddingsWrapper(mock_client, enforcer)

        result = wrapper(
            model="nomic-embed-text",
            prompt="Hello world",
        )
        assert result is not None
        mock_client.embeddings.assert_called_once()

    def test_embeddings_wrapper_list(self, mock_client, allow_policy_set):
        """Test EmbeddingsWrapper with list input."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = EmbeddingsWrapper(mock_client, enforcer)

        result = wrapper(
            model="nomic-embed-text",
            prompt=["Hello", "World"],
        )
        assert result is not None


class TestEmbedWrapper:
    """Tests for EmbedWrapper (newer API)."""

    @pytest.fixture
    def allow_policy_set(self):
        """Create a policy set that allows all requests."""
        rule = PolicyRule(
            name="allow-all",
            description="Allow all requests",
            match_conditions={},
            action="ALLOW",
            priority=0,
        )
        return PolicySet(name="test-policies", rules=[rule])

    @pytest.fixture
    def mock_client(self):
        """Create a mock Ollama client."""
        client = MagicMock()
        client.embed = MagicMock(return_value={"embeddings": [[0.1, 0.2, 0.3]]})
        return client

    def test_embed_wrapper(self, mock_client, allow_policy_set):
        """Test EmbedWrapper."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = EmbedWrapper(mock_client, enforcer)

        result = wrapper(
            model="nomic-embed-text",
            input="Hello world",
        )
        assert result is not None
        mock_client.embed.assert_called_once()


class TestPullWrapper:
    """Tests for PullWrapper."""

    @pytest.fixture
    def allow_policy_set(self):
        """Create a policy set that allows all requests."""
        rule = PolicyRule(
            name="allow-all",
            description="Allow all requests",
            match_conditions={},
            action="ALLOW",
            priority=0,
        )
        return PolicySet(name="test-policies", rules=[rule])

    @pytest.fixture
    def mock_client(self):
        """Create a mock Ollama client."""
        client = MagicMock()
        client.pull = MagicMock(return_value={"status": "success"})
        return client

    def test_pull_wrapper(self, mock_client, allow_policy_set):
        """Test PullWrapper."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = PullWrapper(mock_client, enforcer)

        result = wrapper(model="llama3.2")
        assert result is not None
        mock_client.pull.assert_called_once()


class TestPolicyBindOllama:
    """Tests for PolicyBindOllama wrapper."""

    @pytest.fixture
    def allow_policy_set(self):
        """Create a policy set that allows all requests."""
        rule = PolicyRule(
            name="allow-all",
            description="Allow all requests",
            match_conditions={},
            action="ALLOW",
            priority=0,
        )
        return PolicySet(name="test-policies", rules=[rule])

    @pytest.fixture
    def mock_client(self):
        """Create a mock Ollama client."""
        client = MagicMock()
        client.chat = MagicMock(return_value={"message": {"content": "Hi"}})
        client.generate = MagicMock(return_value={"response": "Story"})
        client.embeddings = MagicMock(return_value={"embedding": [0.1]})
        client.embed = MagicMock(return_value={"embeddings": [[0.1]]})
        client.pull = MagicMock(return_value={"status": "success"})
        return client

    def test_wrapper_creation(self, mock_client, allow_policy_set):
        """Test creating a wrapper."""
        wrapped = PolicyBindOllama(
            client=mock_client,
            policy_set=allow_policy_set,
            user_id="test@example.com",
        )
        assert wrapped._enforcer is not None

    def test_wrapper_has_chat(self, mock_client, allow_policy_set):
        """Test wrapper has chat method."""
        wrapped = PolicyBindOllama(
            client=mock_client,
            policy_set=allow_policy_set,
        )
        assert hasattr(wrapped, "chat")
        assert isinstance(wrapped.chat, ChatWrapper)

    def test_wrapper_has_generate(self, mock_client, allow_policy_set):
        """Test wrapper has generate method."""
        wrapped = PolicyBindOllama(
            client=mock_client,
            policy_set=allow_policy_set,
        )
        assert hasattr(wrapped, "generate")
        assert isinstance(wrapped.generate, GenerateWrapper)

    def test_wrapper_has_embeddings(self, mock_client, allow_policy_set):
        """Test wrapper has embeddings method."""
        wrapped = PolicyBindOllama(
            client=mock_client,
            policy_set=allow_policy_set,
        )
        assert hasattr(wrapped, "embeddings")
        assert isinstance(wrapped.embeddings, EmbeddingsWrapper)

    def test_wrapper_has_pull(self, mock_client, allow_policy_set):
        """Test wrapper has pull method."""
        wrapped = PolicyBindOllama(
            client=mock_client,
            policy_set=allow_policy_set,
        )
        assert hasattr(wrapped, "pull")
        assert isinstance(wrapped.pull, PullWrapper)

    def test_wrapper_stats(self, mock_client, allow_policy_set):
        """Test wrapper stats tracking."""
        wrapped = PolicyBindOllama(
            client=mock_client,
            policy_set=allow_policy_set,
        )
        wrapped.chat(
            model="llama3.2",
            messages=[{"role": "user", "content": "Hello"}],
        )

        stats = wrapped.stats
        assert stats["total_requests"] == 1

    def test_wrapper_attribute_forwarding(self, mock_client, allow_policy_set):
        """Test wrapper forwards attributes to client."""
        mock_client.custom_attr = "custom_value"
        wrapped = PolicyBindOllama(
            client=mock_client,
            policy_set=allow_policy_set,
        )
        assert wrapped.custom_attr == "custom_value"


class TestApprovalRequired:
    """Tests for approval required handling."""

    @pytest.fixture
    def approval_policy_set(self):
        """Create a policy set that requires approval."""
        rule = PolicyRule(
            name="require-approval",
            description="Require approval for all",
            match_conditions={},
            action="REQUIRE_APPROVAL",
            action_params={"reason": "All requests need approval"},
            priority=100,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_approval_required_raises(self, approval_policy_set):
        """Test approval required raises when configured."""
        enforcer = PolicyEnforcer(
            policy_set=approval_policy_set,
            raise_on_approval_required=True,
        )
        with pytest.raises(PolicyApprovalRequiredError):
            enforcer.enforce(model="llama3.2", content="Hello")

    def test_approval_required_no_raise(self, approval_policy_set):
        """Test approval required doesn't raise when not configured."""
        enforcer = PolicyEnforcer(
            policy_set=approval_policy_set,
            raise_on_approval_required=False,
        )
        result = enforcer.enforce(model="llama3.2", content="Hello")
        assert result.response.decision == Decision.REQUIRE_APPROVAL


class TestModifyDecision:
    """Tests for MODIFY decision handling."""

    @pytest.fixture
    def modify_policy_set(self):
        """Create a policy set that modifies requests."""
        rule = PolicyRule(
            name="modify-request",
            description="Modify all requests",
            match_conditions={},
            action="MODIFY",
            action_params={"redact_patterns": ["secret"]},
            priority=100,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_modify_allowed(self, modify_policy_set):
        """Test modify decision is allowed."""
        enforcer = PolicyEnforcer(policy_set=modify_policy_set)
        result = enforcer.enforce(model="llama3.2", content="Hello")
        assert result.allowed is True
        assert result.modified is True

    def test_modify_tracks_stats(self, modify_policy_set):
        """Test modify decision is tracked in stats."""
        enforcer = PolicyEnforcer(policy_set=modify_policy_set)
        enforcer.enforce(model="llama3.2", content="Hello")

        stats = enforcer.stats
        assert stats["modified_requests"] == 1


class TestCreatePolicyClient:
    """Tests for create_policy_client factory function."""

    @pytest.fixture
    def allow_policy_set(self):
        """Create a policy set that allows all requests."""
        rule = PolicyRule(
            name="allow-all",
            description="Allow all requests",
            match_conditions={},
            action="ALLOW",
            priority=0,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_create_policy_client_without_sdk(self, allow_policy_set):
        """Test create_policy_client raises ImportError without SDK."""
        with pytest.raises(ImportError) as exc_info:
            create_policy_client(
                policy_set=allow_policy_set,
                user_id="test@example.com",
            )
        assert "ollama" in str(exc_info.value).lower()


class TestWrapClient:
    """Tests for wrap_client function."""

    @pytest.fixture
    def allow_policy_set(self):
        """Create a policy set that allows all requests."""
        rule = PolicyRule(
            name="allow-all",
            description="Allow all requests",
            match_conditions={},
            action="ALLOW",
            priority=0,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_wrap_client(self, allow_policy_set):
        """Test wrapping an existing client."""
        mock_client = MagicMock()

        wrapped = wrap_client(
            client=mock_client,
            policy_set=allow_policy_set,
            user_id="test@example.com",
        )

        assert isinstance(wrapped, PolicyBindOllama)


class TestDepartmentPolicies:
    """Tests for department-based policies."""

    @pytest.fixture
    def department_policy_set(self):
        """Create a policy set with department restrictions."""
        deny_rule = PolicyRule(
            name="deny-finance",
            description="Deny finance department",
            match_conditions={"department": {"eq": "finance"}},
            action="DENY",
            action_params={"reason": "Finance department not allowed"},
            priority=100,
        )
        allow_rule = PolicyRule(
            name="allow-all",
            description="Allow all other requests",
            match_conditions={},
            action="ALLOW",
            priority=0,
        )
        return PolicySet(name="test-policies", rules=[deny_rule, allow_rule])

    def test_department_allowed(self, department_policy_set):
        """Test department allowed."""
        ctx = EnforcementContext(department="engineering")
        enforcer = PolicyEnforcer(
            policy_set=department_policy_set,
            context=ctx,
            raise_on_deny=False,
        )
        result = enforcer.enforce(model="llama3.2", content="Hello")
        assert result.allowed is True

    def test_department_denied(self, department_policy_set):
        """Test department denied."""
        ctx = EnforcementContext(department="finance")
        enforcer = PolicyEnforcer(
            policy_set=department_policy_set,
            context=ctx,
            raise_on_deny=False,
        )
        result = enforcer.enforce(model="llama3.2", content="Hello")
        assert result.allowed is False


class TestModelPolicies:
    """Tests for model-specific policies."""

    @pytest.fixture
    def model_policy_set(self):
        """Create a policy set with model restrictions."""
        deny_rule = PolicyRule(
            name="deny-large-models",
            description="Deny 70B+ models",
            match_conditions={"model": {"contains": "70b"}},
            action="DENY",
            action_params={"reason": "Large models restricted"},
            priority=100,
        )
        allow_rule = PolicyRule(
            name="allow-all",
            description="Allow all other requests",
            match_conditions={},
            action="ALLOW",
            priority=0,
        )
        return PolicySet(name="test-policies", rules=[deny_rule, allow_rule])

    def test_model_allowed(self, model_policy_set):
        """Test model allowed."""
        enforcer = PolicyEnforcer(
            policy_set=model_policy_set,
            raise_on_deny=False,
        )
        result = enforcer.enforce(model="llama3.2", content="Hello")
        assert result.allowed is True

    def test_model_denied(self, model_policy_set):
        """Test model denied."""
        enforcer = PolicyEnforcer(
            policy_set=model_policy_set,
            raise_on_deny=False,
        )
        result = enforcer.enforce(model="llama3.1:70b", content="Hello")
        assert result.allowed is False


class TestProviderPolicies:
    """Tests for provider-specific policies."""

    @pytest.fixture
    def provider_policy_set(self):
        """Create a policy set that only allows Ollama."""
        allow_rule = PolicyRule(
            name="allow-ollama",
            description="Allow Ollama provider",
            match_conditions={"provider": {"eq": "ollama"}},
            action="ALLOW",
            priority=100,
        )
        deny_rule = PolicyRule(
            name="deny-all",
            description="Deny all other providers",
            match_conditions={},
            action="DENY",
            priority=0,
        )
        return PolicySet(name="test-policies", rules=[allow_rule, deny_rule])

    def test_ollama_provider_allowed(self, provider_policy_set):
        """Test Ollama provider is allowed."""
        enforcer = PolicyEnforcer(
            policy_set=provider_policy_set,
            raise_on_deny=False,
        )
        result = enforcer.enforce(model="llama3.2", content="Hello")
        assert result.allowed is True
        assert result.request.provider == "ollama"


class TestOllamaMetadata:
    """Tests for Ollama-specific metadata."""

    @pytest.fixture
    def allow_policy_set(self):
        """Create a policy set that allows all requests."""
        rule = PolicyRule(
            name="allow-all",
            description="Allow all requests",
            match_conditions={},
            action="ALLOW",
            priority=0,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_ollama_metadata(self, allow_policy_set):
        """Test Ollama metadata is set."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model="llama3.2",
            content="Hello",
            request_type="chat",
        )
        assert result.request.metadata.get("ollama") is True
        assert result.request.metadata.get("local_model") is True
        assert result.request.metadata.get("request_type") == "chat"

    def test_model_size_metadata(self, allow_policy_set):
        """Test model size is tracked in metadata."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model="llama3.1:70b",
            content="Hello",
        )
        assert result.request.metadata.get("model_size") == "70b"

    def test_context_length_metadata(self, allow_policy_set):
        """Test context length is tracked in metadata."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model="llama3.2",
            content="Hello",
        )
        assert result.request.metadata.get("context_length") == 131072

    def test_embedding_model_metadata(self, allow_policy_set):
        """Test embedding model metadata."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model="nomic-embed-text",
            content="Hello",
            request_type="embeddings",
        )
        assert result.request.metadata.get("is_embedding") is True

    def test_vision_model_metadata(self, allow_policy_set):
        """Test vision model metadata."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model="llava",
            content="Hello",
        )
        assert result.request.metadata.get("is_vision") is True


class TestPolicyDeniedWhenNotAllowed:
    """Tests for denied request behavior."""

    @pytest.fixture
    def deny_policy_set(self):
        """Create a policy set that denies all requests."""
        rule = PolicyRule(
            name="deny-all",
            description="Deny all requests",
            match_conditions={},
            action="DENY",
            action_params={"reason": "All requests denied"},
            priority=100,
        )
        return PolicySet(name="test-policies", rules=[rule])

    @pytest.fixture
    def mock_client(self):
        """Create a mock Ollama client."""
        client = MagicMock()
        client.chat = MagicMock(return_value={"message": {"content": "Hi"}})
        client.generate = MagicMock(return_value={"response": "Story"})
        client.embeddings = MagicMock(return_value={"embedding": [0.1]})
        client.embed = MagicMock(return_value={"embeddings": [[0.1]]})
        return client

    def test_chat_denied_returns_none(self, mock_client, deny_policy_set):
        """Test chat returns None when denied."""
        wrapped = PolicyBindOllama(
            client=mock_client,
            policy_set=deny_policy_set,
            raise_on_deny=False,
        )
        result = wrapped.chat(
            model="llama3.2",
            messages=[{"role": "user", "content": "Hello"}],
        )
        assert result is None
        mock_client.chat.assert_not_called()

    def test_generate_denied_returns_none(self, mock_client, deny_policy_set):
        """Test generate returns None when denied."""
        wrapped = PolicyBindOllama(
            client=mock_client,
            policy_set=deny_policy_set,
            raise_on_deny=False,
        )
        result = wrapped.generate(
            model="llama3.2",
            prompt="Hello",
        )
        assert result is None
        mock_client.generate.assert_not_called()


class TestEnforcementResult:
    """Tests for EnforcementResult dataclass."""

    @pytest.fixture
    def allow_policy_set(self):
        """Create a policy set that allows all requests."""
        rule = PolicyRule(
            name="allow-all",
            description="Allow all requests",
            match_conditions={},
            action="ALLOW",
            priority=0,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_enforcement_result_fields(self, allow_policy_set):
        """Test EnforcementResult has all fields."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(model="llama3.2", content="Hello")

        assert hasattr(result, "allowed")
        assert hasattr(result, "request")
        assert hasattr(result, "response")
        assert hasattr(result, "enforcement_time_ms")
        assert hasattr(result, "modified")
        assert hasattr(result, "modifications")

    def test_enforcement_time_tracked(self, allow_policy_set):
        """Test enforcement time is tracked."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(model="llama3.2", content="Hello")

        assert result.enforcement_time_ms >= 0


class TestContextOverride:
    """Tests for context override functionality."""

    @pytest.fixture
    def department_policy_set(self):
        """Create a policy set with department restrictions."""
        deny_rule = PolicyRule(
            name="deny-sales",
            description="Deny sales department",
            match_conditions={"department": {"eq": "sales"}},
            action="DENY",
            action_params={"reason": "Sales department not allowed"},
            priority=100,
        )
        allow_rule = PolicyRule(
            name="allow-all",
            description="Allow all other requests",
            match_conditions={},
            action="ALLOW",
            priority=0,
        )
        return PolicySet(name="test-policies", rules=[deny_rule, allow_rule])

    def test_context_override(self, department_policy_set):
        """Test context can be overridden per request."""
        default_ctx = EnforcementContext(department="engineering")
        enforcer = PolicyEnforcer(
            policy_set=department_policy_set,
            context=default_ctx,
            raise_on_deny=False,
        )

        # Default context allows
        result1 = enforcer.enforce(model="llama3.2", content="Hello")
        assert result1.allowed is True

        # Override context denies
        override_ctx = EnforcementContext(department="sales")
        result2 = enforcer.enforce(
            model="llama3.2",
            content="Hello",
            context_override=override_ctx,
        )
        assert result2.allowed is False


class TestMultipleModelFamilies:
    """Tests for different model families."""

    @pytest.fixture
    def allow_policy_set(self):
        """Create a policy set that allows all requests."""
        rule = PolicyRule(
            name="allow-all",
            description="Allow all requests",
            match_conditions={},
            action="ALLOW",
            priority=0,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_llama_model(self, allow_policy_set):
        """Test Llama model."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(model="llama3.2", content="Hello")
        assert result.request.metadata.get("model_size") == "3b"

    def test_mistral_model(self, allow_policy_set):
        """Test Mistral model."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(model="mistral", content="Hello")
        assert result.request.metadata.get("model_size") == "7b"

    def test_phi_model(self, allow_policy_set):
        """Test Phi model."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(model="phi3", content="Hello")
        assert result.request.metadata.get("model_size") == "3.8b"

    def test_gemma_model(self, allow_policy_set):
        """Test Gemma model."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(model="gemma2", content="Hello")
        assert result.request.metadata.get("model_size") == "9b"

    def test_qwen_model(self, allow_policy_set):
        """Test Qwen model."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(model="qwen2", content="Hello")
        assert result.request.metadata.get("model_size") == "7b"

    def test_codellama_model(self, allow_policy_set):
        """Test CodeLlama model."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(model="codellama", content="Hello")
        assert result.request.metadata.get("model_size") == "7b"
