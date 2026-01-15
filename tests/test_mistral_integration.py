"""
Tests for the Mistral AI SDK integration.

Tests the policy enforcement wrapper for the Mistral AI Python SDK.
"""

import pytest
from unittest.mock import MagicMock, patch

from policybind.integrations.mistral_integration import (
    ChatCompleteWrapper,
    ChatResourceWrapper,
    ChatStreamWrapper,
    ClassifiersModerateWrapper,
    ClassifiersResourceWrapper,
    EmbeddingsCreateWrapper,
    EmbeddingsResourceWrapper,
    EnforcementContext,
    EnforcementResult,
    FIMCompleteWrapper,
    FIMResourceWrapper,
    PolicyApprovalRequiredError,
    PolicyBindMistral,
    PolicyDeniedError,
    PolicyEnforcer,
    create_policy_client,
    estimate_cost,
    estimate_message_tokens,
    estimate_tokens,
    extract_content_for_hash,
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

    def test_estimate_message_tokens_multimodal(self):
        """Test message token estimation with multimodal content."""
        messages = [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "What is this?"},
                    {"type": "image_url", "image_url": {"url": "http://example.com/img.png"}},
                ],
            }
        ]
        result = estimate_message_tokens(messages)
        # 4 (overhead) + text tokens + 85 (base image tokens)
        assert result >= 89


class TestCostEstimation:
    """Tests for cost estimation functions."""

    def test_estimate_cost_mistral_large(self):
        """Test cost estimation for Mistral Large."""
        # 1M tokens input at $2.00/1M + 1M tokens output at $6.00/1M
        cost = estimate_cost("mistral-large-latest", 1_000_000, 1_000_000)
        assert abs(cost - 8.0) < 0.01

    def test_estimate_cost_mistral_small(self):
        """Test cost estimation for Mistral Small."""
        # 1M tokens input at $0.20/1M + 1M tokens output at $0.60/1M
        cost = estimate_cost("mistral-small-latest", 1_000_000, 1_000_000)
        assert abs(cost - 0.80) < 0.01

    def test_estimate_cost_codestral(self):
        """Test cost estimation for Codestral."""
        # 1M tokens input at $0.20/1M + 1M tokens output at $0.60/1M
        cost = estimate_cost("codestral-latest", 1_000_000, 1_000_000)
        assert abs(cost - 0.80) < 0.01

    def test_estimate_cost_ministral_8b(self):
        """Test cost estimation for Ministral 8B."""
        # 1M tokens at $0.10/1M both input and output
        cost = estimate_cost("ministral-8b-latest", 1_000_000, 1_000_000)
        assert abs(cost - 0.20) < 0.01

    def test_estimate_cost_ministral_3b(self):
        """Test cost estimation for Ministral 3B."""
        # 1M tokens at $0.04/1M both input and output
        cost = estimate_cost("ministral-3b-latest", 1_000_000, 1_000_000)
        assert abs(cost - 0.08) < 0.01

    def test_estimate_cost_pixtral_large(self):
        """Test cost estimation for Pixtral Large."""
        # 1M tokens input at $2.00/1M + 1M tokens output at $6.00/1M
        cost = estimate_cost("pixtral-large-latest", 1_000_000, 1_000_000)
        assert abs(cost - 8.0) < 0.01

    def test_estimate_cost_embed(self):
        """Test cost estimation for embed models."""
        # Embed models have input only pricing at $0.10/1M
        cost = estimate_cost("mistral-embed", 1_000_000, 0)
        assert abs(cost - 0.10) < 0.01

    def test_estimate_cost_open_mistral_nemo(self):
        """Test cost estimation for Open Mistral NeMo."""
        cost = estimate_cost("open-mistral-nemo", 1_000_000, 1_000_000)
        assert abs(cost - 0.30) < 0.01

    def test_estimate_cost_unknown_model(self):
        """Test cost estimation with unknown model falls back."""
        # Should fall back to mistral-small pricing
        cost = estimate_cost("unknown-model", 1_000_000, 0)
        assert cost > 0

    def test_estimate_cost_input_only(self):
        """Test cost estimation with input only."""
        cost = estimate_cost("mistral-large-latest", 1000, 0)
        # 1K tokens at $2.00/1M
        assert abs(cost - 0.002) < 0.0001

    def test_estimate_cost_case_insensitive(self):
        """Test cost estimation is case insensitive."""
        cost1 = estimate_cost("mistral-large-latest", 1000, 0)
        cost2 = estimate_cost("Mistral-Large-Latest", 1000, 0)
        assert cost1 == cost2


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

    def test_extract_content_for_hash_multimodal(self):
        """Test extracting multimodal content for hashing."""
        messages = [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Describe this"},
                    {"type": "image_url", "image_url": {"url": "http://example.com"}},
                ],
            }
        ]
        result = extract_content_for_hash(messages=messages)
        assert "Describe this" in result

    def test_extract_content_for_hash_inputs(self):
        """Test extracting inputs content for hashing."""
        result = extract_content_for_hash(inputs=["Hello", "World"])
        assert "Hello" in result
        assert "World" in result

    def test_extract_content_for_hash_input_string(self):
        """Test extracting input string for hashing."""
        result = extract_content_for_hash(input="Hello world")
        assert "Hello world" in result

    def test_extract_content_for_hash_input_list(self):
        """Test extracting input list for hashing."""
        result = extract_content_for_hash(input=["Hello", "World"])
        assert "Hello" in result
        assert "World" in result


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
        """Create a policy set that denies Mistral requests."""
        rule = PolicyRule(
            name="deny-mistral",
            description="Deny Mistral provider",
            match_conditions={"provider": {"eq": "mistral"}},
            action="DENY",
            action_params={"reason": "Mistral not allowed"},
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
            model="mistral-large-latest",
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
            model="mistral-large-latest",
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
            enforcer.enforce(model="mistral-large-latest", content="Hello")
        assert exc_info.value.decision == Decision.DENY

    def test_enforcer_stats(self, allow_policy_set):
        """Test enforcer tracks statistics."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        enforcer.enforce(model="mistral-large-latest", content="Hello")
        enforcer.enforce(model="mistral-small-latest", content="World")

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
        enforcer.enforce(model="mistral-large-latest", content="Hello")

        assert len(callback_called) == 1
        assert callback_called[0][0].provider == "mistral"

    def test_enforcer_request_type(self, allow_policy_set):
        """Test enforcer tracks request type."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model="mistral-large-latest",
            content="Hello",
            request_type="chat",
        )
        assert result.request.metadata.get("request_type") == "chat"


class TestChatResourceWrapper:
    """Tests for ChatResourceWrapper and related classes."""

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
    def mock_chat_resource(self):
        """Create a mock chat resource."""
        resource = MagicMock()
        resource.complete = MagicMock(return_value={"choices": [{"message": {"content": "Hi"}}]})
        resource.stream = MagicMock(return_value=iter([{"choices": [{"delta": {"content": "Hi"}}]}]))
        return resource

    def test_chat_complete_wrapper(self, mock_chat_resource, allow_policy_set):
        """Test ChatCompleteWrapper."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = ChatCompleteWrapper(mock_chat_resource, enforcer)

        result = wrapper(
            model="mistral-large-latest",
            messages=[{"role": "user", "content": "Hello"}],
        )
        assert result is not None
        mock_chat_resource.complete.assert_called_once()

    def test_chat_stream_wrapper(self, mock_chat_resource, allow_policy_set):
        """Test ChatStreamWrapper."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = ChatStreamWrapper(mock_chat_resource, enforcer)

        result = wrapper(
            model="mistral-large-latest",
            messages=[{"role": "user", "content": "Hello"}],
        )
        assert result is not None
        mock_chat_resource.stream.assert_called_once()

    def test_chat_resource_wrapper(self, mock_chat_resource, allow_policy_set):
        """Test ChatResourceWrapper."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = ChatResourceWrapper(mock_chat_resource, enforcer)

        # Test complete
        result = wrapper.complete(
            model="mistral-large-latest",
            messages=[{"role": "user", "content": "Hello"}],
        )
        assert result is not None

        # Test stream
        result = wrapper.stream(
            model="mistral-large-latest",
            messages=[{"role": "user", "content": "Hello"}],
        )
        assert result is not None


class TestEmbeddingsResourceWrapper:
    """Tests for EmbeddingsResourceWrapper and related classes."""

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
    def mock_embeddings_resource(self):
        """Create a mock embeddings resource."""
        resource = MagicMock()
        resource.create = MagicMock(return_value={"data": [{"embedding": [0.1, 0.2, 0.3]}]})
        return resource

    def test_embeddings_create_wrapper(self, mock_embeddings_resource, allow_policy_set):
        """Test EmbeddingsCreateWrapper."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = EmbeddingsCreateWrapper(mock_embeddings_resource, enforcer)

        result = wrapper(
            model="mistral-embed",
            inputs=["Hello world"],
        )
        assert result is not None
        mock_embeddings_resource.create.assert_called_once()

    def test_embeddings_resource_wrapper(self, mock_embeddings_resource, allow_policy_set):
        """Test EmbeddingsResourceWrapper."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = EmbeddingsResourceWrapper(mock_embeddings_resource, enforcer)

        result = wrapper.create(
            model="mistral-embed",
            inputs=["Hello world"],
        )
        assert result is not None


class TestFIMResourceWrapper:
    """Tests for FIMResourceWrapper and related classes."""

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
    def mock_fim_resource(self):
        """Create a mock FIM resource."""
        resource = MagicMock()
        resource.complete = MagicMock(return_value={"choices": [{"message": {"content": "completion"}}]})
        return resource

    def test_fim_complete_wrapper(self, mock_fim_resource, allow_policy_set):
        """Test FIMCompleteWrapper."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = FIMCompleteWrapper(mock_fim_resource, enforcer)

        result = wrapper(
            model="codestral-latest",
            prompt="def hello():\n    ",
            suffix="\n\nprint(hello())",
        )
        assert result is not None
        mock_fim_resource.complete.assert_called_once()

    def test_fim_resource_wrapper(self, mock_fim_resource, allow_policy_set):
        """Test FIMResourceWrapper."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = FIMResourceWrapper(mock_fim_resource, enforcer)

        result = wrapper.complete(
            model="codestral-latest",
            prompt="def hello():\n    ",
        )
        assert result is not None


class TestClassifiersResourceWrapper:
    """Tests for ClassifiersResourceWrapper and related classes."""

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
    def mock_classifiers_resource(self):
        """Create a mock classifiers resource."""
        resource = MagicMock()
        resource.moderate = MagicMock(return_value={"results": [{"categories": {}}]})
        return resource

    def test_classifiers_moderate_wrapper(self, mock_classifiers_resource, allow_policy_set):
        """Test ClassifiersModerateWrapper."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = ClassifiersModerateWrapper(mock_classifiers_resource, enforcer)

        result = wrapper(
            model="mistral-moderation-latest",
            inputs=["Hello world"],
        )
        assert result is not None
        mock_classifiers_resource.moderate.assert_called_once()

    def test_classifiers_resource_wrapper(self, mock_classifiers_resource, allow_policy_set):
        """Test ClassifiersResourceWrapper."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = ClassifiersResourceWrapper(mock_classifiers_resource, enforcer)

        result = wrapper.moderate(
            model="mistral-moderation-latest",
            inputs=["Hello world"],
        )
        assert result is not None


class TestPolicyBindMistral:
    """Tests for PolicyBindMistral wrapper."""

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
        """Create a mock Mistral client."""
        client = MagicMock()
        client.chat = MagicMock()
        client.chat.complete = MagicMock(return_value={"choices": [{"message": {"content": "Hi"}}]})
        client.chat.stream = MagicMock(return_value=iter([]))
        client.embeddings = MagicMock()
        client.embeddings.create = MagicMock(return_value={"data": []})
        client.fim = MagicMock()
        client.fim.complete = MagicMock(return_value={"choices": []})
        client.classifiers = MagicMock()
        client.classifiers.moderate = MagicMock(return_value={"results": []})
        return client

    def test_wrapper_creation(self, mock_client, allow_policy_set):
        """Test creating a wrapper."""
        wrapped = PolicyBindMistral(
            client=mock_client,
            policy_set=allow_policy_set,
            user_id="test@example.com",
        )
        assert wrapped._enforcer is not None

    def test_wrapper_has_chat(self, mock_client, allow_policy_set):
        """Test wrapper has chat resource."""
        wrapped = PolicyBindMistral(
            client=mock_client,
            policy_set=allow_policy_set,
        )
        assert hasattr(wrapped, "chat")
        assert isinstance(wrapped.chat, ChatResourceWrapper)

    def test_wrapper_has_embeddings(self, mock_client, allow_policy_set):
        """Test wrapper has embeddings resource."""
        wrapped = PolicyBindMistral(
            client=mock_client,
            policy_set=allow_policy_set,
        )
        assert hasattr(wrapped, "embeddings")
        assert isinstance(wrapped.embeddings, EmbeddingsResourceWrapper)

    def test_wrapper_has_fim(self, mock_client, allow_policy_set):
        """Test wrapper has FIM resource."""
        wrapped = PolicyBindMistral(
            client=mock_client,
            policy_set=allow_policy_set,
        )
        assert hasattr(wrapped, "fim")
        assert isinstance(wrapped.fim, FIMResourceWrapper)

    def test_wrapper_has_classifiers(self, mock_client, allow_policy_set):
        """Test wrapper has classifiers resource."""
        wrapped = PolicyBindMistral(
            client=mock_client,
            policy_set=allow_policy_set,
        )
        assert hasattr(wrapped, "classifiers")
        assert isinstance(wrapped.classifiers, ClassifiersResourceWrapper)

    def test_wrapper_stats(self, mock_client, allow_policy_set):
        """Test wrapper stats tracking."""
        wrapped = PolicyBindMistral(
            client=mock_client,
            policy_set=allow_policy_set,
        )
        wrapped.chat.complete(
            model="mistral-large-latest",
            messages=[{"role": "user", "content": "Hello"}],
        )

        stats = wrapped.stats
        assert stats["total_requests"] == 1

    def test_wrapper_attribute_forwarding(self, mock_client, allow_policy_set):
        """Test wrapper forwards attributes to client."""
        mock_client.custom_attr = "custom_value"
        wrapped = PolicyBindMistral(
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
            enforcer.enforce(model="mistral-large-latest", content="Hello")

    def test_approval_required_no_raise(self, approval_policy_set):
        """Test approval required doesn't raise when not configured."""
        enforcer = PolicyEnforcer(
            policy_set=approval_policy_set,
            raise_on_approval_required=False,
        )
        result = enforcer.enforce(model="mistral-large-latest", content="Hello")
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
        result = enforcer.enforce(model="mistral-large-latest", content="Hello")
        assert result.allowed is True
        assert result.modified is True

    def test_modify_tracks_stats(self, modify_policy_set):
        """Test modify decision is tracked in stats."""
        enforcer = PolicyEnforcer(policy_set=modify_policy_set)
        enforcer.enforce(model="mistral-large-latest", content="Hello")

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
        assert "mistralai" in str(exc_info.value).lower() or "mistral" in str(exc_info.value).lower()


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
        mock_client.chat = MagicMock()
        mock_client.embeddings = MagicMock()

        wrapped = wrap_client(
            client=mock_client,
            policy_set=allow_policy_set,
            user_id="test@example.com",
        )

        assert isinstance(wrapped, PolicyBindMistral)


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
        result = enforcer.enforce(model="mistral-large-latest", content="Hello")
        assert result.allowed is True

    def test_department_denied(self, department_policy_set):
        """Test department denied."""
        ctx = EnforcementContext(department="finance")
        enforcer = PolicyEnforcer(
            policy_set=department_policy_set,
            context=ctx,
            raise_on_deny=False,
        )
        result = enforcer.enforce(model="mistral-large-latest", content="Hello")
        assert result.allowed is False


class TestDataClassificationPolicies:
    """Tests for data classification policies."""

    @pytest.fixture
    def classification_policy_set(self):
        """Create a policy set with data classification restrictions."""
        deny_rule = PolicyRule(
            name="deny-pii",
            description="Deny PII data",
            match_conditions={"data_classification": {"contains": "pii"}},
            action="DENY",
            action_params={"reason": "PII data not allowed"},
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

    def test_classification_allowed(self, classification_policy_set):
        """Test classification allowed."""
        ctx = EnforcementContext(data_classification=("public",))
        enforcer = PolicyEnforcer(
            policy_set=classification_policy_set,
            context=ctx,
            raise_on_deny=False,
        )
        result = enforcer.enforce(model="mistral-large-latest", content="Hello")
        assert result.allowed is True

    def test_classification_denied(self, classification_policy_set):
        """Test classification denied."""
        ctx = EnforcementContext(data_classification=("pii", "confidential"))
        enforcer = PolicyEnforcer(
            policy_set=classification_policy_set,
            context=ctx,
            raise_on_deny=False,
        )
        result = enforcer.enforce(model="mistral-large-latest", content="Hello")
        assert result.allowed is False


class TestModelPolicies:
    """Tests for model-specific policies."""

    @pytest.fixture
    def model_policy_set(self):
        """Create a policy set with model restrictions."""
        deny_rule = PolicyRule(
            name="deny-large-models",
            description="Deny large models",
            match_conditions={"model": {"contains": "large"}},
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
        result = enforcer.enforce(model="mistral-small-latest", content="Hello")
        assert result.allowed is True

    def test_model_denied(self, model_policy_set):
        """Test model denied."""
        enforcer = PolicyEnforcer(
            policy_set=model_policy_set,
            raise_on_deny=False,
        )
        result = enforcer.enforce(model="mistral-large-latest", content="Hello")
        assert result.allowed is False


class TestProviderPolicies:
    """Tests for provider-specific policies."""

    @pytest.fixture
    def provider_policy_set(self):
        """Create a policy set that only allows Mistral."""
        allow_rule = PolicyRule(
            name="allow-mistral",
            description="Allow Mistral provider",
            match_conditions={"provider": {"eq": "mistral"}},
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

    def test_mistral_provider_allowed(self, provider_policy_set):
        """Test Mistral provider is allowed."""
        enforcer = PolicyEnforcer(
            policy_set=provider_policy_set,
            raise_on_deny=False,
        )
        result = enforcer.enforce(model="mistral-large-latest", content="Hello")
        assert result.allowed is True
        assert result.request.provider == "mistral"


class TestCostBasedPolicies:
    """Tests for cost-based policies."""

    @pytest.fixture
    def cost_policy_set(self):
        """Create a policy set with cost restrictions."""
        deny_rule = PolicyRule(
            name="deny-expensive",
            description="Deny expensive requests",
            match_conditions={"estimated_cost": {"gt": 0.01}},
            action="DENY",
            action_params={"reason": "Request too expensive"},
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

    def test_cheap_request_allowed(self, cost_policy_set):
        """Test cheap request is allowed."""
        enforcer = PolicyEnforcer(
            policy_set=cost_policy_set,
            raise_on_deny=False,
        )
        # Very short content = low cost
        result = enforcer.enforce(model="ministral-3b-latest", content="Hi")
        assert result.allowed is True

    def test_expensive_request_denied(self, cost_policy_set):
        """Test expensive request is denied."""
        enforcer = PolicyEnforcer(
            policy_set=cost_policy_set,
            raise_on_deny=False,
        )
        # Very long content = high cost
        long_content = "word " * 10000
        result = enforcer.enforce(model="mistral-large-latest", content=long_content)
        assert result.allowed is False


class TestMistralMetadata:
    """Tests for Mistral-specific metadata."""

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

    def test_mistral_metadata(self, allow_policy_set):
        """Test Mistral metadata is set."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model="mistral-large-latest",
            content="Hello",
            request_type="chat",
        )
        assert result.request.metadata.get("mistral") is True
        assert result.request.metadata.get("request_type") == "chat"

    def test_request_type_fim(self, allow_policy_set):
        """Test FIM request type in metadata."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model="codestral-latest",
            content="def hello():\n    ",
            request_type="fim",
            max_tokens=100,
        )
        assert result.request.metadata.get("request_type") == "fim"
        assert result.request.metadata.get("max_tokens") == 100

    def test_request_type_embed(self, allow_policy_set):
        """Test embed request type in metadata."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model="mistral-embed",
            content="Hello world",
            request_type="embed",
        )
        assert result.request.metadata.get("request_type") == "embed"

    def test_request_type_moderation(self, allow_policy_set):
        """Test moderation request type in metadata."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model="mistral-moderation-latest",
            content="Hello world",
            request_type="moderation",
        )
        assert result.request.metadata.get("request_type") == "moderation"


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
        """Create a mock Mistral client."""
        client = MagicMock()
        client.chat = MagicMock()
        client.chat.complete = MagicMock(return_value={"choices": []})
        client.embeddings = MagicMock()
        client.embeddings.create = MagicMock(return_value={"data": []})
        client.fim = MagicMock()
        client.fim.complete = MagicMock(return_value={"choices": []})
        client.classifiers = MagicMock()
        client.classifiers.moderate = MagicMock(return_value={"results": []})
        return client

    def test_chat_denied_returns_none(self, mock_client, deny_policy_set):
        """Test chat complete returns None when denied."""
        wrapped = PolicyBindMistral(
            client=mock_client,
            policy_set=deny_policy_set,
            raise_on_deny=False,
        )
        result = wrapped.chat.complete(
            model="mistral-large-latest",
            messages=[{"role": "user", "content": "Hello"}],
        )
        assert result is None
        mock_client.chat.complete.assert_not_called()

    def test_embeddings_denied_returns_none(self, mock_client, deny_policy_set):
        """Test embeddings create returns None when denied."""
        wrapped = PolicyBindMistral(
            client=mock_client,
            policy_set=deny_policy_set,
            raise_on_deny=False,
        )
        result = wrapped.embeddings.create(
            model="mistral-embed",
            inputs=["Hello"],
        )
        assert result is None
        mock_client.embeddings.create.assert_not_called()


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
        result = enforcer.enforce(model="mistral-large-latest", content="Hello")

        assert hasattr(result, "allowed")
        assert hasattr(result, "request")
        assert hasattr(result, "response")
        assert hasattr(result, "enforcement_time_ms")
        assert hasattr(result, "modified")
        assert hasattr(result, "modifications")

    def test_enforcement_time_tracked(self, allow_policy_set):
        """Test enforcement time is tracked."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(model="mistral-large-latest", content="Hello")

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
        result1 = enforcer.enforce(model="mistral-large-latest", content="Hello")
        assert result1.allowed is True

        # Override context denies
        override_ctx = EnforcementContext(department="sales")
        result2 = enforcer.enforce(
            model="mistral-large-latest",
            content="Hello",
            context_override=override_ctx,
        )
        assert result2.allowed is False
