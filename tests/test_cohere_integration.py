"""
Tests for the Cohere SDK integration.

Tests the policy enforcement wrapper for the Cohere Python SDK.
"""

import pytest
from unittest.mock import MagicMock, patch

from policybind.integrations.cohere_integration import (
    ChatWrapper,
    ClassifyWrapper,
    EmbedWrapper,
    EnforcementContext,
    EnforcementResult,
    GenerateWrapper,
    PolicyApprovalRequiredError,
    PolicyBindCohere,
    PolicyDeniedError,
    PolicyEnforcer,
    RerankWrapper,
    create_async_policy_client,
    create_policy_client,
    estimate_chat_tokens,
    estimate_cost,
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

    def test_estimate_chat_tokens_message_only(self):
        """Test chat token estimation with message only."""
        result = estimate_chat_tokens("Hello world")
        # 2 words * 1.3 = 2.6 -> 2
        assert result == 2

    def test_estimate_chat_tokens_with_preamble(self):
        """Test chat token estimation with preamble."""
        result = estimate_chat_tokens(
            message="Hello",
            preamble="You are a helpful assistant",
        )
        # 1 word + 5 words = 6 words * 1.3 ≈ 7
        assert result >= 6

    def test_estimate_chat_tokens_with_history(self):
        """Test chat token estimation with history."""
        result = estimate_chat_tokens(
            message="Hello",
            chat_history=[
                {"role": "user", "message": "Hi there"},
                {"role": "assistant", "message": "Hello!"},
            ],
        )
        # Should include history tokens
        assert result >= 5


class TestCostEstimation:
    """Tests for cost estimation functions."""

    def test_estimate_cost_command_r_plus(self):
        """Test cost estimation for Command R+."""
        # 1M tokens input at $2.50/1M + 1M tokens output at $10.00/1M
        cost = estimate_cost("command-r-plus", 1_000_000, 1_000_000)
        assert abs(cost - 12.50) < 0.01

    def test_estimate_cost_command_r(self):
        """Test cost estimation for Command R."""
        # 1M tokens input at $0.50/1M + 1M tokens output at $1.50/1M
        cost = estimate_cost("command-r", 1_000_000, 1_000_000)
        assert abs(cost - 2.0) < 0.01

    def test_estimate_cost_command(self):
        """Test cost estimation for Command."""
        # 1M tokens input at $1.00/1M + 1M tokens output at $2.00/1M
        cost = estimate_cost("command", 1_000_000, 1_000_000)
        assert abs(cost - 3.0) < 0.01

    def test_estimate_cost_embed(self):
        """Test cost estimation for embed models."""
        # Embed models have input only pricing
        cost = estimate_cost("embed-english-v3.0", 1_000_000, 0)
        assert abs(cost - 0.10) < 0.01

    def test_estimate_cost_unknown_model(self):
        """Test cost estimation with unknown model falls back."""
        # Should fall back to command pricing
        cost = estimate_cost("unknown-model", 1_000_000, 0)
        assert cost > 0

    def test_estimate_cost_input_only(self):
        """Test cost estimation with input only."""
        cost = estimate_cost("command-r-plus", 1000, 0)
        # 1K tokens at $2.50/1M
        assert abs(cost - 0.0025) < 0.0001

    def test_estimate_cost_case_insensitive(self):
        """Test cost estimation is case insensitive."""
        cost1 = estimate_cost("command-r-plus", 1000, 0)
        cost2 = estimate_cost("Command-R-Plus", 1000, 0)
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

    def test_extract_content_for_hash_message(self):
        """Test extracting message content for hashing."""
        result = extract_content_for_hash(message="Hello world")
        assert result == "Hello world"

    def test_extract_content_for_hash_prompt(self):
        """Test extracting prompt content for hashing."""
        result = extract_content_for_hash(prompt="Write a story")
        assert result == "Write a story"

    def test_extract_content_for_hash_texts(self):
        """Test extracting texts content for hashing."""
        result = extract_content_for_hash(texts=["Hello", "World"])
        assert "Hello" in result
        assert "World" in result

    def test_extract_content_for_hash_chat_history(self):
        """Test extracting chat history for hashing."""
        result = extract_content_for_hash(
            chat_history=[
                {"message": "Hello"},
                {"text": "World"},
            ]
        )
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
        """Create a policy set that denies Cohere requests."""
        rule = PolicyRule(
            name="deny-cohere",
            description="Deny Cohere provider",
            match_conditions={"provider": {"eq": "cohere"}},
            action="DENY",
            action_params={"reason": "Cohere not allowed"},
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
            model="command-r-plus",
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
            model="command-r-plus",
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
            enforcer.enforce(model="command-r-plus", content="Hello")
        assert exc_info.value.decision == Decision.DENY

    def test_enforcer_stats(self, allow_policy_set):
        """Test enforcer tracks statistics."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        enforcer.enforce(model="command-r-plus", content="Hello")
        enforcer.enforce(model="command-r-plus", content="World")

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
        enforcer.enforce(model="command-r-plus", content="Hello")

        assert len(callback_called) == 1
        assert callback_called[0][0].provider == "cohere"

    def test_enforcer_request_type(self, allow_policy_set):
        """Test enforcer tracks request type."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model="command-r-plus",
            content="Hello",
            request_type="chat",
        )
        assert result.request.metadata.get("request_type") == "chat"


class TestPolicyBindCohere:
    """Tests for PolicyBindCohere wrapper."""

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
        """Create a mock Cohere client."""
        client = MagicMock()
        client.chat = MagicMock(return_value="chat response")
        client.generate = MagicMock(return_value="generate response")
        client.embed = MagicMock(return_value={"embeddings": [[0.1, 0.2]]})
        client.rerank = MagicMock(return_value={"results": []})
        client.classify = MagicMock(return_value={"classifications": []})
        return client

    def test_wrapper_creation(self, mock_client, allow_policy_set):
        """Test creating a wrapper."""
        wrapped = PolicyBindCohere(
            client=mock_client,
            policy_set=allow_policy_set,
            user_id="test@example.com",
        )
        assert wrapped._enforcer is not None

    def test_wrapper_chat(self, mock_client, allow_policy_set):
        """Test chat with wrapper."""
        wrapped = PolicyBindCohere(
            client=mock_client,
            policy_set=allow_policy_set,
        )
        result = wrapped.chat(message="Hello", model="command-r-plus")
        assert result == "chat response"
        mock_client.chat.assert_called_once()

    def test_wrapper_generate(self, mock_client, allow_policy_set):
        """Test generate with wrapper."""
        wrapped = PolicyBindCohere(
            client=mock_client,
            policy_set=allow_policy_set,
        )
        result = wrapped.generate(prompt="Write a story", model="command")
        assert result == "generate response"
        mock_client.generate.assert_called_once()

    def test_wrapper_embed(self, mock_client, allow_policy_set):
        """Test embed with wrapper."""
        wrapped = PolicyBindCohere(
            client=mock_client,
            policy_set=allow_policy_set,
        )
        result = wrapped.embed(texts=["Hello", "World"])
        assert result["embeddings"] == [[0.1, 0.2]]
        mock_client.embed.assert_called_once()

    def test_wrapper_rerank(self, mock_client, allow_policy_set):
        """Test rerank with wrapper."""
        wrapped = PolicyBindCohere(
            client=mock_client,
            policy_set=allow_policy_set,
        )
        result = wrapped.rerank(
            query="search query",
            documents=["doc1", "doc2"],
        )
        assert result["results"] == []
        mock_client.rerank.assert_called_once()

    def test_wrapper_classify(self, mock_client, allow_policy_set):
        """Test classify with wrapper."""
        wrapped = PolicyBindCohere(
            client=mock_client,
            policy_set=allow_policy_set,
        )
        result = wrapped.classify(inputs=["Hello", "World"])
        assert result["classifications"] == []
        mock_client.classify.assert_called_once()

    def test_wrapper_stats(self, mock_client, allow_policy_set):
        """Test wrapper stats tracking."""
        wrapped = PolicyBindCohere(
            client=mock_client,
            policy_set=allow_policy_set,
        )
        wrapped.chat(message="Hello", model="command-r-plus")
        wrapped.generate(prompt="Test", model="command")

        stats = wrapped.stats
        assert stats["total_requests"] == 2

    def test_wrapper_attribute_forwarding(self, mock_client, allow_policy_set):
        """Test wrapper forwards attributes to client."""
        mock_client.custom_attr = "custom_value"
        wrapped = PolicyBindCohere(
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
            enforcer.enforce(model="command-r-plus", content="Hello")

    def test_approval_required_no_raise(self, approval_policy_set):
        """Test approval required doesn't raise when not configured."""
        enforcer = PolicyEnforcer(
            policy_set=approval_policy_set,
            raise_on_approval_required=False,
        )
        result = enforcer.enforce(model="command-r-plus", content="Hello")
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
        result = enforcer.enforce(model="command-r-plus", content="Hello")
        assert result.allowed is True
        assert result.modified is True

    def test_modify_tracks_stats(self, modify_policy_set):
        """Test modify decision is tracked in stats."""
        enforcer = PolicyEnforcer(policy_set=modify_policy_set)
        enforcer.enforce(model="command-r-plus", content="Hello")

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
        assert "cohere" in str(exc_info.value)

    def test_create_async_policy_client_without_sdk(self, allow_policy_set):
        """Test create_async_policy_client raises ImportError without SDK."""
        with pytest.raises(ImportError) as exc_info:
            create_async_policy_client(
                policy_set=allow_policy_set,
                user_id="test@example.com",
            )
        assert "cohere" in str(exc_info.value)


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

        assert isinstance(wrapped, PolicyBindCohere)


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
        result = enforcer.enforce(model="command-r-plus", content="Hello")
        assert result.allowed is True

    def test_department_denied(self, department_policy_set):
        """Test department denied."""
        ctx = EnforcementContext(department="finance")
        enforcer = PolicyEnforcer(
            policy_set=department_policy_set,
            context=ctx,
            raise_on_deny=False,
        )
        result = enforcer.enforce(model="command-r-plus", content="Hello")
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
        result = enforcer.enforce(model="command-r-plus", content="Hello")
        assert result.allowed is True

    def test_classification_denied(self, classification_policy_set):
        """Test classification denied."""
        ctx = EnforcementContext(data_classification=("pii", "confidential"))
        enforcer = PolicyEnforcer(
            policy_set=classification_policy_set,
            context=ctx,
            raise_on_deny=False,
        )
        result = enforcer.enforce(model="command-r-plus", content="Hello")
        assert result.allowed is False


class TestModelPolicies:
    """Tests for model-specific policies."""

    @pytest.fixture
    def model_policy_set(self):
        """Create a policy set with model restrictions."""
        deny_rule = PolicyRule(
            name="deny-command-r-plus",
            description="Deny Command R+ models",
            match_conditions={"model": {"contains": "command-r-plus"}},
            action="DENY",
            action_params={"reason": "Command R+ restricted"},
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
        result = enforcer.enforce(model="command-r", content="Hello")
        assert result.allowed is True

    def test_model_denied(self, model_policy_set):
        """Test model denied."""
        enforcer = PolicyEnforcer(
            policy_set=model_policy_set,
            raise_on_deny=False,
        )
        result = enforcer.enforce(model="command-r-plus", content="Hello")
        assert result.allowed is False


class TestProviderPolicies:
    """Tests for provider-specific policies."""

    @pytest.fixture
    def provider_policy_set(self):
        """Create a policy set that only allows Cohere."""
        allow_rule = PolicyRule(
            name="allow-cohere",
            description="Allow Cohere provider",
            match_conditions={"provider": {"eq": "cohere"}},
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

    def test_cohere_provider_allowed(self, provider_policy_set):
        """Test Cohere provider is allowed."""
        enforcer = PolicyEnforcer(
            policy_set=provider_policy_set,
            raise_on_deny=False,
        )
        result = enforcer.enforce(model="command-r-plus", content="Hello")
        assert result.allowed is True
        assert result.request.provider == "cohere"


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
        result = enforcer.enforce(model="command-light", content="Hi")
        assert result.allowed is True

    def test_expensive_request_denied(self, cost_policy_set):
        """Test expensive request is denied."""
        enforcer = PolicyEnforcer(
            policy_set=cost_policy_set,
            raise_on_deny=False,
        )
        # Very long content = high cost
        long_content = "word " * 10000
        result = enforcer.enforce(model="command-r-plus", content=long_content)
        assert result.allowed is False


class TestCohereMetadata:
    """Tests for Cohere-specific metadata."""

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

    def test_cohere_metadata(self, allow_policy_set):
        """Test Cohere metadata is set."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model="command-r-plus",
            content="Hello",
            request_type="chat",
        )
        assert result.request.metadata.get("cohere") is True
        assert result.request.metadata.get("request_type") == "chat"

    def test_request_type_generate(self, allow_policy_set):
        """Test generate request type in metadata."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model="command",
            content="Hello",
            request_type="generate",
            max_tokens=100,
        )
        assert result.request.metadata.get("request_type") == "generate"
        assert result.request.metadata.get("max_tokens") == 100


class TestRerankWrapper:
    """Tests for RerankWrapper."""

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

    def test_rerank_with_string_docs(self, allow_policy_set):
        """Test rerank with string documents."""
        mock_client = MagicMock()
        mock_client.rerank.return_value = {"results": []}

        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = RerankWrapper(client=mock_client, enforcer=enforcer)

        result = wrapper(
            query="search query",
            documents=["doc1", "doc2"],
            model="rerank-english-v3.0",
        )
        assert result["results"] == []
        mock_client.rerank.assert_called_once()

    def test_rerank_with_dict_docs(self, allow_policy_set):
        """Test rerank with dict documents."""
        mock_client = MagicMock()
        mock_client.rerank.return_value = {"results": []}

        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = RerankWrapper(client=mock_client, enforcer=enforcer)

        result = wrapper(
            query="search query",
            documents=[{"text": "doc1"}, {"text": "doc2"}],
            model="rerank-english-v3.0",
        )
        assert result["results"] == []


class TestClassifyWrapper:
    """Tests for ClassifyWrapper."""

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

    def test_classify(self, allow_policy_set):
        """Test classify with wrapper."""
        mock_client = MagicMock()
        mock_client.classify.return_value = {"classifications": []}

        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = ClassifyWrapper(client=mock_client, enforcer=enforcer)

        result = wrapper(inputs=["Hello", "World"])
        assert result["classifications"] == []
        mock_client.classify.assert_called_once()
