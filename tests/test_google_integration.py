"""
Tests for the Google Gemini/Vertex AI SDK integration.

Tests the policy enforcement wrapper for the Google Generative AI
and Vertex AI Python SDKs.
"""

import pytest
from unittest.mock import MagicMock, patch, AsyncMock

from policybind.engine.pipeline import PipelineConfig
from policybind.integrations.google_integration import (
    ChatSessionWrapper,
    CountTokensWrapper,
    EmbedContentWrapper,
    EnforcementContext,
    EnforcementResult,
    GenerateContentAsyncWrapper,
    GenerateContentWrapper,
    PolicyApprovalRequiredError,
    PolicyBindGenerativeModel,
    PolicyDeniedError,
    PolicyEnforcer,
    create_policy_client,
    create_vertex_policy_client,
    estimate_content_tokens,
    estimate_cost,
    estimate_tokens,
    extract_content_for_hash,
    extract_model_name,
    hash_content,
    wrap_model,
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

    def test_estimate_content_tokens_string(self):
        """Test content token estimation with string."""
        result = estimate_content_tokens("Hello world")
        # 2 words * 1.3 = 2.6 -> 2
        assert result == 2

    def test_estimate_content_tokens_list(self):
        """Test content token estimation with list."""
        content = ["Hello", "world"]
        result = estimate_content_tokens(content)
        # 2 words total
        assert result == 2

    def test_estimate_content_tokens_dict_list(self):
        """Test content token estimation with dict list."""
        content = [
            {"text": "Hello world"},
            {"text": "How are you"},
        ]
        result = estimate_content_tokens(content)
        assert result >= 4

    def test_estimate_content_tokens_with_image(self):
        """Test content token estimation with inline image."""
        content = [
            {"text": "What is this?"},
            {"inline_data": {"mime_type": "image/png", "data": "base64..."}}
        ]
        result = estimate_content_tokens(content)
        # Should include base image tokens (258)
        assert result >= 258


class TestCostEstimation:
    """Tests for cost estimation functions."""

    def test_estimate_cost_gemini_15_pro(self):
        """Test cost estimation for Gemini 1.5 Pro."""
        # 1M tokens input at $1.25/1M + 1M tokens output at $5.00/1M
        cost = estimate_cost("gemini-1.5-pro", 1_000_000, 1_000_000)
        assert abs(cost - 6.25) < 0.01

    def test_estimate_cost_gemini_15_flash(self):
        """Test cost estimation for Gemini 1.5 Flash."""
        # 1M tokens input at $0.075/1M + 1M tokens output at $0.30/1M
        cost = estimate_cost("gemini-1.5-flash", 1_000_000, 1_000_000)
        assert abs(cost - 0.375) < 0.01

    def test_estimate_cost_gemini_10_pro(self):
        """Test cost estimation for Gemini 1.0 Pro."""
        # 1M tokens input at $0.50/1M + 1M tokens output at $1.50/1M
        cost = estimate_cost("gemini-1.0-pro", 1_000_000, 1_000_000)
        assert abs(cost - 2.0) < 0.01

    def test_estimate_cost_alias(self):
        """Test cost estimation with model alias."""
        cost = estimate_cost("gemini-pro", 1_000_000, 0)
        # Should use gemini-1.0-pro pricing
        assert abs(cost - 0.5) < 0.01

    def test_estimate_cost_unknown_model(self):
        """Test cost estimation with unknown model falls back."""
        # Should fall back to gemini-1.5-flash pricing
        cost = estimate_cost("unknown-model", 1_000_000, 0)
        assert cost > 0

    def test_estimate_cost_input_only(self):
        """Test cost estimation with input only."""
        cost = estimate_cost("gemini-1.5-pro", 1000, 0)
        # 1K tokens at $1.25/1M
        assert abs(cost - 0.00125) < 0.0001

    def test_estimate_cost_case_insensitive(self):
        """Test cost estimation is case insensitive."""
        cost1 = estimate_cost("gemini-1.5-pro", 1000, 0)
        cost2 = estimate_cost("Gemini-1.5-Pro", 1000, 0)
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

    def test_extract_content_for_hash_string(self):
        """Test extracting string content for hashing."""
        content = "Hello world"
        result = extract_content_for_hash(content)
        assert result == "Hello world"

    def test_extract_content_for_hash_list(self):
        """Test extracting list content for hashing."""
        content = ["Hello", "world"]
        result = extract_content_for_hash(content)
        assert "Hello" in result
        assert "world" in result

    def test_extract_content_for_hash_dict_list(self):
        """Test extracting dict list content for hashing."""
        content = [
            {"text": "Hello"},
            {"text": "world"},
        ]
        result = extract_content_for_hash(content)
        assert "Hello" in result
        assert "world" in result


class TestModelNameExtraction:
    """Tests for model name extraction."""

    def test_extract_model_name_string(self):
        """Test extracting model name from string."""
        assert extract_model_name("gemini-1.5-pro") == "gemini-1.5-pro"

    def test_extract_model_name_with_prefix(self):
        """Test extracting model name with models/ prefix."""
        assert extract_model_name("models/gemini-1.5-pro") == "gemini-1.5-pro"

    def test_extract_model_name_from_object(self):
        """Test extracting model name from object."""
        mock_model = MagicMock()
        mock_model.model_name = "models/gemini-1.5-flash"
        assert extract_model_name(mock_model) == "gemini-1.5-flash"

    def test_extract_model_name_unknown(self):
        """Test extracting model name from unknown object."""
        assert extract_model_name(object()) == "unknown"


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
        """Create a policy set that denies Google requests."""
        rule = PolicyRule(
            name="deny-google",
            description="Deny Google provider",
            match_conditions={"provider": {"eq": "google"}},
            action="DENY",
            action_params={"reason": "Google not allowed"},
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
            model="gemini-1.5-pro",
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
            model="gemini-1.5-pro",
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
            enforcer.enforce(model="gemini-1.5-pro", content="Hello")
        assert exc_info.value.decision == Decision.DENY

    def test_enforcer_stats(self, allow_policy_set):
        """Test enforcer tracks statistics."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        enforcer.enforce(model="gemini-1.5-pro", content="Hello")
        enforcer.enforce(model="gemini-1.5-pro", content="World")

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
        enforcer.enforce(model="gemini-1.5-pro", content="Hello")

        assert len(callback_called) == 1
        assert callback_called[0][0].provider == "google"


class TestPolicyBindGenerativeModel:
    """Tests for PolicyBindGenerativeModel wrapper."""

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
    def mock_model(self):
        """Create a mock GenerativeModel."""
        model = MagicMock()
        model.model_name = "models/gemini-1.5-pro"
        model.generate_content = MagicMock(return_value="response")
        model.generate_content_async = AsyncMock(return_value="async response")
        model.count_tokens = MagicMock(return_value={"total_tokens": 10})
        return model

    def test_wrapper_creation(self, mock_model, allow_policy_set):
        """Test creating a wrapper."""
        wrapped = PolicyBindGenerativeModel(
            model=mock_model,
            policy_set=allow_policy_set,
            user_id="test@example.com",
        )
        assert wrapped.model_name == "gemini-1.5-pro"
        assert wrapped._enforcer is not None

    def test_wrapper_generate_content(self, mock_model, allow_policy_set):
        """Test generate_content with wrapper."""
        wrapped = PolicyBindGenerativeModel(
            model=mock_model,
            policy_set=allow_policy_set,
        )
        result = wrapped.generate_content("Hello")
        assert result == "response"
        mock_model.generate_content.assert_called_once()

    def test_wrapper_count_tokens(self, mock_model, allow_policy_set):
        """Test count_tokens with wrapper (no policy enforcement)."""
        wrapped = PolicyBindGenerativeModel(
            model=mock_model,
            policy_set=allow_policy_set,
        )
        result = wrapped.count_tokens("Hello")
        assert result["total_tokens"] == 10
        mock_model.count_tokens.assert_called_once()

    def test_wrapper_stats(self, mock_model, allow_policy_set):
        """Test wrapper stats tracking."""
        wrapped = PolicyBindGenerativeModel(
            model=mock_model,
            policy_set=allow_policy_set,
        )
        wrapped.generate_content("Hello")
        wrapped.generate_content("World")

        stats = wrapped.stats
        assert stats["total_requests"] == 2

    def test_wrapper_attribute_forwarding(self, mock_model, allow_policy_set):
        """Test wrapper forwards attributes to model."""
        mock_model.custom_attr = "custom_value"
        wrapped = PolicyBindGenerativeModel(
            model=mock_model,
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
            enforcer.enforce(model="gemini-1.5-pro", content="Hello")

    def test_approval_required_no_raise(self, approval_policy_set):
        """Test approval required doesn't raise when not configured."""
        enforcer = PolicyEnforcer(
            policy_set=approval_policy_set,
            raise_on_approval_required=False,
        )
        result = enforcer.enforce(model="gemini-1.5-pro", content="Hello")
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
        result = enforcer.enforce(model="gemini-1.5-pro", content="Hello")
        assert result.allowed is True
        assert result.modified is True

    def test_modify_tracks_stats(self, modify_policy_set):
        """Test modify decision is tracked in stats."""
        enforcer = PolicyEnforcer(policy_set=modify_policy_set)
        enforcer.enforce(model="gemini-1.5-pro", content="Hello")

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
        # The SDK is not installed, so this should raise ImportError
        with pytest.raises(ImportError) as exc_info:
            create_policy_client(
                model_name="gemini-1.5-pro",
                policy_set=allow_policy_set,
                user_id="test@example.com",
            )
        assert "google-generativeai" in str(exc_info.value)

    def test_create_vertex_policy_client_without_sdk(self, allow_policy_set):
        """Test create_vertex_policy_client raises ImportError without SDK."""
        # The SDK is not installed, so this should raise ImportError
        with pytest.raises(ImportError) as exc_info:
            create_vertex_policy_client(
                model_name="gemini-1.5-pro",
                policy_set=allow_policy_set,
                project="test-project",
                location="us-central1",
                user_id="test@example.com",
            )
        assert "google-cloud-aiplatform" in str(exc_info.value)


class TestWrapModel:
    """Tests for wrap_model function."""

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

    def test_wrap_model(self, allow_policy_set):
        """Test wrapping an existing model."""
        mock_model = MagicMock()
        mock_model.model_name = "models/gemini-1.5-pro"

        wrapped = wrap_model(
            model=mock_model,
            policy_set=allow_policy_set,
            user_id="test@example.com",
        )

        assert isinstance(wrapped, PolicyBindGenerativeModel)
        assert wrapped.model_name == "gemini-1.5-pro"


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
        result = enforcer.enforce(model="gemini-1.5-pro", content="Hello")
        assert result.allowed is True

    def test_department_denied(self, department_policy_set):
        """Test department denied."""
        ctx = EnforcementContext(department="finance")
        enforcer = PolicyEnforcer(
            policy_set=department_policy_set,
            context=ctx,
            raise_on_deny=False,
        )
        result = enforcer.enforce(model="gemini-1.5-pro", content="Hello")
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
        result = enforcer.enforce(model="gemini-1.5-pro", content="Hello")
        assert result.allowed is True

    def test_classification_denied(self, classification_policy_set):
        """Test classification denied."""
        ctx = EnforcementContext(data_classification=("pii", "confidential"))
        enforcer = PolicyEnforcer(
            policy_set=classification_policy_set,
            context=ctx,
            raise_on_deny=False,
        )
        result = enforcer.enforce(model="gemini-1.5-pro", content="Hello")
        assert result.allowed is False


class TestModelPolicies:
    """Tests for model-specific policies."""

    @pytest.fixture
    def model_policy_set(self):
        """Create a policy set with model restrictions."""
        deny_rule = PolicyRule(
            name="deny-pro",
            description="Deny Pro models",
            match_conditions={"model": {"contains": "pro"}},
            action="DENY",
            action_params={"reason": "Pro models restricted"},
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
        result = enforcer.enforce(model="gemini-1.5-flash", content="Hello")
        assert result.allowed is True

    def test_model_denied(self, model_policy_set):
        """Test model denied."""
        enforcer = PolicyEnforcer(
            policy_set=model_policy_set,
            raise_on_deny=False,
        )
        result = enforcer.enforce(model="gemini-1.5-pro", content="Hello")
        assert result.allowed is False


class TestProviderPolicies:
    """Tests for provider-specific policies."""

    @pytest.fixture
    def provider_policy_set(self):
        """Create a policy set that only allows Google."""
        allow_rule = PolicyRule(
            name="allow-google",
            description="Allow Google provider",
            match_conditions={"provider": {"eq": "google"}},
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

    def test_google_provider_allowed(self, provider_policy_set):
        """Test Google provider is allowed."""
        enforcer = PolicyEnforcer(
            policy_set=provider_policy_set,
            raise_on_deny=False,
        )
        result = enforcer.enforce(model="gemini-1.5-pro", content="Hello")
        assert result.allowed is True
        assert result.request.provider == "google"


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
        result = enforcer.enforce(model="gemini-1.5-flash", content="Hi")
        assert result.allowed is True

    def test_expensive_request_denied(self, cost_policy_set):
        """Test expensive request is denied."""
        enforcer = PolicyEnforcer(
            policy_set=cost_policy_set,
            raise_on_deny=False,
        )
        # Very long content = high cost
        long_content = "word " * 10000
        result = enforcer.enforce(model="gemini-1.5-pro", content=long_content)
        assert result.allowed is False


class TestGoogleMetadata:
    """Tests for Google-specific metadata."""

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

    def test_google_gemini_metadata(self, allow_policy_set):
        """Test Google Gemini metadata is set."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model="gemini-1.5-pro",
            content="Hello",
            generation_config={"temperature": 0.7},
        )
        assert result.request.metadata.get("google_gemini") is True
        assert result.request.metadata.get("generation_config") == {"temperature": 0.7}

    def test_safety_settings_metadata(self, allow_policy_set):
        """Test safety settings are included in metadata."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        safety_settings = {"harassment": "block_none"}
        result = enforcer.enforce(
            model="gemini-1.5-pro",
            content="Hello",
            safety_settings=safety_settings,
        )
        assert result.request.metadata.get("safety_settings") == safety_settings


class TestChatSessionWrapper:
    """Tests for ChatSessionWrapper."""

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

    def test_chat_send_message(self, allow_policy_set):
        """Test chat session send_message."""
        mock_chat = MagicMock()
        mock_chat.send_message.return_value = "response"
        mock_chat.history = []

        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = ChatSessionWrapper(
            chat=mock_chat,
            enforcer=enforcer,
            model_name="gemini-1.5-pro",
        )

        result = wrapper.send_message("Hello")
        assert result == "response"
        mock_chat.send_message.assert_called_once()

    def test_chat_history_access(self, allow_policy_set):
        """Test chat session history access."""
        mock_chat = MagicMock()
        mock_chat.history = ["message1", "message2"]

        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = ChatSessionWrapper(
            chat=mock_chat,
            enforcer=enforcer,
            model_name="gemini-1.5-pro",
        )

        assert wrapper.history == ["message1", "message2"]


class TestEmbedContentWrapper:
    """Tests for EmbedContentWrapper."""

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

    def test_embed_content(self, allow_policy_set):
        """Test embedding content with wrapper."""
        mock_model = MagicMock()
        mock_model.embed_content.return_value = {"embedding": [0.1, 0.2, 0.3]}

        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = EmbedContentWrapper(
            model=mock_model,
            enforcer=enforcer,
            model_name="text-embedding-004",
        )

        result = wrapper("Hello world")
        assert result["embedding"] == [0.1, 0.2, 0.3]
        mock_model.embed_content.assert_called_once()
