"""
Tests for the AWS Bedrock SDK integration.

Tests the policy enforcement wrapper for the AWS Bedrock Runtime SDK.
"""

import json
import pytest
from unittest.mock import MagicMock, patch

from policybind.integrations.bedrock_integration import (
    ApplyGuardrailWrapper,
    ConverseStreamWrapper,
    ConverseWrapper,
    EnforcementContext,
    EnforcementResult,
    InvokeModelWithResponseStreamWrapper,
    InvokeModelWrapper,
    PolicyApprovalRequiredError,
    PolicyBindBedrock,
    PolicyDeniedError,
    PolicyEnforcer,
    create_policy_client,
    estimate_cost,
    estimate_message_tokens,
    estimate_tokens,
    extract_content_from_body,
    extract_content_from_converse,
    get_provider_from_model_id,
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

    def test_estimate_message_tokens_converse_format(self):
        """Test message token estimation with Converse API format."""
        messages = [
            {"role": "user", "content": [{"text": "What is this?"}]},
            {"role": "assistant", "content": [{"text": "Hello!"}]},
        ]
        result = estimate_message_tokens(messages)
        assert result >= 10

    def test_estimate_message_tokens_multimodal(self):
        """Test message token estimation with multimodal content."""
        messages = [
            {
                "role": "user",
                "content": [
                    {"text": "What is this?"},
                    {"image": {"format": "png", "source": {"bytes": b"..."}}},
                ],
            }
        ]
        result = estimate_message_tokens(messages)
        # 4 (overhead) + text tokens + 85 (base image tokens)
        assert result >= 89


class TestCostEstimation:
    """Tests for cost estimation functions."""

    def test_estimate_cost_claude_3_opus(self):
        """Test cost estimation for Claude 3 Opus on Bedrock."""
        # 1K tokens input at $15.00/1K + 1K tokens output at $75.00/1K
        cost = estimate_cost("anthropic.claude-3-opus-20240229-v1:0", 1000, 1000)
        assert abs(cost - 90.0) < 0.01

    def test_estimate_cost_claude_3_sonnet(self):
        """Test cost estimation for Claude 3 Sonnet."""
        # 1K tokens input at $3.00/1K + 1K tokens output at $15.00/1K
        cost = estimate_cost("anthropic.claude-3-sonnet-20240229-v1:0", 1000, 1000)
        assert abs(cost - 18.0) < 0.01

    def test_estimate_cost_claude_3_haiku(self):
        """Test cost estimation for Claude 3 Haiku."""
        # 1K tokens input at $0.25/1K + 1K tokens output at $1.25/1K
        cost = estimate_cost("anthropic.claude-3-haiku-20240307-v1:0", 1000, 1000)
        assert abs(cost - 1.50) < 0.01

    def test_estimate_cost_titan_text_express(self):
        """Test cost estimation for Titan Text Express."""
        # 1K tokens input at $0.20/1K + 1K tokens output at $0.60/1K
        cost = estimate_cost("amazon.titan-text-express-v1", 1000, 1000)
        assert abs(cost - 0.80) < 0.01

    def test_estimate_cost_llama_3_70b(self):
        """Test cost estimation for Llama 3 70B."""
        # 1K tokens input at $2.65/1K + 1K tokens output at $3.50/1K
        cost = estimate_cost("meta.llama3-70b-instruct-v1:0", 1000, 1000)
        assert abs(cost - 6.15) < 0.01

    def test_estimate_cost_mistral_large(self):
        """Test cost estimation for Mistral Large on Bedrock."""
        # 1K tokens input at $4.00/1K + 1K tokens output at $12.00/1K
        cost = estimate_cost("mistral.mistral-large-2407-v1:0", 1000, 1000)
        assert abs(cost - 16.0) < 0.01

    def test_estimate_cost_cohere_command_r_plus(self):
        """Test cost estimation for Cohere Command R+."""
        # 1K tokens input at $3.00/1K + 1K tokens output at $15.00/1K
        cost = estimate_cost("cohere.command-r-plus-v1:0", 1000, 1000)
        assert abs(cost - 18.0) < 0.01

    def test_estimate_cost_titan_embed(self):
        """Test cost estimation for Titan Embeddings."""
        # Embed models have input only pricing at $0.02/1K
        cost = estimate_cost("amazon.titan-embed-text-v2:0", 1000, 0)
        assert abs(cost - 0.02) < 0.001

    def test_estimate_cost_unknown_model(self):
        """Test cost estimation with unknown model falls back."""
        cost = estimate_cost("unknown.model-v1:0", 1000, 0)
        assert cost > 0

    def test_estimate_cost_input_only(self):
        """Test cost estimation with input only."""
        cost = estimate_cost("anthropic.claude-3-haiku-20240307-v1:0", 100, 0)
        # 100 tokens at $0.25/1K = 0.025
        assert abs(cost - 0.025) < 0.001

    def test_estimate_cost_case_insensitive(self):
        """Test cost estimation is case insensitive."""
        cost1 = estimate_cost("anthropic.claude-3-haiku-20240307-v1:0", 100, 0)
        cost2 = estimate_cost("ANTHROPIC.CLAUDE-3-HAIKU-20240307-V1:0", 100, 0)
        assert cost1 == cost2


class TestContentExtraction:
    """Tests for content extraction functions."""

    def test_extract_content_from_body_anthropic_messages(self):
        """Test extracting content from Anthropic messages format."""
        body = json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 1024,
            "messages": [
                {"role": "user", "content": "Hello world"},
                {"role": "assistant", "content": "Hi there"},
            ]
        })
        result = extract_content_from_body(body)
        assert "Hello world" in result
        assert "Hi there" in result

    def test_extract_content_from_body_anthropic_prompt(self):
        """Test extracting content from Anthropic legacy prompt format."""
        body = json.dumps({
            "prompt": "\n\nHuman: Hello\n\nAssistant:",
            "max_tokens_to_sample": 100,
        })
        result = extract_content_from_body(body)
        assert "Hello" in result

    def test_extract_content_from_body_titan_format(self):
        """Test extracting content from Titan format."""
        body = json.dumps({
            "inputText": "Hello from Titan",
            "textGenerationConfig": {"maxTokenCount": 100}
        })
        result = extract_content_from_body(body)
        assert "Hello from Titan" in result

    def test_extract_content_from_body_cohere_format(self):
        """Test extracting content from Cohere format."""
        body = json.dumps({
            "message": "Hello from Cohere",
        })
        result = extract_content_from_body(body)
        assert "Hello from Cohere" in result

    def test_extract_content_from_body_ai21_format(self):
        """Test extracting content from AI21 format."""
        body = json.dumps({
            "text": "Hello from AI21",
        })
        result = extract_content_from_body(body)
        assert "Hello from AI21" in result

    def test_extract_content_from_body_bytes(self):
        """Test extracting content from bytes body."""
        body = json.dumps({"messages": [{"role": "user", "content": "Hello"}]}).encode()
        result = extract_content_from_body(body)
        assert "Hello" in result

    def test_extract_content_from_body_with_system(self):
        """Test extracting content including system prompt."""
        body = json.dumps({
            "system": "You are a helpful assistant.",
            "messages": [{"role": "user", "content": "Hello"}]
        })
        result = extract_content_from_body(body)
        assert "You are a helpful assistant" in result
        assert "Hello" in result

    def test_extract_content_from_converse_simple(self):
        """Test extracting content from Converse API messages."""
        messages = [
            {"role": "user", "content": [{"text": "Hello world"}]},
            {"role": "assistant", "content": [{"text": "Hi there"}]},
        ]
        result = extract_content_from_converse(messages)
        assert "Hello world" in result
        assert "Hi there" in result


class TestProviderExtraction:
    """Tests for provider extraction from model ID."""

    def test_get_provider_anthropic(self):
        """Test getting Anthropic provider."""
        result = get_provider_from_model_id("anthropic.claude-3-sonnet-20240229-v1:0")
        assert result == "anthropic"

    def test_get_provider_amazon(self):
        """Test getting Amazon provider."""
        result = get_provider_from_model_id("amazon.titan-text-express-v1")
        assert result == "amazon"

    def test_get_provider_meta(self):
        """Test getting Meta provider."""
        result = get_provider_from_model_id("meta.llama3-70b-instruct-v1:0")
        assert result == "meta"

    def test_get_provider_mistral(self):
        """Test getting Mistral provider."""
        result = get_provider_from_model_id("mistral.mistral-large-2407-v1:0")
        assert result == "mistral"

    def test_get_provider_cohere(self):
        """Test getting Cohere provider."""
        result = get_provider_from_model_id("cohere.command-r-plus-v1:0")
        assert result == "cohere"

    def test_get_provider_ai21(self):
        """Test getting AI21 provider."""
        result = get_provider_from_model_id("ai21.jamba-instruct-v1:0")
        assert result == "ai21"

    def test_get_provider_unknown(self):
        """Test getting unknown provider."""
        result = get_provider_from_model_id("some-random-model")
        assert result == "unknown"


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
        """Create a policy set that denies Bedrock requests."""
        rule = PolicyRule(
            name="deny-bedrock",
            description="Deny Bedrock provider",
            match_conditions={"provider": {"contains": "bedrock"}},
            action="DENY",
            action_params={"reason": "Bedrock not allowed"},
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
            model_id="anthropic.claude-3-sonnet-20240229-v1:0",
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
            model_id="anthropic.claude-3-sonnet-20240229-v1:0",
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
            enforcer.enforce(
                model_id="anthropic.claude-3-sonnet-20240229-v1:0",
                content="Hello",
            )
        assert exc_info.value.decision == Decision.DENY

    def test_enforcer_stats(self, allow_policy_set):
        """Test enforcer tracks statistics."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        enforcer.enforce(model_id="anthropic.claude-3-sonnet-20240229-v1:0", content="Hello")
        enforcer.enforce(model_id="amazon.titan-text-express-v1", content="World")

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
        enforcer.enforce(model_id="anthropic.claude-3-sonnet-20240229-v1:0", content="Hello")

        assert len(callback_called) == 1
        assert "bedrock" in callback_called[0][0].provider

    def test_enforcer_request_type(self, allow_policy_set):
        """Test enforcer tracks request type."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model_id="anthropic.claude-3-sonnet-20240229-v1:0",
            content="Hello",
            request_type="converse",
        )
        assert result.request.metadata.get("request_type") == "converse"


class TestInvokeModelWrapper:
    """Tests for InvokeModelWrapper."""

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
        """Create a mock Bedrock client."""
        client = MagicMock()
        client.invoke_model = MagicMock(return_value={"body": MagicMock()})
        return client

    def test_invoke_model_wrapper(self, mock_client, allow_policy_set):
        """Test InvokeModelWrapper."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = InvokeModelWrapper(mock_client, enforcer)

        body = json.dumps({"messages": [{"role": "user", "content": "Hello"}]})
        result = wrapper(
            modelId="anthropic.claude-3-sonnet-20240229-v1:0",
            body=body,
        )
        assert result is not None
        mock_client.invoke_model.assert_called_once()


class TestInvokeModelWithResponseStreamWrapper:
    """Tests for InvokeModelWithResponseStreamWrapper."""

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
        """Create a mock Bedrock client."""
        client = MagicMock()
        client.invoke_model_with_response_stream = MagicMock(return_value={"body": iter([])})
        return client

    def test_invoke_model_stream_wrapper(self, mock_client, allow_policy_set):
        """Test InvokeModelWithResponseStreamWrapper."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = InvokeModelWithResponseStreamWrapper(mock_client, enforcer)

        body = json.dumps({"messages": [{"role": "user", "content": "Hello"}]})
        result = wrapper(
            modelId="anthropic.claude-3-sonnet-20240229-v1:0",
            body=body,
        )
        assert result is not None
        mock_client.invoke_model_with_response_stream.assert_called_once()


class TestConverseWrapper:
    """Tests for ConverseWrapper."""

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
        """Create a mock Bedrock client."""
        client = MagicMock()
        client.converse = MagicMock(return_value={"output": {"message": {"content": [{"text": "Hi"}]}}})
        return client

    def test_converse_wrapper(self, mock_client, allow_policy_set):
        """Test ConverseWrapper."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = ConverseWrapper(mock_client, enforcer)

        result = wrapper(
            modelId="anthropic.claude-3-sonnet-20240229-v1:0",
            messages=[{"role": "user", "content": [{"text": "Hello"}]}],
        )
        assert result is not None
        mock_client.converse.assert_called_once()

    def test_converse_wrapper_with_system(self, mock_client, allow_policy_set):
        """Test ConverseWrapper with system prompt."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = ConverseWrapper(mock_client, enforcer)

        result = wrapper(
            modelId="anthropic.claude-3-sonnet-20240229-v1:0",
            messages=[{"role": "user", "content": [{"text": "Hello"}]}],
            system=[{"text": "You are helpful."}],
        )
        assert result is not None
        mock_client.converse.assert_called_once()


class TestConverseStreamWrapper:
    """Tests for ConverseStreamWrapper."""

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
        """Create a mock Bedrock client."""
        client = MagicMock()
        client.converse_stream = MagicMock(return_value={"stream": iter([])})
        return client

    def test_converse_stream_wrapper(self, mock_client, allow_policy_set):
        """Test ConverseStreamWrapper."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = ConverseStreamWrapper(mock_client, enforcer)

        result = wrapper(
            modelId="anthropic.claude-3-sonnet-20240229-v1:0",
            messages=[{"role": "user", "content": [{"text": "Hello"}]}],
        )
        assert result is not None
        mock_client.converse_stream.assert_called_once()


class TestApplyGuardrailWrapper:
    """Tests for ApplyGuardrailWrapper."""

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
        """Create a mock Bedrock client."""
        client = MagicMock()
        client.apply_guardrail = MagicMock(return_value={"action": "NONE"})
        return client

    def test_apply_guardrail_wrapper(self, mock_client, allow_policy_set):
        """Test ApplyGuardrailWrapper."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = ApplyGuardrailWrapper(mock_client, enforcer)

        result = wrapper(
            guardrailIdentifier="my-guardrail",
            guardrailVersion="1",
            source="INPUT",
            content=[{"text": {"text": "Hello world"}}],
        )
        assert result is not None
        mock_client.apply_guardrail.assert_called_once()


class TestPolicyBindBedrock:
    """Tests for PolicyBindBedrock wrapper."""

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
        """Create a mock Bedrock client."""
        client = MagicMock()
        client.invoke_model = MagicMock(return_value={"body": MagicMock()})
        client.invoke_model_with_response_stream = MagicMock(return_value={"body": iter([])})
        client.converse = MagicMock(return_value={"output": {}})
        client.converse_stream = MagicMock(return_value={"stream": iter([])})
        client.apply_guardrail = MagicMock(return_value={"action": "NONE"})
        return client

    def test_wrapper_creation(self, mock_client, allow_policy_set):
        """Test creating a wrapper."""
        wrapped = PolicyBindBedrock(
            client=mock_client,
            policy_set=allow_policy_set,
            user_id="test@example.com",
        )
        assert wrapped._enforcer is not None

    def test_wrapper_has_invoke_model(self, mock_client, allow_policy_set):
        """Test wrapper has invoke_model method."""
        wrapped = PolicyBindBedrock(
            client=mock_client,
            policy_set=allow_policy_set,
        )
        assert hasattr(wrapped, "invoke_model")
        assert isinstance(wrapped.invoke_model, InvokeModelWrapper)

    def test_wrapper_has_converse(self, mock_client, allow_policy_set):
        """Test wrapper has converse method."""
        wrapped = PolicyBindBedrock(
            client=mock_client,
            policy_set=allow_policy_set,
        )
        assert hasattr(wrapped, "converse")
        assert isinstance(wrapped.converse, ConverseWrapper)

    def test_wrapper_has_apply_guardrail(self, mock_client, allow_policy_set):
        """Test wrapper has apply_guardrail method."""
        wrapped = PolicyBindBedrock(
            client=mock_client,
            policy_set=allow_policy_set,
        )
        assert hasattr(wrapped, "apply_guardrail")
        assert isinstance(wrapped.apply_guardrail, ApplyGuardrailWrapper)

    def test_wrapper_stats(self, mock_client, allow_policy_set):
        """Test wrapper stats tracking."""
        wrapped = PolicyBindBedrock(
            client=mock_client,
            policy_set=allow_policy_set,
        )
        body = json.dumps({"messages": [{"role": "user", "content": "Hello"}]})
        wrapped.invoke_model(
            modelId="anthropic.claude-3-sonnet-20240229-v1:0",
            body=body,
        )

        stats = wrapped.stats
        assert stats["total_requests"] == 1

    def test_wrapper_attribute_forwarding(self, mock_client, allow_policy_set):
        """Test wrapper forwards attributes to client."""
        mock_client.custom_attr = "custom_value"
        wrapped = PolicyBindBedrock(
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
            enforcer.enforce(
                model_id="anthropic.claude-3-sonnet-20240229-v1:0",
                content="Hello",
            )

    def test_approval_required_no_raise(self, approval_policy_set):
        """Test approval required doesn't raise when not configured."""
        enforcer = PolicyEnforcer(
            policy_set=approval_policy_set,
            raise_on_approval_required=False,
        )
        result = enforcer.enforce(
            model_id="anthropic.claude-3-sonnet-20240229-v1:0",
            content="Hello",
        )
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
        result = enforcer.enforce(
            model_id="anthropic.claude-3-sonnet-20240229-v1:0",
            content="Hello",
        )
        assert result.allowed is True
        assert result.modified is True

    def test_modify_tracks_stats(self, modify_policy_set):
        """Test modify decision is tracked in stats."""
        enforcer = PolicyEnforcer(policy_set=modify_policy_set)
        enforcer.enforce(
            model_id="anthropic.claude-3-sonnet-20240229-v1:0",
            content="Hello",
        )

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

    def test_create_policy_client_with_mock(self, allow_policy_set):
        """Test create_policy_client creates a wrapped client."""
        # Mock boto3 to avoid real AWS calls
        import sys
        mock_boto3 = MagicMock()
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client

        with patch.dict(sys.modules, {"boto3": mock_boto3}):
            # Need to reimport to pick up the mock
            from policybind.integrations import bedrock_integration
            import importlib
            importlib.reload(bedrock_integration)

            client = bedrock_integration.create_policy_client(
                policy_set=allow_policy_set,
                region_name="us-east-1",
                user_id="test@example.com",
            )

            assert isinstance(client, bedrock_integration.PolicyBindBedrock)
            mock_boto3.client.assert_called_once()


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

        # Use class name check to avoid reload issues
        assert wrapped.__class__.__name__ == "PolicyBindBedrock"


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
        result = enforcer.enforce(
            model_id="anthropic.claude-3-sonnet-20240229-v1:0",
            content="Hello",
        )
        assert result.allowed is True

    def test_department_denied(self, department_policy_set):
        """Test department denied."""
        ctx = EnforcementContext(department="finance")
        enforcer = PolicyEnforcer(
            policy_set=department_policy_set,
            context=ctx,
            raise_on_deny=False,
        )
        result = enforcer.enforce(
            model_id="anthropic.claude-3-sonnet-20240229-v1:0",
            content="Hello",
        )
        assert result.allowed is False


class TestModelPolicies:
    """Tests for model-specific policies."""

    @pytest.fixture
    def model_policy_set(self):
        """Create a policy set with model restrictions."""
        deny_rule = PolicyRule(
            name="deny-opus",
            description="Deny Claude 3 Opus",
            match_conditions={"model": {"contains": "opus"}},
            action="DENY",
            action_params={"reason": "Opus models restricted"},
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
        result = enforcer.enforce(
            model_id="anthropic.claude-3-sonnet-20240229-v1:0",
            content="Hello",
        )
        assert result.allowed is True

    def test_model_denied(self, model_policy_set):
        """Test model denied."""
        enforcer = PolicyEnforcer(
            policy_set=model_policy_set,
            raise_on_deny=False,
        )
        result = enforcer.enforce(
            model_id="anthropic.claude-3-opus-20240229-v1:0",
            content="Hello",
        )
        assert result.allowed is False


class TestProviderPolicies:
    """Tests for provider-specific policies."""

    @pytest.fixture
    def provider_policy_set(self):
        """Create a policy set that only allows Anthropic on Bedrock."""
        allow_rule = PolicyRule(
            name="allow-anthropic",
            description="Allow Anthropic provider",
            match_conditions={"provider": {"contains": "anthropic"}},
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

    def test_anthropic_provider_allowed(self, provider_policy_set):
        """Test Anthropic provider on Bedrock is allowed."""
        enforcer = PolicyEnforcer(
            policy_set=provider_policy_set,
            raise_on_deny=False,
        )
        result = enforcer.enforce(
            model_id="anthropic.claude-3-sonnet-20240229-v1:0",
            content="Hello",
        )
        assert result.allowed is True
        assert "bedrock-anthropic" == result.request.provider

    def test_other_provider_denied(self, provider_policy_set):
        """Test other providers are denied."""
        enforcer = PolicyEnforcer(
            policy_set=provider_policy_set,
            raise_on_deny=False,
        )
        result = enforcer.enforce(
            model_id="amazon.titan-text-express-v1",
            content="Hello",
        )
        assert result.allowed is False


class TestCostBasedPolicies:
    """Tests for cost-based policies."""

    @pytest.fixture
    def cost_policy_set(self):
        """Create a policy set with cost restrictions."""
        deny_rule = PolicyRule(
            name="deny-expensive",
            description="Deny expensive requests",
            match_conditions={"estimated_cost": {"gt": 1.0}},
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
        result = enforcer.enforce(
            model_id="anthropic.claude-3-haiku-20240307-v1:0",
            content="Hi",
        )
        assert result.allowed is True

    def test_expensive_request_denied(self, cost_policy_set):
        """Test expensive request is denied."""
        enforcer = PolicyEnforcer(
            policy_set=cost_policy_set,
            raise_on_deny=False,
        )
        # Very long content with expensive model = high cost
        long_content = "word " * 5000
        result = enforcer.enforce(
            model_id="anthropic.claude-3-opus-20240229-v1:0",
            content=long_content,
        )
        assert result.allowed is False


class TestBedrockMetadata:
    """Tests for Bedrock-specific metadata."""

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

    def test_bedrock_metadata(self, allow_policy_set):
        """Test Bedrock metadata is set."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model_id="anthropic.claude-3-sonnet-20240229-v1:0",
            content="Hello",
            request_type="converse",
        )
        assert result.request.metadata.get("bedrock") is True
        assert result.request.metadata.get("bedrock_provider") == "anthropic"
        assert result.request.metadata.get("request_type") == "converse"

    def test_request_type_invoke_model(self, allow_policy_set):
        """Test invoke_model request type in metadata."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model_id="amazon.titan-text-express-v1",
            content="Hello",
            request_type="invoke_model",
        )
        assert result.request.metadata.get("request_type") == "invoke_model"
        assert result.request.metadata.get("bedrock_provider") == "amazon"

    def test_request_type_apply_guardrail(self, allow_policy_set):
        """Test apply_guardrail request type in metadata."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model_id="guardrail:my-guardrail",
            content="Hello",
            request_type="apply_guardrail",
        )
        assert result.request.metadata.get("request_type") == "apply_guardrail"


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
        """Create a mock Bedrock client."""
        client = MagicMock()
        client.invoke_model = MagicMock(return_value={"body": MagicMock()})
        client.converse = MagicMock(return_value={"output": {}})
        return client

    def test_invoke_model_denied_returns_none(self, mock_client, deny_policy_set):
        """Test invoke_model returns None when denied."""
        wrapped = PolicyBindBedrock(
            client=mock_client,
            policy_set=deny_policy_set,
            raise_on_deny=False,
        )
        body = json.dumps({"messages": [{"role": "user", "content": "Hello"}]})
        result = wrapped.invoke_model(
            modelId="anthropic.claude-3-sonnet-20240229-v1:0",
            body=body,
        )
        assert result is None
        mock_client.invoke_model.assert_not_called()

    def test_converse_denied_returns_none(self, mock_client, deny_policy_set):
        """Test converse returns None when denied."""
        wrapped = PolicyBindBedrock(
            client=mock_client,
            policy_set=deny_policy_set,
            raise_on_deny=False,
        )
        result = wrapped.converse(
            modelId="anthropic.claude-3-sonnet-20240229-v1:0",
            messages=[{"role": "user", "content": [{"text": "Hello"}]}],
        )
        assert result is None
        mock_client.converse.assert_not_called()


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
        result = enforcer.enforce(
            model_id="anthropic.claude-3-sonnet-20240229-v1:0",
            content="Hello",
        )

        assert hasattr(result, "allowed")
        assert hasattr(result, "request")
        assert hasattr(result, "response")
        assert hasattr(result, "enforcement_time_ms")
        assert hasattr(result, "modified")
        assert hasattr(result, "modifications")

    def test_enforcement_time_tracked(self, allow_policy_set):
        """Test enforcement time is tracked."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model_id="anthropic.claude-3-sonnet-20240229-v1:0",
            content="Hello",
        )

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
        result1 = enforcer.enforce(
            model_id="anthropic.claude-3-sonnet-20240229-v1:0",
            content="Hello",
        )
        assert result1.allowed is True

        # Override context denies
        override_ctx = EnforcementContext(department="sales")
        result2 = enforcer.enforce(
            model_id="anthropic.claude-3-sonnet-20240229-v1:0",
            content="Hello",
            context_override=override_ctx,
        )
        assert result2.allowed is False


class TestMultipleProviderModels:
    """Tests for different provider models on Bedrock."""

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

    def test_anthropic_model(self, allow_policy_set):
        """Test Anthropic model on Bedrock."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model_id="anthropic.claude-3-sonnet-20240229-v1:0",
            content="Hello",
        )
        assert result.request.provider == "bedrock-anthropic"

    def test_amazon_model(self, allow_policy_set):
        """Test Amazon Titan model on Bedrock."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model_id="amazon.titan-text-express-v1",
            content="Hello",
        )
        assert result.request.provider == "bedrock-amazon"

    def test_meta_model(self, allow_policy_set):
        """Test Meta Llama model on Bedrock."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model_id="meta.llama3-70b-instruct-v1:0",
            content="Hello",
        )
        assert result.request.provider == "bedrock-meta"

    def test_mistral_model(self, allow_policy_set):
        """Test Mistral model on Bedrock."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model_id="mistral.mistral-large-2407-v1:0",
            content="Hello",
        )
        assert result.request.provider == "bedrock-mistral"

    def test_cohere_model(self, allow_policy_set):
        """Test Cohere model on Bedrock."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model_id="cohere.command-r-plus-v1:0",
            content="Hello",
        )
        assert result.request.provider == "bedrock-cohere"

    def test_ai21_model(self, allow_policy_set):
        """Test AI21 model on Bedrock."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model_id="ai21.jamba-instruct-v1:0",
            content="Hello",
        )
        assert result.request.provider == "bedrock-ai21"
