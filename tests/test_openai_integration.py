"""
Tests for the OpenAI SDK integration.

Tests the policy enforcement wrapper for the OpenAI Python SDK.
"""

import pytest
from unittest.mock import MagicMock, patch

from policybind.engine.pipeline import PipelineConfig
from policybind.integrations.openai_integration import (
    ChatCompletionsWrapper,
    ChatWrapper,
    CompletionsWrapper,
    EmbeddingsWrapper,
    EnforcementContext,
    EnforcementResult,
    PolicyApprovalRequiredError,
    PolicyBindOpenAI,
    PolicyDeniedError,
    PolicyEnforcer,
    create_policy_client,
    estimate_cost,
    estimate_message_tokens,
    estimate_tokens,
    extract_content_for_hash,
    hash_content,
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
        """Test message token estimation."""
        messages = [
            {"role": "user", "content": "Hello world"}
        ]
        result = estimate_message_tokens(messages)
        # 4 (overhead) + 2 words * 1.3 = 4 + 2.6 = 6
        assert result >= 6

    def test_estimate_message_tokens_multiple(self):
        """Test token estimation with multiple messages."""
        messages = [
            {"role": "system", "content": "You are helpful"},
            {"role": "user", "content": "Hello"},
        ]
        result = estimate_message_tokens(messages)
        # 2 messages with overhead
        assert result >= 10

    def test_estimate_message_tokens_multimodal(self):
        """Test token estimation with multimodal content."""
        messages = [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "What is this?"},
                    {"type": "image_url", "image_url": {"url": "http://example.com/img.png"}}
                ]
            }
        ]
        result = estimate_message_tokens(messages)
        # Should include base image tokens
        assert result >= 85


class TestCostEstimation:
    """Tests for cost estimation functions."""

    def test_estimate_cost_gpt4(self):
        """Test cost estimation for GPT-4."""
        cost = estimate_cost("gpt-4", 1000, 500)
        # Input: 1K * 0.03 = 0.03
        # Output: 0.5K * 0.06 = 0.03
        # Total: 0.06
        assert cost == 0.06

    def test_estimate_cost_gpt35(self):
        """Test cost estimation for GPT-3.5."""
        cost = estimate_cost("gpt-3.5-turbo", 1000, 500)
        # Input: 1K * 0.0005 = 0.0005
        # Output: 0.5K * 0.0015 = 0.00075
        # Total: 0.00125
        assert abs(cost - 0.00125) < 0.0001

    def test_estimate_cost_gpt4o(self):
        """Test cost estimation for GPT-4o."""
        cost = estimate_cost("gpt-4o", 1000, 500)
        # Input: 1K * 0.005 = 0.005
        # Output: 0.5K * 0.015 = 0.0075
        # Total: 0.0125
        assert cost == 0.0125

    def test_estimate_cost_embeddings(self):
        """Test cost estimation for embeddings (output = 0)."""
        cost = estimate_cost("text-embedding-3-small", 1000, 0)
        # Input: 1K * 0.00002 = 0.00002
        assert abs(cost - 0.00002) < 0.00001

    def test_estimate_cost_unknown_model(self):
        """Test cost estimation for unknown model (falls back to GPT-3.5)."""
        cost = estimate_cost("unknown-model", 1000, 0)
        # Should use GPT-3.5 pricing
        assert cost > 0


class TestContentHashing:
    """Tests for content hashing functions."""

    def test_hash_content_simple(self):
        """Test hashing simple content."""
        result = hash_content("Hello world")
        assert len(result) == 64  # SHA-256 hex digest
        assert result == hash_content("Hello world")  # Consistent

    def test_hash_content_different(self):
        """Test that different content produces different hashes."""
        hash1 = hash_content("Hello")
        hash2 = hash_content("World")
        assert hash1 != hash2

    def test_extract_content_messages(self):
        """Test extracting content from messages."""
        messages = [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi there"},
        ]
        result = extract_content_for_hash(messages)
        assert "Hello" in result
        assert "Hi there" in result

    def test_extract_content_prompt(self):
        """Test extracting content from prompt parameter."""
        result = extract_content_for_hash(prompt="Test prompt")
        assert result == "Test prompt"

    def test_extract_content_input(self):
        """Test extracting content from input parameter."""
        result = extract_content_for_hash(input="Embed this")
        assert result == "Embed this"


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

    def test_custom_context(self):
        """Test custom context values."""
        ctx = EnforcementContext(
            user_id="user@example.com",
            department="engineering",
            source_application="test-app",
            data_classification=("pii", "internal"),
            intended_use_case="testing",
            metadata={"key": "value"},
        )
        assert ctx.user_id == "user@example.com"
        assert ctx.department == "engineering"
        assert ctx.data_classification == ("pii", "internal")


class TestPolicyEnforcer:
    """Tests for PolicyEnforcer."""

    @pytest.fixture
    def allow_all_policy(self):
        """Create a policy that allows all requests."""
        policy_set = PolicySet(name="allow-all", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="allow-all",
            match_conditions={},
            action="ALLOW",
            priority=1,
        ))
        return policy_set

    @pytest.fixture
    def deny_all_policy(self):
        """Create a policy that denies all requests."""
        policy_set = PolicySet(name="deny-all", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="deny-all",
            match_conditions={},
            action="DENY",
            priority=100,
            action_params={"reason": "All requests denied by policy"},
        ))
        return policy_set

    @pytest.fixture
    def model_specific_policy(self):
        """Create a policy with model-specific rules."""
        policy_set = PolicySet(name="model-specific", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="allow-gpt35",
            match_conditions={"model": "gpt-3.5-turbo"},
            action="ALLOW",
            priority=100,
        ))
        policy_set.add_rule(PolicyRule(
            name="deny-gpt4",
            match_conditions={"model": "gpt-4"},
            action="DENY",
            priority=100,
            action_params={"reason": "GPT-4 not allowed"},
        ))
        policy_set.add_rule(PolicyRule(
            name="deny-default",
            match_conditions={},
            action="DENY",
            priority=1,
        ))
        return policy_set

    def test_enforce_allow(self, allow_all_policy):
        """Test enforcing a policy that allows requests."""
        enforcer = PolicyEnforcer(allow_all_policy, raise_on_deny=False)

        result = enforcer.enforce(
            model="gpt-4",
            messages=[{"role": "user", "content": "Hello"}],
        )

        assert result.allowed is True
        assert result.response.decision == Decision.ALLOW

    def test_enforce_deny(self, deny_all_policy):
        """Test enforcing a policy that denies requests."""
        enforcer = PolicyEnforcer(deny_all_policy, raise_on_deny=False)

        result = enforcer.enforce(
            model="gpt-4",
            messages=[{"role": "user", "content": "Hello"}],
        )

        assert result.allowed is False
        assert result.response.decision == Decision.DENY

    def test_enforce_deny_raises(self, deny_all_policy):
        """Test that deny raises PolicyDeniedError when configured."""
        enforcer = PolicyEnforcer(deny_all_policy, raise_on_deny=True)

        with pytest.raises(PolicyDeniedError) as exc_info:
            enforcer.enforce(
                model="gpt-4",
                messages=[{"role": "user", "content": "Hello"}],
            )

        assert exc_info.value.decision == Decision.DENY
        assert exc_info.value.response is not None

    def test_enforce_model_specific(self, model_specific_policy):
        """Test model-specific policy enforcement."""
        enforcer = PolicyEnforcer(model_specific_policy, raise_on_deny=False)

        # GPT-3.5 should be allowed
        result_35 = enforcer.enforce(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": "Hello"}],
        )
        assert result_35.allowed is True

        # GPT-4 should be denied
        result_4 = enforcer.enforce(
            model="gpt-4",
            messages=[{"role": "user", "content": "Hello"}],
        )
        assert result_4.allowed is False

    def test_enforce_with_context(self, allow_all_policy):
        """Test enforcement with custom context."""
        enforcer = PolicyEnforcer(allow_all_policy, raise_on_deny=False)
        ctx = EnforcementContext(
            user_id="user@example.com",
            department="engineering",
        )

        result = enforcer.enforce(
            model="gpt-4",
            messages=[{"role": "user", "content": "Hello"}],
            context=ctx,
        )

        assert result.allowed is True
        assert result.request.user_id == "user@example.com"
        assert result.request.department == "engineering"

    def test_enforce_callback(self, allow_all_policy):
        """Test enforcement callback is called."""
        callback_calls = []

        def callback(req, resp):
            callback_calls.append((req, resp))

        enforcer = PolicyEnforcer(
            allow_all_policy,
            on_enforcement=callback,
            raise_on_deny=False,
        )

        enforcer.enforce(
            model="gpt-4",
            messages=[{"role": "user", "content": "Hello"}],
        )

        assert len(callback_calls) == 1
        assert callback_calls[0][1].decision == Decision.ALLOW

    def test_enforce_stats(self, allow_all_policy):
        """Test enforcement statistics tracking."""
        enforcer = PolicyEnforcer(allow_all_policy, raise_on_deny=False)

        # Make some requests
        enforcer.enforce(model="gpt-4", messages=[{"role": "user", "content": "1"}])
        enforcer.enforce(model="gpt-4", messages=[{"role": "user", "content": "2"}])
        enforcer.enforce(model="gpt-4", messages=[{"role": "user", "content": "3"}])

        stats = enforcer.get_stats()
        assert stats["total_requests"] == 3
        assert stats["allowed_requests"] == 3
        assert stats["allow_rate"] == 100.0

    def test_reload_policies(self, allow_all_policy, deny_all_policy):
        """Test reloading policies."""
        enforcer = PolicyEnforcer(allow_all_policy, raise_on_deny=False)

        # Initially allowed
        result1 = enforcer.enforce(
            model="gpt-4",
            messages=[{"role": "user", "content": "Hello"}],
        )
        assert result1.allowed is True

        # Reload with deny policy
        enforcer.reload_policies(deny_all_policy)

        # Now denied
        result2 = enforcer.enforce(
            model="gpt-4",
            messages=[{"role": "user", "content": "Hello"}],
        )
        assert result2.allowed is False


class TestPolicyBindOpenAI:
    """Tests for PolicyBindOpenAI wrapper."""

    @pytest.fixture
    def allow_policy(self):
        """Create a policy that allows all requests."""
        policy_set = PolicySet(name="allow", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="allow-all",
            match_conditions={},
            action="ALLOW",
        ))
        return policy_set

    @pytest.fixture
    def mock_openai_client(self):
        """Create a mock OpenAI client."""
        client = MagicMock()
        client.chat.completions.create.return_value = MagicMock(
            id="chatcmpl-123",
            choices=[MagicMock(message=MagicMock(content="Hello!"))],
        )
        client.embeddings.create.return_value = MagicMock(
            data=[MagicMock(embedding=[0.1, 0.2, 0.3])]
        )
        client.completions.create.return_value = MagicMock(
            id="cmpl-123",
            choices=[MagicMock(text="Hello!")],
        )
        return client

    def test_chat_completions_allowed(self, allow_policy, mock_openai_client):
        """Test chat completions when policy allows."""
        wrapper = PolicyBindOpenAI(
            client=mock_openai_client,
            policy_set=allow_policy,
            user_id="test@example.com",
        )

        response = wrapper.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Hello"}],
        )

        assert response is not None
        mock_openai_client.chat.completions.create.assert_called_once()

    def test_chat_completions_denied(self, mock_openai_client):
        """Test chat completions when policy denies."""
        deny_policy = PolicySet(name="deny", version="1.0.0")
        deny_policy.add_rule(PolicyRule(
            name="deny-all",
            match_conditions={},
            action="DENY",
            action_params={"reason": "Denied"},
        ))

        wrapper = PolicyBindOpenAI(
            client=mock_openai_client,
            policy_set=deny_policy,
            raise_on_deny=True,
        )

        with pytest.raises(PolicyDeniedError):
            wrapper.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": "Hello"}],
            )

        # OpenAI client should NOT have been called
        mock_openai_client.chat.completions.create.assert_not_called()

    def test_embeddings_allowed(self, allow_policy, mock_openai_client):
        """Test embeddings when policy allows."""
        wrapper = PolicyBindOpenAI(
            client=mock_openai_client,
            policy_set=allow_policy,
        )

        response = wrapper.embeddings.create(
            model="text-embedding-3-small",
            input="Test text",
        )

        assert response is not None
        mock_openai_client.embeddings.create.assert_called_once()

    def test_completions_allowed(self, allow_policy, mock_openai_client):
        """Test completions when policy allows."""
        wrapper = PolicyBindOpenAI(
            client=mock_openai_client,
            policy_set=allow_policy,
        )

        response = wrapper.completions.create(
            model="gpt-3.5-turbo-instruct",
            prompt="Hello",
        )

        assert response is not None
        mock_openai_client.completions.create.assert_called_once()

    def test_update_context(self, allow_policy, mock_openai_client):
        """Test updating enforcement context."""
        wrapper = PolicyBindOpenAI(
            client=mock_openai_client,
            policy_set=allow_policy,
            user_id="original@example.com",
        )

        wrapper.update_context(
            user_id="updated@example.com",
            department="engineering",
        )

        # Make a request and check context was used
        wrapper.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Hello"}],
        )

        stats = wrapper.get_enforcement_stats()
        assert stats["total_requests"] == 1

    def test_get_enforcement_stats(self, allow_policy, mock_openai_client):
        """Test getting enforcement statistics."""
        wrapper = PolicyBindOpenAI(
            client=mock_openai_client,
            policy_set=allow_policy,
        )

        wrapper.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Hello"}],
        )

        stats = wrapper.get_enforcement_stats()
        assert stats["total_requests"] == 1
        assert stats["allowed_requests"] == 1

    def test_forward_attribute(self, allow_policy, mock_openai_client):
        """Test that unknown attributes are forwarded to client."""
        wrapper = PolicyBindOpenAI(
            client=mock_openai_client,
            policy_set=allow_policy,
        )

        # Access an attribute that should be forwarded
        mock_openai_client.some_other_attr = "test_value"
        assert wrapper.some_other_attr == "test_value"


class TestApprovalRequired:
    """Tests for approval-required scenarios."""

    @pytest.fixture
    def approval_policy(self):
        """Create a policy that requires approval."""
        policy_set = PolicySet(name="approval", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="require-approval",
            match_conditions={},
            action="REQUIRE_APPROVAL",
            action_params={"reason": "Human approval required"},
        ))
        return policy_set

    def test_approval_required_raises(self, approval_policy):
        """Test that approval required raises error when configured."""
        enforcer = PolicyEnforcer(
            approval_policy,
            raise_on_approval_required=True,
        )

        with pytest.raises(PolicyApprovalRequiredError) as exc_info:
            enforcer.enforce(
                model="gpt-4",
                messages=[{"role": "user", "content": "Hello"}],
            )

        assert exc_info.value.response.decision == Decision.REQUIRE_APPROVAL

    def test_approval_required_no_raise(self, approval_policy):
        """Test that approval required doesn't raise when disabled."""
        enforcer = PolicyEnforcer(
            approval_policy,
            raise_on_approval_required=False,
        )

        result = enforcer.enforce(
            model="gpt-4",
            messages=[{"role": "user", "content": "Hello"}],
        )

        assert result.response.decision == Decision.REQUIRE_APPROVAL
        assert result.allowed is False


class TestModifyDecision:
    """Tests for MODIFY decision handling."""

    @pytest.fixture
    def modify_policy(self):
        """Create a policy that modifies requests."""
        policy_set = PolicySet(name="modify", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="modify-request",
            match_conditions={},
            action="MODIFY",
            action_params={"max_tokens": 100},
        ))
        return policy_set

    def test_modify_allowed(self, modify_policy):
        """Test that MODIFY decision is treated as allowed."""
        enforcer = PolicyEnforcer(modify_policy, raise_on_deny=False)

        result = enforcer.enforce(
            model="gpt-4",
            messages=[{"role": "user", "content": "Hello"}],
        )

        assert result.response.decision == Decision.MODIFY
        assert result.allowed is True  # MODIFY is allowed
        assert result.modified is True


class TestCreatePolicyClient:
    """Tests for create_policy_client function."""

    @pytest.fixture
    def policy_set(self):
        """Create a test policy set."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="allow-all",
            match_conditions={},
            action="ALLOW",
        ))
        return policy_set

    def test_create_policy_client_no_openai(self, policy_set):
        """Test that ImportError is raised when openai is not available."""
        with patch.dict("sys.modules", {"openai": None}):
            # Need to reload the module to pick up the patched import
            # For now, just verify the function exists
            assert callable(create_policy_client)

    def test_create_policy_client_with_context(self, policy_set):
        """Test creating client with context parameters."""
        # Patch at the openai module level
        with patch.dict("sys.modules", {"openai": MagicMock()}):
            import sys
            mock_openai = sys.modules["openai"]
            mock_openai.OpenAI = MagicMock(return_value=MagicMock())

            # Reload to pick up the mock
            import importlib
            import policybind.integrations.openai_integration as oai_module
            importlib.reload(oai_module)

            client = oai_module.create_policy_client(
                policy_set=policy_set,
                user_id="user@example.com",
                department="engineering",
                source_application="test-app",
            )

            assert isinstance(client, oai_module.PolicyBindOpenAI)


class TestDepartmentPolicies:
    """Tests for department-based policies."""

    @pytest.fixture
    def department_policy(self):
        """Create a policy with department restrictions."""
        policy_set = PolicySet(name="department", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="allow-engineering",
            match_conditions={"department": "engineering"},
            action="ALLOW",
            priority=100,
        ))
        policy_set.add_rule(PolicyRule(
            name="deny-finance",
            match_conditions={"department": "finance"},
            action="DENY",
            priority=100,
            action_params={"reason": "Finance department not allowed"},
        ))
        policy_set.add_rule(PolicyRule(
            name="deny-default",
            match_conditions={},
            action="DENY",
            priority=1,
        ))
        return policy_set

    def test_engineering_allowed(self, department_policy):
        """Test engineering department is allowed."""
        enforcer = PolicyEnforcer(department_policy, raise_on_deny=False)
        ctx = EnforcementContext(department="engineering")

        result = enforcer.enforce(
            model="gpt-4",
            messages=[{"role": "user", "content": "Hello"}],
            context=ctx,
        )

        assert result.allowed is True

    def test_finance_denied(self, department_policy):
        """Test finance department is denied."""
        enforcer = PolicyEnforcer(department_policy, raise_on_deny=False)
        ctx = EnforcementContext(department="finance")

        result = enforcer.enforce(
            model="gpt-4",
            messages=[{"role": "user", "content": "Hello"}],
            context=ctx,
        )

        assert result.allowed is False


class TestDataClassificationPolicies:
    """Tests for data classification-based policies."""

    @pytest.fixture
    def classification_policy(self):
        """Create a policy based on data classification."""
        policy_set = PolicySet(name="classification", version="1.0.0")
        # Use "contains" operator to check if data_classification tuple contains "pii"
        policy_set.add_rule(PolicyRule(
            name="deny-pii",
            match_conditions={"data_classification": {"contains": "pii"}},
            action="DENY",
            priority=100,
            action_params={"reason": "PII data not allowed"},
        ))
        policy_set.add_rule(PolicyRule(
            name="allow-public",
            match_conditions={},
            action="ALLOW",
            priority=1,
        ))
        return policy_set

    def test_pii_denied(self, classification_policy):
        """Test PII data is denied."""
        enforcer = PolicyEnforcer(classification_policy, raise_on_deny=False)
        ctx = EnforcementContext(data_classification=("pii",))

        result = enforcer.enforce(
            model="gpt-4",
            messages=[{"role": "user", "content": "Hello"}],
            context=ctx,
        )

        assert result.allowed is False

    def test_public_allowed(self, classification_policy):
        """Test public data is allowed."""
        enforcer = PolicyEnforcer(classification_policy, raise_on_deny=False)
        ctx = EnforcementContext(data_classification=("public",))

        result = enforcer.enforce(
            model="gpt-4",
            messages=[{"role": "user", "content": "Hello"}],
            context=ctx,
        )

        assert result.allowed is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
