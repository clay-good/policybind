"""
Tests for the Hugging Face Hub SDK integration.

Tests the policy enforcement wrapper for the Hugging Face InferenceClient.
"""

import pytest
from unittest.mock import MagicMock, patch

from policybind.integrations.huggingface_integration import (
    AudioClassificationWrapper,
    AutomaticSpeechRecognitionWrapper,
    ChatCompletionWrapper,
    EnforcementContext,
    EnforcementResult,
    FeatureExtractionWrapper,
    FillMaskWrapper,
    ImageClassificationWrapper,
    ImageSegmentationWrapper,
    ImageToTextWrapper,
    ObjectDetectionWrapper,
    PolicyApprovalRequiredError,
    PolicyBindHuggingFace,
    PolicyDeniedError,
    PolicyEnforcer,
    QuestionAnsweringWrapper,
    SentenceSimilarityWrapper,
    SummarizationWrapper,
    TextClassificationWrapper,
    TextGenerationWrapper,
    TextToImageWrapper,
    TextToSpeechWrapper,
    TokenClassificationWrapper,
    TranslationWrapper,
    ZeroShotClassificationWrapper,
    calculate_cost,
    create_policy_client,
    estimate_message_tokens,
    estimate_tokens,
    extract_content_for_hash,
    get_model_metadata,
    get_model_pricing,
    hash_content,
    wrap_client,
)
from policybind.models.policy import PolicyRule, PolicySet
from policybind.models.request import Decision


class TestTokenEstimation:
    """Tests for token estimation functions."""

    def test_estimate_tokens_empty(self):
        """Test token estimation for empty string."""
        assert estimate_tokens("") == 0

    def test_estimate_tokens_simple(self):
        """Test token estimation for simple text."""
        # 5 words * 1.3 tokens/word = 6.5, rounded to 6
        result = estimate_tokens("Hello world how are you")
        assert result == 6

    def test_estimate_tokens_longer(self):
        """Test token estimation for longer text."""
        text = "This is a much longer sentence with many more words to count"
        result = estimate_tokens(text)
        assert result > 0
        assert result == int(len(text.split()) * 1.3)

    def test_estimate_message_tokens(self):
        """Test token estimation for chat messages."""
        messages = [
            {"role": "user", "content": "Hello world"},
            {"role": "assistant", "content": "Hi there"},
        ]
        result = estimate_message_tokens(messages)
        # Should include overhead + content tokens
        assert result > 0

    def test_estimate_message_tokens_multimodal(self):
        """Test token estimation for multimodal messages."""
        messages = [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Hello"},
                    {"type": "image_url", "image_url": {"url": "http://example.com/img.png"}},
                ],
            }
        ]
        result = estimate_message_tokens(messages)
        # Should include text tokens + image token overhead
        assert result > 85  # At least the image overhead


class TestModelInfo:
    """Tests for model information retrieval."""

    def test_get_model_pricing_known_model(self):
        """Test getting pricing for a known model."""
        pricing = get_model_pricing("meta-llama/Llama-3.1-8B-Instruct")
        assert "input" in pricing
        assert "output" in pricing
        assert pricing["input"] > 0

    def test_get_model_pricing_partial_match(self):
        """Test getting pricing with partial model name match."""
        pricing = get_model_pricing("llama-3.1-8b")
        assert "input" in pricing
        assert "output" in pricing

    def test_get_model_pricing_unknown(self):
        """Test getting pricing for unknown model returns defaults."""
        pricing = get_model_pricing("unknown-model-xyz")
        assert pricing["input"] == 0.10
        assert pricing["output"] == 0.15

    def test_get_model_metadata_known(self):
        """Test getting metadata for a known model."""
        metadata = get_model_metadata("meta-llama/Llama-3.1-70B-Instruct")
        assert metadata["params"] == "70b"
        assert metadata["context"] == 131072
        assert metadata["type"] == "text"

    def test_get_model_metadata_embedding(self):
        """Test getting metadata for embedding model."""
        metadata = get_model_metadata("sentence-transformers/all-MiniLM-L6-v2")
        assert metadata["type"] == "embedding"

    def test_get_model_metadata_image(self):
        """Test getting metadata for image model."""
        metadata = get_model_metadata("black-forest-labs/FLUX.1-dev")
        assert metadata["type"] == "image"

    def test_get_model_metadata_unknown(self):
        """Test getting metadata for unknown model."""
        metadata = get_model_metadata("unknown-model")
        assert metadata["params"] == "unknown"
        assert metadata["context"] == 4096
        assert metadata["type"] == "text"

    def test_calculate_cost(self):
        """Test cost calculation."""
        cost = calculate_cost("meta-llama/Llama-3.1-8B-Instruct", 1000, 500)
        assert cost > 0
        assert cost < 1.0  # Should be very small for this many tokens

    def test_calculate_cost_per_image(self):
        """Test cost calculation for per-image pricing."""
        cost = calculate_cost("black-forest-labs/FLUX.1-dev", 0, 0)
        # Per-image models return the per-image cost
        assert cost == 0.025


class TestContentHashing:
    """Tests for content hashing."""

    def test_hash_content_produces_hex(self):
        """Test that hash produces hex string."""
        result = hash_content("test content")
        assert len(result) == 64  # SHA-256 hex length
        assert all(c in "0123456789abcdef" for c in result)

    def test_hash_content_deterministic(self):
        """Test that same content produces same hash."""
        content = "test content"
        assert hash_content(content) == hash_content(content)

    def test_hash_content_different_for_different_content(self):
        """Test that different content produces different hash."""
        assert hash_content("content1") != hash_content("content2")

    def test_extract_content_for_hash_prompt(self):
        """Test content extraction from prompt."""
        content = extract_content_for_hash(prompt="Hello world")
        assert content == "Hello world"

    def test_extract_content_for_hash_text(self):
        """Test content extraction from text."""
        content = extract_content_for_hash(text="Some text")
        assert content == "Some text"

    def test_extract_content_for_hash_text_list(self):
        """Test content extraction from text list."""
        content = extract_content_for_hash(text=["text1", "text2"])
        assert "text1" in content
        assert "text2" in content

    def test_extract_content_for_hash_messages(self):
        """Test content extraction from messages."""
        messages = [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi there"},
        ]
        content = extract_content_for_hash(messages=messages)
        assert "Hello" in content
        assert "Hi there" in content


class TestEnforcementContext:
    """Tests for EnforcementContext dataclass."""

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
        """Test context with specified values."""
        ctx = EnforcementContext(
            user_id="user@test.com",
            department="engineering",
            source_application="test-app",
            data_classification=("pii", "confidential"),
            intended_use_case="testing",
            metadata={"key": "value"},
        )
        assert ctx.user_id == "user@test.com"
        assert ctx.department == "engineering"
        assert ctx.data_classification == ("pii", "confidential")
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
            priority=100,
        )
        return PolicySet(name="test-policies", rules=[rule])

    @pytest.fixture
    def deny_policy_set(self):
        """Create a policy set that denies all requests."""
        rule = PolicyRule(
            name="deny-all",
            description="Deny all requests",
            match_conditions={},
            action="DENY",
            action_params={"reason": "Request denied by policy"},
            priority=100,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_enforcer_creation(self, allow_policy_set):
        """Test creating an enforcer."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        assert enforcer.policy_set == allow_policy_set
        assert enforcer.stats["total_requests"] == 0

    def test_enforcer_with_context(self, allow_policy_set):
        """Test creating an enforcer with context."""
        ctx = EnforcementContext(user_id="test@test.com")
        enforcer = PolicyEnforcer(policy_set=allow_policy_set, context=ctx)
        assert enforcer.context.user_id == "test@test.com"

    def test_enforce_allowed(self, allow_policy_set):
        """Test enforcing an allowed request."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model="meta-llama/Llama-3.1-8B-Instruct",
            content="Hello world",
            request_type="chat_completion",
        )
        assert result.allowed
        assert enforcer.stats["allowed_requests"] == 1

    def test_enforce_denied(self, deny_policy_set):
        """Test enforcing a denied request raises error."""
        enforcer = PolicyEnforcer(policy_set=deny_policy_set)
        with pytest.raises(PolicyDeniedError):
            enforcer.enforce(
                model="meta-llama/Llama-3.1-8B-Instruct",
                content="Hello world",
            )
        assert enforcer.stats["denied_requests"] == 1

    def test_enforce_denied_no_raise(self, deny_policy_set):
        """Test enforcing a denied request without raising."""
        enforcer = PolicyEnforcer(policy_set=deny_policy_set, raise_on_deny=False)
        result = enforcer.enforce(
            model="meta-llama/Llama-3.1-8B-Instruct",
            content="Hello world",
        )
        assert not result.allowed

    def test_enforce_callback(self, allow_policy_set):
        """Test enforcement callback is called."""
        callback_called = {"value": False}

        def callback(request, response):
            callback_called["value"] = True

        enforcer = PolicyEnforcer(
            policy_set=allow_policy_set,
            on_enforcement=callback,
        )
        enforcer.enforce(
            model="meta-llama/Llama-3.1-8B-Instruct",
            content="Hello",
        )
        assert callback_called["value"]

    def test_enforce_cost_tracking(self, allow_policy_set):
        """Test that cost is tracked."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        enforcer.enforce(
            model="meta-llama/Llama-3.1-8B-Instruct",
            content="Hello world test",
        )
        assert enforcer.stats["total_cost"] > 0

    def test_enforce_huggingface_metadata(self, allow_policy_set):
        """Test Hugging Face specific metadata."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model="meta-llama/Llama-3.1-8B-Instruct",
            content="Hello",
            request_type="chat_completion",
        )
        assert result.request.metadata["huggingface"] is True
        assert result.request.metadata["request_type"] == "chat_completion"


class TestChatCompletionWrapper:
    """Tests for ChatCompletionWrapper."""

    @pytest.fixture
    def allow_policy_set(self):
        """Create a policy set that allows all requests."""
        rule = PolicyRule(
            name="allow-all",
            description="Allow all requests",
            match_conditions={},
            action="ALLOW",
            priority=100,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_chat_completion_allowed(self, allow_policy_set):
        """Test chat completion when allowed."""
        mock_client = MagicMock()
        mock_client.model = "meta-llama/Llama-3.1-8B-Instruct"
        mock_client.chat_completion.return_value = {"content": "Hi!"}

        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = ChatCompletionWrapper(mock_client, enforcer)

        result = wrapper(
            messages=[{"role": "user", "content": "Hello"}],
            model="meta-llama/Llama-3.1-8B-Instruct",
        )

        assert result == {"content": "Hi!"}
        mock_client.chat_completion.assert_called_once()

    def test_chat_completion_with_stream(self, allow_policy_set):
        """Test chat completion with streaming."""
        mock_client = MagicMock()
        mock_client.model = "meta-llama/Llama-3.1-8B-Instruct"

        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = ChatCompletionWrapper(mock_client, enforcer)

        wrapper(
            messages=[{"role": "user", "content": "Hello"}],
            stream=True,
        )

        mock_client.chat_completion.assert_called_with(
            messages=[{"role": "user", "content": "Hello"}],
            model=None,
            stream=True,
        )


class TestTextGenerationWrapper:
    """Tests for TextGenerationWrapper."""

    @pytest.fixture
    def allow_policy_set(self):
        """Create a policy set that allows all requests."""
        rule = PolicyRule(
            name="allow-all",
            description="Allow all requests",
            match_conditions={},
            action="ALLOW",
            priority=100,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_text_generation_allowed(self, allow_policy_set):
        """Test text generation when allowed."""
        mock_client = MagicMock()
        mock_client.model = "mistralai/Mistral-7B-Instruct-v0.3"
        mock_client.text_generation.return_value = "Once upon a time..."

        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = TextGenerationWrapper(mock_client, enforcer)

        result = wrapper(
            prompt="Once upon a time",
            model="mistralai/Mistral-7B-Instruct-v0.3",
        )

        assert result == "Once upon a time..."
        mock_client.text_generation.assert_called_once()


class TestFeatureExtractionWrapper:
    """Tests for FeatureExtractionWrapper."""

    @pytest.fixture
    def allow_policy_set(self):
        """Create a policy set that allows all requests."""
        rule = PolicyRule(
            name="allow-all",
            description="Allow all requests",
            match_conditions={},
            action="ALLOW",
            priority=100,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_feature_extraction_single_text(self, allow_policy_set):
        """Test feature extraction with single text."""
        mock_client = MagicMock()
        mock_client.model = "sentence-transformers/all-MiniLM-L6-v2"
        mock_client.feature_extraction.return_value = [[0.1, 0.2, 0.3]]

        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = FeatureExtractionWrapper(mock_client, enforcer)

        result = wrapper(
            text="Hello world",
            model="sentence-transformers/all-MiniLM-L6-v2",
        )

        assert result == [[0.1, 0.2, 0.3]]
        mock_client.feature_extraction.assert_called_once()

    def test_feature_extraction_multiple_texts(self, allow_policy_set):
        """Test feature extraction with multiple texts."""
        mock_client = MagicMock()
        mock_client.model = "sentence-transformers/all-MiniLM-L6-v2"
        mock_client.feature_extraction.return_value = [[0.1, 0.2], [0.3, 0.4]]

        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = FeatureExtractionWrapper(mock_client, enforcer)

        result = wrapper(
            text=["Hello", "World"],
        )

        assert len(result) == 2


class TestTextClassificationWrapper:
    """Tests for TextClassificationWrapper."""

    @pytest.fixture
    def allow_policy_set(self):
        """Create a policy set that allows all requests."""
        rule = PolicyRule(
            name="allow-all",
            description="Allow all requests",
            match_conditions={},
            action="ALLOW",
            priority=100,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_text_classification(self, allow_policy_set):
        """Test text classification."""
        mock_client = MagicMock()
        mock_client.model = "distilbert-base-uncased-finetuned-sst-2-english"
        mock_client.text_classification.return_value = [{"label": "POSITIVE", "score": 0.99}]

        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = TextClassificationWrapper(mock_client, enforcer)

        result = wrapper(text="I love this!")

        assert result[0]["label"] == "POSITIVE"


class TestZeroShotClassificationWrapper:
    """Tests for ZeroShotClassificationWrapper."""

    @pytest.fixture
    def allow_policy_set(self):
        """Create a policy set that allows all requests."""
        rule = PolicyRule(
            name="allow-all",
            description="Allow all requests",
            match_conditions={},
            action="ALLOW",
            priority=100,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_zero_shot_classification(self, allow_policy_set):
        """Test zero-shot classification."""
        mock_client = MagicMock()
        mock_client.model = "facebook/bart-large-mnli"
        mock_client.zero_shot_classification.return_value = {
            "labels": ["positive", "negative"],
            "scores": [0.9, 0.1],
        }

        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = ZeroShotClassificationWrapper(mock_client, enforcer)

        result = wrapper(
            text="I love this product!",
            candidate_labels=["positive", "negative"],
        )

        assert "labels" in result


class TestQuestionAnsweringWrapper:
    """Tests for QuestionAnsweringWrapper."""

    @pytest.fixture
    def allow_policy_set(self):
        """Create a policy set that allows all requests."""
        rule = PolicyRule(
            name="allow-all",
            description="Allow all requests",
            match_conditions={},
            action="ALLOW",
            priority=100,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_question_answering(self, allow_policy_set):
        """Test question answering."""
        mock_client = MagicMock()
        mock_client.model = "deepset/roberta-base-squad2"
        mock_client.question_answering.return_value = {
            "answer": "Paris",
            "score": 0.99,
        }

        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = QuestionAnsweringWrapper(mock_client, enforcer)

        result = wrapper(
            question="What is the capital of France?",
            context="The capital of France is Paris.",
        )

        assert result["answer"] == "Paris"


class TestSummarizationWrapper:
    """Tests for SummarizationWrapper."""

    @pytest.fixture
    def allow_policy_set(self):
        """Create a policy set that allows all requests."""
        rule = PolicyRule(
            name="allow-all",
            description="Allow all requests",
            match_conditions={},
            action="ALLOW",
            priority=100,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_summarization(self, allow_policy_set):
        """Test summarization."""
        mock_client = MagicMock()
        mock_client.model = "facebook/bart-large-cnn"
        mock_client.summarization.return_value = {"summary_text": "Summary here."}

        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = SummarizationWrapper(mock_client, enforcer)

        result = wrapper(text="Long text to summarize...")

        assert "summary_text" in result


class TestTranslationWrapper:
    """Tests for TranslationWrapper."""

    @pytest.fixture
    def allow_policy_set(self):
        """Create a policy set that allows all requests."""
        rule = PolicyRule(
            name="allow-all",
            description="Allow all requests",
            match_conditions={},
            action="ALLOW",
            priority=100,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_translation(self, allow_policy_set):
        """Test translation."""
        mock_client = MagicMock()
        mock_client.model = "Helsinki-NLP/opus-mt-en-fr"
        mock_client.translation.return_value = {"translation_text": "Bonjour"}

        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = TranslationWrapper(mock_client, enforcer)

        result = wrapper(text="Hello")

        assert "translation_text" in result


class TestTextToImageWrapper:
    """Tests for TextToImageWrapper."""

    @pytest.fixture
    def allow_policy_set(self):
        """Create a policy set that allows all requests."""
        rule = PolicyRule(
            name="allow-all",
            description="Allow all requests",
            match_conditions={},
            action="ALLOW",
            priority=100,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_text_to_image(self, allow_policy_set):
        """Test text to image."""
        mock_client = MagicMock()
        mock_client.model = "black-forest-labs/FLUX.1-dev"
        mock_client.text_to_image.return_value = b"fake_image_data"

        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = TextToImageWrapper(mock_client, enforcer)

        result = wrapper(prompt="A beautiful sunset")

        assert result == b"fake_image_data"

    def test_text_to_image_with_negative_prompt(self, allow_policy_set):
        """Test text to image with negative prompt."""
        mock_client = MagicMock()
        mock_client.model = "black-forest-labs/FLUX.1-dev"

        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = TextToImageWrapper(mock_client, enforcer)

        wrapper(
            prompt="A beautiful sunset",
            negative_prompt="blurry, low quality",
        )

        mock_client.text_to_image.assert_called_once()


class TestImageWrappers:
    """Tests for image-related wrappers."""

    @pytest.fixture
    def allow_policy_set(self):
        """Create a policy set that allows all requests."""
        rule = PolicyRule(
            name="allow-all",
            description="Allow all requests",
            match_conditions={},
            action="ALLOW",
            priority=100,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_image_classification(self, allow_policy_set):
        """Test image classification."""
        mock_client = MagicMock()
        mock_client.model = "google/vit-base-patch16-224"
        mock_client.image_classification.return_value = [{"label": "cat", "score": 0.99}]

        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = ImageClassificationWrapper(mock_client, enforcer)

        result = wrapper(image=b"fake_image")

        assert result[0]["label"] == "cat"

    def test_image_to_text(self, allow_policy_set):
        """Test image to text."""
        mock_client = MagicMock()
        mock_client.model = "Salesforce/blip-image-captioning-base"
        mock_client.image_to_text.return_value = {"generated_text": "A cat sitting"}

        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = ImageToTextWrapper(mock_client, enforcer)

        result = wrapper(image=b"fake_image")

        assert "generated_text" in result

    def test_object_detection(self, allow_policy_set):
        """Test object detection."""
        mock_client = MagicMock()
        mock_client.model = "facebook/detr-resnet-50"
        mock_client.object_detection.return_value = [{"label": "cat", "box": {}}]

        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = ObjectDetectionWrapper(mock_client, enforcer)

        result = wrapper(image=b"fake_image")

        assert result[0]["label"] == "cat"

    def test_image_segmentation(self, allow_policy_set):
        """Test image segmentation."""
        mock_client = MagicMock()
        mock_client.model = "facebook/mask2former-swin-base-coco-panoptic"
        mock_client.image_segmentation.return_value = [{"label": "sky", "mask": b"mask"}]

        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = ImageSegmentationWrapper(mock_client, enforcer)

        result = wrapper(image=b"fake_image")

        assert result[0]["label"] == "sky"


class TestAudioWrappers:
    """Tests for audio-related wrappers."""

    @pytest.fixture
    def allow_policy_set(self):
        """Create a policy set that allows all requests."""
        rule = PolicyRule(
            name="allow-all",
            description="Allow all requests",
            match_conditions={},
            action="ALLOW",
            priority=100,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_automatic_speech_recognition(self, allow_policy_set):
        """Test automatic speech recognition."""
        mock_client = MagicMock()
        mock_client.model = "openai/whisper-large-v3"
        mock_client.automatic_speech_recognition.return_value = {"text": "Hello world"}

        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = AutomaticSpeechRecognitionWrapper(mock_client, enforcer)

        result = wrapper(audio=b"fake_audio")

        assert result["text"] == "Hello world"

    def test_text_to_speech(self, allow_policy_set):
        """Test text to speech."""
        mock_client = MagicMock()
        mock_client.model = "facebook/mms-tts-eng"
        mock_client.text_to_speech.return_value = b"audio_data"

        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = TextToSpeechWrapper(mock_client, enforcer)

        result = wrapper(text="Hello world")

        assert result == b"audio_data"

    def test_audio_classification(self, allow_policy_set):
        """Test audio classification."""
        mock_client = MagicMock()
        mock_client.model = "MIT/ast-finetuned-audioset-10-10-0.4593"
        mock_client.audio_classification.return_value = [{"label": "music", "score": 0.99}]

        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = AudioClassificationWrapper(mock_client, enforcer)

        result = wrapper(audio=b"fake_audio")

        assert result[0]["label"] == "music"


class TestPolicyBindHuggingFace:
    """Tests for PolicyBindHuggingFace wrapper class."""

    @pytest.fixture
    def allow_policy_set(self):
        """Create a policy set that allows all requests."""
        rule = PolicyRule(
            name="allow-all",
            description="Allow all requests",
            match_conditions={},
            action="ALLOW",
            priority=100,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_wrapper_creation(self, allow_policy_set):
        """Test creating a wrapper."""
        mock_client = MagicMock()
        mock_client.model = "test-model"

        wrapper = PolicyBindHuggingFace(
            client=mock_client,
            policy_set=allow_policy_set,
            user_id="test@test.com",
            department="engineering",
        )

        assert wrapper.model == "test-model"
        assert hasattr(wrapper, "chat_completion")
        assert hasattr(wrapper, "text_generation")
        assert hasattr(wrapper, "feature_extraction")

    def test_wrapper_stats(self, allow_policy_set):
        """Test wrapper statistics."""
        mock_client = MagicMock()
        mock_client.model = "meta-llama/Llama-3.1-8B-Instruct"
        mock_client.chat_completion.return_value = {"content": "Hi"}

        wrapper = PolicyBindHuggingFace(
            client=mock_client,
            policy_set=allow_policy_set,
        )

        wrapper.chat_completion(
            messages=[{"role": "user", "content": "Hello"}],
        )

        assert wrapper.stats["total_requests"] == 1
        assert wrapper.stats["allowed_requests"] == 1

    def test_wrapper_passthrough(self, allow_policy_set):
        """Test attribute passthrough to underlying client."""
        mock_client = MagicMock()
        mock_client.custom_attr = "custom_value"

        wrapper = PolicyBindHuggingFace(
            client=mock_client,
            policy_set=allow_policy_set,
        )

        assert wrapper.custom_attr == "custom_value"

    def test_wrapper_all_methods(self, allow_policy_set):
        """Test that all expected methods are wrapped."""
        mock_client = MagicMock()

        wrapper = PolicyBindHuggingFace(
            client=mock_client,
            policy_set=allow_policy_set,
        )

        # Check all wrapped methods exist
        assert hasattr(wrapper, "chat_completion")
        assert hasattr(wrapper, "text_generation")
        assert hasattr(wrapper, "feature_extraction")
        assert hasattr(wrapper, "sentence_similarity")
        assert hasattr(wrapper, "text_classification")
        assert hasattr(wrapper, "token_classification")
        assert hasattr(wrapper, "fill_mask")
        assert hasattr(wrapper, "zero_shot_classification")
        assert hasattr(wrapper, "question_answering")
        assert hasattr(wrapper, "summarization")
        assert hasattr(wrapper, "translation")
        assert hasattr(wrapper, "text_to_image")
        assert hasattr(wrapper, "image_classification")
        assert hasattr(wrapper, "image_to_text")
        assert hasattr(wrapper, "object_detection")
        assert hasattr(wrapper, "image_segmentation")
        assert hasattr(wrapper, "automatic_speech_recognition")
        assert hasattr(wrapper, "text_to_speech")
        assert hasattr(wrapper, "audio_classification")


class TestApprovalRequired:
    """Tests for approval required handling."""

    @pytest.fixture
    def approval_policy_set(self):
        """Create a policy set that requires approval."""
        rule = PolicyRule(
            name="require-approval",
            description="Require approval for all requests",
            match_conditions={},
            action="REQUIRE_APPROVAL",
            action_params={"reason": "All requests need approval"},
            priority=100,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_approval_required_raises(self, approval_policy_set):
        """Test that approval required raises error."""
        enforcer = PolicyEnforcer(policy_set=approval_policy_set)
        with pytest.raises(PolicyApprovalRequiredError):
            enforcer.enforce(
                model="meta-llama/Llama-3.1-8B-Instruct",
                content="Hello",
            )

    def test_approval_required_no_raise(self, approval_policy_set):
        """Test approval required without raising."""
        enforcer = PolicyEnforcer(
            policy_set=approval_policy_set,
            raise_on_approval_required=False,
        )
        result = enforcer.enforce(
            model="meta-llama/Llama-3.1-8B-Instruct",
            content="Hello",
        )
        assert not result.allowed


class TestModifyDecision:
    """Tests for modify decision handling."""

    @pytest.fixture
    def modify_policy_set(self):
        """Create a policy set that modifies requests."""
        rule = PolicyRule(
            name="modify-all",
            description="Modify all requests",
            match_conditions={},
            action="MODIFY",
            action_params={"redact_patterns": ["secret"]},
            priority=100,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_modify_decision(self, modify_policy_set):
        """Test that modify decision is handled."""
        enforcer = PolicyEnforcer(policy_set=modify_policy_set)
        result = enforcer.enforce(
            model="meta-llama/Llama-3.1-8B-Instruct",
            content="Hello",
        )
        assert result.modified
        assert enforcer.stats["modified_requests"] == 1


class TestCreatePolicyClient:
    """Tests for create_policy_client function."""

    @pytest.fixture
    def allow_policy_set(self):
        """Create a policy set that allows all requests."""
        rule = PolicyRule(
            name="allow-all",
            description="Allow all requests",
            match_conditions={},
            action="ALLOW",
            priority=100,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_create_policy_client_without_sdk(self, allow_policy_set):
        """Test create_policy_client raises ImportError without SDK."""
        with patch.dict("sys.modules", {"huggingface_hub": None}):
            with pytest.raises(ImportError) as exc_info:
                create_policy_client(
                    policy_set=allow_policy_set,
                    user_id="test@example.com",
                )
            assert "huggingface_hub" in str(exc_info.value)

    def test_create_policy_client_with_mock(self, allow_policy_set):
        """Test create_policy_client creates a wrapped client."""
        mock_hf = MagicMock()
        mock_client = MagicMock()
        mock_hf.InferenceClient.return_value = mock_client

        with patch.dict("sys.modules", {"huggingface_hub": mock_hf}):
            # Need to reimport to pick up the mock
            from policybind.integrations import huggingface_integration
            import importlib
            importlib.reload(huggingface_integration)

            client = huggingface_integration.create_policy_client(
                policy_set=allow_policy_set,
                model="meta-llama/Llama-3.1-8B-Instruct",
                token="hf_test_token",
                user_id="test@example.com",
            )

            # Use class name check to avoid reload issues
            assert client.__class__.__name__ == "PolicyBindHuggingFace"
            mock_hf.InferenceClient.assert_called_once()


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
            priority=100,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_wrap_client(self, allow_policy_set):
        """Test wrap_client wraps an existing client."""
        mock_client = MagicMock()

        wrapped = wrap_client(
            client=mock_client,
            policy_set=allow_policy_set,
            user_id="test@example.com",
        )

        assert wrapped.__class__.__name__ == "PolicyBindHuggingFace"


class TestDepartmentPolicies:
    """Tests for department-based policies."""

    @pytest.fixture
    def department_policy_set(self):
        """Create a policy set with department restrictions."""
        deny_rule = PolicyRule(
            name="deny-marketing-large",
            description="Deny marketing department for large models",
            match_conditions={
                "department": {"eq": "marketing"},
                "model": {"contains": "70B"},  # uppercase B to match model naming
            },
            action="DENY",
            action_params={"reason": "Large models restricted to engineering"},
            priority=100,
        )
        allow_rule = PolicyRule(
            name="allow-others",
            description="Allow other requests",
            match_conditions={},
            action="ALLOW",
            priority=10,
        )
        return PolicySet(name="test-policies", rules=[deny_rule, allow_rule])

    def test_department_allowed(self, department_policy_set):
        """Test request allowed for engineering department."""
        ctx = EnforcementContext(department="engineering")
        enforcer = PolicyEnforcer(
            policy_set=department_policy_set,
            context=ctx,
        )

        result = enforcer.enforce(
            model="meta-llama/Llama-3.1-70B-Instruct",
            content="Hello",
        )
        assert result.allowed

    def test_department_denied(self, department_policy_set):
        """Test request denied for marketing department."""
        ctx = EnforcementContext(department="marketing")
        enforcer = PolicyEnforcer(
            policy_set=department_policy_set,
            context=ctx,
        )

        # Use Exception and check class name to avoid module reload issues
        with pytest.raises(Exception) as exc_info:
            enforcer.enforce(
                model="meta-llama/Llama-3.1-70B-Instruct",
                content="Hello",
            )
        assert exc_info.type.__name__ == "PolicyDeniedError"
        assert "engineering" in str(exc_info.value).lower()


class TestModelPolicies:
    """Tests for model-based policies."""

    @pytest.fixture
    def model_policy_set(self):
        """Create a policy set with model restrictions."""
        deny_rule = PolicyRule(
            name="no-405b",
            description="Block 405B model",
            match_conditions={"model": {"contains": "405B"}},  # uppercase B to match model naming
            action="DENY",
            action_params={"reason": "405B model not allowed"},
            priority=100,
        )
        allow_rule = PolicyRule(
            name="allow-others",
            description="Allow other requests",
            match_conditions={},
            action="ALLOW",
            priority=10,
        )
        return PolicySet(name="test-policies", rules=[deny_rule, allow_rule])

    def test_model_denied(self, model_policy_set):
        """Test 405B model is denied."""
        enforcer = PolicyEnforcer(policy_set=model_policy_set)

        # Use Exception and check class name to avoid module reload issues
        with pytest.raises(Exception) as exc_info:
            enforcer.enforce(
                model="meta-llama/Llama-3.1-405B-Instruct",
                content="Hello",
            )
        assert exc_info.type.__name__ == "PolicyDeniedError"

    def test_model_allowed(self, model_policy_set):
        """Test other models are allowed."""
        enforcer = PolicyEnforcer(policy_set=model_policy_set)

        result = enforcer.enforce(
            model="meta-llama/Llama-3.1-8B-Instruct",
            content="Hello",
        )
        assert result.allowed


class TestProviderPolicies:
    """Tests for provider-based policies."""

    @pytest.fixture
    def provider_policy_set(self):
        """Create a policy set for huggingface provider."""
        rule = PolicyRule(
            name="huggingface-allowed",
            description="Allow huggingface provider",
            match_conditions={"provider": {"eq": "huggingface"}},
            action="ALLOW",
            priority=100,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_provider_metadata(self, provider_policy_set):
        """Test provider is set correctly."""
        enforcer = PolicyEnforcer(policy_set=provider_policy_set)
        result = enforcer.enforce(
            model="meta-llama/Llama-3.1-8B-Instruct",
            content="Hello",
        )
        assert result.request.provider == "huggingface"


class TestHuggingFaceMetadata:
    """Tests for Hugging Face specific metadata."""

    @pytest.fixture
    def allow_policy_set(self):
        """Create a policy set that allows all requests."""
        rule = PolicyRule(
            name="allow-all",
            description="Allow all requests",
            match_conditions={},
            action="ALLOW",
            priority=100,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_metadata_text_model(self, allow_policy_set):
        """Test metadata for text models."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model="meta-llama/Llama-3.1-8B-Instruct",
            content="Hello",
            request_type="chat_completion",
        )
        assert result.request.metadata["model_type"] == "text"
        assert result.request.metadata["model_params"] == "8b"

    def test_metadata_embedding_model(self, allow_policy_set):
        """Test metadata for embedding models."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model="sentence-transformers/all-MiniLM-L6-v2",
            content="Hello",
            request_type="feature_extraction",
        )
        assert result.request.metadata["model_type"] == "embedding"

    def test_metadata_image_model(self, allow_policy_set):
        """Test metadata for image models."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model="black-forest-labs/FLUX.1-dev",
            content="A sunset",
            request_type="text_to_image",
        )
        assert result.request.metadata["model_type"] == "image"

    def test_metadata_vision_model(self, allow_policy_set):
        """Test metadata for vision models."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model="meta-llama/Llama-3.2-11B-Vision-Instruct",
            content="Describe this image",
            request_type="chat_completion",
        )
        assert result.request.metadata["model_type"] == "vision"


class TestCostBasedPolicies:
    """Tests for cost-based policies."""

    @pytest.fixture
    def cost_limit_policy_set(self):
        """Create a policy set with cost limits."""
        deny_rule = PolicyRule(
            name="cost-limit",
            description="Limit estimated cost",
            match_conditions={"estimated_cost": {"greater_than": 0.01}},
            action="DENY",
            action_params={"reason": "Request exceeds cost limit"},
            priority=100,
        )
        allow_rule = PolicyRule(
            name="allow-cheap",
            description="Allow cheap requests",
            match_conditions={},
            action="ALLOW",
            priority=10,
        )
        return PolicySet(name="test-policies", rules=[deny_rule, allow_rule])

    def test_cost_tracking(self, cost_limit_policy_set):
        """Test that cost is tracked in request."""
        enforcer = PolicyEnforcer(policy_set=cost_limit_policy_set, raise_on_deny=False)
        result = enforcer.enforce(
            model="meta-llama/Llama-3.1-8B-Instruct",
            content="Short",
        )
        assert result.request.estimated_cost >= 0


class TestPolicyDeniedWhenNotAllowed:
    """Tests for policy denial behavior."""

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

    def test_wrapper_returns_none_when_denied(self, deny_policy_set):
        """Test that wrapper returns None when denied (without raising)."""
        mock_client = MagicMock()
        mock_client.model = "meta-llama/Llama-3.1-8B-Instruct"

        wrapper = PolicyBindHuggingFace(
            client=mock_client,
            policy_set=deny_policy_set,
            raise_on_deny=False,
        )

        result = wrapper.chat_completion(
            messages=[{"role": "user", "content": "Hello"}],
        )

        assert result is None
        mock_client.chat_completion.assert_not_called()


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
            priority=100,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_enforcement_result_fields(self, allow_policy_set):
        """Test EnforcementResult has all expected fields."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model="meta-llama/Llama-3.1-8B-Instruct",
            content="Hello",
        )

        assert hasattr(result, "allowed")
        assert hasattr(result, "request")
        assert hasattr(result, "response")
        assert hasattr(result, "enforcement_time_ms")
        assert hasattr(result, "modified")
        assert hasattr(result, "modifications")

    def test_enforcement_time_recorded(self, allow_policy_set):
        """Test enforcement time is recorded."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        result = enforcer.enforce(
            model="meta-llama/Llama-3.1-8B-Instruct",
            content="Hello",
        )

        assert result.enforcement_time_ms > 0


class TestContextOverride:
    """Tests for context override functionality."""

    @pytest.fixture
    def allow_policy_set(self):
        """Create a policy set that allows all requests."""
        rule = PolicyRule(
            name="allow-all",
            description="Allow all requests",
            match_conditions={},
            action="ALLOW",
            priority=100,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_context_override(self, allow_policy_set):
        """Test that context can be overridden per-request."""
        default_ctx = EnforcementContext(user_id="default@test.com")
        override_ctx = EnforcementContext(user_id="override@test.com")

        enforcer = PolicyEnforcer(
            policy_set=allow_policy_set,
            context=default_ctx,
        )

        result = enforcer.enforce(
            model="meta-llama/Llama-3.1-8B-Instruct",
            content="Hello",
            context_override=override_ctx,
        )

        assert result.request.user_id == "override@test.com"


class TestMultipleModelFamilies:
    """Tests for various model families."""

    @pytest.fixture
    def allow_policy_set(self):
        """Create a policy set that allows all requests."""
        rule = PolicyRule(
            name="allow-all",
            description="Allow all requests",
            match_conditions={},
            action="ALLOW",
            priority=100,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_llama_models(self, allow_policy_set):
        """Test Llama model metadata."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)

        models = [
            ("meta-llama/Llama-3.1-8B-Instruct", "8b"),
            ("meta-llama/Llama-3.1-70B-Instruct", "70b"),
            ("meta-llama/Llama-3.2-3B-Instruct", "3b"),
        ]

        for model, expected_params in models:
            result = enforcer.enforce(model=model, content="Test")
            assert result.request.metadata["model_params"] == expected_params

    def test_mistral_models(self, allow_policy_set):
        """Test Mistral model metadata."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)

        result = enforcer.enforce(
            model="mistralai/Mistral-7B-Instruct-v0.3",
            content="Test",
        )
        assert result.request.metadata["model_params"] == "7b"

    def test_qwen_models(self, allow_policy_set):
        """Test Qwen model metadata."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)

        result = enforcer.enforce(
            model="Qwen/Qwen2.5-72B-Instruct",
            content="Test",
        )
        assert result.request.metadata["model_params"] == "72b"

    def test_google_gemma_models(self, allow_policy_set):
        """Test Gemma model metadata."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)

        result = enforcer.enforce(
            model="google/gemma-2-9b-it",
            content="Test",
        )
        assert result.request.metadata["model_params"] == "9b"

    def test_microsoft_phi_models(self, allow_policy_set):
        """Test Phi model metadata."""
        enforcer = PolicyEnforcer(policy_set=allow_policy_set)

        result = enforcer.enforce(
            model="microsoft/phi-3.5-mini-instruct",
            content="Test",
        )
        assert result.request.metadata["model_params"] == "3.8b"


class TestTokenClassificationWrapper:
    """Tests for TokenClassificationWrapper."""

    @pytest.fixture
    def allow_policy_set(self):
        """Create a policy set that allows all requests."""
        rule = PolicyRule(
            name="allow-all",
            description="Allow all requests",
            match_conditions={},
            action="ALLOW",
            priority=100,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_token_classification(self, allow_policy_set):
        """Test token classification (NER)."""
        mock_client = MagicMock()
        mock_client.model = "dslim/bert-base-NER"
        mock_client.token_classification.return_value = [
            {"entity": "PER", "word": "John", "score": 0.99}
        ]

        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = TokenClassificationWrapper(mock_client, enforcer)

        result = wrapper(text="John went to Paris")

        assert result[0]["entity"] == "PER"


class TestFillMaskWrapper:
    """Tests for FillMaskWrapper."""

    @pytest.fixture
    def allow_policy_set(self):
        """Create a policy set that allows all requests."""
        rule = PolicyRule(
            name="allow-all",
            description="Allow all requests",
            match_conditions={},
            action="ALLOW",
            priority=100,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_fill_mask(self, allow_policy_set):
        """Test fill mask."""
        mock_client = MagicMock()
        mock_client.model = "bert-base-uncased"
        mock_client.fill_mask.return_value = [
            {"token_str": "world", "score": 0.99}
        ]

        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = FillMaskWrapper(mock_client, enforcer)

        result = wrapper(text="Hello [MASK]!")

        assert result[0]["token_str"] == "world"


class TestSentenceSimilarityWrapper:
    """Tests for SentenceSimilarityWrapper."""

    @pytest.fixture
    def allow_policy_set(self):
        """Create a policy set that allows all requests."""
        rule = PolicyRule(
            name="allow-all",
            description="Allow all requests",
            match_conditions={},
            action="ALLOW",
            priority=100,
        )
        return PolicySet(name="test-policies", rules=[rule])

    def test_sentence_similarity(self, allow_policy_set):
        """Test sentence similarity."""
        mock_client = MagicMock()
        mock_client.model = "sentence-transformers/all-MiniLM-L6-v2"
        mock_client.sentence_similarity.return_value = [0.9, 0.3]

        enforcer = PolicyEnforcer(policy_set=allow_policy_set)
        wrapper = SentenceSimilarityWrapper(mock_client, enforcer)

        result = wrapper(
            sentence="I love programming",
            other_sentences=["I enjoy coding", "I like pizza"],
        )

        assert len(result) == 2
        assert result[0] == 0.9
