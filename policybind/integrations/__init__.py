"""
SDK integrations for PolicyBind.

This package provides middleware and integration layers for popular
AI SDKs, enabling transparent policy enforcement without modifying
application code.

Supported SDKs:
    openai: OpenAI Python SDK integration
    anthropic: Anthropic Python SDK integration
    google: Google Gemini/Vertex AI SDK integration
    cohere: Cohere Python SDK integration
    mistral: Mistral AI Python SDK integration
    bedrock: AWS Bedrock Runtime SDK integration
    ollama: Ollama local model integration
    huggingface: Hugging Face Hub InferenceClient integration
    langchain: LangChain integration (callbacks and wrappers)

Example:
    Using OpenAI integration::

        from openai import OpenAI
        from policybind.integrations.openai_integration import create_policy_client

        # Create a policy-enforced OpenAI client
        client = create_policy_client(
            policy_set=policy_set,
            user_id="user@example.com",
            department="engineering",
        )

        # Use normally - policies are automatically enforced
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Hello!"}]
        )

    Using Anthropic integration::

        from anthropic import Anthropic
        from policybind.integrations.anthropic_integration import create_policy_client

        # Create a policy-enforced Anthropic client
        client = create_policy_client(
            policy_set=policy_set,
            user_id="user@example.com",
            department="engineering",
        )

        # Use normally - policies are automatically enforced
        response = client.messages.create(
            model="claude-3-opus-20240229",
            max_tokens=1024,
            messages=[{"role": "user", "content": "Hello!"}]
        )

    Using Google Gemini integration::

        from policybind.integrations.google_integration import create_policy_client

        # Create a policy-enforced Gemini model
        model = create_policy_client(
            model_name="gemini-1.5-pro",
            policy_set=policy_set,
            user_id="user@example.com",
            department="engineering",
        )

        # Use normally - policies are automatically enforced
        response = model.generate_content("Hello!")

    Using Google Vertex AI integration::

        from policybind.integrations.google_integration import create_vertex_policy_client

        # Create a policy-enforced Vertex AI model
        model = create_vertex_policy_client(
            model_name="gemini-1.5-pro",
            policy_set=policy_set,
            project="my-project",
            location="us-central1",
            user_id="user@example.com",
        )

        # Use normally - policies are automatically enforced
        response = model.generate_content("Hello!")

    Using Cohere integration::

        from policybind.integrations.cohere_integration import create_policy_client

        # Create a policy-enforced Cohere client
        client = create_policy_client(
            policy_set=policy_set,
            user_id="user@example.com",
            department="engineering",
        )

        # Use normally - policies are automatically enforced
        response = client.chat(
            model="command-r-plus",
            message="Hello!",
        )

    Using Mistral AI integration::

        from policybind.integrations.mistral_integration import create_policy_client

        # Create a policy-enforced Mistral client
        client = create_policy_client(
            policy_set=policy_set,
            user_id="user@example.com",
            department="engineering",
        )

        # Use normally - policies are automatically enforced
        response = client.chat.complete(
            model="mistral-large-latest",
            messages=[{"role": "user", "content": "Hello!"}],
        )

    Using AWS Bedrock integration::

        from policybind.integrations.bedrock_integration import create_policy_client

        # Create a policy-enforced Bedrock client
        client = create_policy_client(
            policy_set=policy_set,
            region_name="us-east-1",
            user_id="user@example.com",
            department="engineering",
        )

        # Use normally - policies are automatically enforced
        response = client.converse(
            modelId="anthropic.claude-3-sonnet-20240229-v1:0",
            messages=[{"role": "user", "content": [{"text": "Hello!"}]}],
        )

    Using Ollama integration (local models)::

        from policybind.integrations.ollama_integration import create_policy_client

        # Create a policy-enforced Ollama client
        client = create_policy_client(
            policy_set=policy_set,
            user_id="user@example.com",
            department="engineering",
        )

        # Use normally - policies are automatically enforced
        response = client.chat(
            model="llama3.2",
            messages=[{"role": "user", "content": "Hello!"}],
        )

    Using Hugging Face Hub integration::

        from policybind.integrations.huggingface_integration import create_policy_client

        # Create a policy-enforced Hugging Face client
        client = create_policy_client(
            policy_set=policy_set,
            token="hf_...",
            user_id="user@example.com",
            department="engineering",
        )

        # Use normally - policies are automatically enforced
        response = client.chat_completion(
            model="meta-llama/Llama-3.1-8B-Instruct",
            messages=[{"role": "user", "content": "Hello!"}],
        )

        # Text generation
        response = client.text_generation(
            model="mistralai/Mistral-7B-Instruct-v0.3",
            prompt="Once upon a time",
        )

        # Embeddings
        embeddings = client.feature_extraction(
            model="sentence-transformers/all-MiniLM-L6-v2",
            text="Hello, world!",
        )

    Using LangChain integration (callback)::

        from langchain_openai import ChatOpenAI
        from policybind.integrations.langchain_integration import create_policy_callback

        # Create a policy callback handler
        callback = create_policy_callback(
            policy_set=policy_set,
            user_id="user@example.com",
            department="engineering",
        )

        # Use with any LangChain LLM
        llm = ChatOpenAI(model="gpt-4")
        response = llm.invoke("Hello!", config={"callbacks": [callback]})

    Using LangChain integration (wrapper)::

        from langchain_openai import ChatOpenAI
        from policybind.integrations.langchain_integration import wrap_llm

        # Wrap any LangChain LLM
        llm = wrap_llm(
            llm=ChatOpenAI(model="gpt-4"),
            policy_set=policy_set,
            user_id="user@example.com",
        )

        # Use normally - policies automatically enforced
        response = llm.invoke("Hello!")
"""

from policybind.integrations import (
    anthropic_integration,
    bedrock_integration,
    cohere_integration,
    google_integration,
    huggingface_integration,
    langchain_integration,
    mistral_integration,
    ollama_integration,
    openai_integration,
)

__all__ = [
    "openai_integration",
    "anthropic_integration",
    "google_integration",
    "cohere_integration",
    "mistral_integration",
    "bedrock_integration",
    "ollama_integration",
    "huggingface_integration",
    "langchain_integration",
]
