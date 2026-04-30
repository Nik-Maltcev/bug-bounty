"""Unit-тесты для LLMProviderManager."""

import pytest
from unittest.mock import MagicMock, patch

from app.core.ai_exceptions import LLMProviderError, LLMRateLimitError
from app.models.ai_schemas import LLMConfig, LLMResponse, ProviderType
from app.services.ai.llm_provider_manager import (
    LLMProviderManager,
    DEFAULT_CONFIGS,
    _encrypt_api_key,
    _decrypt_api_key,
)


@pytest.fixture
def manager():
    return LLMProviderManager()


@pytest.fixture
def deepseek_config():
    return LLMConfig(
        provider=ProviderType.DEEPSEEK,
        api_key="test-key-123",
        base_url="https://api.deepseek.com",
        model="deepseek-v4-flash",
        temperature=0.3,
    )


@pytest.fixture
def openai_config():
    return LLMConfig(
        provider=ProviderType.OPENAI,
        api_key="sk-test-key",
        base_url="https://api.openai.com/v1",
        model="gpt-4o",
        temperature=0.3,
    )


@pytest.fixture
def ollama_config():
    return LLMConfig(
        provider=ProviderType.OLLAMA,
        base_url="http://localhost:11434/v1",
        model="llama3",
        temperature=0.3,
    )


def _mock_completion_response(content="Hello!", model="deepseek-v4-flash"):
    """Create a mock OpenAI completion response."""
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = content
    mock_response.model = model
    mock_response.usage = MagicMock()
    mock_response.usage.prompt_tokens = 10
    mock_response.usage.completion_tokens = 5
    mock_response.usage.total_tokens = 15
    return mock_response


# --- Encryption round-trip ---


class TestEncryption:
    def test_encrypt_decrypt_roundtrip(self):
        key = "sk-test-api-key-12345"
        encrypted = _encrypt_api_key(key)
        assert encrypted != key
        assert _decrypt_api_key(encrypted) == key

    def test_encrypted_differs_from_original(self):
        key = "my-secret-key"
        encrypted = _encrypt_api_key(key)
        assert encrypted != key


# --- get_client() ---


class TestGetClient:
    def test_creates_client_for_deepseek(self, manager, deepseek_config):
        client = manager.get_client(deepseek_config)
        assert client is not None

    def test_creates_client_for_openai(self, manager, openai_config):
        client = manager.get_client(openai_config)
        assert client is not None

    def test_creates_client_for_ollama(self, manager, ollama_config):
        client = manager.get_client(ollama_config)
        assert client is not None

    def test_caches_client(self, manager, deepseek_config):
        client1 = manager.get_client(deepseek_config)
        client2 = manager.get_client(deepseek_config)
        assert client1 is client2


# --- complete() ---


class TestComplete:
    @patch("app.services.ai.llm_provider_manager.OpenAI")
    def test_complete_returns_llm_response(self, mock_openai_cls, deepseek_config):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _mock_completion_response()
        mock_openai_cls.return_value = mock_client

        manager = LLMProviderManager()
        # Clear cache so our mock is used
        manager._clients = {}
        manager._clients[f"{deepseek_config.provider}:{deepseek_config.base_url}:{deepseek_config.model}"] = mock_client

        result = manager.complete(
            messages=[{"role": "user", "content": "Hello"}],
            config=deepseek_config,
        )

        assert isinstance(result, LLMResponse)
        assert result.content == "Hello!"
        assert result.provider == ProviderType.DEEPSEEK

    @patch("app.services.ai.llm_provider_manager.OpenAI")
    def test_complete_uses_default_config(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _mock_completion_response()
        mock_openai_cls.return_value = mock_client

        manager = LLMProviderManager()
        default_cfg = DEFAULT_CONFIGS["deepseek-flash"]
        cache_key = f"{default_cfg.provider}:{default_cfg.base_url}:{default_cfg.model}"
        manager._clients[cache_key] = mock_client

        result = manager.complete(
            messages=[{"role": "user", "content": "Hello"}],
        )

        assert result.provider == ProviderType.DEEPSEEK

    @patch("app.services.ai.llm_provider_manager.OpenAI")
    def test_complete_raises_provider_error(self, mock_openai_cls, deepseek_config):
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = Exception("Connection refused")
        mock_openai_cls.return_value = mock_client

        manager = LLMProviderManager()
        cache_key = f"{deepseek_config.provider}:{deepseek_config.base_url}:{deepseek_config.model}"
        manager._clients[cache_key] = mock_client

        with pytest.raises(LLMProviderError) as exc_info:
            manager.complete(
                messages=[{"role": "user", "content": "Hello"}],
                config=deepseek_config,
            )
        assert "Connection refused" in exc_info.value.reason

    @patch("app.services.ai.llm_provider_manager.OpenAI")
    def test_complete_raises_rate_limit_error(self, mock_openai_cls, deepseek_config):
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = Exception("rate_limit exceeded 429")
        mock_openai_cls.return_value = mock_client

        manager = LLMProviderManager()
        cache_key = f"{deepseek_config.provider}:{deepseek_config.base_url}:{deepseek_config.model}"
        manager._clients[cache_key] = mock_client

        with pytest.raises(LLMRateLimitError):
            manager.complete(
                messages=[{"role": "user", "content": "Hello"}],
                config=deepseek_config,
            )


# --- complete_with_pro() ---


class TestCompleteWithPro:
    @patch("app.services.ai.llm_provider_manager.OpenAI")
    def test_uses_pro_config(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _mock_completion_response(
            model="deepseek-v4-pro"
        )
        mock_openai_cls.return_value = mock_client

        manager = LLMProviderManager()
        pro_cfg = DEFAULT_CONFIGS["deepseek-pro"]
        cache_key = f"{pro_cfg.provider}:{pro_cfg.base_url}:{pro_cfg.model}"
        manager._clients[cache_key] = mock_client

        result = manager.complete_with_pro(
            messages=[{"role": "user", "content": "Generate report"}],
        )

        assert result.model == "deepseek-v4-pro"


# --- test_connection() ---


class TestTestConnection:
    @patch("app.services.ai.llm_provider_manager.OpenAI")
    def test_connection_success(self, mock_openai_cls, deepseek_config):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _mock_completion_response()
        mock_openai_cls.return_value = mock_client

        manager = LLMProviderManager()
        cache_key = f"{deepseek_config.provider}:{deepseek_config.base_url}:{deepseek_config.model}"
        manager._clients[cache_key] = mock_client

        assert manager.test_connection(deepseek_config) is True

    @patch("app.services.ai.llm_provider_manager.OpenAI")
    def test_connection_failure(self, mock_openai_cls, deepseek_config):
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = Exception("Connection refused")
        mock_openai_cls.return_value = mock_client

        manager = LLMProviderManager()
        cache_key = f"{deepseek_config.provider}:{deepseek_config.base_url}:{deepseek_config.model}"
        manager._clients[cache_key] = mock_client

        assert manager.test_connection(deepseek_config) is False


# --- DEFAULT_CONFIGS ---


class TestDefaultConfigs:
    def test_has_deepseek_flash(self):
        assert "deepseek-flash" in DEFAULT_CONFIGS
        cfg = DEFAULT_CONFIGS["deepseek-flash"]
        assert cfg.provider == ProviderType.DEEPSEEK
        assert cfg.model == "deepseek-v4-flash"

    def test_has_deepseek_pro(self):
        assert "deepseek-pro" in DEFAULT_CONFIGS
        cfg = DEFAULT_CONFIGS["deepseek-pro"]
        assert cfg.provider == ProviderType.DEEPSEEK
        assert cfg.model == "deepseek-v4-pro"
