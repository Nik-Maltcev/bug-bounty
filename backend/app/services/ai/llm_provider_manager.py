"""LLMProviderManager — менеджер LLM-провайдеров.

Единый интерфейс для взаимодействия со всеми LLM-провайдерами.
Использует OpenAI SDK как базовый клиент для DeepSeek, OpenAI и Ollama.
"""

import base64
import uuid

from openai import OpenAI

from app.core.ai_exceptions import LLMProviderError, LLMRateLimitError
from app.models.ai_schemas import LLMConfig, LLMResponse, ProviderType
from app.models.database import LLMProviderConfig


# Конфигурации по умолчанию
DEFAULT_CONFIGS: dict[str, LLMConfig] = {
    "deepseek-flash": LLMConfig(
        provider=ProviderType.DEEPSEEK,
        base_url="https://api.deepseek.com",
        model="deepseek-v4-flash",
        temperature=0.3,
    ),
    "deepseek-pro": LLMConfig(
        provider=ProviderType.DEEPSEEK,
        base_url="https://api.deepseek.com",
        model="deepseek-v4-pro",
        temperature=0.2,
    ),
}


def _encrypt_api_key(api_key: str) -> str:
    """Шифрование API-ключа (base64 для MVP)."""
    return base64.b64encode(api_key.encode("utf-8")).decode("utf-8")


def _decrypt_api_key(encrypted: str) -> str:
    """Расшифровка API-ключа (base64 для MVP)."""
    return base64.b64decode(encrypted.encode("utf-8")).decode("utf-8")


class LLMProviderManager:
    """Менеджер LLM-провайдеров с единым интерфейсом."""

    def __init__(self, db_session=None):
        self._db = db_session
        self._clients: dict[str, OpenAI] = {}

    def get_client(self, config: LLMConfig) -> OpenAI:
        """Возвращает OpenAI-совместимый клиент для провайдера."""
        cache_key = f"{config.provider}:{config.base_url}:{config.model}"
        if cache_key not in self._clients:
            self._clients[cache_key] = OpenAI(
                api_key=config.api_key or "not-needed",
                base_url=config.base_url,
            )
        return self._clients[cache_key]

    def complete(
        self,
        messages: list[dict[str, str]],
        config: LLMConfig | None = None,
    ) -> LLMResponse:
        """Отправляет запрос к LLM и возвращает ответ.

        По умолчанию использует DeepSeek V4-Flash.
        Raises: LLMProviderError при ошибке.
        """
        if config is None:
            # Try to load saved config with API key first
            saved = self.load_provider_config()
            config = saved if saved else DEFAULT_CONFIGS["deepseek-flash"]

        client = self.get_client(config)

        try:
            response = client.chat.completions.create(
                model=config.model,
                messages=messages,
                max_tokens=config.max_tokens,
                temperature=config.temperature,
            )

            choice = response.choices[0]
            usage = {}
            if response.usage:
                usage = {
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens,
                    "total_tokens": response.usage.total_tokens,
                }

            return LLMResponse(
                content=choice.message.content or "",
                model=response.model,
                usage=usage,
                provider=config.provider,
            )
        except Exception as e:
            error_str = str(e)
            if "rate_limit" in error_str.lower() or "429" in error_str:
                raise LLMRateLimitError(provider=config.provider.value)
            raise LLMProviderError(
                provider=config.provider.value,
                reason=error_str,
            )

    def complete_with_pro(
        self,
        messages: list[dict[str, str]],
    ) -> LLMResponse:
        """Отправляет запрос к DeepSeek V4-Pro (для отчётов)."""
        return self.complete(messages, config=DEFAULT_CONFIGS["deepseek-pro"])

    def save_provider_config(self, config: LLMConfig) -> None:
        """Сохраняет конфигурацию провайдера (API-ключ шифруется)."""
        if self._db is None:
            raise LLMProviderError("system", "Database session not available")

        # Деактивируем все текущие конфигурации
        existing = self._db.query(LLMProviderConfig).filter(
            LLMProviderConfig.is_active == True  # noqa: E712
        ).all()
        for cfg in existing:
            cfg.is_active = False

        encrypted_key = None
        if config.api_key:
            encrypted_key = _encrypt_api_key(config.api_key)

        db_config = LLMProviderConfig(
            id=str(uuid.uuid4()),
            provider=config.provider.value,
            base_url=config.base_url,
            model=config.model,
            api_key_encrypted=encrypted_key,
            max_tokens=config.max_tokens,
            temperature=config.temperature,
            is_active=True,
        )
        self._db.add(db_config)
        self._db.commit()

    def load_provider_config(self) -> LLMConfig | None:
        """Загружает активную конфигурацию провайдера."""
        if self._db is None:
            return None

        db_config = self._db.query(LLMProviderConfig).filter(
            LLMProviderConfig.is_active == True  # noqa: E712
        ).first()

        if db_config is None:
            return None

        api_key = None
        if db_config.api_key_encrypted:
            api_key = _decrypt_api_key(db_config.api_key_encrypted)

        return LLMConfig(
            provider=ProviderType(db_config.provider),
            api_key=api_key,
            base_url=db_config.base_url,
            model=db_config.model,
            max_tokens=db_config.max_tokens,
            temperature=db_config.temperature,
        )

    def test_connection(self, config: LLMConfig) -> bool:
        """Проверяет подключение к провайдеру."""
        try:
            self.complete(
                messages=[{"role": "user", "content": "ping"}],
                config=config,
            )
            return True
        except (LLMProviderError, Exception):
            return False
