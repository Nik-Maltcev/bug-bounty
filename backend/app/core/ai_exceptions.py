"""Иерархия исключений AI-модуля.

Все исключения наследуют от SiteScannerError:
- AIError — базовое исключение AI-модуля
- LLMProviderError — ошибка LLM-провайдера (сеть, аутентификация)
- LLMRateLimitError — превышен лимит запросов к LLM
- PromptInjectionError — обнаружена попытка prompt injection
- InputTooLongError — превышена максимальная длина ввода
- ContextOverflowError — контекст превышает лимит окна LLM
- IntentClassificationError — ошибка классификации намерения
"""

from app.core.exceptions import BugBountyAgentError


class AIError(BugBountyAgentError):
    """Базовое исключение AI-модуля."""

    pass


class LLMProviderError(AIError):
    """Ошибка LLM-провайдера (сеть, аутентификация, лимиты)."""

    def __init__(self, provider: str, reason: str, status_code: int | None = None):
        self.provider = provider
        self.reason = reason
        self.status_code = status_code
        super().__init__(f"Ошибка LLM-провайдера '{provider}': {reason}")


class LLMRateLimitError(LLMProviderError):
    """Превышен лимит запросов к LLM-провайдеру."""

    def __init__(self, provider: str, retry_after: int | None = None):
        super().__init__(provider, "Превышен лимит запросов")
        self.retry_after = retry_after


class PromptInjectionError(AIError):
    """Обнаружена попытка prompt injection."""

    def __init__(self, detected_patterns: list[str]):
        self.detected_patterns = detected_patterns
        super().__init__(
            f"Обнаружена попытка prompt injection: {', '.join(detected_patterns)}"
        )


class InputTooLongError(AIError):
    """Превышена максимальная длина ввода."""

    def __init__(self, length: int, max_length: int):
        self.length = length
        self.max_length = max_length
        super().__init__(
            f"Длина ввода ({length}) превышает максимум ({max_length})"
        )


class ContextOverflowError(AIError):
    """Контекст превышает лимит окна LLM."""

    def __init__(self, context_tokens: int, max_tokens: int):
        self.context_tokens = context_tokens
        self.max_tokens = max_tokens
        super().__init__(
            f"Размер контекста ({context_tokens} токенов) превышает лимит ({max_tokens})"
        )


class IntentClassificationError(AIError):
    """Ошибка классификации намерения."""

    def __init__(self, message: str, raw_response: str):
        self.user_message = message
        self.raw_response = raw_response
        super().__init__(
            f"Не удалось классифицировать намерение для сообщения: {message[:100]}"
        )
