"""PromptSanitizer — санитизация пользовательского ввода перед передачей в LLM.

Защита от prompt injection, удаление чувствительных данных,
валидация длины ввода.
"""

import re


MAX_INPUT_LENGTH = 10000

# Паттерны prompt injection (case-insensitive)
INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"forget\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"override\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"system\s*:", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\b", re.IGNORECASE),
    re.compile(r"act\s+as\s+(a\s+)?", re.IGNORECASE),
    re.compile(r"pretend\s+(you\s+are|to\s+be)\b", re.IGNORECASE),
    re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
    re.compile(r"<\|?\s*system\s*\|?>", re.IGNORECASE),
    re.compile(r"\[system\]", re.IGNORECASE),
    re.compile(r"###\s*instruction", re.IGNORECASE),
    re.compile(r"ignore\s+the\s+above", re.IGNORECASE),
    re.compile(r"do\s+not\s+follow\s+(the\s+)?(above|previous)", re.IGNORECASE),
]

# Паттерны чувствительных данных
SENSITIVE_PATTERNS: list[tuple[re.Pattern, str]] = [
    # JWT tokens (eyJ...)
    (re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "[JWT_REDACTED]"),
    # Passwords in key=value format
    (re.compile(r"password\s*=\s*\S+", re.IGNORECASE), "password=[REDACTED]"),
    # API keys starting with sk-
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "[API_KEY_REDACTED]"),
    # Generic API keys (key=...)
    (re.compile(r"(?:api[_-]?key|secret[_-]?key|access[_-]?key)\s*=\s*\S+", re.IGNORECASE), "[API_KEY_REDACTED]"),
    # Bearer tokens
    (re.compile(r"Bearer\s+[A-Za-z0-9_.-]+", re.IGNORECASE), "Bearer [TOKEN_REDACTED]"),
]


class PromptSanitizer:
    """Санитизация пользовательского ввода перед передачей в LLM."""

    def sanitize(self, user_input: str) -> str:
        """Санитизирует пользовательский ввод.

        Удаляет паттерны prompt injection из текста.
        """
        result = user_input
        for pattern in INJECTION_PATTERNS:
            result = pattern.sub("", result)
        # Убираем лишние пробелы после удаления паттернов
        result = re.sub(r"\s{2,}", " ", result).strip()
        return result

    def validate_length(self, text: str, max_length: int = MAX_INPUT_LENGTH) -> bool:
        """Проверяет длину ввода.

        Returns:
            True если длина <= max_length, False иначе.
        """
        return len(text) <= max_length

    def strip_sensitive_data(self, text: str) -> str:
        """Удаляет чувствительные данные (JWT, пароли, API-ключи) из текста."""
        result = text
        for pattern, replacement in SENSITIVE_PATTERNS:
            result = pattern.sub(replacement, result)
        return result
