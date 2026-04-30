"""Иерархия исключений модуля интеграции инструментов безопасности.

Все исключения наследуют от SiteScannerError через ToolIntegrationError:
- ToolNotFoundError — инструмент не найден в системе
- ToolInstallError — ошибка установки инструмента
- ToolVersionError — версия не соответствует минимальной
- ProcessExecutionError — ошибка выполнения процесса
- ProcessTimeoutError — таймаут выполнения процесса
- OutputParseError — ошибка парсинга вывода инструмента
- ScopeViolationError — нарушение scope
- RateLimitExceededError — превышен лимит запросов
- KillSwitchActiveError — Kill Switch активен
- NoToolsAvailableError — нет доступных инструментов
"""

from __future__ import annotations

from app.core.exceptions import BugBountyAgentError
from app.models.schemas import AssetType


class ToolIntegrationError(BugBountyAgentError):
    """Базовое исключение модуля интеграции инструментов."""

    pass


class ToolNotFoundError(ToolIntegrationError):
    """Инструмент не найден в системе."""

    def __init__(self, tool_name: str, install_hint: str):
        self.tool_name = tool_name
        self.install_hint = install_hint
        super().__init__(
            f"Инструмент '{tool_name}' не найден. Подсказка: {install_hint}"
        )


class ToolInstallError(ToolIntegrationError):
    """Ошибка установки инструмента."""

    def __init__(self, tool_name: str, reason: str, manual_instructions: str):
        self.tool_name = tool_name
        self.reason = reason
        self.manual_instructions = manual_instructions
        super().__init__(
            f"Ошибка установки '{tool_name}': {reason}"
        )


class ToolVersionError(ToolIntegrationError):
    """Версия инструмента не соответствует минимальной."""

    def __init__(self, tool_name: str, current: str, required: str):
        self.tool_name = tool_name
        self.current_version = current
        self.required_version = required
        super().__init__(
            f"Версия '{tool_name}' ({current}) ниже минимальной ({required})"
        )


class ProcessExecutionError(ToolIntegrationError):
    """Ошибка выполнения процесса инструмента."""

    def __init__(self, tool_name: str, exit_code: int, stderr: str):
        self.tool_name = tool_name
        self.exit_code = exit_code
        self.stderr = stderr
        super().__init__(
            f"Процесс '{tool_name}' завершился с кодом {exit_code}"
        )


class ProcessTimeoutError(ToolIntegrationError):
    """Таймаут выполнения процесса."""

    def __init__(self, tool_name: str, timeout_seconds: int, partial_output: str):
        self.tool_name = tool_name
        self.timeout_seconds = timeout_seconds
        self.partial_output = partial_output
        super().__init__(
            f"Таймаут процесса '{tool_name}' ({timeout_seconds}с)"
        )


class OutputParseError(ToolIntegrationError):
    """Ошибка парсинга вывода инструмента."""

    def __init__(self, tool_name: str, reason: str, raw_fragment: str):
        self.tool_name = tool_name
        self.reason = reason
        self.raw_fragment = raw_fragment[:500]
        super().__init__(
            f"Ошибка парсинга вывода '{tool_name}': {reason}"
        )


class ScopeViolationError(ToolIntegrationError):
    """Нарушение области действия (scope) — попытка доступа к цели вне scope."""

    def __init__(self, target: str, resolved_ips: list[str]):
        self.target = target
        self.resolved_ips = resolved_ips
        super().__init__(
            f"Цель '{target}' вне scope (IP: {', '.join(resolved_ips)})"
        )


class RateLimitExceededError(ToolIntegrationError):
    """Превышен лимит частоты запросов."""

    def __init__(self, target: str, current_rps: float, limit_rps: int):
        self.target = target
        self.current_rps = current_rps
        self.limit_rps = limit_rps
        super().__init__(
            f"Превышен лимит запросов к '{target}': {current_rps:.1f}/{limit_rps} rps"
        )


class KillSwitchActiveError(ToolIntegrationError):
    """Попытка запуска инструмента при активном Kill Switch."""

    def __init__(self) -> None:
        super().__init__("Kill Switch активен — запуск инструментов заблокирован")


class NoToolsAvailableError(ToolIntegrationError):
    """Ни один инструмент не доступен для данного типа актива."""

    def __init__(self, asset_type: AssetType, recommended_tools: list[str]):
        self.asset_type = asset_type
        self.recommended_tools = recommended_tools
        super().__init__(
            f"Нет доступных инструментов для '{asset_type.value}'. "
            f"Рекомендуемые: {', '.join(recommended_tools)}"
        )
