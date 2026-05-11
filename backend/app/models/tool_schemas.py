"""Pydantic-модели данных для модуля интеграции инструментов безопасности.

Содержит модели: ToolStatus, ToolInfo, ToolSpec, ProcessResult, ProcessInfo,
ScanPlan, ExcludedTool, SafetyStatus, KillSwitchResult, RateLimitConfig.
"""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from app.models.schemas import AssetType


class ToolStatus(str, Enum):
    """Статус инструмента безопасности."""

    INSTALLED = "installed"
    NOT_INSTALLED = "not_installed"
    OUTDATED = "outdated"


class ToolInfo(BaseModel):
    """Информация об инструменте безопасности."""

    name: str
    status: ToolStatus
    version: str | None = None
    min_version: str
    path: str | None = None
    install_command: str
    asset_types: list[AssetType]


class ToolSpec(BaseModel):
    """Спецификация поддерживаемого инструмента (конфигурация)."""

    name: str
    binary_name: str
    min_version: str
    version_command: list[str]
    version_regex: str
    install_commands: dict[str, list[str]]
    asset_types: list[AssetType]
    default_args: list[str]
    output_format: str


class ProcessResult(BaseModel):
    """Результат выполнения процесса инструмента."""

    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool = False
    duration_seconds: float = 0.0


class ProcessInfo(BaseModel):
    """Информация об активном процессе."""

    process_id: str
    tool_name: str
    scan_id: str
    started_at: datetime
    command: list[str]


class ExcludedTool(BaseModel):
    """Инструмент, исключённый из плана сканирования."""

    tool_name: str
    reason: str


class ScanPlan(BaseModel):
    """План сканирования, сформированный оркестратором."""

    scan_id: str
    asset_type: AssetType
    target: str
    tools: list[str]
    excluded_tools: list[ExcludedTool] = []
    execution_order: list[str] = []
    estimated_duration_minutes: int | None = None

    # AI-Driven Scan (Stage 2) настройки
    enable_ai_stage2: bool = False
    ai_supervised_mode: bool = False
    ai_max_iterations: int = 3
    ai_max_requests: int = 50
    ai_rate_limit: float = 5.0


class SafetyStatus(BaseModel):
    """Текущее состояние слоя безопасности."""

    kill_switch_active: bool
    active_processes_count: int
    rate_limit_rps: int
    active_scans: list[str]


class KillSwitchResult(BaseModel):
    """Результат активации Kill Switch."""

    terminated_processes: int
    cancelled_scans: list[str]
    timestamp: datetime


class RateLimitConfig(BaseModel):
    """Конфигурация rate limiting."""

    requests_per_second: int = 10
    burst_size: int = 20
    per_target: bool = True
