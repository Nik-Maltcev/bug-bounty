"""Pydantic-модели данных для Сканера сайтов.

Содержит все схемы валидации: перечисления (Enum), модели программ,
сканирования, уязвимостей, отчётов, аудита и соответствия.
"""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


# --- Перечисления (Enums) ---


class AssetType(str, Enum):
    """Тип актива в области действия программы."""

    WEB_APPLICATION = "web_application"


class SeverityLevel(str, Enum):
    """Уровень серьёзности уязвимости."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ActionResult(str, Enum):
    """Результат проверки действия на соответствие правилам."""

    ALLOWED = "allowed"
    BLOCKED = "blocked"


class ScanStatus(str, Enum):
    """Статус сканирования."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# --- Программа Bug Bounty ---


class ProgramSource(BaseModel):
    """Источник данных программы (URL или текст)."""

    url: str | None = None
    text: str | None = None


class Asset(BaseModel):
    """Актив в области действия программы."""

    id: str
    name: str
    asset_type: AssetType
    target: str  # URL, адрес контракта и т.д.
    in_scope: bool = True
    notes: str = ""


class ProgramRule(BaseModel):
    """Правило программы bug bounty."""

    id: str
    description: str
    is_allowed: bool  # True = разрешено, False = запрещено
    category: str  # "testing_method", "scope", "disclosure" и т.д.


class RewardTier(BaseModel):
    """Уровень вознаграждения за уязвимость."""

    severity: SeverityLevel
    min_reward: float
    max_reward: float
    currency: str = "USD"


class ParsedProgram(BaseModel):
    """Структурированные данные программы bug bounty."""

    id: str
    name: str
    platform: str  # "hackerone", "bugcrowd", "immunefi", "custom"
    assets: list[Asset]
    rules: list[ProgramRule]
    reward_tiers: list[RewardTier]
    disclosure_requirements: str
    raw_text: str
    created_at: datetime
    is_archived: bool = False


# --- Сканирование ---


class ScanConfig(BaseModel):
    """Конфигурация сканирования."""

    asset_id: str
    program_id: str
    check_types: list[str] = []  # пустой = все доступные


class ScanProgress(BaseModel):
    """Прогресс текущего сканирования."""

    scan_id: str
    status: ScanStatus
    current_stage: str
    percent_complete: int = Field(ge=0, le=100)  # 0-100
    findings_count: int


class RawFinding(BaseModel):
    """Сырая находка сканера (до классификации)."""

    vulnerability_type: str
    description: str
    evidence: str
    affected_asset_id: str
    raw_data: dict


class Vulnerability(BaseModel):
    """Классифицированная уязвимость."""

    id: str
    scan_id: str
    program_id: str
    vulnerability_type: str
    severity: SeverityLevel
    description: str
    steps_to_reproduce: str
    evidence: str
    affected_asset: Asset
    impact_assessment: str
    remediation: str
    status: str  # "new", "reported", "accepted", "rejected"
    created_at: datetime


# --- Отчёты ---


class Report(BaseModel):
    """Отчёт об уязвимости."""

    id: str
    vulnerability_id: str
    program_id: str
    title: str
    description: str
    steps_to_reproduce: str
    proof_of_concept: str
    impact: str
    severity: SeverityLevel
    remediation: str
    format_version: str
    created_at: datetime
    updated_at: datetime


# --- Аудит ---


class AuditEntry(BaseModel):
    """Запись журнала аудита (неизменяемая после создания)."""

    id: str
    timestamp: datetime
    action_type: str
    target_asset: str
    result: ActionResult
    program_id: str
    rule_reference: str  # ссылка на правило, разрешающее/запрещающее действие
    details: str


class AuditFilters(BaseModel):
    """Фильтры для запроса журнала аудита."""

    start_date: datetime | None = None
    end_date: datetime | None = None
    action_type: str | None = None
    program_id: str | None = None
    result: ActionResult | None = None


# --- Соответствие (Compliance) ---


class ComplianceResult(BaseModel):
    """Результат проверки действия на соответствие правилам."""

    action_allowed: bool
    reason: str
    rule_reference: str | None = None


class ComplianceSummary(BaseModel):
    """Сводка по соблюдению правил программы."""

    program_id: str
    total_actions: int
    allowed_actions: int
    blocked_actions: int
    blocked_reasons: list[dict]  # [{"reason": str, "count": int}]
