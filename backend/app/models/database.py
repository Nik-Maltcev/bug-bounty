"""SQLAlchemy ORM-модели для Bug Bounty Security Agent.

Содержит все таблицы базы данных: Program, Asset, ProgramRule, RewardTier,
Scan, Vulnerability, Report, AuditLog, User.
Использует SQLAlchemy 2.0+ стиль с mapped_column.
"""

from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    event,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Базовый класс для всех ORM-моделей."""
    pass


class Program(Base):
    """Программа bug bounty."""

    __tablename__ = "programs"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    platform: Mapped[str] = mapped_column(String, nullable=False)  # hackerone, bugcrowd, immunefi, custom
    disclosure_requirements: Mapped[str] = mapped_column(Text, default="")
    raw_text: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))
    is_archived: Mapped[bool] = mapped_column(Boolean, default=False)

    # Связи
    assets: Mapped[list["Asset"]] = relationship(back_populates="program", cascade="all, delete-orphan")
    rules: Mapped[list["ProgramRule"]] = relationship(back_populates="program", cascade="all, delete-orphan")
    reward_tiers: Mapped[list["RewardTier"]] = relationship(back_populates="program", cascade="all, delete-orphan")
    scans: Mapped[list["Scan"]] = relationship(back_populates="program", cascade="all, delete-orphan")
    vulnerabilities: Mapped[list["VulnerabilityRecord"]] = relationship(back_populates="program", cascade="all, delete-orphan")
    reports: Mapped[list["Report"]] = relationship(back_populates="program", cascade="all, delete-orphan")
    conversation_messages: Mapped[list["ConversationMessage"]] = relationship(back_populates="program", cascade="all, delete-orphan")


class Asset(Base):
    """Актив в области действия программы."""

    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    program_id: Mapped[str] = mapped_column(String, ForeignKey("programs.id"), nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    asset_type: Mapped[str] = mapped_column(String, nullable=False)  # web_application, smart_contract, api, mobile_app
    target: Mapped[str] = mapped_column(String, nullable=False)  # URL, адрес контракта и т.д.
    in_scope: Mapped[bool] = mapped_column(Boolean, default=True)
    notes: Mapped[str] = mapped_column(Text, default="")

    # Связи
    program: Mapped["Program"] = relationship(back_populates="assets")
    scans: Mapped[list["Scan"]] = relationship(back_populates="asset", cascade="all, delete-orphan")


class ProgramRule(Base):
    """Правило программы bug bounty."""

    __tablename__ = "program_rules"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    program_id: Mapped[str] = mapped_column(String, ForeignKey("programs.id"), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    is_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False)  # True = разрешено, False = запрещено
    category: Mapped[str] = mapped_column(String, nullable=False)  # testing_method, scope, disclosure и т.д.

    # Связи
    program: Mapped["Program"] = relationship(back_populates="rules")


class RewardTier(Base):
    """Уровень вознаграждения за уязвимость."""

    __tablename__ = "reward_tiers"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    program_id: Mapped[str] = mapped_column(String, ForeignKey("programs.id"), nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)  # critical, high, medium, low, informational
    min_reward: Mapped[float] = mapped_column(Float, nullable=False)
    max_reward: Mapped[float] = mapped_column(Float, nullable=False)
    currency: Mapped[str] = mapped_column(String, default="USD")

    # Связи
    program: Mapped["Program"] = relationship(back_populates="reward_tiers")


class Scan(Base):
    """Сканирование актива."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    program_id: Mapped[str] = mapped_column(String, ForeignKey("programs.id"), nullable=False)
    asset_id: Mapped[str] = mapped_column(String, ForeignKey("assets.id"), nullable=False)
    status: Mapped[str] = mapped_column(String, default="pending")  # pending, running, completed, failed, cancelled
    current_stage: Mapped[str] = mapped_column(String, default="")
    percent_complete: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Связи
    program: Mapped["Program"] = relationship(back_populates="scans")
    asset: Mapped["Asset"] = relationship(back_populates="scans")
    vulnerabilities: Mapped[list["VulnerabilityRecord"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class VulnerabilityRecord(Base):
    """Классифицированная уязвимость (запись в БД)."""

    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), nullable=False)
    program_id: Mapped[str] = mapped_column(String, ForeignKey("programs.id"), nullable=False)
    vulnerability_type: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)  # critical, high, medium, low, informational
    description: Mapped[str] = mapped_column(Text, nullable=False)
    steps_to_reproduce: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[str] = mapped_column(Text, default="")
    impact_assessment: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String, default="new")  # new, reported, accepted, rejected
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))

    # Связи
    scan: Mapped["Scan"] = relationship(back_populates="vulnerabilities")
    program: Mapped["Program"] = relationship(back_populates="vulnerabilities")
    report: Mapped["Report | None"] = relationship(back_populates="vulnerability", uselist=False)
    finding_analyses: Mapped[list["FindingAnalysisRecord"]] = relationship(back_populates="vulnerability", cascade="all, delete-orphan")


class Report(Base):
    """Отчёт об уязвимости."""

    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    vulnerability_id: Mapped[str] = mapped_column(String, ForeignKey("vulnerabilities.id"), nullable=False)
    program_id: Mapped[str] = mapped_column(String, ForeignKey("programs.id"), nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    steps_to_reproduce: Mapped[str] = mapped_column(Text, default="")
    proof_of_concept: Mapped[str] = mapped_column(Text, default="")
    impact: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC))

    # Связи
    vulnerability: Mapped["VulnerabilityRecord"] = relationship(back_populates="report")
    program: Mapped["Program"] = relationship(back_populates="reports")


class AuditLog(Base):
    """Запись журнала аудита (append-only).

    Таблица поддерживает append-only семантику:
    - Записи создаются и никогда не изменяются/удаляются
    - SQLAlchemy-события блокируют UPDATE и DELETE операции
    """

    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC), nullable=False)
    action_type: Mapped[str] = mapped_column(String, nullable=False)
    target_asset: Mapped[str] = mapped_column(String, nullable=False)
    result: Mapped[str] = mapped_column(String, nullable=False)  # allowed, blocked
    program_id: Mapped[str] = mapped_column(String, ForeignKey("programs.id"), nullable=False)
    rule_reference: Mapped[str] = mapped_column(String, default="")
    details: Mapped[str] = mapped_column(Text, default="")


# --- Append-only защита для AuditLog ---
# Блокируем UPDATE и DELETE на уровне ORM-событий (Требование 9.3)

@event.listens_for(AuditLog, "before_update")
def _block_audit_log_update(mapper, connection, target):
    """Запрет обновления записей журнала аудита."""
    raise RuntimeError("Записи журнала аудита неизменяемы (append-only): UPDATE запрещён")


@event.listens_for(AuditLog, "before_delete")
def _block_audit_log_delete(mapper, connection, target):
    """Запрет удаления записей журнала аудита."""
    raise RuntimeError("Записи журнала аудита неизменяемы (append-only): DELETE запрещён")


class User(Base):
    """Пользователь системы.

    Поддерживает блокировку после неудачных попыток входа (Требование 7.4):
    - failed_login_attempts: счётчик последовательных неудачных попыток
    - locked_until: время, до которого аккаунт заблокирован
    """

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    username: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))


class ToolStatusRecord(Base):
    """Запись статуса инструмента безопасности."""

    __tablename__ = "tool_status"

    name: Mapped[str] = mapped_column(String, primary_key=True)
    status: Mapped[str] = mapped_column(String, nullable=False)  # installed, not_installed, outdated
    version: Mapped[str | None] = mapped_column(String, nullable=True)
    min_version: Mapped[str] = mapped_column(String, nullable=False)
    path: Mapped[str | None] = mapped_column(String, nullable=True)
    last_checked: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))


class ScanPlanRecord(Base):
    """Запись плана сканирования."""

    __tablename__ = "scan_plans"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), nullable=False)
    asset_type: Mapped[str] = mapped_column(String, nullable=False)
    target: Mapped[str] = mapped_column(String, nullable=False)
    tools_json: Mapped[str] = mapped_column(Text, default="[]")
    excluded_tools_json: Mapped[str] = mapped_column(Text, default="[]")
    execution_order_json: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))


class ConversationMessage(Base):
    """Сообщение в истории диалога."""

    __tablename__ = "conversation_messages"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    program_id: Mapped[str] = mapped_column(String, ForeignKey("programs.id"), nullable=False)
    role: Mapped[str] = mapped_column(String, nullable=False)  # "user" | "assistant"
    content: Mapped[str] = mapped_column(Text, nullable=False)
    intent: Mapped[str | None] = mapped_column(String, nullable=True)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))

    # Связи
    program: Mapped["Program"] = relationship(back_populates="conversation_messages")


class LLMProviderConfig(Base):
    """Конфигурация LLM-провайдера."""

    __tablename__ = "llm_provider_configs"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    provider: Mapped[str] = mapped_column(String, nullable=False)  # deepseek, openai, anthropic, ollama
    base_url: Mapped[str] = mapped_column(String, nullable=False)
    model: Mapped[str] = mapped_column(String, nullable=False)
    api_key_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    max_tokens: Mapped[int] = mapped_column(Integer, default=4096)
    temperature: Mapped[float] = mapped_column(Float, default=0.3)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))


class FindingAnalysisRecord(Base):
    """Результат LLM-анализа находки."""

    __tablename__ = "finding_analyses"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    vulnerability_id: Mapped[str] = mapped_column(String, ForeignKey("vulnerabilities.id"), nullable=False)
    is_real_vulnerability: Mapped[bool] = mapped_column(Boolean, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    exploitability: Mapped[str] = mapped_column(String, default="")
    reasoning: Mapped[str] = mapped_column(Text, default="")
    llm_model: Mapped[str] = mapped_column(String, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))

    # Связи
    vulnerability: Mapped["VulnerabilityRecord"] = relationship(back_populates="finding_analyses")
