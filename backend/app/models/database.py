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
    category: Mapped[str] = mapped_column(String, default="")  # отрасль: fintech, ecommerce, healthcare, government, general

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
    raw_data_json: Mapped[str] = mapped_column(Text, default="{}")  # JSON с данными от инструментов (технологии и т.д.)
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


class ScanReport(Base):
    """Редактируемый AI-отчёт по скану."""

    __tablename__ = "scan_reports"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), nullable=False)
    report_type: Mapped[str] = mapped_column(String, default="full")  # full, medium, demo
    title: Mapped[str] = mapped_column(String, nullable=False)
    target_url: Mapped[str] = mapped_column(String, default="")
    category: Mapped[str] = mapped_column(String, default="")  # отрасль
    executive_summary: Mapped[str] = mapped_column(Text, default="")
    findings_summary: Mapped[str] = mapped_column(Text, default="")  # JSON: список находок
    risk_assessment: Mapped[str] = mapped_column(Text, default="")
    compliance_notes: Mapped[str] = mapped_column(Text, default="")
    recommendations: Mapped[str] = mapped_column(Text, default="")
    conclusion: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String, default="draft")  # draft, final
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC))


# =============================================================================
# AI-Driven Scan (Stage 2) — ORM-модели
# =============================================================================


class AITechnologyFingerprint(Base):
    """Идентифицированная технология из Stage 1."""

    __tablename__ = "ai_technology_fingerprints"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)  # nginx, php, wordpress
    version: Mapped[str | None] = mapped_column(String, nullable=True)  # 1.18.0, 7.4
    category: Mapped[str] = mapped_column(String, nullable=False)  # web_server, cms, framework
    source: Mapped[str] = mapped_column(String, nullable=False)  # nmap, nuclei, httpx
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    raw_evidence: Mapped[str] = mapped_column(Text, default="")
    known_cves_json: Mapped[str] = mapped_column(Text, default="[]")  # JSON array of CVE info
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))

    # Связи
    hypotheses: Mapped[list["AITestHypothesis"]] = relationship(
        back_populates="source_fingerprint",
        foreign_keys="AITestHypothesis.source_fingerprint_id",
    )


class AITestHypothesis(Base):
    """Гипотеза AI о потенциальной уязвимости."""

    __tablename__ = "ai_test_hypotheses"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)  # "Я тестирую это, потому что..."
    target_url: Mapped[str] = mapped_column(String, nullable=False)
    vulnerability_type: Mapped[str] = mapped_column(String, nullable=False)  # path_traversal, ssrf, sqli
    severity_estimate: Mapped[str] = mapped_column(String, nullable=False)  # critical, high, medium, low
    source_fingerprint_id: Mapped[str | None] = mapped_column(
        String, ForeignKey("ai_technology_fingerprints.id"), nullable=True
    )
    source_finding_id: Mapped[str | None] = mapped_column(String, nullable=True)  # ID из Stage 1
    parent_hypothesis_id: Mapped[str | None] = mapped_column(
        String, ForeignKey("ai_test_hypotheses.id"), nullable=True
    )
    iteration: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String, default="pending")  # pending, approved, rejected, executed, confirmed, refuted, blocked
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))

    # Связи
    source_fingerprint: Mapped["AITechnologyFingerprint | None"] = relationship(
        back_populates="hypotheses",
        foreign_keys=[source_fingerprint_id],
    )
    parent_hypothesis: Mapped["AITestHypothesis | None"] = relationship(
        remote_side="AITestHypothesis.id",
        foreign_keys=[parent_hypothesis_id],
    )
    requests: Mapped[list["AIRequestRecord"]] = relationship(
        back_populates="hypothesis",
        cascade="all, delete-orphan",
    )


class AIRequestRecord(Base):
    """HTTP-запрос, сгенерированный AI для проверки гипотезы."""

    __tablename__ = "ai_requests"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    hypothesis_id: Mapped[str] = mapped_column(String, ForeignKey("ai_test_hypotheses.id"), nullable=False)
    method: Mapped[str] = mapped_column(String, nullable=False)  # GET, POST, HEAD
    url: Mapped[str] = mapped_column(String, nullable=False)
    headers_json: Mapped[str] = mapped_column(Text, default="{}")
    body: Mapped[str | None] = mapped_column(Text, nullable=True)
    expected_indicators_json: Mapped[str] = mapped_column(Text, default="[]")
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=30)

    # Результаты выполнения
    status: Mapped[str] = mapped_column(String, default="pending")  # pending, compliance_blocked, awaiting_approval, user_rejected, executing, completed, failed, timeout
    compliance_status: Mapped[str] = mapped_column(String, default="pending")  # pending, allowed, blocked
    compliance_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    user_approved: Mapped[bool | None] = mapped_column(Boolean, nullable=True)  # None = not in supervised mode
    user_rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Ответ
    response_status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_headers_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_body: Mapped[str | None] = mapped_column(Text, nullable=True)  # обрезано до 100KB
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    executed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))

    # Связи
    hypothesis: Mapped["AITestHypothesis"] = relationship(back_populates="requests")
    analysis: Mapped["AIResponseAnalysis | None"] = relationship(
        back_populates="request",
        uselist=False,
        cascade="all, delete-orphan",
    )


class AIResponseAnalysis(Base):
    """Результат анализа ответа через LLM."""

    __tablename__ = "ai_response_analyses"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    request_id: Mapped[str] = mapped_column(String, ForeignKey("ai_requests.id"), nullable=False)
    is_confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)  # 0.0-1.0
    reasoning: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)  # critical, high, medium, low, informational
    requires_manual_review: Mapped[bool] = mapped_column(Boolean, default=False)
    follow_up_hints_json: Mapped[str] = mapped_column(Text, default="[]")
    analyzed_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))

    # Связи
    request: Mapped["AIRequestRecord"] = relationship(back_populates="analysis")


class AIFindingRecord(Base):
    """Подтверждённая находка второго этапа с PoC."""

    __tablename__ = "ai_findings"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), nullable=False)
    hypothesis_id: Mapped[str] = mapped_column(String, ForeignKey("ai_test_hypotheses.id"), nullable=False)
    vulnerability_type: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    poc_request: Mapped[str] = mapped_column(Text, nullable=False)  # полный HTTP-запрос
    poc_response: Mapped[str] = mapped_column(Text, nullable=False)  # релевантная часть ответа
    reasoning: Mapped[str] = mapped_column(Text, nullable=False)  # объяснение AI
    remediation: Mapped[str] = mapped_column(Text, default="")
    requires_manual_review: Mapped[bool] = mapped_column(Boolean, default=False)
    source_technology: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))


class AIAuditLog(Base):
    """Журнал решений AI (append-only).

    Записывает все решения AI: гипотезы, запросы, результаты compliance,
    одобрения пользователя, результаты выполнения, анализ.
    """

    __tablename__ = "ai_audit_log"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC), nullable=False)
    entry_type: Mapped[str] = mapped_column(String, nullable=False)  # tech_extracted, hypothesis_generated, etc.
    hypothesis_id: Mapped[str | None] = mapped_column(String, nullable=True)
    request_id: Mapped[str | None] = mapped_column(String, nullable=True)
    iteration: Mapped[int] = mapped_column(Integer, default=0)
    parent_test_id: Mapped[str | None] = mapped_column(String, nullable=True)
    decision: Mapped[str] = mapped_column(String, nullable=False)  # generated, approved, rejected, executed, confirmed
    reasoning: Mapped[str] = mapped_column(Text, default="")
    details_json: Mapped[str] = mapped_column(Text, default="{}")


# --- Append-only защита для AIAuditLog ---

@event.listens_for(AIAuditLog, "before_update")
def _block_ai_audit_log_update(mapper, connection, target):
    """Запрет обновления записей AI журнала аудита."""
    raise RuntimeError("AI Audit Log неизменяем (append-only): UPDATE запрещён")


@event.listens_for(AIAuditLog, "before_delete")
def _block_ai_audit_log_delete(mapper, connection, target):
    """Запрет удаления записей AI журнала аудита."""
    raise RuntimeError("AI Audit Log неизменяем (append-only): DELETE запрещён")


class AIScanState(Base):
    """Состояние AI-сканирования (Stage 2)."""

    __tablename__ = "ai_scan_states"

    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), primary_key=True)
    status: Mapped[str] = mapped_column(String, default="pending")  # pending, running, completed, cancelled, failed
    current_phase: Mapped[str] = mapped_column(String, default="")  # tech_extraction, hypothesis_generation, testing, analysis
    supervised_mode: Mapped[bool] = mapped_column(Boolean, default=False)
    max_iterations: Mapped[int] = mapped_column(Integer, default=3)
    max_requests: Mapped[int] = mapped_column(Integer, default=50)
    rate_limit: Mapped[float] = mapped_column(Float, default=5.0)

    # Счётчики
    technologies_found: Mapped[int] = mapped_column(Integer, default=0)
    hypotheses_generated: Mapped[int] = mapped_column(Integer, default=0)
    hypotheses_tested: Mapped[int] = mapped_column(Integer, default=0)
    requests_executed: Mapped[int] = mapped_column(Integer, default=0)
    requests_blocked: Mapped[int] = mapped_column(Integer, default=0)
    findings_confirmed: Mapped[int] = mapped_column(Integer, default=0)
    current_iteration: Mapped[int] = mapped_column(Integer, default=0)

    # Временные метки
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC))

    # Kill switch
    stop_requested: Mapped[bool] = mapped_column(Boolean, default=False)
