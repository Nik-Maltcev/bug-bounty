"""Pydantic-схемы для AI-Driven Scan (Stage 2).

Содержит все модели данных для второго этапа сканирования:
технологии, гипотезы, запросы, результаты анализа, находки.
"""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


# --- Перечисления ---


class TechCategory(str, Enum):
    """Категория технологии."""

    WEB_SERVER = "web_server"
    CMS = "cms"
    FRAMEWORK = "framework"
    LANGUAGE = "language"
    DATABASE = "database"
    CACHE = "cache"
    CDN = "cdn"
    WAF = "waf"
    OTHER = "other"


class AIAuditType(str, Enum):
    """Тип записи в AI Audit Trail."""

    TECH_EXTRACTED = "tech_extracted"
    HYPOTHESIS_GENERATED = "hypothesis_generated"
    REQUEST_CREATED = "request_created"
    COMPLIANCE_CHECK = "compliance_check"
    COMPLIANCE_BLOCKED = "compliance_blocked"
    USER_APPROVAL_REQUESTED = "user_approval_requested"
    USER_APPROVED = "user_approved"
    USER_REJECTED = "user_rejected"
    REQUEST_EXECUTED = "request_executed"
    REQUEST_FAILED = "request_failed"
    RESPONSE_ANALYZED = "response_analyzed"
    FINDING_CONFIRMED = "finding_confirmed"
    ITERATION_STARTED = "iteration_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_CANCELLED = "scan_cancelled"


class HypothesisStatus(str, Enum):
    """Статус гипотезы."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    BLOCKED = "blocked"


class AIRequestStatus(str, Enum):
    """Статус AI-запроса."""

    PENDING = "pending"
    COMPLIANCE_BLOCKED = "compliance_blocked"
    AWAITING_APPROVAL = "awaiting_approval"
    USER_REJECTED = "user_rejected"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


# --- Технологии ---


class CVEInfo(BaseModel):
    """Информация о CVE."""

    cve_id: str
    description: str
    severity: str
    cvss_score: float | None = None
    affected_versions: str = ""
    exploit_available: bool = False


class TechnologyFingerprint(BaseModel):
    """Идентифицированная технология с версией."""

    id: str
    name: str  # "nginx", "php", "wordpress"
    version: str | None = None  # "1.18.0", "7.4", "5.8"
    category: TechCategory
    source: str  # "nmap", "nuclei", "httpx"
    confidence: float = Field(ge=0.0, le=1.0)
    raw_evidence: str = ""
    known_cves: list[CVEInfo] = []


# --- Гипотезы ---


class TestHypothesis(BaseModel):
    """Гипотеза AI о потенциальной уязвимости."""

    id: str
    scan_id: str
    description: str  # "Path traversal в nginx через ..%2f"
    rationale: str  # "Я тестирую это, потому что..."
    target_url: str
    vulnerability_type: str  # "path_traversal", "ssrf", "sqli"
    severity_estimate: str  # critical, high, medium, low
    source_fingerprint_id: str | None = None  # ссылка на TechnologyFingerprint
    source_finding_id: str | None = None  # ссылка на RawFinding Stage 1
    parent_hypothesis_id: str | None = None  # для follow-up тестов
    iteration: int = 0
    status: HypothesisStatus = HypothesisStatus.PENDING
    created_at: datetime | None = None


# --- AI-запросы ---


class AIRequest(BaseModel):
    """HTTP-запрос, сгенерированный AI для проверки гипотезы."""

    id: str
    hypothesis_id: str
    method: str  # GET, POST, HEAD
    url: str
    headers: dict[str, str] = {}
    body: str | None = None
    expected_indicators: list[str] = []  # ["root:", "etc/passwd", "500"]
    timeout_seconds: int = 30
    status: AIRequestStatus = AIRequestStatus.PENDING
    created_at: datetime | None = None


class AIRequestResult(BaseModel):
    """Результат выполнения AI-запроса."""

    request_id: str
    hypothesis_id: str
    status_code: int | None = None
    response_headers: dict[str, str] = {}
    response_body: str = ""  # обрезано до 100KB
    duration_ms: int = 0
    error: str | None = None
    executed_at: datetime | None = None


# --- Анализ ответов ---


class AnalysisResult(BaseModel):
    """Результат анализа ответа через LLM."""

    hypothesis_id: str
    request_id: str
    is_confirmed: bool
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str
    severity: str  # critical, high, medium, low, informational
    requires_manual_review: bool = False  # True если confidence 0.4-0.7
    follow_up_hints: list[str] = []  # подсказки для follow-up тестов
    analyzed_at: datetime | None = None


# --- AI Findings ---


class AIFinding(BaseModel):
    """Подтверждённая находка второго этапа с PoC."""

    id: str
    scan_id: str
    hypothesis_id: str
    vulnerability_type: str
    severity: str
    confidence: float = Field(ge=0.0, le=1.0)
    description: str
    poc_request: str  # полный HTTP-запрос
    poc_response: str  # релевантная часть ответа
    reasoning: str  # объяснение AI почему это уязвимость
    remediation: str  # рекомендации по исправлению
    requires_manual_review: bool = False
    source_technology: str | None = None  # связь с технологией
    created_at: datetime | None = None


# --- Результат сканирования ---


class Stage2Status(BaseModel):
    """Статус второго этапа сканирования."""

    scan_id: str
    status: str  # running, completed, cancelled, failed
    current_phase: str  # tech_extraction, hypothesis_generation, testing, analysis
    technologies_found: int = 0
    hypotheses_generated: int = 0
    hypotheses_tested: int = 0
    requests_executed: int = 0
    requests_blocked: int = 0
    findings_confirmed: int = 0
    current_iteration: int = 0
    max_iterations: int = 3
    percent_complete: int = Field(ge=0, le=100, default=0)
    started_at: datetime | None = None
    updated_at: datetime | None = None


class AIScanResult(BaseModel):
    """Полный результат AI-сканирования (Stage 2)."""

    scan_id: str
    status: str  # completed, cancelled, failed
    technologies: list[TechnologyFingerprint] = []
    hypotheses_tested: int = 0
    hypotheses_confirmed: int = 0
    requests_executed: int = 0
    requests_blocked: int = 0
    findings: list[AIFinding] = []
    investigation_tree: dict = {}  # дерево исследования
    audit_trail_id: str | None = None
    duration_seconds: float = 0.0
    started_at: datetime | None = None
    completed_at: datetime | None = None


# --- Supervised Mode ---


class ApprovalRequest(BaseModel):
    """Запрос на одобрение в Supervised Mode."""

    request_id: str
    scan_id: str
    hypothesis: TestHypothesis
    ai_request: AIRequest
    risks: list[str] = []  # потенциальные риски
    created_at: datetime | None = None


class ApprovalDecision(BaseModel):
    """Решение пользователя по запросу."""

    request_id: str
    approved: bool
    reason: str | None = None
    decided_at: datetime | None = None


# --- AI Audit Trail ---


class AIAuditEntry(BaseModel):
    """Запись в журнале решений AI."""

    id: str
    scan_id: str
    timestamp: datetime
    entry_type: AIAuditType
    hypothesis_id: str | None = None
    request_id: str | None = None
    iteration: int = 0
    parent_test_id: str | None = None
    decision: str  # generated, approved, rejected, executed, confirmed, etc.
    reasoning: str = ""
    details: dict = {}


# --- API Request/Response ---


class StartStage2Request(BaseModel):
    """Запрос на запуск Stage 2."""

    supervised_mode: bool = False
    max_iterations: int = Field(default=3, ge=1, le=5)
    max_requests: int = Field(default=50, ge=10, le=200)
    rate_limit: float = Field(default=5.0, ge=0.5, le=20.0)


class Stage2StopResponse(BaseModel):
    """Ответ на остановку Stage 2."""

    scan_id: str
    stopped: bool
    message: str
    requests_completed: int
    requests_pending: int
