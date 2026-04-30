"""Pydantic-схемы для AI-модуля.

Содержит перечисления и модели для LLM-провайдеров, чата,
классификации намерений, анализа находок и отчётов.
"""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from app.models.schemas import SeverityLevel


# --- Перечисления ---


class ProviderType(str, Enum):
    """Тип LLM-провайдера."""

    DEEPSEEK = "deepseek"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"


class IntentType(str, Enum):
    """Тип намерения пользователя."""

    SCAN = "scan"
    QUERY_RESULTS = "query_results"
    ANALYZE_FINDING = "analyze_finding"
    GENERATE_REPORT = "generate_report"
    QUERY_RULES = "query_rules"
    RECOMMENDATIONS = "recommendations"
    CLEAR_HISTORY = "clear_history"
    GENERAL = "general"


# --- Модели LLM ---


class LLMConfig(BaseModel):
    """Конфигурация LLM-провайдера."""

    provider: ProviderType
    api_key: str | None = None
    base_url: str
    model: str
    max_tokens: int = 4096
    temperature: float = 0.3


class LLMResponse(BaseModel):
    """Ответ от LLM-провайдера."""

    content: str
    model: str
    usage: dict = {}  # {"prompt_tokens": int, "completion_tokens": int, "total_tokens": int}
    provider: ProviderType


# --- Модели намерений ---


class ParsedIntent(BaseModel):
    """Результат классификации намерения."""

    intent: IntentType
    params: dict = {}  # {"target": "example.com", "scan_type": "xss", ...}
    confidence: float = Field(ge=0.0, le=1.0)


# --- Модели контекста и чата ---


class SessionContext(BaseModel):
    """Контекст сессии для LLM-запроса."""

    program_id: str
    program_name: str
    rules: list[dict] = []
    assets: list[dict] = []
    recent_findings: list[dict] = []
    recent_scans: list[dict] = []
    conversation_history: list[dict] = []


class ChatMessage(BaseModel):
    """Сообщение чата."""

    id: str
    program_id: str
    role: str  # "user" | "assistant"
    content: str
    intent: str | None = None
    metadata: dict = {}
    created_at: datetime


class ChatResponse(BaseModel):
    """Ответ AI на сообщение чата."""

    message: str
    intent: str
    metadata: dict = {}


class ChatRequest(BaseModel):
    """Запрос на отправку сообщения в чат."""

    program_id: str
    message: str = Field(max_length=10000)


# --- Модели настроек ---


class LLMSettingsRequest(BaseModel):
    """Запрос на обновление настроек LLM-провайдера."""

    provider: ProviderType
    api_key: str | None = None
    base_url: str
    model: str
    max_tokens: int = Field(default=4096, ge=256, le=32768)
    temperature: float = Field(default=0.3, ge=0.0, le=2.0)


class LLMSettingsResponse(BaseModel):
    """Ответ с текущими настройками LLM-провайдера."""

    provider: ProviderType
    base_url: str
    model: str
    max_tokens: int
    temperature: float
    is_connected: bool


# --- Модели анализа находок ---


class FindingAnalysis(BaseModel):
    """Результат LLM-анализа находки."""

    is_real_vulnerability: bool
    confidence: float = Field(ge=0.0, le=1.0)
    severity: SeverityLevel
    exploitability: str  # "easy", "moderate", "difficult", "theoretical"
    reasoning: str
    false_positive_indicators: list[str] = []


class FindingAnalysisResponse(BaseModel):
    """Ответ API с результатом анализа находки."""

    is_real_vulnerability: bool
    confidence: float
    severity: SeverityLevel
    exploitability: str
    reasoning: str


# --- Модели правил ---


class RuleAnalysisResult(BaseModel):
    """Результат анализа правил."""

    is_allowed: bool
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str
    relevant_rules: list[str] = []


# --- Модели отчётов ---


class ReportImproveRequest(BaseModel):
    """Запрос на улучшение отчёта."""

    instruction: str = Field(max_length=2000)


# --- Модели ответов ---


class ChatMessageResponse(BaseModel):
    """Ответ API с сообщением чата."""

    id: str
    role: str
    content: str
    intent: str | None = None
    metadata: dict = {}
    created_at: datetime
