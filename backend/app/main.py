"""Сканер сайтов — основное FastAPI-приложение."""

import logging
import os
import sys

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.audit import router as audit_router
from app.api.auth import router as auth_router
from app.api.compliance import router as compliance_router
from app.api.programs import router as programs_router
from app.api.scans import router as scans_router
from app.api.vulnerabilities import router as vulnerabilities_router
from app.api.tools import router as tools_router
from app.api.safety import router as safety_router
from app.api.ai import router as ai_router
from app.core.database import init_db
from app.core.ai_exceptions import (
    InputTooLongError,
    LLMProviderError,
    LLMRateLimitError,
    PromptInjectionError,
)
from app.core.exceptions import (
    AccountLockedError,
    AuthenticationError,
    SiteScannerError,
    ComplianceViolationError,
    InsufficientDataError,
    ParseError,
    ScanError,
)
from app.core.tool_exceptions import (
    KillSwitchActiveError,
    NoToolsAvailableError,
    RateLimitExceededError,
    ToolIntegrationError,
)

# Разрешённые источники для CORS (по умолчанию — все, для разработки)
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")

app = FastAPI(
    title="Сканер сайтов",
    description="AI-агент для автоматизированного тестирования безопасности веб-сайтов",
    version="0.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Обработчики исключений ---


@app.exception_handler(ParseError)
async def parse_error_handler(request: Request, exc: ParseError) -> JSONResponse:
    """Обработчик ошибок парсинга → HTTP 400."""
    return JSONResponse(
        status_code=400,
        content={
            "error": "parse_error",
            "source": exc.source,
            "reason": exc.reason,
            "detail": str(exc),
        },
    )


@app.exception_handler(AuthenticationError)
async def authentication_error_handler(
    request: Request, exc: AuthenticationError
) -> JSONResponse:
    """Обработчик ошибок аутентификации → HTTP 401."""
    return JSONResponse(
        status_code=401,
        content={
            "error": "authentication_error",
            "detail": str(exc) if str(exc) else "Ошибка аутентификации",
        },
    )


@app.exception_handler(ComplianceViolationError)
async def compliance_violation_handler(
    request: Request, exc: ComplianceViolationError
) -> JSONResponse:
    """Обработчик нарушений правил программы → HTTP 403."""
    return JSONResponse(
        status_code=403,
        content={
            "error": "compliance_violation",
            "action": exc.action,
            "rule": exc.rule,
            "reason": exc.reason,
            "detail": str(exc),
        },
    )


@app.exception_handler(InsufficientDataError)
async def insufficient_data_handler(
    request: Request, exc: InsufficientDataError
) -> JSONResponse:
    """Обработчик недостаточных данных → HTTP 422."""
    return JSONResponse(
        status_code=422,
        content={
            "error": "insufficient_data",
            "missing_fields": exc.missing_fields,
            "detail": str(exc),
        },
    )


@app.exception_handler(AccountLockedError)
async def account_locked_handler(
    request: Request, exc: AccountLockedError
) -> JSONResponse:
    """Обработчик блокировки аккаунта → HTTP 423."""
    return JSONResponse(
        status_code=423,
        content={
            "error": "account_locked",
            "locked_until": exc.locked_until.isoformat(),
            "detail": str(exc),
        },
    )


@app.exception_handler(ScanError)
async def scan_error_handler(request: Request, exc: ScanError) -> JSONResponse:
    """Обработчик ошибок сканирования → HTTP 500."""
    return JSONResponse(
        status_code=500,
        content={
            "error": "scan_error",
            "scan_id": exc.scan_id,
            "stage": exc.stage,
            "detail": str(exc),
        },
    )


@app.exception_handler(SiteScannerError)
async def generic_agent_error_handler(
    request: Request, exc: SiteScannerError
) -> JSONResponse:
    """Обработчик всех прочих ошибок агента → HTTP 500."""
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_error",
            "detail": "Внутренняя ошибка сервера",
        },
    )


# --- AI exception handlers ---


@app.exception_handler(LLMRateLimitError)
async def llm_rate_limit_handler(
    request: Request, exc: LLMRateLimitError
) -> JSONResponse:
    """Превышен лимит запросов к LLM → HTTP 429."""
    return JSONResponse(
        status_code=429,
        content={
            "error": "llm_rate_limit",
            "provider": exc.provider,
            "detail": str(exc),
        },
    )


@app.exception_handler(LLMProviderError)
async def llm_provider_error_handler(
    request: Request, exc: LLMProviderError
) -> JSONResponse:
    """Ошибка LLM-провайдера → HTTP 502."""
    return JSONResponse(
        status_code=502,
        content={
            "error": "llm_provider_error",
            "provider": exc.provider,
            "reason": exc.reason,
            "detail": str(exc),
        },
    )


@app.exception_handler(InputTooLongError)
async def input_too_long_handler(
    request: Request, exc: InputTooLongError
) -> JSONResponse:
    """Превышена длина ввода → HTTP 400."""
    return JSONResponse(
        status_code=400,
        content={
            "error": "input_too_long",
            "length": exc.length,
            "max_length": exc.max_length,
            "detail": str(exc),
        },
    )


@app.exception_handler(PromptInjectionError)
async def prompt_injection_handler(
    request: Request, exc: PromptInjectionError
) -> JSONResponse:
    """Обнаружена prompt injection → HTTP 400."""
    return JSONResponse(
        status_code=400,
        content={
            "error": "prompt_injection",
            "detail": str(exc),
        },
    )


# --- Tool integration exception handlers ---


@app.exception_handler(KillSwitchActiveError)
async def kill_switch_active_handler(
    request: Request, exc: KillSwitchActiveError
) -> JSONResponse:
    """Kill Switch активен → HTTP 503."""
    return JSONResponse(
        status_code=503,
        content={
            "error": "kill_switch_active",
            "detail": str(exc),
        },
    )


@app.exception_handler(NoToolsAvailableError)
async def no_tools_available_handler(
    request: Request, exc: NoToolsAvailableError
) -> JSONResponse:
    """Нет доступных инструментов → HTTP 424."""
    return JSONResponse(
        status_code=424,
        content={
            "error": "no_tools_available",
            "asset_type": exc.asset_type.value,
            "recommended_tools": exc.recommended_tools,
            "detail": str(exc),
        },
    )


@app.exception_handler(RateLimitExceededError)
async def rate_limit_exceeded_handler(
    request: Request, exc: RateLimitExceededError
) -> JSONResponse:
    """Превышен rate limit → HTTP 429."""
    return JSONResponse(
        status_code=429,
        content={
            "error": "rate_limit_exceeded",
            "target": exc.target,
            "detail": str(exc),
        },
    )


@app.exception_handler(ToolIntegrationError)
async def tool_integration_error_handler(
    request: Request, exc: ToolIntegrationError
) -> JSONResponse:
    """Общая ошибка интеграции инструментов → HTTP 500."""
    return JSONResponse(
        status_code=500,
        content={
            "error": "tool_integration_error",
            "detail": str(exc),
        },
    )


# --- Регистрация маршрутов ---
app.include_router(auth_router)
app.include_router(audit_router)
app.include_router(compliance_router)
app.include_router(programs_router)
app.include_router(scans_router)
app.include_router(vulnerabilities_router)
app.include_router(tools_router)
app.include_router(safety_router)
app.include_router(ai_router)


@app.on_event("startup")
def on_startup():
    """Инициализация базы данных при запуске приложения."""
    init_db()
    _ensure_admin_exists()


def _ensure_admin_exists():
    """Создаёт пользователя admin если его нет."""
    import uuid
    import bcrypt
    from app.core.database import SessionLocal
    from app.models.database import User
    
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.username == "admin").first()
        if not existing:
            hashed = bcrypt.hashpw(b"admin", bcrypt.gensalt()).decode()
            user = User(
                id=str(uuid.uuid4()),
                username="admin",
                password_hash=hashed
            )
            db.add(user)
            db.commit()
            logging.info("Default admin user created: admin/admin")
        else:
            logging.info("Admin user already exists")
    except Exception as e:
        logging.error(f"Failed to create admin user: {e}")
    finally:
        db.close()


@app.get("/health")
async def health_check():
    """Проверка работоспособности сервиса."""
    return {"status": "ok", "version": app.version}
