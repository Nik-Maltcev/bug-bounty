"""Тесты иерархии исключений и обработчиков FastAPI."""

from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.core.exceptions import (
    AccountLockedError,
    AuthenticationError,
    BugBountyAgentError,
    ComplianceViolationError,
    InsufficientDataError,
    ParseError,
    ScanError,
)
from app.main import app


# --- Тесты иерархии исключений ---


class TestExceptionHierarchy:
    """Проверка наследования и атрибутов исключений."""

    def test_parse_error_is_bug_bounty_error(self):
        exc = ParseError(source="https://example.com", reason="невалидный формат")
        assert isinstance(exc, BugBountyAgentError)
        assert exc.source == "https://example.com"
        assert exc.reason == "невалидный формат"

    def test_compliance_violation_error_is_bug_bounty_error(self):
        exc = ComplianceViolationError(
            action="dos_attack", rule="R-001", reason="DoS запрещён"
        )
        assert isinstance(exc, BugBountyAgentError)
        assert exc.action == "dos_attack"
        assert exc.rule == "R-001"
        assert exc.reason == "DoS запрещён"

    def test_scan_error_is_bug_bounty_error(self):
        exc = ScanError(scan_id="scan-1", stage="init", reason="таймаут")
        assert isinstance(exc, BugBountyAgentError)
        assert exc.scan_id == "scan-1"
        assert exc.stage == "init"
        assert exc.reason == "таймаут"

    def test_insufficient_data_error_is_bug_bounty_error(self):
        exc = InsufficientDataError(missing_fields=["description", "evidence"])
        assert isinstance(exc, BugBountyAgentError)
        assert exc.missing_fields == ["description", "evidence"]

    def test_authentication_error_is_bug_bounty_error(self):
        exc = AuthenticationError("неверный пароль")
        assert isinstance(exc, BugBountyAgentError)

    def test_account_locked_error_is_authentication_error(self):
        locked = datetime(2025, 1, 1, 12, 0, 0)
        exc = AccountLockedError(locked_until=locked)
        assert isinstance(exc, AuthenticationError)
        assert isinstance(exc, BugBountyAgentError)
        assert exc.locked_until == locked


# --- Тесты обработчиков FastAPI ---


# Временные маршруты для тестирования обработчиков
@app.get("/test/parse-error")
async def raise_parse_error():
    raise ParseError(source="test.txt", reason="пустой файл")


@app.get("/test/compliance-error")
async def raise_compliance_error():
    raise ComplianceViolationError(
        action="scan_external", rule="R-002", reason="вне scope"
    )


@app.get("/test/scan-error")
async def raise_scan_error():
    raise ScanError(scan_id="s-1", stage="discovery", reason="сеть недоступна")


@app.get("/test/insufficient-data")
async def raise_insufficient_data():
    raise InsufficientDataError(missing_fields=["steps_to_reproduce", "evidence"])


@app.get("/test/auth-error")
async def raise_auth_error():
    raise AuthenticationError("токен истёк")


@app.get("/test/account-locked")
async def raise_account_locked():
    raise AccountLockedError(locked_until=datetime(2025, 6, 15, 10, 30, 0))


@app.get("/test/generic-error")
async def raise_generic_error():
    raise BugBountyAgentError("неизвестная ошибка")


client = TestClient(app)


class TestExceptionHandlers:
    """Проверка HTTP-ответов при возникновении исключений."""

    def test_parse_error_returns_400(self):
        resp = client.get("/test/parse-error")
        assert resp.status_code == 400
        data = resp.json()
        assert data["error"] == "parse_error"
        assert data["source"] == "test.txt"
        assert data["reason"] == "пустой файл"

    def test_compliance_violation_returns_403(self):
        resp = client.get("/test/compliance-error")
        assert resp.status_code == 403
        data = resp.json()
        assert data["error"] == "compliance_violation"
        assert data["action"] == "scan_external"
        assert data["rule"] == "R-002"

    def test_scan_error_returns_500(self):
        resp = client.get("/test/scan-error")
        assert resp.status_code == 500
        data = resp.json()
        assert data["error"] == "scan_error"
        assert data["scan_id"] == "s-1"
        assert data["stage"] == "discovery"

    def test_insufficient_data_returns_422(self):
        resp = client.get("/test/insufficient-data")
        assert resp.status_code == 422
        data = resp.json()
        assert data["error"] == "insufficient_data"
        assert "steps_to_reproduce" in data["missing_fields"]
        assert "evidence" in data["missing_fields"]

    def test_auth_error_returns_401(self):
        resp = client.get("/test/auth-error")
        assert resp.status_code == 401
        data = resp.json()
        assert data["error"] == "authentication_error"

    def test_account_locked_returns_423(self):
        resp = client.get("/test/account-locked")
        assert resp.status_code == 423
        data = resp.json()
        assert data["error"] == "account_locked"
        assert data["locked_until"] == "2025-06-15T10:30:00"

    def test_generic_agent_error_returns_500(self):
        resp = client.get("/test/generic-error")
        assert resp.status_code == 500
        data = resp.json()
        assert data["error"] == "internal_error"
