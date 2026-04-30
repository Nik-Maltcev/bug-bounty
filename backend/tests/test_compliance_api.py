"""Тесты API-эндпоинта статуса соответствия.

Покрывает:
- GET /api/compliance/{program_id} — сводка по соблюдению правил

Требования: 3.4
"""

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.auth import create_access_token, hash_password
from app.core.database import get_db
from app.main import app
from app.models.database import AuditLog, Base, User


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


@pytest.fixture()
def client(db_session: Session):
    """TestClient с подменённой зависимостью get_db."""
    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture()
def user(db_session: Session) -> User:
    """Тестовый пользователь."""
    u = User(
        id="u-test",
        username="testuser",
        password_hash=hash_password("password123"),
        failed_login_attempts=0,
        locked_until=None,
    )
    db_session.add(u)
    db_session.commit()
    return u


@pytest.fixture()
def auth_header(user: User) -> dict:
    """Заголовок авторизации с валидным JWT."""
    token = create_access_token(user.username)
    return {"Authorization": f"Bearer {token}"}


def _add_audit_log(db: Session, program_id: str, result: str, details: str = "") -> None:
    """Вспомогательная функция для добавления записи в журнал аудита."""
    db.add(AuditLog(
        id=str(uuid.uuid4()),
        action_type="scan",
        target_asset="https://example.com",
        result=result,
        program_id=program_id,
        rule_reference="rule-1",
        details=details,
    ))
    db.commit()


class TestGetComplianceSummary:
    """GET /api/compliance/{program_id}"""

    def test_empty_program_returns_zeros(self, client, auth_header):
        """Программа без действий — все счётчики нулевые."""
        resp = client.get("/api/compliance/prog-1", headers=auth_header)
        assert resp.status_code == 200
        data = resp.json()
        assert data["program_id"] == "prog-1"
        assert data["total_actions"] == 0
        assert data["allowed_actions"] == 0
        assert data["blocked_actions"] == 0
        assert data["blocked_reasons"] == []

    def test_counts_allowed_actions(self, client, auth_header, db_session):
        """Подсчёт разрешённых действий."""
        _add_audit_log(db_session, "prog-1", "allowed")
        _add_audit_log(db_session, "prog-1", "allowed")

        resp = client.get("/api/compliance/prog-1", headers=auth_header)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_actions"] == 2
        assert data["allowed_actions"] == 2
        assert data["blocked_actions"] == 0

    def test_counts_blocked_actions(self, client, auth_header, db_session):
        """Подсчёт заблокированных действий."""
        _add_audit_log(db_session, "prog-1", "blocked", "DoS запрещён")
        _add_audit_log(db_session, "prog-1", "blocked", "DoS запрещён")
        _add_audit_log(db_session, "prog-1", "blocked", "Вне scope")

        resp = client.get("/api/compliance/prog-1", headers=auth_header)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_actions"] == 3
        assert data["allowed_actions"] == 0
        assert data["blocked_actions"] == 3
        reasons = {r["reason"]: r["count"] for r in data["blocked_reasons"]}
        assert reasons["DoS запрещён"] == 2
        assert reasons["Вне scope"] == 1

    def test_mixed_actions(self, client, auth_header, db_session):
        """Смешанные действия: разрешённые и заблокированные."""
        _add_audit_log(db_session, "prog-1", "allowed")
        _add_audit_log(db_session, "prog-1", "blocked", "Запрещено правилами")
        _add_audit_log(db_session, "prog-1", "allowed")

        resp = client.get("/api/compliance/prog-1", headers=auth_header)
        data = resp.json()
        assert data["total_actions"] == 3
        assert data["allowed_actions"] == 2
        assert data["blocked_actions"] == 1

    def test_isolates_by_program_id(self, client, auth_header, db_session):
        """Данные изолированы по program_id."""
        _add_audit_log(db_session, "prog-1", "allowed")
        _add_audit_log(db_session, "prog-2", "blocked", "Нарушение")

        resp = client.get("/api/compliance/prog-1", headers=auth_header)
        data = resp.json()
        assert data["total_actions"] == 1
        assert data["allowed_actions"] == 1
        assert data["blocked_actions"] == 0

        resp2 = client.get("/api/compliance/prog-2", headers=auth_header)
        data2 = resp2.json()
        assert data2["total_actions"] == 1
        assert data2["allowed_actions"] == 0
        assert data2["blocked_actions"] == 1

    def test_requires_auth(self, client):
        """Эндпоинт требует аутентификации."""
        resp = client.get("/api/compliance/prog-1")
        assert resp.status_code == 422
