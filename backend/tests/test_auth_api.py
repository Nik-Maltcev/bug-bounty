"""Тесты API-эндпоинтов аутентификации.

Покрывает:
- POST /api/auth/login — успешный вход, неверные данные, заблокированный аккаунт
- POST /api/auth/logout — завершение сессии
"""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.auth import create_access_token, hash_password, verify_token
from app.core.database import get_db
from app.main import app
from app.models.database import Base, User


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


class TestLoginEndpoint:
    """POST /api/auth/login"""

    def test_successful_login(self, client, user):
        resp = client.post(
            "/api/auth/login",
            json={"username": "testuser", "password": "password123"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        # Verify the token is valid and contains the correct username
        payload = verify_token(data["access_token"])
        assert payload["sub"] == "testuser"

    def test_wrong_password(self, client, user):
        resp = client.post(
            "/api/auth/login",
            json={"username": "testuser", "password": "wrong"},
        )
        assert resp.status_code == 401
        assert resp.json()["error"] == "authentication_error"

    def test_nonexistent_user(self, client):
        resp = client.post(
            "/api/auth/login",
            json={"username": "nobody", "password": "any"},
        )
        assert resp.status_code == 401

    def test_locked_account(self, client, user, db_session):
        user.locked_until = datetime.now(UTC) + timedelta(minutes=15)
        user.failed_login_attempts = 3
        db_session.commit()

        resp = client.post(
            "/api/auth/login",
            json={"username": "testuser", "password": "password123"},
        )
        assert resp.status_code == 423
        assert resp.json()["error"] == "account_locked"

    def test_lockout_after_three_failures(self, client, user):
        for _ in range(2):
            resp = client.post(
                "/api/auth/login",
                json={"username": "testuser", "password": "wrong"},
            )
            assert resp.status_code == 401

        # Third failure triggers lockout
        resp = client.post(
            "/api/auth/login",
            json={"username": "testuser", "password": "wrong"},
        )
        assert resp.status_code == 423

    def test_missing_fields(self, client):
        resp = client.post("/api/auth/login", json={"username": "testuser"})
        assert resp.status_code == 422  # Pydantic validation


class TestLogoutEndpoint:
    """POST /api/auth/logout"""

    def test_logout_returns_success(self, client):
        resp = client.post("/api/auth/logout")
        assert resp.status_code == 200
        assert "detail" in resp.json()
