"""Тесты модуля JWT-аутентификации (app/core/auth.py).

Покрывает:
- Хеширование и проверку паролей (bcrypt)
- Создание и верификацию JWT-токенов
- FastAPI-зависимость get_current_user
"""

from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.auth import (
    JWT_ALGORITHM,
    JWT_SECRET_KEY,
    create_access_token,
    get_current_user,
    hash_password,
    verify_password,
    verify_token,
)
from app.core.exceptions import AccountLockedError, AuthenticationError
from app.models.database import Base, User


# --- Фикстуры ---

@pytest.fixture()
def db_session():
    """Создаёт in-memory SQLite БД и сессию для тестов."""
    # StaticPool + check_same_thread=False — необходимо для in-memory SQLite с TestClient
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestSession = sessionmaker(bind=engine)
    session = TestSession()
    yield session
    session.close()


@pytest.fixture()
def test_user(db_session: Session) -> User:
    """Создаёт тестового пользователя в БД."""
    user = User(
        id="user-1",
        username="testuser",
        password_hash=hash_password("correct-password"),
        failed_login_attempts=0,
        locked_until=None,
    )
    db_session.add(user)
    db_session.commit()
    return user


# --- Тесты хеширования паролей ---


class TestPasswordHashing:
    """Проверка хеширования и верификации паролей."""

    def test_hash_password_returns_string(self):
        hashed = hash_password("mypassword")
        assert isinstance(hashed, str)
        assert hashed != "mypassword"

    def test_hash_password_produces_different_hashes(self):
        """Каждый вызов генерирует уникальный хеш (разные salt)."""
        h1 = hash_password("same")
        h2 = hash_password("same")
        assert h1 != h2

    def test_verify_password_correct(self):
        hashed = hash_password("secret123")
        assert verify_password("secret123", hashed) is True

    def test_verify_password_incorrect(self):
        hashed = hash_password("secret123")
        assert verify_password("wrong", hashed) is False

    def test_verify_password_empty(self):
        hashed = hash_password("")
        assert verify_password("", hashed) is True
        assert verify_password("notempty", hashed) is False


# --- Тесты JWT-токенов ---


class TestJWTTokens:
    """Проверка создания и верификации JWT-токенов."""

    def test_create_access_token_returns_string(self):
        token = create_access_token("alice")
        assert isinstance(token, str)
        assert len(token) > 0

    def test_create_access_token_contains_username(self):
        token = create_access_token("bob")
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        assert payload["sub"] == "bob"

    def test_create_access_token_has_expiration(self):
        token = create_access_token("charlie")
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        assert "exp" in payload
        assert "iat" in payload

    def test_create_access_token_custom_expiration(self):
        delta = timedelta(minutes=5)
        token = create_access_token("dave", expires_delta=delta)
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        # Проверяем, что exp примерно через 5 минут от iat
        assert payload["exp"] - payload["iat"] == pytest.approx(300, abs=2)

    def test_verify_token_valid(self):
        token = create_access_token("eve")
        payload = verify_token(token)
        assert payload["sub"] == "eve"

    def test_verify_token_expired(self):
        token = create_access_token("frank", expires_delta=timedelta(seconds=-1))
        with pytest.raises(AuthenticationError, match="Токен истёк"):
            verify_token(token)

    def test_verify_token_invalid_signature(self):
        token = jwt.encode(
            {"sub": "hacker", "exp": datetime.now(UTC) + timedelta(hours=1)},
            "wrong-secret",
            algorithm=JWT_ALGORITHM,
        )
        with pytest.raises(AuthenticationError, match="Невалидный токен"):
            verify_token(token)

    def test_verify_token_malformed(self):
        with pytest.raises(AuthenticationError, match="Невалидный токен"):
            verify_token("not.a.valid.token")


# --- Тесты FastAPI-зависимости get_current_user ---


class TestGetCurrentUser:
    """Проверка FastAPI-зависимости для аутентификации."""

    def _make_app(self, db_session: Session) -> TestClient:
        """Создаёт тестовое FastAPI-приложение с зависимостью get_current_user."""
        from app.core.database import get_db

        test_app = FastAPI()

        @test_app.exception_handler(AuthenticationError)
        async def auth_error_handler(request: Request, exc: AuthenticationError):
            return JSONResponse(status_code=401, content={"error": str(exc)})

        @test_app.exception_handler(AccountLockedError)
        async def locked_handler(request: Request, exc: AccountLockedError):
            return JSONResponse(
                status_code=423,
                content={"error": "account_locked", "locked_until": exc.locked_until.isoformat()},
            )

        @test_app.get("/protected")
        def protected_route(user: User = Depends(get_current_user)):
            return {"username": user.username}

        # Подмена зависимости get_db на тестовую сессию
        def override_get_db():
            yield db_session

        test_app.dependency_overrides[get_db] = override_get_db

        return TestClient(test_app)

    def test_valid_token_returns_user(self, db_session, test_user):
        client = self._make_app(db_session)
        token = create_access_token(test_user.username)
        resp = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["username"] == "testuser"

    def test_missing_authorization_header(self, db_session, test_user):
        client = self._make_app(db_session)
        resp = client.get("/protected")
        assert resp.status_code == 422  # FastAPI валидация обязательного заголовка

    def test_invalid_bearer_format(self, db_session, test_user):
        client = self._make_app(db_session)
        resp = client.get("/protected", headers={"Authorization": "Token abc123"})
        assert resp.status_code == 401

    def test_expired_token(self, db_session, test_user):
        client = self._make_app(db_session)
        token = create_access_token(test_user.username, expires_delta=timedelta(seconds=-1))
        resp = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401

    def test_user_not_found(self, db_session, test_user):
        client = self._make_app(db_session)
        token = create_access_token("nonexistent")
        resp = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401

    def test_locked_user(self, db_session, test_user):
        # Блокируем пользователя на 15 минут
        test_user.locked_until = datetime.now(UTC) + timedelta(minutes=15)
        db_session.commit()

        client = self._make_app(db_session)
        token = create_access_token(test_user.username)
        resp = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 423
