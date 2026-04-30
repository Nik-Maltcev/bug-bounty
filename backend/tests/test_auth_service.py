"""Тесты сервиса аутентификации с блокировкой аккаунта.

Покрывает:
- Успешную аутентификацию и сброс счётчика
- Инкремент неудачных попыток
- Блокировку после 3 неудачных попыток
- Отказ при заблокированном аккаунте
- Логирование инцидентов блокировки
- Пользователь не найден
"""

import logging
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.auth import hash_password
from app.core.exceptions import AccountLockedError, AuthenticationError
from app.models.database import Base, User
from app.services.auth_service import (
    LOCKOUT_DURATION_MINUTES,
    MAX_FAILED_ATTEMPTS,
    authenticate_user,
)


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
def user(db_session: Session) -> User:
    """Тестовый пользователь с известным паролем."""
    u = User(
        id="u1",
        username="alice",
        password_hash=hash_password("secret"),
        failed_login_attempts=0,
        locked_until=None,
    )
    db_session.add(u)
    db_session.commit()
    return u


class TestAuthenticateUserSuccess:
    """Успешная аутентификация."""

    def test_returns_user_on_correct_credentials(self, db_session, user):
        result = authenticate_user("alice", "secret", db_session)
        assert result.username == "alice"

    def test_resets_failed_attempts_on_success(self, db_session, user):
        # Имитируем 2 неудачные попытки
        user.failed_login_attempts = 2
        db_session.commit()

        result = authenticate_user("alice", "secret", db_session)
        assert result.failed_login_attempts == 0
        assert result.locked_until is None


class TestAuthenticateUserFailure:
    """Неудачная аутентификация."""

    def test_wrong_password_raises_auth_error(self, db_session, user):
        with pytest.raises(AuthenticationError):
            authenticate_user("alice", "wrong", db_session)

    def test_increments_failed_attempts(self, db_session, user):
        with pytest.raises(AuthenticationError):
            authenticate_user("alice", "wrong", db_session)
        db_session.refresh(user)
        assert user.failed_login_attempts == 1

    def test_user_not_found_raises_auth_error(self, db_session):
        with pytest.raises(AuthenticationError):
            authenticate_user("nonexistent", "any", db_session)


class TestAccountLockout:
    """Блокировка аккаунта после 3 неудачных попыток."""

    def test_locks_after_three_failures(self, db_session, user):
        for _ in range(2):
            with pytest.raises(AuthenticationError):
                authenticate_user("alice", "wrong", db_session)

        # Третья попытка — блокировка
        with pytest.raises(AccountLockedError):
            authenticate_user("alice", "wrong", db_session)

        db_session.refresh(user)
        assert user.failed_login_attempts == MAX_FAILED_ATTEMPTS
        assert user.locked_until is not None

    def test_locked_account_rejects_correct_password(self, db_session, user):
        user.locked_until = datetime.now(UTC) + timedelta(minutes=15)
        db_session.commit()

        with pytest.raises(AccountLockedError):
            authenticate_user("alice", "secret", db_session)

    def test_lockout_expires(self, db_session, user):
        # Блокировка в прошлом — должна быть снята
        user.locked_until = datetime.now(UTC) - timedelta(minutes=1)
        user.failed_login_attempts = 3
        db_session.commit()

        result = authenticate_user("alice", "secret", db_session)
        assert result.username == "alice"
        assert result.failed_login_attempts == 0

    def test_success_between_failures_resets_counter(self, db_session, user):
        # 2 неудачи
        for _ in range(2):
            with pytest.raises(AuthenticationError):
                authenticate_user("alice", "wrong", db_session)

        # Успешный вход — сброс
        authenticate_user("alice", "secret", db_session)
        db_session.refresh(user)
        assert user.failed_login_attempts == 0

        # Ещё 2 неудачи — не должно заблокировать
        for _ in range(2):
            with pytest.raises(AuthenticationError):
                authenticate_user("alice", "wrong", db_session)
        db_session.refresh(user)
        assert user.failed_login_attempts == 2
        assert user.locked_until is None


class TestSecurityLogging:
    """Логирование инцидентов блокировки."""

    def test_lockout_logs_security_event(self, db_session, user, caplog):
        with caplog.at_level(logging.WARNING, logger="security"):
            for _ in range(2):
                with pytest.raises(AuthenticationError):
                    authenticate_user("alice", "wrong", db_session)
            with pytest.raises(AccountLockedError):
                authenticate_user("alice", "wrong", db_session)

        assert any("Account locked" in r.message for r in caplog.records)
        assert any("alice" in r.message for r in caplog.records)
