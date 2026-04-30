"""Сервис аутентификации с логикой блокировки аккаунта.

Реализует:
- authenticate_user: проверка учётных данных с блокировкой после 3 неудачных попыток
- Сброс счётчика при успешном входе
- Логирование инцидентов блокировки в журнал безопасности

Требования: 7.4
"""

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.core.auth import verify_password
from app.core.exceptions import AccountLockedError, AuthenticationError
from app.models.database import User

# Конфигурация блокировки
MAX_FAILED_ATTEMPTS: int = 3
LOCKOUT_DURATION_MINUTES: int = 15

# Логгер безопасности для инцидентов блокировки
security_logger = logging.getLogger("security")


def authenticate_user(username: str, password: str, db: Session) -> User:
    """Аутентификация пользователя с защитой от перебора паролей.

    Логика:
    1. Поиск пользователя по username
    2. Проверка блокировки (locked_until > now) → AccountLockedError
    3. Проверка пароля:
       - Неудача: инкремент failed_login_attempts, при >= 3 → блокировка на 15 мин
       - Успех: сброс failed_login_attempts до 0, возврат пользователя

    Args:
        username: имя пользователя
        password: пароль в открытом виде
        db: сессия SQLAlchemy

    Returns:
        User: аутентифицированный пользователь

    Raises:
        AuthenticationError: неверные учётные данные или пользователь не найден
        AccountLockedError: аккаунт заблокирован после неудачных попыток
    """
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise AuthenticationError("Неверное имя пользователя или пароль")

    # Проверка блокировки аккаунта
    _check_account_locked(user)

    # Проверка пароля
    if not verify_password(password, user.password_hash):
        _handle_failed_attempt(user, db)
        raise AuthenticationError("Неверное имя пользователя или пароль")

    # Успешный вход — сброс счётчика
    _reset_failed_attempts(user, db)
    return user


def _check_account_locked(user: User) -> None:
    """Проверяет, заблокирован ли аккаунт.

    Raises:
        AccountLockedError: если аккаунт заблокирован и время блокировки не истекло
    """
    if user.locked_until is not None:
        locked = user.locked_until
        # SQLite может хранить naive datetime — приводим к aware
        if locked.tzinfo is None:
            locked = locked.replace(tzinfo=UTC)
        if locked > datetime.now(UTC):
            raise AccountLockedError(locked_until=locked)


def _handle_failed_attempt(user: User, db: Session) -> None:
    """Обрабатывает неудачную попытку входа.

    Инкрементирует счётчик, при достижении порога — блокирует аккаунт.
    """
    user.failed_login_attempts += 1

    if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
        user.locked_until = datetime.now(UTC) + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
        db.commit()
        security_logger.warning(
            "Account locked: username=%s, failed_attempts=%d, locked_until=%s",
            user.username,
            user.failed_login_attempts,
            user.locked_until.isoformat(),
        )
        raise AccountLockedError(locked_until=user.locked_until)

    db.commit()


def _reset_failed_attempts(user: User, db: Session) -> None:
    """Сбрасывает счётчик неудачных попыток при успешном входе."""
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()
