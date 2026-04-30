"""Модуль JWT-аутентификации для Bug Bounty Security Agent.

Содержит функции для:
- Создания и верификации JWT-токенов (PyJWT)
- Хеширования и проверки паролей (bcrypt)
- FastAPI-зависимость get_current_user для защищённых маршрутов

Требования: 7.1, 7.3
"""

import os
from datetime import UTC, datetime, timedelta

import bcrypt
import jwt
from fastapi import Depends, Header
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.exceptions import AuthenticationError
from app.models.database import User

# Секретный ключ для подписи JWT — из переменной окружения или значение по умолчанию для разработки
JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "dev-secret-key-change-in-production")

# Алгоритм подписи JWT
JWT_ALGORITHM: str = "HS256"

# Время жизни токена (по умолчанию — 60 минут)
JWT_EXPIRATION_MINUTES: int = int(os.getenv("JWT_EXPIRATION_MINUTES", "60"))


def hash_password(password: str) -> str:
    """Хеширование пароля с помощью bcrypt.

    Args:
        password: пароль в открытом виде

    Returns:
        Хеш пароля (строка)
    """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Проверка пароля по хешу bcrypt.

    Args:
        password: пароль в открытом виде
        password_hash: хеш пароля из БД

    Returns:
        True если пароль совпадает, False иначе
    """
    return bcrypt.checkpw(
        password.encode("utf-8"),
        password_hash.encode("utf-8"),
    )


def create_access_token(username: str, expires_delta: timedelta | None = None) -> str:
    """Создание JWT-токена доступа.

    Args:
        username: имя пользователя для включения в payload
        expires_delta: время жизни токена (по умолчанию — JWT_EXPIRATION_MINUTES)

    Returns:
        Подписанный JWT-токен (строка)
    """
    if expires_delta is None:
        expires_delta = timedelta(minutes=JWT_EXPIRATION_MINUTES)

    now = datetime.now(UTC)
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + expires_delta,
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def verify_token(token: str) -> dict:
    """Верификация и декодирование JWT-токена.

    Args:
        token: JWT-токен для проверки

    Returns:
        Декодированный payload токена

    Raises:
        AuthenticationError: если токен невалиден или истёк
    """
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise AuthenticationError("Токен истёк")
    except jwt.InvalidTokenError:
        raise AuthenticationError("Невалидный токен")


def get_current_user(
    authorization: str = Header(..., description="Bearer <JWT-токен>"),
    db: Session = Depends(get_db),
) -> User:
    """FastAPI-зависимость для получения текущего аутентифицированного пользователя.

    Извлекает JWT из заголовка Authorization (формат: Bearer <token>),
    верифицирует токен и возвращает объект User из БД.

    Args:
        authorization: заголовок Authorization с Bearer-токеном
        db: сессия SQLAlchemy

    Returns:
        Объект User текущего пользователя

    Raises:
        AuthenticationError: если токен отсутствует, невалиден или пользователь не найден
    """
    # Извлечение токена из заголовка "Bearer <token>"
    if not authorization.startswith("Bearer "):
        raise AuthenticationError("Неверный формат заголовка Authorization. Ожидается: Bearer <token>")

    token = authorization[len("Bearer "):]
    if not token:
        raise AuthenticationError("Токен не предоставлен")

    # Верификация токена
    payload = verify_token(token)
    username: str | None = payload.get("sub")
    if username is None:
        raise AuthenticationError("Невалидный payload токена: отсутствует sub")

    # Поиск пользователя в БД
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise AuthenticationError("Пользователь не найден")

    # Проверка блокировки аккаунта
    if user.locked_until is not None:
        # SQLite может хранить naive datetime — приводим к aware для сравнения
        locked = user.locked_until
        if locked.tzinfo is None:
            locked = locked.replace(tzinfo=UTC)
        if locked > datetime.now(UTC):
            from app.core.exceptions import AccountLockedError
            raise AccountLockedError(locked_until=locked)

    return user
