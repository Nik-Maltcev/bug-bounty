"""API-эндпоинты аутентификации.

Содержит:
- POST /api/auth/login — аутентификация, возврат JWT
- POST /api/auth/logout — завершение сессии (stateless)

Требования: 7.1, 7.3
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.auth import create_access_token
from app.core.database import get_db
from app.services.auth_service import authenticate_user

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    """Запрос на аутентификацию."""

    username: str
    password: str


class LoginResponse(BaseModel):
    """Ответ с JWT-токеном."""

    access_token: str
    token_type: str = "bearer"


@router.post("/login", response_model=LoginResponse)
def login(body: LoginRequest, db: Session = Depends(get_db)) -> LoginResponse:
    """Аутентификация пользователя и выдача JWT-токена.

    Raises:
        AuthenticationError: неверные учётные данные
        AccountLockedError: аккаунт заблокирован
    """
    user = authenticate_user(body.username, body.password, db)
    token = create_access_token(user.username)
    return LoginResponse(access_token=token)


@router.post("/logout")
def logout() -> dict:
    """Завершение сессии.

    JWT — stateless, поэтому серверная инвалидация не требуется.
    Клиент должен удалить токен из памяти браузера.
    """
    return {"detail": "Сессия завершена"}
