"""Настройка SQLite-подключения и сессий SQLAlchemy.

Конфигурация базы данных для Bug Bounty Security Agent:
- SQLite для простоты развёртывания (Railway)
- Асинхронная поддержка не требуется (SQLite — однопользовательский инструмент)
- Автоматическое создание таблиц при запуске
"""

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.models.database import Base

# Путь к файлу БД: по умолчанию — в корне backend/, переопределяется через переменную окружения
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./bugbounty.db")

# Создание движка SQLAlchemy
engine = create_engine(
    DATABASE_URL,
    # SQLite требует check_same_thread=False для многопоточного доступа (FastAPI)
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
    echo=False,
)

# Фабрика сессий
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


def init_db() -> None:
    """Создание всех таблиц в базе данных (миграция при запуске).

    Вызывается при старте приложения. Создаёт таблицы, если они ещё не существуют.
    Существующие таблицы не затрагиваются (CREATE IF NOT EXISTS).
    """
    Base.metadata.create_all(bind=engine)
    
    # Миграции для новых столбцов в существующих таблицах
    _run_migrations()


def _run_migrations() -> None:
    """Добавляет новые столбцы в существующие таблицы (safe ALTER TABLE)."""
    import sqlite3
    
    db_url = engine.url.render_as_string(hide_password=False)
    if "sqlite" not in db_url:
        return
    
    # Извлекаем путь к БД
    db_path = db_url.replace("sqlite:///", "").replace("sqlite://", "")
    if not db_path or db_path == ":memory:":
        return
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Добавляем category в scans если нет
        cursor.execute("PRAGMA table_info(scans)")
        columns = [row[1] for row in cursor.fetchall()]
        if "category" not in columns:
            cursor.execute("ALTER TABLE scans ADD COLUMN category TEXT DEFAULT ''")
            conn.commit()
        
        conn.close()
    except Exception:
        pass  # Игнорируем ошибки миграции


def get_db() -> Session:
    """FastAPI-зависимость для получения сессии БД.

    Использование:
        @app.get("/example")
        def example(db: Session = Depends(get_db)):
            ...

    Yields:
        Session: сессия SQLAlchemy, автоматически закрывается после запроса.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
