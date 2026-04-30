"""Тесты API-эндпоинтов журнала аудита.

Покрывает задачу 9.3:
- GET /api/audit — журнал аудита с фильтрацией
- GET /api/audit/export — экспорт в JSON
"""

import json
import uuid
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.auth import create_access_token, hash_password
from app.core.database import get_db
from app.main import app
from app.models.database import AuditLog, Base, Program, User


@pytest.fixture()
def db_session():
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
    def override_get_db():
        yield db_session
    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture()
def user(db_session: Session) -> User:
    u = User(
        id="u-test",
        username="testuser",
        password_hash=hash_password("password123"),
    )
    db_session.add(u)
    db_session.commit()
    return u


@pytest.fixture()
def auth_header(user: User) -> dict:
    token = create_access_token(user.username)
    return {"Authorization": f"Bearer {token}"}


def _seed_audit_entries(db: Session, count: int = 3) -> list[str]:
    """Создаёт записи аудита. Возвращает список ID."""
    prog = db.query(Program).filter(Program.id == "prog-1").first()
    if not prog:
        db.add(Program(id="prog-1", name="Test", platform="custom"))
        db.commit()

    ids = []
    for i in range(count):
        entry_id = str(uuid.uuid4())
        db.add(AuditLog(
            id=entry_id,
            timestamp=datetime.now(UTC),
            action_type="scan" if i % 2 == 0 else "report",
            target_asset="https://example.com",
            result="allowed" if i % 2 == 0 else "blocked",
            program_id="prog-1",
            rule_reference=f"rule-{i}",
            details=f"Action {i}",
        ))
        ids.append(entry_id)
    db.commit()
    return ids


class TestListAuditLog:
    """GET /api/audit"""

    def test_list_all(self, client, auth_header, db_session):
        _seed_audit_entries(db_session, 3)
        resp = client.get("/api/audit", headers=auth_header)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 3

    def test_filter_by_action_type(self, client, auth_header, db_session):
        _seed_audit_entries(db_session, 4)
        resp = client.get("/api/audit?action_type=scan", headers=auth_header)
        assert resp.status_code == 200
        data = resp.json()
        assert all(e["action_type"] == "scan" for e in data)

    def test_filter_by_result(self, client, auth_header, db_session):
        _seed_audit_entries(db_session, 4)
        resp = client.get("/api/audit?result=blocked", headers=auth_header)
        assert resp.status_code == 200
        data = resp.json()
        assert all(e["result"] == "blocked" for e in data)

    def test_filter_by_program_id(self, client, auth_header, db_session):
        _seed_audit_entries(db_session, 2)
        resp = client.get("/api/audit?program_id=prog-1", headers=auth_header)
        assert resp.status_code == 200
        assert len(resp.json()) == 2

        resp = client.get("/api/audit?program_id=nonexistent", headers=auth_header)
        assert resp.status_code == 200
        assert len(resp.json()) == 0

    def test_empty_log(self, client, auth_header):
        resp = client.get("/api/audit", headers=auth_header)
        assert resp.status_code == 200
        assert resp.json() == []

    def test_requires_auth(self, client):
        resp = client.get("/api/audit")
        assert resp.status_code == 422


class TestExportAuditLog:
    """GET /api/audit/export"""

    def test_export_valid_json(self, client, auth_header, db_session):
        _seed_audit_entries(db_session, 2)
        resp = client.get("/api/audit/export", headers=auth_header)
        assert resp.status_code == 200
        assert "application/json" in resp.headers.get("content-type", "")
        data = json.loads(resp.text)
        assert isinstance(data, list)
        assert len(data) == 2

    def test_export_with_filter(self, client, auth_header, db_session):
        _seed_audit_entries(db_session, 4)
        resp = client.get("/api/audit/export?action_type=scan", headers=auth_header)
        assert resp.status_code == 200
        data = json.loads(resp.text)
        assert all(e["action_type"] == "scan" for e in data)

    def test_export_empty(self, client, auth_header):
        resp = client.get("/api/audit/export", headers=auth_header)
        assert resp.status_code == 200
        data = json.loads(resp.text)
        assert data == []

    def test_export_requires_auth(self, client):
        resp = client.get("/api/audit/export")
        assert resp.status_code == 422
