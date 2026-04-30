"""Тесты API-эндпоинтов управления программами.

Покрывает:
- POST /api/programs — импорт программы (парсинг + сохранение)
- GET /api/programs — список программ (с фильтром archived)
- GET /api/programs/{id} — детали программы
- PUT /api/programs/{id} — обновление программы
- PATCH /api/programs/{id}/archive — архивирование программы
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.auth import create_access_token, hash_password
from app.core.database import get_db
from app.main import app
from app.models.database import Base, Program, User


SAMPLE_PROGRAM_TEXT = """# Program: Test Bug Bounty
Platform: hackerone

## Assets
- [web] https://example.com (Main Website)
- [api] https://api.example.com (API)

## Rules
- [ALLOWED] Testing XSS vulnerabilities
- [FORBIDDEN] Denial of service attacks

## Rewards
- critical: $5000-$10000
- high: $1000-$5000
- medium: $500-$1000

## Disclosure
Report within 90 days
Do not disclose publicly before fix
"""


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


@pytest.fixture()
def imported_program(client, auth_header) -> dict:
    """Импортированная программа для тестов."""
    resp = client.post(
        "/api/programs",
        json={"text": SAMPLE_PROGRAM_TEXT},
        headers=auth_header,
    )
    assert resp.status_code == 201
    return resp.json()


class TestImportProgram:
    """POST /api/programs"""

    def test_import_from_text(self, client, auth_header):
        resp = client.post(
            "/api/programs",
            json={"text": SAMPLE_PROGRAM_TEXT},
            headers=auth_header,
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "Test Bug Bounty"
        assert data["platform"] == "hackerone"
        assert data["is_archived"] is False
        assert len(data["assets"]) == 2
        assert len(data["rules"]) == 2
        assert len(data["reward_tiers"]) == 3

    def test_import_saves_assets(self, client, auth_header):
        resp = client.post(
            "/api/programs",
            json={"text": SAMPLE_PROGRAM_TEXT},
            headers=auth_header,
        )
        data = resp.json()
        targets = [a["target"] for a in data["assets"]]
        assert "https://example.com" in targets
        assert "https://api.example.com" in targets

    def test_import_saves_rules(self, client, auth_header):
        resp = client.post(
            "/api/programs",
            json={"text": SAMPLE_PROGRAM_TEXT},
            headers=auth_header,
        )
        data = resp.json()
        allowed = [r for r in data["rules"] if r["is_allowed"]]
        forbidden = [r for r in data["rules"] if not r["is_allowed"]]
        assert len(allowed) == 1
        assert len(forbidden) == 1

    def test_import_saves_reward_tiers(self, client, auth_header):
        resp = client.post(
            "/api/programs",
            json={"text": SAMPLE_PROGRAM_TEXT},
            headers=auth_header,
        )
        data = resp.json()
        severities = {rt["severity"] for rt in data["reward_tiers"]}
        assert "critical" in severities
        assert "high" in severities
        assert "medium" in severities

    def test_import_empty_text_returns_400(self, client, auth_header):
        resp = client.post(
            "/api/programs",
            json={"text": ""},
            headers=auth_header,
        )
        assert resp.status_code == 400

    def test_import_requires_auth(self, client):
        resp = client.post(
            "/api/programs",
            json={"text": SAMPLE_PROGRAM_TEXT},
        )
        assert resp.status_code == 422  # missing Authorization header


class TestListPrograms:
    """GET /api/programs"""

    def test_list_empty(self, client, auth_header):
        resp = client.get("/api/programs", headers=auth_header)
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_returns_programs(self, client, auth_header, imported_program):
        resp = client.get("/api/programs", headers=auth_header)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["id"] == imported_program["id"]

    def test_list_filter_archived_false(self, client, auth_header, imported_program):
        resp = client.get("/api/programs?archived=false", headers=auth_header)
        assert resp.status_code == 200
        assert len(resp.json()) == 1

    def test_list_filter_archived_true(self, client, auth_header, imported_program):
        resp = client.get("/api/programs?archived=true", headers=auth_header)
        assert resp.status_code == 200
        assert len(resp.json()) == 0

    def test_list_requires_auth(self, client):
        resp = client.get("/api/programs")
        assert resp.status_code == 422


class TestGetProgram:
    """GET /api/programs/{id}"""

    def test_get_existing_program(self, client, auth_header, imported_program):
        pid = imported_program["id"]
        resp = client.get(f"/api/programs/{pid}", headers=auth_header)
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == pid
        assert data["name"] == "Test Bug Bounty"
        assert len(data["assets"]) == 2
        assert len(data["rules"]) == 2
        assert len(data["reward_tiers"]) == 3

    def test_get_nonexistent_program(self, client, auth_header):
        resp = client.get("/api/programs/nonexistent", headers=auth_header)
        assert resp.status_code == 404

    def test_get_requires_auth(self, client, imported_program):
        pid = imported_program["id"]
        resp = client.get(f"/api/programs/{pid}")
        assert resp.status_code == 422


class TestUpdateProgram:
    """PUT /api/programs/{id}"""

    def test_update_name(self, client, auth_header, imported_program):
        pid = imported_program["id"]
        resp = client.put(
            f"/api/programs/{pid}",
            json={"name": "Updated Name"},
            headers=auth_header,
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "Updated Name"

    def test_update_platform(self, client, auth_header, imported_program):
        pid = imported_program["id"]
        resp = client.put(
            f"/api/programs/{pid}",
            json={"platform": "bugcrowd"},
            headers=auth_header,
        )
        assert resp.status_code == 200
        assert resp.json()["platform"] == "bugcrowd"

    def test_update_partial(self, client, auth_header, imported_program):
        """Partial update should not change unspecified fields."""
        pid = imported_program["id"]
        original_platform = imported_program["platform"]
        resp = client.put(
            f"/api/programs/{pid}",
            json={"name": "New Name"},
            headers=auth_header,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "New Name"
        assert data["platform"] == original_platform

    def test_update_nonexistent(self, client, auth_header):
        resp = client.put(
            "/api/programs/nonexistent",
            json={"name": "X"},
            headers=auth_header,
        )
        assert resp.status_code == 404

    def test_update_requires_auth(self, client, imported_program):
        pid = imported_program["id"]
        resp = client.put(f"/api/programs/{pid}", json={"name": "X"})
        assert resp.status_code == 422


class TestArchiveProgram:
    """PATCH /api/programs/{id}/archive"""

    def test_archive_program(self, client, auth_header, imported_program):
        pid = imported_program["id"]
        resp = client.patch(f"/api/programs/{pid}/archive", headers=auth_header)
        assert resp.status_code == 200
        assert resp.json()["is_archived"] is True

    def test_archive_shows_in_archived_filter(self, client, auth_header, imported_program):
        pid = imported_program["id"]
        client.patch(f"/api/programs/{pid}/archive", headers=auth_header)
        resp = client.get("/api/programs?archived=true", headers=auth_header)
        assert len(resp.json()) == 1

    def test_archive_nonexistent(self, client, auth_header):
        resp = client.patch("/api/programs/nonexistent/archive", headers=auth_header)
        assert resp.status_code == 404

    def test_archive_requires_auth(self, client, imported_program):
        pid = imported_program["id"]
        resp = client.patch(f"/api/programs/{pid}/archive")
        assert resp.status_code == 422
