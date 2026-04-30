"""Тесты API-эндпоинтов сканирования.

Покрывает задачу 6.4:
- POST /api/programs/{id}/scans — запуск сканирования
- GET /api/scans/{id} — статус сканирования
- GET /api/scans/{id}/progress — прогресс сканирования
- GET /api/programs/{id}/assets — активы программы
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
from app.models.database import Base, Program, User
from app.models.database import Asset as AssetDB


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


def _seed_program_and_asset(
    db: Session,
    program_id: str = "prog-1",
    asset_type: str = "web_application",
    target: str = "https://example.com",
    in_scope: bool = True,
) -> tuple[Program, AssetDB]:
    """Создаёт программу и актив в БД."""
    p = Program(id=program_id, name="Test Program", platform="custom")
    db.add(p)
    db.flush()
    a = AssetDB(
        id=str(uuid.uuid4()),
        program_id=program_id,
        name="Test Asset",
        asset_type=asset_type,
        target=target,
        in_scope=in_scope,
    )
    db.add(a)
    db.commit()
    return p, a


class TestStartScanAPI:
    """POST /api/programs/{id}/scans"""

    def test_start_scan_success(self, client, auth_header, db_session):
        _, asset = _seed_program_and_asset(db_session)
        resp = client.post(
            "/api/programs/prog-1/scans",
            json={"asset_id": asset.id},
            headers=auth_header,
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "completed"
        assert data["percent_complete"] == 100
        assert data["findings_count"] >= 0
        assert "scan_id" in data

    def test_start_scan_program_not_found(self, client, auth_header):
        resp = client.post(
            "/api/programs/nonexistent/scans",
            json={"asset_id": "a1"},
            headers=auth_header,
        )
        assert resp.status_code == 404

    def test_start_scan_asset_not_found(self, client, auth_header, db_session):
        _seed_program_and_asset(db_session)
        resp = client.post(
            "/api/programs/prog-1/scans",
            json={"asset_id": "nonexistent"},
            headers=auth_header,
        )
        assert resp.status_code == 404

    def test_start_scan_asset_out_of_scope(self, client, auth_header, db_session):
        _, asset = _seed_program_and_asset(db_session, in_scope=False)
        resp = client.post(
            "/api/programs/prog-1/scans",
            json={"asset_id": asset.id},
            headers=auth_header,
        )
        assert resp.status_code == 403

    def test_start_scan_requires_auth(self, client, db_session):
        _, asset = _seed_program_and_asset(db_session)
        resp = client.post(
            "/api/programs/prog-1/scans",
            json={"asset_id": asset.id},
        )
        assert resp.status_code == 422

    def test_start_scan_with_specific_checks(self, client, auth_header, db_session):
        _, asset = _seed_program_and_asset(db_session)
        resp = client.post(
            "/api/programs/prog-1/scans",
            json={"asset_id": asset.id, "check_types": ["nmap_port_scan"]},
            headers=auth_header,
        )
        assert resp.status_code == 201
        data = resp.json()
        # Real plugins return 0 findings when tools are not installed
        assert data["findings_count"] >= 0


class TestGetScanAPI:
    """GET /api/scans/{id}"""

    def test_get_scan_after_start(self, client, auth_header, db_session):
        _, asset = _seed_program_and_asset(db_session)
        start_resp = client.post(
            "/api/programs/prog-1/scans",
            json={"asset_id": asset.id},
            headers=auth_header,
        )
        scan_id = start_resp.json()["scan_id"]

        resp = client.get(f"/api/scans/{scan_id}", headers=auth_header)
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == scan_id
        assert data["status"] == "completed"
        assert data["program_id"] == "prog-1"

    def test_get_scan_not_found(self, client, auth_header):
        resp = client.get("/api/scans/nonexistent", headers=auth_header)
        assert resp.status_code == 404

    def test_get_scan_requires_auth(self, client):
        resp = client.get("/api/scans/some-id")
        assert resp.status_code == 422


class TestGetScanProgressAPI:
    """GET /api/scans/{id}/progress"""

    def test_get_progress_after_scan(self, client, auth_header, db_session):
        _, asset = _seed_program_and_asset(db_session)
        start_resp = client.post(
            "/api/programs/prog-1/scans",
            json={"asset_id": asset.id},
            headers=auth_header,
        )
        scan_id = start_resp.json()["scan_id"]

        resp = client.get(f"/api/scans/{scan_id}/progress", headers=auth_header)
        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_id"] == scan_id
        assert data["percent_complete"] == 100

    def test_get_progress_not_found(self, client, auth_header):
        resp = client.get("/api/scans/nonexistent/progress", headers=auth_header)
        assert resp.status_code == 404


class TestListProgramAssetsAPI:
    """GET /api/programs/{id}/assets"""

    def test_list_assets(self, client, auth_header, db_session):
        _seed_program_and_asset(db_session)
        resp = client.get("/api/programs/prog-1/assets", headers=auth_header)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["asset_type"] == "web_application"
        assert data[0]["target"] == "https://example.com"

    def test_list_assets_program_not_found(self, client, auth_header):
        resp = client.get("/api/programs/nonexistent/assets", headers=auth_header)
        assert resp.status_code == 404

    def test_list_assets_empty(self, client, auth_header, db_session):
        p = Program(id="prog-empty", name="Empty", platform="custom")
        db_session.add(p)
        db_session.commit()
        resp = client.get("/api/programs/prog-empty/assets", headers=auth_header)
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_assets_requires_auth(self, client, db_session):
        _seed_program_and_asset(db_session)
        resp = client.get("/api/programs/prog-1/assets")
        assert resp.status_code == 422
