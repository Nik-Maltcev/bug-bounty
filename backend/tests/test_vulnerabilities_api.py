"""Тесты API-эндпоинтов уязвимостей и отчётов.

Покрывает задачу 8.3:
- GET /api/vulnerabilities — список с фильтрацией
- GET /api/vulnerabilities/{id} — детали
- POST /api/vulnerabilities/{id}/report — генерация отчёта
- GET /api/reports/{id} — просмотр отчёта
- GET /api/reports/{id}/export — экспорт (md/pdf)
"""

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
from app.models.database import (
    Base,
    Program,
    Scan,
    User,
    VulnerabilityRecord,
)
from app.models.database import Asset as AssetDB


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


def _seed_full_data(db: Session) -> tuple[str, str]:
    """Создаёт программу, актив, скан и уязвимость. Возвращает (vuln_id, scan_id)."""
    prog = Program(id="prog-1", name="Test Program", platform="hackerone")
    db.add(prog)
    db.flush()

    asset = AssetDB(
        id="asset-1",
        program_id="prog-1",
        name="Web App",
        asset_type="web_application",
        target="https://example.com",
        in_scope=True,
    )
    db.add(asset)
    db.flush()

    scan = Scan(
        id="scan-1",
        program_id="prog-1",
        asset_id="asset-1",
        status="completed",
        percent_complete=100,
        started_at=datetime.now(UTC),
        completed_at=datetime.now(UTC),
    )
    db.add(scan)
    db.flush()

    vuln_id = str(uuid.uuid4())
    vuln = VulnerabilityRecord(
        id=vuln_id,
        scan_id="scan-1",
        program_id="prog-1",
        vulnerability_type="XSS",
        severity="high",
        description="Reflected XSS in search",
        steps_to_reproduce="1. Go to /search\n2. Enter payload",
        evidence="<script>alert(1)</script>",
        impact_assessment="Arbitrary JS execution",
        remediation="Sanitize input",
        status="new",
        created_at=datetime.now(UTC),
    )
    db.add(vuln)
    db.commit()
    return vuln_id, "scan-1"


class TestListVulnerabilities:
    """GET /api/vulnerabilities"""

    def test_list_all(self, client, auth_header, db_session):
        _seed_full_data(db_session)
        resp = client.get("/api/vulnerabilities", headers=auth_header)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["vulnerability_type"] == "XSS"

    def test_filter_by_severity(self, client, auth_header, db_session):
        _seed_full_data(db_session)
        resp = client.get("/api/vulnerabilities?severity=high", headers=auth_header)
        assert resp.status_code == 200
        assert len(resp.json()) == 1

        resp = client.get("/api/vulnerabilities?severity=low", headers=auth_header)
        assert resp.status_code == 200
        assert len(resp.json()) == 0

    def test_filter_by_status(self, client, auth_header, db_session):
        _seed_full_data(db_session)
        resp = client.get("/api/vulnerabilities?status=new", headers=auth_header)
        assert resp.status_code == 200
        assert len(resp.json()) == 1

        resp = client.get("/api/vulnerabilities?status=reported", headers=auth_header)
        assert resp.status_code == 200
        assert len(resp.json()) == 0

    def test_filter_by_asset_type(self, client, auth_header, db_session):
        _seed_full_data(db_session)
        resp = client.get("/api/vulnerabilities?asset_type=web_application", headers=auth_header)
        assert resp.status_code == 200
        assert len(resp.json()) == 1

        resp = client.get("/api/vulnerabilities?asset_type=smart_contract", headers=auth_header)
        assert resp.status_code == 200
        assert len(resp.json()) == 0

    def test_empty_list(self, client, auth_header):
        resp = client.get("/api/vulnerabilities", headers=auth_header)
        assert resp.status_code == 200
        assert resp.json() == []

    def test_requires_auth(self, client):
        resp = client.get("/api/vulnerabilities")
        assert resp.status_code == 422


class TestGetVulnerability:
    """GET /api/vulnerabilities/{id}"""

    def test_get_existing(self, client, auth_header, db_session):
        vuln_id, _ = _seed_full_data(db_session)
        resp = client.get(f"/api/vulnerabilities/{vuln_id}", headers=auth_header)
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == vuln_id
        assert data["severity"] == "high"

    def test_not_found(self, client, auth_header):
        resp = client.get("/api/vulnerabilities/nonexistent", headers=auth_header)
        assert resp.status_code == 404


class TestGenerateReport:
    """POST /api/vulnerabilities/{id}/report"""

    def test_generate_report_success(self, client, auth_header, db_session):
        vuln_id, _ = _seed_full_data(db_session)
        resp = client.post(f"/api/vulnerabilities/{vuln_id}/report", headers=auth_header)
        assert resp.status_code == 201
        data = resp.json()
        assert data["vulnerability_id"] == vuln_id
        assert "XSS" in data["title"]
        assert data["severity"] == "high"

    def test_generate_report_not_found(self, client, auth_header):
        resp = client.post("/api/vulnerabilities/nonexistent/report", headers=auth_header)
        assert resp.status_code == 404

    def test_generate_report_incomplete_data(self, client, auth_header, db_session):
        """Уязвимость без обязательных полей → 422."""
        prog = Program(id="prog-2", name="P2", platform="custom")
        db_session.add(prog)
        db_session.flush()
        asset = AssetDB(
            id="asset-2", program_id="prog-2", name="A2",
            asset_type="web_application", target="https://test.com",
        )
        db_session.add(asset)
        db_session.flush()
        scan = Scan(
            id="scan-2", program_id="prog-2", asset_id="asset-2",
            status="completed", percent_complete=100,
        )
        db_session.add(scan)
        db_session.flush()
        vuln = VulnerabilityRecord(
            id="vuln-incomplete", scan_id="scan-2", program_id="prog-2",
            vulnerability_type="SQLi", severity="critical",
            description="SQL injection", steps_to_reproduce="",
            evidence="", impact_assessment="", remediation="",
            status="new",
        )
        db_session.add(vuln)
        db_session.commit()

        resp = client.post("/api/vulnerabilities/vuln-incomplete/report", headers=auth_header)
        assert resp.status_code == 422


class TestGetReport:
    """GET /api/reports/{id}"""

    def test_get_report_after_generation(self, client, auth_header, db_session):
        vuln_id, _ = _seed_full_data(db_session)
        gen_resp = client.post(f"/api/vulnerabilities/{vuln_id}/report", headers=auth_header)
        report_id = gen_resp.json()["id"]

        resp = client.get(f"/api/reports/{report_id}", headers=auth_header)
        assert resp.status_code == 200
        assert resp.json()["id"] == report_id

    def test_report_not_found(self, client, auth_header):
        resp = client.get("/api/reports/nonexistent", headers=auth_header)
        assert resp.status_code == 404


class TestExportReport:
    """GET /api/reports/{id}/export"""

    def test_export_markdown(self, client, auth_header, db_session):
        vuln_id, _ = _seed_full_data(db_session)
        gen_resp = client.post(f"/api/vulnerabilities/{vuln_id}/report", headers=auth_header)
        report_id = gen_resp.json()["id"]

        resp = client.get(f"/api/reports/{report_id}/export?format=md", headers=auth_header)
        assert resp.status_code == 200
        assert "text/markdown" in resp.headers.get("content-type", "")
        assert "## Описание" in resp.text

    def test_export_pdf(self, client, auth_header, db_session):
        vuln_id, _ = _seed_full_data(db_session)
        gen_resp = client.post(f"/api/vulnerabilities/{vuln_id}/report", headers=auth_header)
        report_id = gen_resp.json()["id"]

        resp = client.get(f"/api/reports/{report_id}/export?format=pdf", headers=auth_header)
        assert resp.status_code == 200
        assert "application/pdf" in resp.headers.get("content-type", "")
        assert len(resp.content) > 0

    def test_export_not_found(self, client, auth_header):
        resp = client.get("/api/reports/nonexistent/export?format=md", headers=auth_header)
        assert resp.status_code == 404
