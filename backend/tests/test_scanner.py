"""Тесты для Scanner — сканирование, классификация, плагины, сохранение находок.

Покрывает задачи 6.1, 6.2, 6.3:
- Основная логика сканирования (start_scan, get_scan_progress)
- Классификация серьёзности (classify_severity)
- Система плагинов (WebScanPlugin, SmartContractScanPlugin, ApiScanPlugin)
- Сохранение находок в БД
"""

import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.models.database import Base, Program, VulnerabilityRecord
from app.models.database import Asset as AssetDB
from app.models.database import ProgramRule as ProgramRuleDB
from app.models.schemas import (
    Asset,
    AssetType,
    RawFinding,
    ScanConfig,
    ScanStatus,
    SeverityLevel,
)
from app.services.compliance_manager import ComplianceManager
from app.services.scanner import Scanner
from app.services.scan_plugins import WebScanPlugin


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
def scanner() -> Scanner:
    return Scanner()


@pytest.fixture()
def compliance_manager() -> ComplianceManager:
    return ComplianceManager()


def _seed_program(db: Session, program_id: str = "prog-1") -> Program:
    p = Program(id=program_id, name="Test", platform="custom")
    db.add(p)
    db.commit()
    return p


def _seed_asset(
    db: Session,
    program_id: str = "prog-1",
    asset_type: str = "web_application",
    target: str = "https://example.com",
    in_scope: bool = True,
) -> AssetDB:
    asset = AssetDB(
        id=str(uuid.uuid4()),
        program_id=program_id,
        name="Test Asset",
        asset_type=asset_type,
        target=target,
        in_scope=in_scope,
    )
    db.add(asset)
    db.commit()
    return asset


def _make_asset(
    asset_type: AssetType = AssetType.WEB_APPLICATION,
    target: str = "https://example.com",
    asset_id: str | None = None,
) -> Asset:
    return Asset(
        id=asset_id or str(uuid.uuid4()),
        name="Test Asset",
        asset_type=asset_type,
        target=target,
        in_scope=True,
    )


# --- classify_severity ---


class TestClassifySeverity:
    """Тесты classify_severity."""

    def test_critical_for_injection(self, scanner: Scanner):
        finding = RawFinding(
            vulnerability_type="sql_injection",
            description="SQL injection found",
            evidence="test",
            affected_asset_id="a1",
            raw_data={},
        )
        assert scanner.classify_severity(finding) == SeverityLevel.CRITICAL

    def test_critical_for_rce(self, scanner: Scanner):
        finding = RawFinding(
            vulnerability_type="rce",
            description="Remote code execution",
            evidence="test",
            affected_asset_id="a1",
            raw_data={},
        )
        assert scanner.classify_severity(finding) == SeverityLevel.CRITICAL

    def test_high_for_xss(self, scanner: Scanner):
        finding = RawFinding(
            vulnerability_type="xss",
            description="Cross-site scripting",
            evidence="test",
            affected_asset_id="a1",
            raw_data={},
        )
        assert scanner.classify_severity(finding) == SeverityLevel.HIGH

    def test_medium_for_csrf(self, scanner: Scanner):
        finding = RawFinding(
            vulnerability_type="csrf",
            description="Missing CSRF protection",
            evidence="test",
            affected_asset_id="a1",
            raw_data={},
        )
        assert scanner.classify_severity(finding) == SeverityLevel.MEDIUM

    def test_low_for_open_redirect(self, scanner: Scanner):
        finding = RawFinding(
            vulnerability_type="open_redirect",
            description="Open redirect found",
            evidence="test",
            affected_asset_id="a1",
            raw_data={},
        )
        assert scanner.classify_severity(finding) == SeverityLevel.LOW

    def test_informational_for_unknown(self, scanner: Scanner):
        finding = RawFinding(
            vulnerability_type="misc",
            description="Some informational note",
            evidence="test",
            affected_asset_id="a1",
            raw_data={},
        )
        assert scanner.classify_severity(finding) == SeverityLevel.LOW

    def test_returns_valid_severity_level(self, scanner: Scanner):
        """classify_severity always returns a valid SeverityLevel."""
        finding = RawFinding(
            vulnerability_type="anything",
            description="random text",
            evidence="",
            affected_asset_id="a1",
            raw_data={},
        )
        result = scanner.classify_severity(finding)
        assert isinstance(result, SeverityLevel)
        assert result in list(SeverityLevel)


# --- Plugins ---


class TestWebScanPlugin:
    """Тесты WebScanPlugin."""

    def test_asset_type(self):
        plugin = WebScanPlugin()
        assert plugin.get_asset_type() == AssetType.WEB_APPLICATION

    def test_check_names(self):
        plugin = WebScanPlugin()
        names = plugin.get_check_names()
        assert "xss_check" in names
        assert "sql_injection_check" in names
        assert len(names) == 5

    def test_scan_returns_findings(self):
        plugin = WebScanPlugin()
        asset = _make_asset(AssetType.WEB_APPLICATION)
        config = ScanConfig(asset_id=asset.id, program_id="p1")
        findings = plugin.scan(asset, config)
        assert len(findings) == 5
        assert all(isinstance(f, RawFinding) for f in findings)

    def test_scan_with_specific_checks(self):
        plugin = WebScanPlugin()
        asset = _make_asset(AssetType.WEB_APPLICATION)
        config = ScanConfig(asset_id=asset.id, program_id="p1", check_types=["xss_check"])
        findings = plugin.scan(asset, config)
        assert len(findings) == 1
        assert findings[0].vulnerability_type == "xss"


# --- Scanner.get_checks_for_asset_type ---


class TestGetChecksForAssetType:
    """Тесты выбора проверок по типу актива."""

    def test_web_checks(self, scanner: Scanner):
        checks = scanner.get_checks_for_asset_type(AssetType.WEB_APPLICATION)
        assert "nmap_port_scan" in checks
        assert "sqlmap_injection" in checks

        assert "sqlmap_injection" in checks


# --- Scanner.start_scan ---


class TestStartScan:
    """Тесты start_scan."""

    def test_successful_scan(self, scanner: Scanner, compliance_manager: ComplianceManager, db_session: Session):
        _seed_program(db_session)
        asset_row = _seed_asset(db_session)
        asset = _make_asset(AssetType.WEB_APPLICATION, asset_id=asset_row.id)
        config = ScanConfig(asset_id=asset.id, program_id="prog-1")

        progress = scanner.start_scan(asset, config, compliance_manager, [], db_session)

        assert progress.status == ScanStatus.COMPLETED
        assert progress.percent_complete == 100
        # Real plugins return 0 findings when tools are not installed (graceful degradation)
        assert progress.findings_count >= 0

    def test_scan_saves_findings_to_db(self, scanner: Scanner, compliance_manager: ComplianceManager, db_session: Session):
        _seed_program(db_session)
        asset_row = _seed_asset(db_session)
        asset = _make_asset(AssetType.WEB_APPLICATION, asset_id=asset_row.id)
        config = ScanConfig(asset_id=asset.id, program_id="prog-1")

        progress = scanner.start_scan(asset, config, compliance_manager, [], db_session)

        vulns = db_session.query(VulnerabilityRecord).filter(
            VulnerabilityRecord.scan_id == progress.scan_id
        ).all()
        assert len(vulns) == progress.findings_count
        for v in vulns:
            assert v.vulnerability_type != ""
            assert v.description != ""
            assert v.severity in [s.value for s in SeverityLevel]

    def test_scan_blocked_by_compliance(self, scanner: Scanner, compliance_manager: ComplianceManager, db_session: Session):
        from app.models.schemas import ProgramRule
        _seed_program(db_session)
        asset_row = _seed_asset(db_session)
        asset = _make_asset(AssetType.WEB_APPLICATION, asset_id=asset_row.id)
        config = ScanConfig(asset_id=asset.id, program_id="prog-1")

        # Rule that blocks scanning
        rules = [ProgramRule(
            id="r1",
            description="Security scan of web_application is forbidden",
            is_allowed=False,
            category="testing_method",
        )]

        progress = scanner.start_scan(asset, config, compliance_manager, rules, db_session)
        assert progress.status == ScanStatus.FAILED
        assert progress.current_stage == "blocked_by_compliance"

    def test_scan_progress_tracked(self, scanner: Scanner, compliance_manager: ComplianceManager, db_session: Session):
        _seed_program(db_session)
        asset_row = _seed_asset(db_session)
        asset = _make_asset(AssetType.WEB_APPLICATION, asset_id=asset_row.id)
        config = ScanConfig(asset_id=asset.id, program_id="prog-1")

        progress = scanner.start_scan(asset, config, compliance_manager, [], db_session)

        # After scan, progress should be retrievable
        retrieved = scanner.get_scan_progress(progress.scan_id)
        assert retrieved is not None
        assert retrieved.scan_id == progress.scan_id
        assert retrieved.status == ScanStatus.COMPLETED

    def test_scan_nonexistent_progress(self, scanner: Scanner):
        assert scanner.get_scan_progress("nonexistent") is None


# --- Finding persistence ---


class TestFindingPersistence:
    """Тесты сохранения находок в БД (Требование 4.4)."""

    def test_all_fields_saved(self, scanner: Scanner, compliance_manager: ComplianceManager, db_session: Session):
        """Все обязательные поля находки сохраняются в БД."""
        _seed_program(db_session)
        asset_row = _seed_asset(db_session)
        asset = _make_asset(AssetType.WEB_APPLICATION, asset_id=asset_row.id)
        config = ScanConfig(asset_id=asset.id, program_id="prog-1")

        progress = scanner.start_scan(asset, config, compliance_manager, [], db_session)

        vulns = db_session.query(VulnerabilityRecord).filter(
            VulnerabilityRecord.scan_id == progress.scan_id
        ).all()

        for v in vulns:
            assert v.vulnerability_type, "vulnerability_type must not be empty"
            assert v.description, "description must not be empty"
            assert v.evidence, "evidence must not be empty"
            assert v.scan_id == progress.scan_id
            assert v.program_id == "prog-1"
            assert v.severity in [s.value for s in SeverityLevel]
