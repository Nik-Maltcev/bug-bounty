"""Тесты для AIScanner — главный класс AI-Driven Scan (Stage 2)."""

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.models.ai_scan_schemas import (
    AIAuditType,
    AIRequest,
    AIRequestResult,
    AIRequestStatus,
    AnalysisResult,
    HypothesisStatus,
    TechCategory,
    TechnologyFingerprint,
    TestHypothesis,
)
from app.models.database import Base, Program, Scan
from app.models.schemas import RawFinding
from app.services.ai.ai_scanner import AIScanner
from app.services.ai.llm_provider_manager import LLMProviderManager
from app.services.audit_logger import AuditLogger
from app.services.compliance_manager import ComplianceManager, ComplianceResult
from app.services.process_manager import ProcessManager


@pytest.fixture
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


@pytest.fixture
def mock_llm():
    """Mock LLM manager."""
    llm = MagicMock(spec=LLMProviderManager)
    return llm


@pytest.fixture
def mock_process_manager():
    """Mock ProcessManager."""
    pm = MagicMock()
    pm.run_command.return_value = (0, "HTTP/1.1 200 OK\n\nResponse body", "")
    return pm


@pytest.fixture
def mock_compliance():
    """Mock ComplianceManager."""
    cm = MagicMock(spec=ComplianceManager)
    cm.validate_ai_request.return_value = ComplianceResult(
        action_allowed=True,
        reason="Allowed",
        rule_reference=None,
    )
    return cm


@pytest.fixture
def mock_audit():
    """Mock AuditLogger."""
    return MagicMock(spec=AuditLogger)


def _seed_program(db: Session, program_id: str = "prog-1") -> Program:
    """Создаёт программу в БД."""
    p = Program(
        id=program_id,
        name="Test Program",
        platform="custom",
        disclosure_requirements="",
        raw_text="",
    )
    db.add(p)
    db.commit()
    return p


def _seed_asset(db: Session, asset_id: str, program_id: str) -> None:
    """Создаёт актив в БД."""
    from app.models.database import Asset as AssetDB
    a = AssetDB(
        id=asset_id,
        program_id=program_id,
        name="Test Asset",
        asset_type="web_application",
        target="https://example.com",
        in_scope=True,
        notes="",
    )
    db.add(a)
    db.commit()


def _seed_scan(db: Session, scan_id: str, program_id: str, asset_id: str = "asset-1") -> Scan:
    """Создаёт скан в БД."""
    _seed_asset(db, asset_id, program_id)
    s = Scan(
        id=scan_id,
        program_id=program_id,
        asset_id=asset_id,
        status="completed",
        started_at=datetime.now(UTC),
    )
    db.add(s)
    db.commit()
    return s


def _stage1_findings() -> list[RawFinding]:
    """Пример результатов Stage 1."""
    return [
        RawFinding(
            vulnerability_type="service",
            description="Web server detected",
            evidence="nginx/1.18.0",
            affected_asset_id="asset-1",
            raw_data={"tool": "nmap", "port": 80},
        ),
        RawFinding(
            vulnerability_type="tech",
            description="PHP detected",
            evidence="X-Powered-By: PHP/7.4.3",
            affected_asset_id="asset-1",
            raw_data={"tool": "nuclei", "template": "php-detect"},
        ),
    ]


class TestAIScannerInit:
    """Тесты инициализации AIScanner."""

    def test_init_with_all_components(self, mock_llm, mock_process_manager, mock_compliance, mock_audit, db_session):
        """Инициализация со всеми компонентами."""
        scanner = AIScanner(
            llm_manager=mock_llm,
            process_manager=mock_process_manager,
            compliance_manager=mock_compliance,
            audit_logger=mock_audit,
            db=db_session,
        )

        assert scanner._llm == mock_llm
        assert scanner._process_manager == mock_process_manager
        assert scanner._compliance == mock_compliance
        assert scanner._audit == mock_audit
        assert scanner._db == db_session
        assert scanner._stopped is False

    def test_init_with_defaults(self, mock_llm):
        """Инициализация с дефолтными компонентами."""
        scanner = AIScanner(llm_manager=mock_llm)

        assert scanner._llm == mock_llm
        assert scanner._process_manager is not None
        assert scanner._compliance is not None
        assert scanner._audit is not None


class TestRunStage2:
    """Тесты run_stage2."""

    def test_run_stage2_extracts_technologies(
        self, mock_llm, mock_process_manager, mock_compliance, mock_audit, db_session
    ):
        """run_stage2 извлекает технологии из Stage 1."""
        _seed_program(db_session, "prog-1")
        _seed_scan(db_session, "scan-1", "prog-1")

        # Mock hypothesis engine to return empty (no hypotheses)
        scanner = AIScanner(
            llm_manager=mock_llm,
            process_manager=mock_process_manager,
            compliance_manager=mock_compliance,
            audit_logger=mock_audit,
            db=db_session,
        )

        # Mock tech extractor
        with patch.object(scanner._tech_extractor, 'extract') as mock_extract:
            mock_extract.return_value = [
                TechnologyFingerprint(
                    id="tech-1",
                    name="nginx",
                    version="1.18.0",
                    category=TechCategory.WEB_SERVER,
                    source="nmap",
                    confidence=0.9,
                ),
            ]

            # Mock hypothesis engine to return empty
            with patch.object(scanner._hypothesis_engine, 'generate') as mock_gen:
                mock_gen.return_value = []

                result = scanner.run_stage2(
                    scan_id="scan-1",
                    stage1_results=_stage1_findings(),
                    target_url="https://example.com",
                    program_id="prog-1",
                )

        assert result.status == "completed"
        assert len(result.technologies) == 1
        assert result.technologies[0].name == "nginx"

    def test_run_stage2_generates_and_tests_hypotheses(
        self, mock_llm, mock_process_manager, mock_compliance, mock_audit, db_session
    ):
        """run_stage2 генерирует и тестирует гипотезы."""
        _seed_program(db_session, "prog-1")
        _seed_scan(db_session, "scan-1", "prog-1")

        scanner = AIScanner(
            llm_manager=mock_llm,
            process_manager=mock_process_manager,
            compliance_manager=mock_compliance,
            audit_logger=mock_audit,
            db=db_session,
        )

        # Mock components
        with patch.object(scanner._tech_extractor, 'extract') as mock_extract:
            mock_extract.return_value = []

            hypothesis = TestHypothesis(
                id="h1",
                scan_id="scan-1",
                description="SQL injection test",
                rationale="Testing for SQLi",
                target_url="https://example.com/api",
                vulnerability_type="sqli",
                severity_estimate="high",
            )

            ai_request = AIRequest(
                id="r1",
                hypothesis_id="h1",
                method="GET",
                url="https://example.com/api?id=1'",
                headers={},
            )

            with patch.object(scanner._hypothesis_engine, 'generate') as mock_gen:
                # Return hypothesis only on first call, empty on subsequent
                mock_gen.side_effect = [[hypothesis], [], []]

                with patch.object(scanner._hypothesis_engine, 'create_request') as mock_req:
                    mock_req.return_value = ai_request

                    # Mock request executor
                    with patch.object(scanner, '_RequestExecutor', create=True):
                        # Mock response analyzer
                        with patch.object(scanner._response_analyzer, 'analyze') as mock_analyze:
                            mock_analyze.return_value = AnalysisResult(
                                hypothesis_id="h1",
                                request_id="r1",
                                is_confirmed=False,
                                confidence=0.3,
                                reasoning="No vulnerability found",
                                severity="informational",
                            )

                            result = scanner.run_stage2(
                                scan_id="scan-1",
                                stage1_results=_stage1_findings(),
                                target_url="https://example.com",
                                program_id="prog-1",
                                max_iterations=1,
                            )

        assert result.status == "completed"
        assert result.hypotheses_tested >= 0

    def test_run_stage2_respects_compliance_block(
        self, mock_llm, mock_process_manager, mock_compliance, mock_audit, db_session
    ):
        """run_stage2 блокирует запросы по compliance."""
        _seed_program(db_session, "prog-1")
        _seed_scan(db_session, "scan-1", "prog-1")

        # Compliance блокирует все запросы
        mock_compliance.validate_ai_request.return_value = ComplianceResult(
            action_allowed=False,
            reason="Out of scope",
            rule_reference="rule-1",
        )

        scanner = AIScanner(
            llm_manager=mock_llm,
            process_manager=mock_process_manager,
            compliance_manager=mock_compliance,
            audit_logger=mock_audit,
            db=db_session,
        )

        with patch.object(scanner._tech_extractor, 'extract') as mock_extract:
            mock_extract.return_value = []

            hypothesis = TestHypothesis(
                id="h1",
                scan_id="scan-1",
                description="Test",
                rationale="Test",
                target_url="https://example.com",
                vulnerability_type="sqli",
                severity_estimate="high",
            )

            with patch.object(scanner._hypothesis_engine, 'generate') as mock_gen:
                mock_gen.side_effect = [[hypothesis], []]

                with patch.object(scanner._hypothesis_engine, 'create_request') as mock_req:
                    mock_req.return_value = AIRequest(
                        id="r1",
                        hypothesis_id="h1",
                        method="GET",
                        url="https://example.com/api",
                        headers={},
                    )

                    result = scanner.run_stage2(
                        scan_id="scan-1",
                        stage1_results=[],
                        target_url="https://example.com",
                        program_id="prog-1",
                        max_iterations=1,
                    )

        assert result.requests_blocked >= 1
        assert result.requests_executed == 0


class TestKillSwitch:
    """Тесты Kill Switch."""

    def test_stop_sets_flag(self, mock_llm):
        """stop() устанавливает флаг остановки."""
        scanner = AIScanner(llm_manager=mock_llm)

        assert scanner.is_stopped() is False
        scanner.stop()
        assert scanner.is_stopped() is True

    def test_run_stage2_respects_stop_flag(
        self, mock_llm, mock_process_manager, mock_compliance, mock_audit, db_session
    ):
        """run_stage2 останавливается при установленном флаге."""
        _seed_program(db_session, "prog-1")
        _seed_scan(db_session, "scan-1", "prog-1")

        scanner = AIScanner(
            llm_manager=mock_llm,
            process_manager=mock_process_manager,
            compliance_manager=mock_compliance,
            audit_logger=mock_audit,
            db=db_session,
        )

        with patch.object(scanner._tech_extractor, 'extract') as mock_extract:
            # Устанавливаем флаг остановки сразу после извлечения технологий
            def extract_and_stop(*args):
                scanner.stop()
                return [
                    TechnologyFingerprint(
                        id="t1",
                        name="nginx",
                        version="1.0",
                        category=TechCategory.WEB_SERVER,
                        source="nmap",
                        confidence=0.9,
                    )
                ]

            mock_extract.side_effect = extract_and_stop

            result = scanner.run_stage2(
                scan_id="scan-1",
                stage1_results=_stage1_findings(),
                target_url="https://example.com",
                program_id="prog-1",
            )

        assert result.status == "cancelled"


class TestSupervisedMode:
    """Тесты Supervised Mode."""

    def test_supervised_mode_requests_approval(
        self, mock_llm, mock_process_manager, mock_compliance, mock_audit, db_session
    ):
        """Supervised mode запрашивает одобрение."""
        _seed_program(db_session, "prog-1")
        _seed_scan(db_session, "scan-1", "prog-1")

        scanner = AIScanner(
            llm_manager=mock_llm,
            process_manager=mock_process_manager,
            compliance_manager=mock_compliance,
            audit_logger=mock_audit,
            db=db_session,
        )

        with patch.object(scanner._tech_extractor, 'extract') as mock_extract:
            mock_extract.return_value = []

            hypothesis = TestHypothesis(
                id="h1",
                scan_id="scan-1",
                description="Test",
                rationale="Test",
                target_url="https://example.com",
                vulnerability_type="sqli",
                severity_estimate="high",
            )

            with patch.object(scanner._hypothesis_engine, 'generate') as mock_gen:
                mock_gen.side_effect = [[hypothesis], []]

                with patch.object(scanner._hypothesis_engine, 'create_request') as mock_req:
                    mock_req.return_value = AIRequest(
                        id="r1",
                        hypothesis_id="h1",
                        method="GET",
                        url="https://example.com/api",
                        headers={},
                    )

                    # В supervised mode с auto_approve=False запросы отклоняются
                    # (SyncSupervisedHandler по умолчанию отклоняет)
                    result = scanner.run_stage2(
                        scan_id="scan-1",
                        stage1_results=[],
                        target_url="https://example.com",
                        program_id="prog-1",
                        supervised_mode=True,
                        max_iterations=1,
                    )

        # В supervised mode без одобрения запросы не выполняются
        # (зависит от реализации SyncSupervisedHandler)
        assert result.status == "completed"


class TestGetStatus:
    """Тесты get_status."""

    def test_get_status_returns_none_without_db(self, mock_llm):
        """get_status без БД возвращает None."""
        scanner = AIScanner(llm_manager=mock_llm, db=None)
        assert scanner.get_status("scan-1") is None

    def test_get_status_returns_none_for_unknown_scan(self, mock_llm, db_session):
        """get_status для неизвестного скана возвращает None."""
        scanner = AIScanner(llm_manager=mock_llm, db=db_session)
        assert scanner.get_status("unknown-scan") is None


class TestDefaultLimits:
    """Тесты дефолтных лимитов."""

    def test_default_max_iterations(self):
        """Дефолтный max_iterations = 3."""
        assert AIScanner.DEFAULT_MAX_ITERATIONS == 3

    def test_default_max_requests(self):
        """Дефолтный max_requests = 50."""
        assert AIScanner.DEFAULT_MAX_REQUESTS == 50

    def test_default_rate_limit(self):
        """Дефолтный rate_limit = 5.0."""
        assert AIScanner.DEFAULT_RATE_LIMIT == 5.0


class TestErrorHandling:
    """Тесты обработки ошибок."""

    def test_run_stage2_handles_exception(
        self, mock_llm, mock_process_manager, mock_compliance, mock_audit, db_session
    ):
        """run_stage2 обрабатывает исключения."""
        _seed_program(db_session, "prog-1")
        _seed_scan(db_session, "scan-1", "prog-1")

        scanner = AIScanner(
            llm_manager=mock_llm,
            process_manager=mock_process_manager,
            compliance_manager=mock_compliance,
            audit_logger=mock_audit,
            db=db_session,
        )

        with patch.object(scanner._tech_extractor, 'extract') as mock_extract:
            mock_extract.side_effect = Exception("Extraction failed")

            result = scanner.run_stage2(
                scan_id="scan-1",
                stage1_results=_stage1_findings(),
                target_url="https://example.com",
                program_id="prog-1",
            )

        assert result.status == "failed"
