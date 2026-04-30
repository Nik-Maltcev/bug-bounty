"""Тесты для AuditLogger.

Покрывает задачи 9.1, 9.2:
- log() — запись в журнал
- query() — запрос с фильтрацией
- export_json() — экспорт в JSON
- archive() — архивирование старых записей
"""

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.models.database import AuditLog, Base, Program
from app.models.schemas import ActionResult, AuditEntry, AuditFilters
from app.services.audit_logger import AuditLogger


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
    # Seed a program for FK
    session.add(Program(id="prog-1", name="Test", platform="custom"))
    session.commit()
    yield session
    session.close()


@pytest.fixture()
def logger():
    return AuditLogger()


def _make_entry(
    action_type: str = "scan",
    result: ActionResult = ActionResult.ALLOWED,
    program_id: str = "prog-1",
    timestamp: datetime | None = None,
) -> AuditEntry:
    return AuditEntry(
        id=str(uuid.uuid4()),
        timestamp=timestamp or datetime.now(UTC),
        action_type=action_type,
        target_asset="https://example.com",
        result=result,
        program_id=program_id,
        rule_reference="rule-1",
        details="Test action",
    )


class TestLog:
    """Тесты log()."""

    def test_log_creates_record(self, logger, db_session):
        entry = _make_entry()
        logger.log(entry, db_session)
        row = db_session.query(AuditLog).filter(AuditLog.id == entry.id).first()
        assert row is not None
        assert row.action_type == "scan"
        assert row.result == "allowed"

    def test_log_multiple_entries(self, logger, db_session):
        for _ in range(3):
            logger.log(_make_entry(), db_session)
        count = db_session.query(AuditLog).count()
        assert count == 3

    def test_logged_entry_is_immutable(self, logger, db_session):
        entry = _make_entry()
        logger.log(entry, db_session)
        row = db_session.query(AuditLog).filter(AuditLog.id == entry.id).first()
        row.action_type = "modified"
        with pytest.raises(RuntimeError, match="append-only"):
            db_session.commit()
        db_session.rollback()


class TestQuery:
    """Тесты query()."""

    def test_query_all(self, logger, db_session):
        logger.log(_make_entry(action_type="scan"), db_session)
        logger.log(_make_entry(action_type="report"), db_session)
        entries = logger.query(AuditFilters(), db_session)
        assert len(entries) == 2

    def test_query_by_action_type(self, logger, db_session):
        logger.log(_make_entry(action_type="scan"), db_session)
        logger.log(_make_entry(action_type="report"), db_session)
        entries = logger.query(AuditFilters(action_type="scan"), db_session)
        assert len(entries) == 1
        assert entries[0].action_type == "scan"

    def test_query_by_result(self, logger, db_session):
        logger.log(_make_entry(result=ActionResult.ALLOWED), db_session)
        logger.log(_make_entry(result=ActionResult.BLOCKED), db_session)
        entries = logger.query(AuditFilters(result=ActionResult.BLOCKED), db_session)
        assert len(entries) == 1
        assert entries[0].result == ActionResult.BLOCKED

    def test_query_by_program_id(self, logger, db_session):
        # Add second program
        db_session.add(Program(id="prog-2", name="Test2", platform="custom"))
        db_session.commit()
        logger.log(_make_entry(program_id="prog-1"), db_session)
        logger.log(_make_entry(program_id="prog-2"), db_session)
        entries = logger.query(AuditFilters(program_id="prog-1"), db_session)
        assert len(entries) == 1
        assert entries[0].program_id == "prog-1"

    def test_query_by_date_range(self, logger, db_session):
        now = datetime.now(UTC)
        old = now - timedelta(days=10)
        logger.log(_make_entry(timestamp=old), db_session)
        logger.log(_make_entry(timestamp=now), db_session)
        entries = logger.query(
            AuditFilters(start_date=now - timedelta(days=1)),
            db_session,
        )
        assert len(entries) == 1

    def test_query_empty(self, logger, db_session):
        entries = logger.query(AuditFilters(), db_session)
        assert entries == []


class TestExportJson:
    """Тесты export_json()."""

    def test_export_valid_json(self, logger, db_session):
        logger.log(_make_entry(), db_session)
        logger.log(_make_entry(), db_session)
        json_str = logger.export_json(AuditFilters(), db_session)
        data = json.loads(json_str)
        assert isinstance(data, list)
        assert len(data) == 2

    def test_export_json_fields(self, logger, db_session):
        logger.log(_make_entry(), db_session)
        json_str = logger.export_json(AuditFilters(), db_session)
        data = json.loads(json_str)
        entry = data[0]
        assert "id" in entry
        assert "timestamp" in entry
        assert "action_type" in entry
        assert "target_asset" in entry
        assert "result" in entry
        assert "program_id" in entry

    def test_export_json_with_filters(self, logger, db_session):
        logger.log(_make_entry(action_type="scan"), db_session)
        logger.log(_make_entry(action_type="report"), db_session)
        json_str = logger.export_json(AuditFilters(action_type="scan"), db_session)
        data = json.loads(json_str)
        assert len(data) == 1
        assert data[0]["action_type"] == "scan"

    def test_export_empty_returns_valid_json(self, logger, db_session):
        json_str = logger.export_json(AuditFilters(), db_session)
        data = json.loads(json_str)
        assert data == []


class TestArchive:
    """Тесты archive()."""

    def test_archive_counts_old_entries(self, logger, db_session):
        now = datetime.now(UTC)
        old = now - timedelta(days=30)
        logger.log(_make_entry(timestamp=old), db_session)
        logger.log(_make_entry(timestamp=old), db_session)
        logger.log(_make_entry(timestamp=now), db_session)
        result = logger.archive(now - timedelta(days=1), db_session)
        assert result.archived_count == 2

    def test_archive_no_old_entries(self, logger, db_session):
        now = datetime.now(UTC)
        logger.log(_make_entry(timestamp=now), db_session)
        result = logger.archive(now - timedelta(days=1), db_session)
        assert result.archived_count == 0
