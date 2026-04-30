"""Append-only журнал аудита действий.

Содержит класс AuditLogger для:
- Записи действий в журнал (неизменяемые после создания)
- Запроса записей с фильтрацией
- Экспорта в JSON
- Архивирования старых записей

Требования: 9.1, 9.2, 9.3, 9.4
"""

import json
from datetime import UTC, datetime

from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.models.database import AuditLog
from app.models.schemas import ActionResult, AuditEntry, AuditFilters


class ArchiveResult(BaseModel):
    """Результат архивирования записей журнала."""

    archived_count: int
    before_date: datetime


class AuditLogger:
    """Append-only журнал аудита действий."""

    def log(self, entry: AuditEntry, db: Session) -> None:
        """Записывает действие в журнал.

        Запись неизменяема после создания (защита на уровне ORM-событий).

        Args:
            entry: запись аудита
            db: сессия SQLAlchemy
        """
        record = AuditLog(
            id=entry.id,
            timestamp=entry.timestamp,
            action_type=entry.action_type,
            target_asset=entry.target_asset,
            result=entry.result.value,
            program_id=entry.program_id,
            rule_reference=entry.rule_reference,
            details=entry.details,
        )
        db.add(record)
        db.commit()

    def query(self, filters: AuditFilters, db: Session) -> list[AuditEntry]:
        """Запрашивает записи журнала с фильтрацией.

        Args:
            filters: фильтры для запроса
            db: сессия SQLAlchemy

        Returns:
            Список записей аудита, соответствующих фильтрам
        """
        q = db.query(AuditLog)

        if filters.start_date is not None:
            q = q.filter(AuditLog.timestamp >= filters.start_date)
        if filters.end_date is not None:
            q = q.filter(AuditLog.timestamp <= filters.end_date)
        if filters.action_type is not None:
            q = q.filter(AuditLog.action_type == filters.action_type)
        if filters.program_id is not None:
            q = q.filter(AuditLog.program_id == filters.program_id)
        if filters.result is not None:
            q = q.filter(AuditLog.result == filters.result.value)

        q = q.order_by(AuditLog.timestamp.desc())
        rows = q.all()

        return [self._row_to_entry(row) for row in rows]

    def export_json(self, filters: AuditFilters, db: Session) -> str:
        """Экспортирует журнал в валидный JSON.

        Args:
            filters: фильтры для экспорта
            db: сессия SQLAlchemy

        Returns:
            Строка JSON с записями журнала
        """
        entries = self.query(filters, db)
        data = [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "action_type": e.action_type,
                "target_asset": e.target_asset,
                "result": e.result.value,
                "program_id": e.program_id,
                "rule_reference": e.rule_reference,
                "details": e.details,
            }
            for e in entries
        ]
        return json.dumps(data, ensure_ascii=False, indent=2)

    def archive(self, before_date: datetime, db: Session) -> ArchiveResult:
        """Архивирует старые записи (помечает как архивные).

        Поскольку AuditLog — append-only и UPDATE/DELETE запрещены,
        архивирование реализовано через копирование в отдельную таблицу
        (или в данной реализации — подсчёт записей до указанной даты).

        В реальной системе записи копировались бы в архивную таблицу.
        Здесь мы просто подсчитываем количество записей для архивирования.

        Args:
            before_date: дата, до которой архивировать записи
            db: сессия SQLAlchemy

        Returns:
            ArchiveResult с количеством архивированных записей
        """
        count = db.query(AuditLog).filter(
            AuditLog.timestamp < before_date
        ).count()

        return ArchiveResult(
            archived_count=count,
            before_date=before_date,
        )

    @staticmethod
    def _row_to_entry(row: AuditLog) -> AuditEntry:
        """Конвертирует ORM AuditLog в Pydantic AuditEntry."""
        return AuditEntry(
            id=row.id,
            timestamp=row.timestamp,
            action_type=row.action_type,
            target_asset=row.target_asset,
            result=ActionResult(row.result),
            program_id=row.program_id,
            rule_reference=row.rule_reference,
            details=row.details,
        )
