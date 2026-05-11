"""Append-only журнал аудита действий.

Содержит класс AuditLogger для:
- Записи действий в журнал (неизменяемые после создания)
- Запроса записей с фильтрацией
- Экспорта в JSON
- Архивирования старых записей
- AI Audit Trail для Stage 2 (Req 9)

Требования: 9.1, 9.2, 9.3, 9.4
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.models.database import AuditLog, AIAuditLog
from app.models.schemas import ActionResult, AuditEntry, AuditFilters

if TYPE_CHECKING:
    from app.models.ai_scan_schemas import AIAuditEntry, AIAuditType


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

    # =========================================================================
    # AI Audit Trail (Stage 2) — Req 9
    # =========================================================================

    def log_ai_decision(
        self,
        scan_id: str,
        entry_type: str,
        decision: str,
        db: Session,
        hypothesis_id: str | None = None,
        request_id: str | None = None,
        iteration: int = 0,
        parent_test_id: str | None = None,
        reasoning: str = "",
        details: dict | None = None,
    ) -> str:
        """Записывает решение AI в журнал.

        Args:
            scan_id: ID сканирования.
            entry_type: тип записи (tech_extracted, hypothesis_generated, etc.).
            decision: решение (generated, approved, rejected, executed, confirmed).
            db: сессия SQLAlchemy.
            hypothesis_id: ID гипотезы (опционально).
            request_id: ID запроса (опционально).
            iteration: номер итерации.
            parent_test_id: ID родительского теста (опционально).
            reasoning: обоснование решения.
            details: дополнительные детали (dict).

        Returns:
            ID созданной записи.
        """
        entry_id = uuid.uuid4().hex[:12]

        record = AIAuditLog(
            id=entry_id,
            scan_id=scan_id,
            timestamp=datetime.now(UTC),
            entry_type=entry_type,
            hypothesis_id=hypothesis_id,
            request_id=request_id,
            iteration=iteration,
            parent_test_id=parent_test_id,
            decision=decision,
            reasoning=reasoning,
            details_json=json.dumps(details or {}, ensure_ascii=False),
        )
        db.add(record)
        db.commit()

        return entry_id

    def query_ai_trail(
        self,
        scan_id: str,
        db: Session,
        entry_type: str | None = None,
        hypothesis_id: str | None = None,
    ) -> list[dict]:
        """Запрашивает записи AI Audit Trail.

        Args:
            scan_id: ID сканирования.
            db: сессия SQLAlchemy.
            entry_type: фильтр по типу записи (опционально).
            hypothesis_id: фильтр по ID гипотезы (опционально).

        Returns:
            Список записей в виде словарей.
        """
        q = db.query(AIAuditLog).filter(AIAuditLog.scan_id == scan_id)

        if entry_type:
            q = q.filter(AIAuditLog.entry_type == entry_type)
        if hypothesis_id:
            q = q.filter(AIAuditLog.hypothesis_id == hypothesis_id)

        q = q.order_by(AIAuditLog.timestamp.asc())
        rows = q.all()

        return [
            {
                "id": row.id,
                "scan_id": row.scan_id,
                "timestamp": row.timestamp.isoformat(),
                "entry_type": row.entry_type,
                "hypothesis_id": row.hypothesis_id,
                "request_id": row.request_id,
                "iteration": row.iteration,
                "parent_test_id": row.parent_test_id,
                "decision": row.decision,
                "reasoning": row.reasoning,
                "details": json.loads(row.details_json) if row.details_json else {},
            }
            for row in rows
        ]

    def export_ai_trail(self, scan_id: str, db: Session) -> str:
        """Экспортирует AI Audit Trail в JSON.

        Args:
            scan_id: ID сканирования.
            db: сессия SQLAlchemy.

        Returns:
            JSON-строка с полным audit trail.
        """
        entries = self.query_ai_trail(scan_id, db)

        # Группируем по итерациям
        by_iteration: dict[int, list] = {}
        for entry in entries:
            iteration = entry.get("iteration", 0)
            if iteration not in by_iteration:
                by_iteration[iteration] = []
            by_iteration[iteration].append(entry)

        # Строим дерево гипотез
        hypothesis_tree = self._build_hypothesis_tree(entries)

        export_data = {
            "scan_id": scan_id,
            "exported_at": datetime.now(UTC).isoformat(),
            "total_entries": len(entries),
            "entries": entries,
            "by_iteration": by_iteration,
            "hypothesis_tree": hypothesis_tree,
            "summary": self._build_ai_trail_summary(entries),
        }

        return json.dumps(export_data, ensure_ascii=False, indent=2)

    def _build_hypothesis_tree(self, entries: list[dict]) -> dict:
        """Строит дерево гипотез из записей audit trail."""
        hypotheses: dict[str, dict] = {}

        for entry in entries:
            h_id = entry.get("hypothesis_id")
            if not h_id:
                continue

            if h_id not in hypotheses:
                hypotheses[h_id] = {
                    "hypothesis_id": h_id,
                    "parent_id": entry.get("parent_test_id"),
                    "iteration": entry.get("iteration", 0),
                    "events": [],
                    "children": [],
                }

            hypotheses[h_id]["events"].append({
                "type": entry.get("entry_type"),
                "decision": entry.get("decision"),
                "timestamp": entry.get("timestamp"),
            })

        # Связываем parent-child
        for h_id, h_data in hypotheses.items():
            parent_id = h_data.get("parent_id")
            if parent_id and parent_id in hypotheses:
                hypotheses[parent_id]["children"].append(h_id)

        # Возвращаем корневые узлы
        roots = [
            h_data for h_data in hypotheses.values()
            if not h_data.get("parent_id") or h_data.get("parent_id") not in hypotheses
        ]

        return {"roots": roots, "total_hypotheses": len(hypotheses)}

    def _build_ai_trail_summary(self, entries: list[dict]) -> dict:
        """Строит сводку по AI Audit Trail."""
        summary = {
            "total_entries": len(entries),
            "by_type": {},
            "by_decision": {},
            "technologies_extracted": 0,
            "hypotheses_generated": 0,
            "requests_executed": 0,
            "requests_blocked": 0,
            "findings_confirmed": 0,
            "user_approvals": 0,
            "user_rejections": 0,
        }

        for entry in entries:
            entry_type = entry.get("entry_type", "unknown")
            decision = entry.get("decision", "unknown")

            # Count by type
            summary["by_type"][entry_type] = summary["by_type"].get(entry_type, 0) + 1

            # Count by decision
            summary["by_decision"][decision] = summary["by_decision"].get(decision, 0) + 1

            # Specific counters
            if entry_type == "tech_extracted":
                summary["technologies_extracted"] += 1
            elif entry_type == "hypothesis_generated":
                summary["hypotheses_generated"] += 1
            elif entry_type == "request_executed":
                summary["requests_executed"] += 1
            elif entry_type == "compliance_blocked":
                summary["requests_blocked"] += 1
            elif entry_type == "finding_confirmed":
                summary["findings_confirmed"] += 1
            elif entry_type == "user_approved":
                summary["user_approvals"] += 1
            elif entry_type == "user_rejected":
                summary["user_rejections"] += 1

        return summary

    def get_ai_trail_stats(self, scan_id: str, db: Session) -> dict:
        """Возвращает статистику AI Audit Trail для API.

        Args:
            scan_id: ID сканирования.
            db: сессия SQLAlchemy.

        Returns:
            Словарь со статистикой.
        """
        entries = self.query_ai_trail(scan_id, db)
        return self._build_ai_trail_summary(entries)
