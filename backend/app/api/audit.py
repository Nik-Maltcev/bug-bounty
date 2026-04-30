"""API-эндпоинты для журнала аудита.

Содержит:
- GET /api/audit — журнал аудита с фильтрацией
- GET /api/audit/export — экспорт журнала в JSON

Требования: 9.2
"""

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.database import get_db
from app.models.database import User
from app.models.schemas import ActionResult, AuditFilters
from app.services.audit_logger import AuditLogger

router = APIRouter(tags=["audit"])

_audit_logger = AuditLogger()


def _build_filters(
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    action_type: str | None = None,
    program_id: str | None = None,
    result: str | None = None,
) -> AuditFilters:
    """Строит AuditFilters из query-параметров."""
    return AuditFilters(
        start_date=start_date,
        end_date=end_date,
        action_type=action_type,
        program_id=program_id,
        result=ActionResult(result) if result else None,
    )


@router.get("/api/audit")
def list_audit_log(
    start_date: datetime | None = Query(None),
    end_date: datetime | None = Query(None),
    action_type: str | None = Query(None),
    program_id: str | None = Query(None),
    result: str | None = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[dict]:
    """Журнал аудита с фильтрацией."""
    filters = _build_filters(start_date, end_date, action_type, program_id, result)
    entries = _audit_logger.query(filters, db)
    return [
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


@router.get("/api/audit/export")
def export_audit_log(
    start_date: datetime | None = Query(None),
    end_date: datetime | None = Query(None),
    action_type: str | None = Query(None),
    program_id: str | None = Query(None),
    result: str | None = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PlainTextResponse:
    """Экспорт журнала аудита в JSON."""
    filters = _build_filters(start_date, end_date, action_type, program_id, result)
    json_str = _audit_logger.export_json(filters, db)
    return PlainTextResponse(content=json_str, media_type="application/json")
